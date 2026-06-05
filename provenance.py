"""Provenance tracing: where a value was set, where it was used.

Builds a per-HAR correlation index once (cached), then answers trace/cookie/token
queries against it without re-scanning the whole file each call.
"""
from __future__ import annotations

import json
from typing import Any, Optional

import har_parser as hp
from har_parser import (MIN_TRACE_LEN, TRACE_HITS_MAX, parse_request,
                        parse_response, parse_cookies, get_all_headers,
                        looks_secret, store)


# --------------------------------------------------------------------------- #
# Index build (lazy, cached on the HAR record)                                 #
# --------------------------------------------------------------------------- #
def build_index(name: str) -> Optional[dict]:
    rec = store.get(name)
    if rec is None:
        return None
    if rec.get("_index") is not None:
        return rec["_index"]

    set_cookies: list[dict] = []
    req_cookies: list[dict] = []
    req_headers: list[dict] = []
    resp_headers: list[dict] = []
    req_bodies: list[dict] = []
    resp_bodies: list[dict] = []

    for i, entry in enumerate(rec["entries"]):
        req = parse_request(entry)
        for h in req["headers"]:
            hn, hv = h.get("name", ""), h.get("value", "")
            req_headers.append({"entry": i, "name": hn, "value": hv})
            if hn.lower() == "cookie":
                for c in parse_cookies(hv):
                    req_cookies.append({"entry": i, "name": c["name"],
                                        "value": c["value"]})
        if req["body"]:
            req_bodies.append({"entry": i, "text": req["body"], "url": _u(req)})

        resp = entry.get("response", {}) or {}
        rheaders = resp.get("headers", []) or []
        for h in rheaders:
            resp_headers.append({"entry": i, "name": h.get("name", ""),
                                 "value": h.get("value", "")})
        for sc in get_all_headers(rheaders, "set-cookie"):
            for c in parse_cookies(sc, set_cookie=True):
                set_cookies.append({"entry": i, "name": c["name"],
                                    "value": c["value"], "attrs": c["attrs"],
                                    "url": _u(req)})
        parsed = parse_response(entry)
        if not parsed["is_binary"] and parsed["text"]:
            resp_bodies.append({"entry": i, "text": parsed["text"], "url": _u(req)})

    index = {
        "set_cookies": set_cookies,
        "req_cookies": req_cookies,
        "req_headers": req_headers,
        "resp_headers": resp_headers,
        "req_bodies": req_bodies,
        "resp_bodies": resp_bodies,
        "urls": {i: _u(parse_request(e)) for i, e in enumerate(rec["entries"])},
    }
    rec["_index"] = index
    return index


def _u(req: dict) -> str:
    return f"{req.get('method', '')} {req.get('path', '') or req.get('url', '')}".strip()


def _preview(value: str) -> str:
    redacted = looks_secret(value)
    head = value[:8]
    tail = "…" if len(value) > 8 else ""
    flag = ", redacted" if redacted else ""
    return f"{head}{tail} (len {len(value)}{flag})"


def _json_path(text: str, value: str) -> Optional[str]:
    """If text is JSON and value sits in it, return a dotted path. Best effort."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None

    def walk(node: Any, path: str) -> Optional[str]:
        if isinstance(node, str) and value in node:
            return path or "$"
        if isinstance(node, dict):
            for k, v in node.items():
                r = walk(v, f"{path}.{k}" if path else k)
                if r:
                    return r
        if isinstance(node, list):
            for idx, v in enumerate(node):
                r = walk(v, f"{path}[{idx}]")
                if r:
                    return r
        return None

    return walk(data, "")


# --------------------------------------------------------------------------- #
# trace_value — the flagship                                                    #
# --------------------------------------------------------------------------- #
def trace_value(name: str, value: str) -> dict:
    if not isinstance(value, str) or len(value) < MIN_TRACE_LEN:
        return {"error": f"value too short to trace reliably (min {MIN_TRACE_LEN} chars)"}
    index = build_index(name)
    if index is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}

    set_by: list[dict] = []
    used_in: list[dict] = []

    # Produced by responses (Set-Cookie + response bodies)
    for c in index["set_cookies"]:
        if value in c["value"]:
            set_by.append({"entry": c["entry"], "where": "response.set_cookie",
                           "key": c["name"], "url": c["url"]})
    for b in index["resp_bodies"]:
        if value in b["text"]:
            jp = _json_path(b["text"], value)
            set_by.append({"entry": b["entry"], "where": "response.body",
                           "key": jp, "url": b["url"]})

    # Consumed by later requests (headers, cookies, body)
    for h in index["req_headers"]:
        if value in (h["value"] or ""):
            used_in.append({"entry": h["entry"], "where": "request.header",
                            "key": h["name"], "url": index["urls"].get(h["entry"], "")})
    for c in index["req_cookies"]:
        if value in c["value"]:
            used_in.append({"entry": c["entry"], "where": "request.cookie",
                            "key": c["name"], "url": index["urls"].get(c["entry"], "")})
    for b in index["req_bodies"]:
        if value in b["text"]:
            jp = _json_path(b["text"], value)
            used_in.append({"entry": b["entry"], "where": "request.body",
                            "key": jp, "url": b["url"]})

    set_by.sort(key=lambda x: x["entry"])
    used_in.sort(key=lambda x: x["entry"])

    truncated = False
    if len(set_by) + len(used_in) > TRACE_HITS_MAX:
        truncated = True
        set_by = set_by[:TRACE_HITS_MAX]
        used_in = used_in[:TRACE_HITS_MAX]

    timeline = sorted({h["entry"] for h in set_by} | {h["entry"] for h in used_in})
    origin = set_by[0] if set_by else (used_in[0] if used_in else None)

    return {
        "value_preview": _preview(value),
        "set_by": set_by,
        "used_in": used_in,
        "timeline": timeline,
        "origin": {"entry": origin["entry"], "where": origin["where"]} if origin else None,
        "truncated": truncated,
    }


def trace_header(name: str, header_name: str) -> dict:
    index = build_index(name)
    if index is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}
    hn = header_name.lower()
    sends = [{"entry": h["entry"], "value": h["value"],
              "url": index["urls"].get(h["entry"], "")}
             for h in index["req_headers"] if h["name"].lower() == hn]
    # Try to find where each value originated (a response that contained it).
    for s in sends:
        s["origin"] = None
        val = s["value"]
        if not val or hn in ("user-agent", "accept", "host"):
            continue
        for b in index["resp_bodies"]:
            if b["entry"] < s["entry"] and val in b["text"]:
                s["origin"] = {"entry": b["entry"], "where": "response.body"}
                break
        if s["origin"] is None:
            for c in index["set_cookies"]:
                if c["entry"] < s["entry"] and val in c["value"]:
                    s["origin"] = {"entry": c["entry"], "where": "response.set_cookie"}
                    break
    return {"header": header_name, "sent_in": sends[:TRACE_HITS_MAX],
            "truncated": len(sends) > TRACE_HITS_MAX}


def cookie_map(name: str) -> dict:
    index = build_index(name)
    if index is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}
    cookies: dict[str, dict] = {}
    for c in index["set_cookies"]:
        info = cookies.setdefault(c["name"], {"set_in": [], "used_in": [], "attrs": {}})
        info["set_in"].append(c["entry"])
        info["attrs"] = c["attrs"]
    for c in index["req_cookies"]:
        info = cookies.setdefault(c["name"], {"set_in": [], "used_in": [], "attrs": {}})
        info["used_in"].append(c["entry"])
    return {"cookies": [{"name": k, **v} for k, v in cookies.items()],
            "count": len(cookies)}


# Per-request diagnostic headers carry high-entropy values that are NOT shared
# secrets (a fresh value every response), so they bury the real tokens. Matched
# by generic naming conventions common to any HTTP server, not specific names.
_NOISE_HEADER_SUBSTRINGS = ("debug", "trace", "request-id", "requestid",
                            "correlation", "x-request", "trip-id")
_NOISE_HEADERS_EXACT = {"etag", "date", "age", "expires", "last-modified"}
# Composite name=value pair headers we already track parsed (avoid phantom tokens).
_COMPOSITE_HEADERS = {"cookie", "set-cookie"}


def _is_noise_header(name: str) -> bool:
    n = name.lower()
    if n in _NOISE_HEADERS_EXACT:
        return True
    return any(sub in n for sub in _NOISE_HEADER_SUBSTRINGS)


def token_map(name: str, all_tokens: bool = False) -> dict:
    """High-entropy secret values: where set vs where used.

    By default returns only *interesting* tokens — those reused across more than
    one request (real shared secrets), filtering out per-request diagnostic
    noise (debug/trace/request-id headers, etags). Pass all_tokens=True for the
    unfiltered set.
    """
    index = build_index(name)
    if index is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}
    seen: dict[str, dict] = {}

    _PER_TOKEN_CAP = 20  # don't let one token emit a giant occurrence list

    def note(value: str, entry: int, role: str, where: str, hdr: str = ""):
        if not looks_secret(value):
            return
        if not all_tokens and hdr and _is_noise_header(hdr):
            return
        info = seen.setdefault(value, {"preview": _preview(value),
                                       "set_by": [], "used_in": [], "_counts": {}})
        info["_counts"][role] = info["_counts"].get(role, 0) + 1
        lst = info[role]
        if len(lst) < _PER_TOKEN_CAP:
            lst.append({"entry": entry, "where": where})

    for c in index["set_cookies"]:
        note(c["value"], c["entry"], "set_by", f"set_cookie:{c['name']}")
    for h in index["resp_headers"]:
        if h["name"].lower() not in _COMPOSITE_HEADERS:
            note(h["value"], h["entry"], "set_by", f"resp_header:{h['name']}", h["name"])
    for h in index["req_headers"]:
        if h["name"].lower() not in _COMPOSITE_HEADERS:
            note(h["value"], h["entry"], "used_in", f"req_header:{h['name']}", h["name"])
    for c in index["req_cookies"]:
        note(c["value"], c["entry"], "used_in", f"req_cookie:{c['name']}")

    # Promote true occurrence counts (full, not the capped list length) and
    # drop the internal bookkeeping field.
    for t in seen.values():
        c = t.pop("_counts")
        t["set_count"] = c.get("set_by", 0)
        t["used_count"] = c.get("used_in", 0)

    tokens = list(seen.values())
    if not all_tokens:
        # Keep tokens that appear in 2+ places (set+used or used multiple times)
        # — i.e. actually shared/propagated, the provenance-interesting ones.
        tokens = [t for t in tokens
                  if t["set_count"] + t["used_count"] >= 2]
    tokens.sort(key=lambda t: t["set_count"] + t["used_count"], reverse=True)
    total = len(tokens)
    return {"tokens": tokens[:TRACE_HITS_MAX], "count": total,
            "truncated": total > TRACE_HITS_MAX, "filtered": not all_tokens}
