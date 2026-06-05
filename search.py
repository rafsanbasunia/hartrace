"""Search / discovery primitives for API testing.

Regex search across scopes, header finder, URL finder, endpoint listing,
query-param extraction. All paginated, clamped, never raising.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Optional

from har_parser import _page, parse_request, parse_response, store

_SCOPES = {"url", "req_headers", "resp_headers", "req_body", "resp_body", "all"}
_CONTEXT = 60  # chars of context around a regex match


def _entries(name: str):
    rec = store.get(name)
    return None if rec is None else rec["entries"]


def _scope_texts(entry: dict, scope: str) -> list[tuple[str, str]]:
    """Return [(scope_label, text)] for the requested scope of one entry."""
    req = parse_request(entry)
    out: list[tuple[str, str]] = []
    if scope in ("url", "all"):
        out.append(("url", req["url"]))
    if scope in ("req_headers", "all"):
        out.append(("req_headers",
                    "\n".join(f"{h.get('name','')}: {h.get('value','')}"
                              for h in req["headers"])))
    if scope in ("req_body", "all"):
        out.append(("req_body", req["body"]))
    if scope in ("resp_headers", "all"):
        rheaders = (entry.get("response", {}) or {}).get("headers", []) or []
        out.append(("resp_headers",
                    "\n".join(f"{h.get('name','')}: {h.get('value','')}"
                              for h in rheaders)))
    if scope in ("resp_body", "all"):
        parsed = parse_response(entry)
        out.append(("resp_body", "" if parsed["is_binary"] else parsed["text"]))
    return out


def search_regex(name: str, pattern: str, scope: str = "all",
                 limit=50, offset=0) -> dict:
    entries = _entries(name)
    if entries is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}
    if scope not in _SCOPES:
        return {"error": f"scope must be one of {sorted(_SCOPES)}"}
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return {"error": f"bad regex: {exc}"}

    limit, offset = _page(limit, offset)
    hits: list[dict] = []
    total = 0
    for i, entry in enumerate(entries):
        for label, text in _scope_texts(entry, scope):
            if not text:
                continue
            for m in rx.finditer(text):
                total += 1
                if offset <= total - 1 < offset + limit:
                    s, e = m.span()
                    ctx = text[max(0, s - _CONTEXT):e + _CONTEXT].replace("\n", " ")
                    hits.append({"entry": i, "scope": label,
                                 "match": m.group(0)[:200],
                                 "context": ctx[:300]})
    return {"total": total, "offset": offset, "limit": limit, "items": hits}


def find_header(name: str, header_name: str, limit=50, offset=0) -> dict:
    entries = _entries(name)
    if entries is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}
    limit, offset = _page(limit, offset)
    hn = header_name.lower()
    items: list[dict] = []
    total = 0
    for i, entry in enumerate(entries):
        req = entry.get("request", {}) or {}
        resp = entry.get("response", {}) or {}
        for side, headers in (("request", req.get("headers", []) or []),
                              ("response", resp.get("headers", []) or [])):
            for h in headers:
                if (h.get("name") or "").lower() == hn:
                    total += 1
                    if offset <= total - 1 < offset + limit:
                        items.append({"entry": i, "side": side,
                                      "value": h.get("value", "")})
    return {"total": total, "offset": offset, "limit": limit, "items": items}


def find_urls(name: str, pattern: str, limit=50, offset=0) -> dict:
    entries = _entries(name)
    if entries is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}
    limit, offset = _page(limit, offset)
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return {"error": f"bad regex: {exc}"}
    items: list[dict] = []
    total = 0
    for i, entry in enumerate(entries):
        req = parse_request(entry)
        if rx.search(req["url"]):
            total += 1
            if offset <= total - 1 < offset + limit:
                items.append({"entry": i, "method": req["method"], "url": req["url"]})
    return {"total": total, "offset": offset, "limit": limit, "items": items}


def list_endpoints(name: str, group_by: str = "path", limit=50, offset=0) -> dict:
    entries = _entries(name)
    if entries is None:
        return {"error": f"no HAR named '{name}' (loaded: {store.names()})"}
    if group_by not in ("path", "host"):
        return {"error": "group_by must be 'path' or 'host'"}
    limit, offset = _page(limit, offset)
    counter: Counter = Counter()
    for entry in entries:
        req = parse_request(entry)
        key = (f"{req['method']} {req['host']}{req['path']}" if group_by == "path"
               else req["host"])
        counter[key] += 1
    ordered = counter.most_common()
    total = len(ordered)
    page = ordered[offset:offset + limit]
    return {"total": total, "offset": offset, "limit": limit,
            "items": [{"endpoint": k, "count": c} for k, c in page]}


def get_query_params(name: str, index: int) -> dict:
    res = store.get_entry(name, index)
    if "error" in res:
        return res
    req = parse_request(res["entry"])
    return {"url": req["url"], "query": req["query"]}
