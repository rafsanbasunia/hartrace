"""HAR / HTTP traffic analysis MCP server.

stdio transport only. FastMCP owns stdout; all logging goes to stderr.
Every tool returns structured output and never raises to the transport.
"""
from __future__ import annotations

import logging
import os
import sys

from fastmcp import FastMCP

import har_parser as hp
import provenance as prov
import search as srch
from har_parser import _page, RESP_CHARS_MAX, LISTDIR_MAX, store

_INSTRUCTIONS = """\
HAR / HTTP traffic analyzer. Analyze captured web/app traffic (.har files)
WITHOUT reading raw JSON into context — every tool extracts and caps server-side.

Typical workflow:
  1. list_har_files(dir) → load_har(path)   load a capture; note the returned `name`
     (or load_har_url(url) for a remote .har)
  2. list_requests / list_endpoints          get a cheap overview
  3. search_regex / find_header / find_urls   locate specific requests or values
  4. get_request / get_response / get_headers inspect one entry (secrets redacted)
  5. trace_value / trace_header / cookie_map / token_map
                                              PROVENANCE: where a value came from
                                              and where it was reused

KEY IDEA — provenance. trace_value(har, "<any string>") answers
"where did this value come from and where was it used?" for ANY value:
auth tokens, cookies, CSRF tokens, ids, device fingerprints, body fields,
query params. It is NOT cookie-only. It returns set_by (the response that
produced it) + used_in (later requests that sent it), with JSON paths.

All list tools paginate (limit/offset, clamped to 200). All output is size-capped.
Secrets are redacted in inspection tools; trace tools correlate on the raw value
but only show a redacted preview. Every tool returns {error: "..."} on failure,
never an exception. Refer to a loaded HAR by the `name` returned from load_har.
"""

mcp = FastMCP("har-analyzer", instructions=_INSTRUCTIONS)


def _guard(fn, *args, **kwargs):
    """Run a handler body; convert any exception to a clean {error}."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # never raise to the transport
        logging.getLogger("har").exception("tool error")
        return {"error": f"{type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# Load / inventory                                                              #
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_har_files(dir: str, limit: int = 50, offset: int = 0) -> dict:
    """Browse a folder for .har files to load (the file-picker step).

    WHEN: the user mentions a folder but not an exact file, or you need to
    discover what captures are available before load_har.
    DOES: lists *.har in `dir` (newest first), with size and mtime. Never opens
    or parses the files. Bounded to 1000 files; non-directory → {error}.
    ARGS: dir = absolute folder path. limit/offset paginate (limit clamped ≤200).
    RETURNS: {total, offset, limit, items:[{name, path, size, modified}]}
    EXAMPLE: list_har_files("C:/dumps") → pick a name → load_har(that path).
    """
    def body():
        real = os.path.realpath(dir)
        if not os.path.isdir(real):
            return {"error": f"not a directory: {dir}"}
        lim, off = _page(limit, offset)
        files = []
        try:
            for ent in os.scandir(real):
                if len(files) >= LISTDIR_MAX:
                    break
                if ent.is_file() and ent.name.lower().endswith(".har"):
                    st = ent.stat()
                    files.append({"name": ent.name, "path": ent.path,
                                  "size": st.st_size, "modified": int(st.st_mtime)})
        except PermissionError as exc:
            return {"error": f"permission denied: {exc}"}
        files.sort(key=lambda f: f["modified"], reverse=True)
        return {"total": len(files), "offset": off, "limit": lim,
                "items": files[off:off + lim]}
    return _guard(body)


@mcp.tool()
def load_har(path: str, name: str = "") -> dict:
    """Load a .har capture into memory. ALWAYS the first step before analysis.

    WHEN: the user gives a path to a .har file, or after list_har_files.
    DOES: validates (exists, .har extension, ≤500MB, ≤50k entries, valid HAR
    JSON) and parses. Returns the `name` you must pass to every other tool.
    ARGS: path = absolute path to the .har. name = optional label; if it
    collides with an already-loaded HAR a unique suffix is added (e.g. cap-2)
    and the ACTUAL assigned name is returned — use that.
    RETURNS: {ok:true, name, entry_count} or {ok:false, error}
    EXAMPLE: load_har("C:/dumps/login.har") → {ok, name:"login", entry_count:112}
    """
    return _guard(store.load, path, name)


@mcp.tool()
def load_har_url(url: str, name: str = "") -> dict:
    """Load a .har capture from an http(s) URL instead of a local file.

    WHEN: the HAR lives at a remote URL (a shared link, an artifact store, a
    teammate's server) rather than on local disk.
    DOES: downloads over http/https and parses it like load_har. SSRF-guarded —
    refuses private/loopback/internal/link-local addresses — and size-capped at
    500MB. Same validation and collision-safe naming as load_har.
    ARGS: url = http(s) URL to the .har. name = optional label (else derived
    from the URL path/host). The ACTUAL assigned name is returned — use it.
    RETURNS: {ok:true, name, entry_count} or {ok:false, error}
    EXAMPLE: load_har_url("https://example.com/captures/login.har")
    """
    return _guard(store.load_url, url, name)


@mcp.tool()
def list_hars() -> dict:
    """List the HARs currently loaded in memory.

    WHEN: you forgot a HAR's name, or to check what's available before a tool
    call that needs a har_name. DOES NOT load anything.
    RETURNS: {hars:[{name, entry_count, path}]}
    """
    return _guard(lambda: {"hars": store.list()})


@mcp.tool()
def unload_har(har_name: str) -> dict:
    """Drop a loaded HAR to free memory. Rarely needed.

    WHEN: a long session has loaded several large HARs and you're done with one.
    RETURNS: {ok:true} if removed, {ok:false} if no HAR had that name.
    """
    return _guard(lambda: {"ok": store.unload(har_name)})


# --------------------------------------------------------------------------- #
# Inspect                                                                       #
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_requests(har_name: str, filter: str = "", limit: int = 50,
                  offset: int = 0) -> dict:
    """Cheap overview of requests — your map of the capture. Start here.

    WHEN: right after load_har, to see what's in the HAR, or to find the
    `index` of a request to inspect with get_request/get_response/get_headers.
    DOES: one compact row per request (index, method, url, status, response
    size). The `index` is the stable handle used by all per-entry tools.
    ARGS: filter = case-insensitive URL substring (""=all). limit/offset paginate.
    RETURNS: {total, offset, limit, items:[{index, method, url, status, response_size}]}
    EXAMPLE: list_requests("cap", filter="/login") → rows whose URL has "/login".
    TIP: for body/header content search use search_regex; for URL patterns use
    find_urls; this filters on the URL only.
    """
    def body():
        entries = store.get_entries(har_name)
        if entries is None:
            return {"error": f"no HAR named '{har_name}' (loaded: {store.names()})"}
        lim, off = _page(limit, offset)
        f = (filter or "").lower()
        matched = []
        for i, entry in enumerate(entries):
            req = hp.parse_request(entry)
            if f and f not in req["url"].lower():
                continue
            matched.append((i, entry, req))
        total = len(matched)
        items = []
        for i, entry, req in matched[off:off + lim]:
            resp = entry.get("response", {}) or {}
            items.append({
                "index": i, "method": req["method"], "url": req["url"],
                "status": resp.get("status", 0),
                "response_size": (resp.get("content", {}) or {}).get("size", 0),
            })
        return {"total": total, "offset": off, "limit": lim, "items": items}
    return _guard(body)


@mcp.tool()
def get_request(har_name: str, index: int) -> dict:
    """Inspect ONE request in full: method, url, query, headers, body.

    WHEN: you have an `index` (from list_requests/search) and want the full
    request detail. DOES: decodes the body and unwraps nested JSON-in-strings.
    Sensitive headers (authorization, cookie, x-api-key, ...) and high-entropy
    secret values are shown as <REDACTED len=N> so they don't leak into context
    — to follow a redacted value's origin, copy it from find_header (raw) into
    trace_value.
    ARGS: index = the request's index from list_requests.
    RETURNS: {method, url, query[], headers[], params[], body} or {error}
    EXAMPLE: get_request("cap", 12) → full request #12, secrets masked.
    """
    def body():
        res = store.get_entry(har_name, index)
        if "error" in res:
            return res
        req = hp.parse_request(res["entry"])
        decoded_body = hp.deep_decode(req["body"]) if req["body"] else ""
        return {
            "method": req["method"], "url": req["url"],
            "query": req["query"],
            "headers": hp.redact_headers(req["headers"]),
            "params": hp.redact(req["params"]),
            "body": hp.redact(decoded_body) if isinstance(decoded_body, (dict, list))
                    else (hp._redact_str(decoded_body) if hp.looks_secret(decoded_body)
                          else decoded_body),
        }
    return _guard(body)


@mcp.tool()
def get_response(har_name: str, index: int, max_chars: int = 4000) -> dict:
    """Inspect ONE response body, decoded and size-capped.

    WHEN: you want to see what a request returned (e.g. the JSON a /login call
    responded with). DOES: handles base64 + gzip/deflate HAR encoding, unwraps
    nested JSON-in-strings, pretty-prints JSON. Binary bodies (images, protobuf)
    are detected and return is_binary=true with a placeholder — never raw bytes.
    ARGS: index = request index. max_chars = max body chars to return
    (default 4000, hard-capped at 50000). If the body was cut, truncated=true.
    RETURNS: {status, size, truncated, is_binary, body}
    EXAMPLE: get_response("cap", 0, max_chars=2000) → first 2000 chars of the
    decoded JSON of response #0, truncated flag tells you if there's more.
    """
    def body():
        res = store.get_entry(har_name, index)
        if "error" in res:
            return res
        parsed = hp.parse_response(res["entry"])
        if parsed["is_binary"]:
            return {"status": parsed["status"], "size": parsed["size"],
                    "truncated": False, "is_binary": True,
                    "body": "<binary response body omitted>"}
        cap = max(1, min(int(max_chars) if str(max_chars).lstrip("-").isdigit()
                         else 4000, RESP_CHARS_MAX))
        text = parsed["text"]
        # Try to pretty-unwrap nested JSON for readability.
        try:
            import json
            text = json.dumps(hp.deep_decode(json.loads(text)), indent=2)
        except (ValueError, TypeError):
            pass
        truncated = len(text) > cap
        return {"status": parsed["status"], "size": parsed["size"],
                "truncated": truncated, "is_binary": False, "body": text[:cap]}
    return _guard(body)


@mcp.tool()
def get_headers(har_name: str, index: int) -> dict:
    """Get both request AND response headers for one entry (secrets redacted).

    WHEN: you want just the headers of a specific request/response pair without
    the bodies. DOES: returns both sides; sensitive/high-entropy values masked.
    ARGS: index = request index.
    RETURNS: {request:[{name,value}], response:[{name,value}]} or {error}
    """
    def body():
        res = store.get_entry(har_name, index)
        if "error" in res:
            return res
        entry = res["entry"]
        req_h = (entry.get("request", {}) or {}).get("headers", []) or []
        resp_h = (entry.get("response", {}) or {}).get("headers", []) or []
        return {"request": hp.redact_headers(req_h),
                "response": hp.redact_headers(resp_h)}
    return _guard(body)


# --------------------------------------------------------------------------- #
# Search                                                                        #
# --------------------------------------------------------------------------- #
@mcp.tool()
def search_regex(har_name: str, pattern: str, scope: str = "all",
                 limit: int = 50, offset: int = 0) -> dict:
    """Full-text REGEX search across the whole capture — the most powerful finder.

    WHEN: you're looking for a value/pattern but don't know which request has it
    — a token, an email, "password", a Bearer header, an error string, anything
    in URLs, headers, OR bodies. This searches request AND response BODIES too,
    which list_requests/find_urls (URL-only) and find_header (name-only) cannot.
    ARGS: pattern = Python regex (e.g. "Bearer \\S+", "user_id=\\d+").
    scope = where to search: url | req_headers | resp_headers | req_body |
    resp_body | all (default all). Invalid regex → {error:"bad regex: ..."}.
    RETURNS: {total, offset, limit, items:[{entry, scope, match, context}]}
    where `context` is ~60 chars around the hit. Once you find an entry, pass
    its `entry` index to get_request/get_response, or the `match` to trace_value.
    EXAMPLE: search_regex("cap", "csrf[_-]?token", scope="resp_body").
    """
    return _guard(srch.search_regex, har_name, pattern, scope, limit, offset)


@mcp.tool()
def find_header(har_name: str, header_name: str, limit: int = 50,
                offset: int = 0) -> dict:
    """List every request/response that carries a named header, with its values.

    WHEN: "which requests send an Authorization header and what's the value?",
    or to grab a header's RAW (un-redacted) value to feed into trace_value.
    Unlike get_request/get_headers, values here are NOT redacted — this is the
    tool for extracting a token to then trace.
    ARGS: header_name = case-insensitive (e.g. "authorization", "set-cookie").
    RETURNS: {total, offset, limit, items:[{entry, side:"request"|"response", value}]}
    EXAMPLE: find_header("cap","authorization") → every entry + OAuth/Bearer value.
    """
    return _guard(srch.find_header, har_name, header_name, limit, offset)


@mcp.tool()
def find_urls(har_name: str, pattern: str, limit: int = 50,
              offset: int = 0) -> dict:
    """Find requests whose URL matches a regex pattern.

    WHEN: you want all calls to a particular endpoint/host/path pattern.
    DOES: matches the pattern against the full request URL only (not bodies).
    For matching inside bodies/headers use search_regex; for a simple substring
    overview use list_requests(filter=).
    ARGS: pattern = Python regex (substring works too, e.g. "graphql", "/api/v\\d").
    RETURNS: {total, offset, limit, items:[{entry, method, url}]}
    EXAMPLE: find_urls("cap", "/login|/auth") → all auth-related requests.
    """
    return _guard(srch.find_urls, har_name, pattern, limit, offset)


@mcp.tool()
def list_endpoints(har_name: str, group_by: str = "path", limit: int = 50,
                   offset: int = 0) -> dict:
    """Summarize the capture as unique endpoints with call counts.

    WHEN: to understand the SHAPE of the traffic at a glance — which APIs were
    hit and how often — without listing all individual requests. Great first
    orientation step on a large HAR.
    ARGS: group_by = "path" (METHOD host/path, default) or "host" (host only).
    RETURNS: {total, offset, limit, items:[{endpoint, count}]} sorted by count.
    EXAMPLE: list_endpoints("cap") → "POST api/graphql"×27, "GET /home"×3, ...
    """
    return _guard(srch.list_endpoints, har_name, group_by, limit, offset)


@mcp.tool()
def get_query_params(har_name: str, index: int) -> dict:
    """Get the parsed query-string (?a=1&b=2) parameters of one request.

    WHEN: you want a request's URL query params as a clean name/value list
    instead of eyeballing the raw URL.
    ARGS: index = request index.
    RETURNS: {url, query:[{name, value}]} or {error}
    """
    return _guard(srch.get_query_params, har_name, index)


# --------------------------------------------------------------------------- #
# Trace (provenance — the flagship)                                            #
# --------------------------------------------------------------------------- #
@mcp.tool()
def trace_value(har_name: str, value: str) -> dict:
    """★ PROVENANCE: trace where ANY value came from and where it was reused.

    This is the flagship tool and the main reason this server exists. Pass it a
    literal value — it works for ANY string, NOT just cookies:
      • auth tokens / Bearer / OAuth tokens     • CSRF tokens
      • session ids, cookies                    • device ids / fingerprints
      • request-body fields, query params       • any id that flows between calls

    WHEN: the user asks "where did this token come from?", "which response set
    this?", "which request produced the value used here?", "how is this id
    propagated?", or you need to reconstruct an auth/request chain. Use this
    INSTEAD of reading many raw entries — it does the correlation server-side.

    HOW IT WORKS: scans an index of the whole capture and splits hits into:
      • set_by  — the response(s) that PRODUCED the value: a Set-Cookie header
                  OR a response body (with the JSON path, e.g.
                  "data.user.token", when the value sits in JSON).
      • used_in — the later request(s) that SENT the value: in a request header,
                  a cookie, or a request body field (with JSON path when known).
    If set_by is empty the value was supplied by the client (not produced by a
    captured response) — e.g. a pre-existing OAuth token. `origin` is the
    earliest producer; `timeline` is the ordered list of entry indices touched.

    GETTING THE VALUE: copy a raw value from find_header / get_response /
    search_regex. (Inspection tools redact secrets, but you can trace a redacted
    value by fetching its raw form from find_header first.)

    ARGS: value = the exact string to trace (≥4 chars; shorter is refused as too
    noisy). Matching is substring on decoded text.
    RETURNS: {value_preview, set_by[], used_in[], timeline[], origin, truncated}
    EXAMPLE: trace_value("cap", "a1B2c3...") →
      set_by:[{entry:4, where:"response.body", key:"data.csrf"}],
      used_in:[{entry:9, where:"request.header", key:"X-CSRF"},
               {entry:9, where:"request.body",   key:"token"}]
      → the CSRF token was returned by response #4 and reused in request #9.
    """
    return _guard(prov.trace_value, har_name, value)


@mcp.tool()
def trace_header(har_name: str, header_name: str) -> dict:
    """Trace a HEADER by name back to where its value originated.

    WHEN: "where does the X-CSRF-Token / Authorization header value come from?"
    Convenience wrapper over trace_value: you give the header NAME (not its
    value), and for every request sending that header it finds the earlier
    response (body or Set-Cookie) that produced the value, if any.
    DIFFERENCE vs trace_value: trace_value takes a literal value; trace_header
    takes a header name and resolves the value(s) for you across all entries.
    ARGS: header_name = case-insensitive (e.g. "x-csrf-token").
    RETURNS: {header, sent_in:[{entry, value, url, origin}], truncated}
    where origin = {entry, where} of the producing response, or null if the
    value wasn't produced by any captured response (client-supplied).
    """
    return _guard(prov.trace_header, har_name, header_name)


@mcp.tool()
def cookie_map(har_name: str) -> dict:
    """Overview of EVERY cookie's lifecycle across the whole session.

    WHEN: "what cookies are in play and how do they flow?" — a one-shot summary
    instead of tracing each cookie individually. Good for understanding session
    state, auth cookies, and whether a Set-Cookie is ever actually used.
    DOES: for each cookie name, lists the entries that SET it (Set-Cookie) vs
    the entries that USED it (request Cookie header), plus its attributes
    (expiry, domain, secure, httponly).
    RETURNS: {cookies:[{name, set_in:[entry...], used_in:[entry...], attrs}], count}
    EXAMPLE: cookie_map("cap") → sessionid set#4 used#7,#9,#12; csrftoken set#4 ...
    """
    return _guard(prov.cookie_map, har_name)


@mcp.tool()
def token_map(har_name: str, all_tokens: bool = False) -> dict:
    """Auto-discover all secret-looking values and how they propagate.

    WHEN: you DON'T have a specific value yet and want to find the interesting
    secrets automatically — "what tokens/ids are reused across this session?"
    Complements trace_value (which needs a value you already have). Detection is
    generic Shannon-entropy + length (no vendor-specific shape).
    DEFAULT: returns only tokens that appear in 2+ places (genuinely shared/
    propagated secrets), sorted by reuse, filtering per-request diagnostic noise
    (debug/trace/request-id headers, etags). Set all_tokens=true to see
    everything. Each token shows set_count/used_count (true totals) and up to 20
    example locations; the value itself is shown only as a redacted preview.
    ARGS: all_tokens = false (curated, default) | true (unfiltered).
    RETURNS: {tokens:[{preview, set_by[], used_in[], set_count, used_count}],
              count, truncated, filtered}
    EXAMPLE: token_map("cap") → session id used 40×, csrf set#4 used#9, ...
    Then trace_value on a specific one for its full timeline.
    """
    return _guard(prov.token_map, har_name, all_tokens)


# --------------------------------------------------------------------------- #
# Diff                                                                          #
# --------------------------------------------------------------------------- #
@mcp.tool()
def diff_hars(har_a: str, har_b: str, limit: int = 50) -> dict:
    """Compare two loaded HARs: which requests are new/removed between them.

    WHEN: comparing two captures of the same flow (e.g. before/after an app
    update, or a working vs failing session) to spot which requests appeared or
    disappeared. Both HARs must be loaded first (two load_har calls).
    HOW: matches requests by (method, url, ordinal) — the ordinal makes repeated
    calls to the same endpoint align instead of collapsing.
    ARGS: har_a, har_b = the two loaded names. limit caps each diff list.
    RETURNS: {only_in_a[], only_in_b[], only_in_a_total, only_in_b_total,
              unchanged_count, limit}
    EXAMPLE: diff_hars("v4","v5") → only_in_b shows a new /save_login request.
    """
    def body():
        ea = store.get_entries(har_a)
        eb = store.get_entries(har_b)
        if ea is None:
            return {"error": f"no HAR named '{har_a}'"}
        if eb is None:
            return {"error": f"no HAR named '{har_b}'"}
        lim, _ = _page(limit, 0)

        def keyset(entries):
            seen = {}
            keys = []
            for entry in entries:
                req = hp.parse_request(entry)
                base = (req["method"], req["url"])
                ordn = seen.get(base, 0)
                seen[base] = ordn + 1
                keys.append((req["method"], req["url"], ordn))
            return keys

        ka, kb = set(keyset(ea)), set(keyset(eb))
        only_a = sorted(ka - kb)
        only_b = sorted(kb - ka)
        return {
            "only_in_a": [{"method": m, "url": u, "ordinal": o}
                          for m, u, o in only_a[:lim]],
            "only_in_b": [{"method": m, "url": u, "ordinal": o}
                          for m, u, o in only_b[:lim]],
            "only_in_a_total": len(only_a),
            "only_in_b_total": len(only_b),
            "unchanged_count": len(ka & kb),
            "limit": lim,
        }
    return _guard(body)


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
