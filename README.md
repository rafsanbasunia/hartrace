# hartrace

[![PyPI](https://img.shields.io/pypi/v/hartrace)](https://pypi.org/project/hartrace/)
[![Python](https://img.shields.io/pypi/pyversions/hartrace)](https://pypi.org/project/hartrace/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

An [MCP](https://modelcontextprotocol.io) server for analyzing HTTP traffic captures (HAR files) — built so an AI agent can answer questions about a capture **without** reading the raw JSON into its context window.

Its distinguishing feature is **value provenance tracing**: given any token, cookie, id, or payload field, `hartrace` reconstructs where the value was *produced* (which response set it) and where it was *consumed* (which later requests sent it), as a compact timeline. Every other tool — search, inspection, diffing — is built to return small, structured results with hard size caps, so analysis stays cheap regardless of how large the capture is.

```
load_har("session.har")
trace_value("session", "<csrf token>")
  → set_by:  response #4 body, JSON path data.csrf
  → used_in: request #9 header X-CSRF, request #9 body field token
```

---

## Why this exists

HAR files are large, deeply nested, and repetitive. The two common ways an AI ends up analyzing them are both bad: writing throwaway extraction scripts every session, or pasting raw HAR JSON into the context window (slow, expensive, and it overflows on anything real). A 100-entry capture can be several megabytes; a single gzipped response can be hundreds of kilobytes.

`hartrace` moves the extraction and correlation to the server. Tools return only what was asked for, capped. The questions that normally require reading many entries by hand — *where did this auth token come from? which request produced this cookie? where is this id reused?* — are answered in one call.

---

## Features

- **Provenance tracing** — `trace_value` follows any value across the capture (responses → requests), reporting JSON paths for body fields. Works on tokens, cookies, ids, headers, and payload fields alike, not just cookies.
- **Search toolkit** — full regex search across URLs, headers, and request/response bodies; header finder; URL/endpoint finder; query-parameter extraction.
- **Inspection** — per-request and per-response retrieval with base64 + gzip/deflate decoding, nested-JSON unwrapping, binary detection, and size caps.
- **Lifecycle maps** — `cookie_map` and `token_map` summarize how cookies and high-entropy secrets flow through a session.
- **Diffing** — compare two captures by `(method, url, ordinal)` so repeated calls to the same endpoint align.
- **Loading** — from a local path or an `http(s)` URL (with SSRF protection and a size cap).
- **Safe by construction** — every list/search tool paginates with server-clamped limits; secrets are redacted in inspection output; no tool raises to the transport (errors are returned as structured values).

---

## Installation

Requires Python 3.10+.

```bash
# recommended — isolated install
pipx install hartrace

# zero-install with uv
uvx hartrace

# plain pip
pip install hartrace

# from source
git clone https://github.com/rafsanbasunia/hartrace
cd hartrace
pip install -e .
```

The only runtime dependency is [`fastmcp`](https://github.com/jlowin/fastmcp).

---

## Quick start with Claude Desktop

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hartrace": {
      "command": "uvx",
      "args": ["hartrace"]
    }
  }
}
```

Or, running from source:

```json
{
  "mcpServers": {
    "hartrace": {
      "command": "python",
      "args": ["/absolute/path/to/hartrace/har_mcp.py"]
    }
  }
}
```

Restart Claude Desktop, then talk to it naturally:

> *"Load `~/captures/login.har` and tell me where the CSRF token comes from."*
> *"Which requests reuse the session cookie?"*
> *"Diff `before.har` and `after.har` — what's new?"*

### Other MCP clients

`hartrace` is a standard stdio MCP server, so it works in any MCP-capable client — only the config file and wrapper key differ.

- **Cursor** (`.cursor/mcp.json`) and **Windsurf** use the same `"mcpServers"` block shown above.
- **VS Code** (`.vscode/mcp.json`) uses a `"servers"` key with an explicit type:

  ```json
  {
    "servers": {
      "hartrace": { "type": "stdio", "command": "uvx", "args": ["hartrace"] }
    }
  }
  ```

In every case the `command`/`args` are identical to the Claude Desktop example.

---

## Tools

`hartrace` exposes 19 tools. Refer to a loaded capture by the `name` returned from `load_har`.

### Loading

| Tool | Purpose |
| --- | --- |
| `list_har_files(dir)` | List `.har` files in a directory to choose from. |
| `load_har(path)` | Load a capture from a local path. Returns the assigned `name`. |
| `load_har_url(url)` | Load a capture from an `http(s)` URL (SSRF-guarded, size-capped). |
| `list_hars()` | List currently loaded captures. |
| `unload_har(name)` | Drop a capture to free memory. |

### Inspection

| Tool | Purpose |
| --- | --- |
| `list_requests(name, filter, …)` | Overview rows: index, method, URL, status, response size. |
| `get_request(name, index)` | One request, decoded; secrets redacted. |
| `get_response(name, index, max_chars)` | One response body, decoded (base64/gzip), JSON unwrapped, capped. |
| `get_headers(name, index)` | Request and response headers for one entry. |
| `get_query_params(name, index)` | Parsed query string of one request. |

### Search

| Tool | Purpose |
| --- | --- |
| `search_regex(name, pattern, scope)` | Regex over `url \| req_headers \| resp_headers \| req_body \| resp_body \| all`. |
| `find_header(name, header_name)` | Every entry carrying a header, with raw values. |
| `find_urls(name, pattern)` | Requests whose URL matches a pattern. |
| `list_endpoints(name, group_by)` | Unique endpoints with call counts. |

### Provenance

| Tool | Purpose |
| --- | --- |
| `trace_value(name, value)` | Where a value was set vs. used — the full timeline. |
| `trace_header(name, header_name)` | Resolve a header's value(s) and trace their origin. |
| `cookie_map(name)` | Every cookie's set/used lifecycle and attributes. |
| `token_map(name, all_tokens)` | High-entropy secrets and how they propagate. |

### Comparison

| Tool | Purpose |
| --- | --- |
| `diff_hars(a, b)` | Requests unique to each capture; matched by `(method, url, ordinal)`. |

Every tool's full description — including argument semantics and a worked example — is available to the model through the MCP protocol.

---

## How provenance tracing works

On first trace, `hartrace` builds a correlation index over the capture (cached for subsequent calls). For a queried value it separates hits into two sides:

- **`set_by`** — responses that *produced* the value: a `Set-Cookie` header, or a response body (with the JSON path when the value sits inside parseable JSON).
- **`used_in`** — later requests that *sent* the value: in a request header, a cookie, or a request body field (again with JSON path where applicable).

An empty `set_by` means the value was supplied by the client rather than produced by any captured response — for example a pre-existing OAuth token. `origin` is the earliest producer; `timeline` is the ordered list of entry indices touched.

Values shorter than four characters are refused, because short strings match everywhere and the result would be noise rather than signal.

---

## Design and safety

- **stdio transport only.** The server communicates over stdin/stdout per the MCP spec. All logging is routed to stderr so it cannot corrupt the protocol stream. There is no web UI, port, or background process.
- **Bounded output.** List and search tools paginate with `limit`/`offset`, and limits are clamped server-side (a request for a million rows returns the cap, not a million rows). Response bodies are capped by `max_chars`. These bounds are what make token usage predictable.
- **Bounded memory.** Captures are rejected above 500 MB or 50,000 entries; nested-JSON decoding is depth- and size-limited.
- **Redaction.** Inspection tools mask sensitive header values and high-entropy secrets as `<REDACTED len=N>`, using a configurable header list plus a generic Shannon-entropy heuristic — not a vendor-specific token shape. Provenance tools correlate on the real value but display only a redacted preview. (`find_header` intentionally returns raw values, since its purpose is to extract a value to trace.)
- **SSRF protection.** `load_har_url` refuses non-`http(s)` schemes and any host resolving to a private, loopback, link-local, reserved, or multicast address (including cloud metadata endpoints), and enforces the size cap on download.
- **No exceptions across the boundary.** Every tool returns a structured `{error: "..."}` on failure rather than raising, so the agent always receives an actionable message.

The server contains no vendor-specific logic. Helpers such as nested-JSON unwrapping are generic and apply to any deeply nested response.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

The suite covers parsing and decoding, redaction and entropy detection, provenance tracing (cookie and non-cookie values, JSON-path resolution), the search toolkit, URL loading and SSRF guards, and the tools driven through the actual FastMCP call path.

Layout:

```
har_mcp.py      MCP server: tool definitions and the stdio entry point
har_parser.py   Parsing, decoding, redaction, and the in-memory store
provenance.py   Correlation index and the trace / cookie / token tools
search.py       Regex, header, URL, and endpoint search
config.json     Redaction settings (sensitive headers, entropy thresholds)
tests/          pytest suite
```

---

## Configuration

`config.json` adjusts redaction without code changes:

```json
{
  "sensitive_headers": ["authorization", "cookie", "set-cookie", "x-csrf-token", "x-api-key"],
  "redact_sensitive_headers": true,
  "entropy_min_len": 24,
  "entropy_bits_min": 3.5
}
```

| Key | Default | Effect |
| --- | --- | --- |
| `sensitive_headers` | common auth headers | Header names to redact by name when `redact_sensitive_headers` is `true`. |
| `redact_sensitive_headers` | `true` | When `true`, values for headers in `sensitive_headers` are replaced with `<REDACTED len=N>` in inspection output. Set to `false` to see raw values everywhere (useful when you trust your environment and need to inspect the actual tokens). |
| `entropy_min_len` / `entropy_bits_min` | 24 / 3.5 | Any value that passes both thresholds is redacted regardless of header name — the entropy check always runs, independent of `redact_sensitive_headers`. |

Note: `find_header` always returns raw values by design — it exists specifically to extract a value so you can pass it to `trace_value`.

---

## License

MIT. See [LICENSE](LICENSE).
