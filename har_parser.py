"""Core HAR parsing, decoding, redaction, and thread-safe storage.

No vendor-specific logic. Everything here works on any HAR from any source.
Only this module and its siblings touch HAR data; FastMCP owns stdout.
"""
from __future__ import annotations

import base64
import gzip
import ipaddress
import json
import logging
import math
import os
import re
import socket
import threading
import urllib.error
import urllib.request
import zlib
from collections import Counter
from typing import Any, Optional
from urllib.parse import urlparse, parse_qsl

log = logging.getLogger("har")

# --------------------------------------------------------------------------- #
# Config (editable, no code change). Safe defaults if config.json is missing.  #
# --------------------------------------------------------------------------- #
_DEFAULT_CONFIG = {
    "sensitive_headers": ["authorization", "cookie", "set-cookie",
                          "x-csrf-token", "x-api-key", "proxy-authorization"],
    "redact_sensitive_headers": False,
    "entropy_min_len": 24,
    "entropy_bits_min": 3.5,
    "friendly_shorten": {},
}


def _load_config() -> dict:
    path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("config root must be an object")
        merged = dict(_DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except Exception as exc:  # never crash on bad/missing config
        log.warning("config.json not loaded (%s); using defaults", exc)
        return dict(_DEFAULT_CONFIG)


_CONFIG = _load_config()
SENSITIVE_HEADERS = {h.lower() for h in _CONFIG["sensitive_headers"]}
REDACT_SENSITIVE_HEADERS: bool = bool(_CONFIG.get("redact_sensitive_headers", False))
ENTROPY_MIN_LEN = int(_CONFIG["entropy_min_len"])
ENTROPY_BITS_MIN = float(_CONFIG["entropy_bits_min"])
FRIENDLY_SHORTEN = dict(_CONFIG.get("friendly_shorten") or {})

# --------------------------------------------------------------------------- #
# Hard limits — the token-budget + memory guarantees.                          #
# --------------------------------------------------------------------------- #
MAX_FILE_BYTES = 500 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_DECODE_BYTES = 5 * 1024 * 1024
MAX_DECODE_DEPTH = 6

LIMIT_MAX = 200
RESP_CHARS_MAX = 50_000
LISTDIR_MAX = 1_000
TRACE_HITS_MAX = 100
MIN_TRACE_LEN = 4
BINARY_SNIFF = 1024


def _page(limit: Any, offset: Any) -> tuple[int, int]:
    """Clamp agent-supplied paging. Never raises."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0
    return max(1, min(limit, LIMIT_MAX)), max(0, offset)


# --------------------------------------------------------------------------- #
# Header / cookie helpers                                                       #
# --------------------------------------------------------------------------- #
def get_header(headers: list[dict], name: str) -> Optional[str]:
    """Case-insensitive single header lookup (first match)."""
    name = name.lower()
    for h in headers or []:
        if (h.get("name") or "").lower() == name:
            return h.get("value")
    return None


def get_all_headers(headers: list[dict], name: str) -> list[str]:
    """All values for a (possibly repeated) header, e.g. Set-Cookie."""
    name = name.lower()
    return [h.get("value", "") for h in headers or []
            if (h.get("name") or "").lower() == name]


def parse_cookies(cookie_header: str, set_cookie: bool = False) -> list[dict]:
    """Tolerant parse of a Cookie / Set-Cookie header value."""
    out: list[dict] = []
    if not cookie_header:
        return out
    if set_cookie:
        parts = cookie_header.split(";")
        if not parts:
            return out
        first = parts[0].strip()
        if "=" not in first:
            return out
        name, _, value = first.partition("=")
        attrs = {}
        for p in parts[1:]:
            k, _, v = p.strip().partition("=")
            if k:
                attrs[k.lower()] = v or True
        out.append({"name": name.strip(), "value": value.strip(), "attrs": attrs})
    else:
        for pair in cookie_header.split(";"):
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            out.append({"name": name.strip(), "value": value.strip(), "attrs": {}})
    return out


# --------------------------------------------------------------------------- #
# Secret detection + redaction (generic, entropy-based — not a vendor shape)    #
# --------------------------------------------------------------------------- #
def _shannon_bits(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_secret(s: str) -> bool:
    """High-entropy opaque string heuristic."""
    if not isinstance(s, str) or len(s) < ENTROPY_MIN_LEN:
        return False
    if " " in s.strip():  # sentences aren't secrets
        return False
    return _shannon_bits(s) >= ENTROPY_BITS_MIN


def _redact_str(s: str) -> str:
    return f"<REDACTED len={len(s)}>"


def redact(obj: Any, _header_name: str | None = None) -> Any:
    """Recursively redact sensitive-header values and high-entropy strings."""
    if not REDACT_SENSITIVE_HEADERS:
        return obj
    if isinstance(obj, str):
        if _header_name and _header_name.lower() in SENSITIVE_HEADERS:
            return _redact_str(obj)
        if looks_secret(obj):
            return _redact_str(obj)
        return obj
    if isinstance(obj, dict):
        return {k: redact(v, _header_name=k if isinstance(k, str) else None)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def redact_headers(headers: list[dict]) -> list[dict]:
    if not REDACT_SENSITIVE_HEADERS:
        return list(headers or [])
    out = []
    for h in headers or []:
        name = h.get("name", "")
        value = h.get("value", "")
        if name.lower() in SENSITIVE_HEADERS or looks_secret(value):
            value = _redact_str(value)
        out.append({"name": name, "value": value})
    return out


# --------------------------------------------------------------------------- #
# deep_decode — unwrap JSON-encoded strings nested inside JSON (generic)        #
# --------------------------------------------------------------------------- #
def deep_decode(obj: Any, depth: int = 0) -> Any:
    if depth >= MAX_DECODE_DEPTH:
        return obj
    if isinstance(obj, str):
        s = obj.strip()
        if len(s) > MAX_DECODE_BYTES:
            return obj
        if s and s[0] in "{[" and s[-1] in "}]":
            try:
                return deep_decode(json.loads(s), depth + 1)
            except (ValueError, TypeError):
                return obj
        return obj
    if isinstance(obj, dict):
        return {k: deep_decode(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deep_decode(v, depth + 1) for v in obj]
    return obj


# --------------------------------------------------------------------------- #
# Body decoding                                                                 #
# --------------------------------------------------------------------------- #
def _looks_binary(raw: bytes) -> bool:
    sniff = raw[:BINARY_SNIFF]
    if b"\x00" in sniff:
        return True
    try:
        sniff.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def _decompress(raw: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(raw)
        if "deflate" in enc:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        return raw
    return raw


def parse_response(entry: dict) -> dict:
    """Return {status, text, size, is_binary}. Never raises."""
    resp = entry.get("response", {}) or {}
    status = resp.get("status", 0)
    content = resp.get("content", {}) or {}
    size = content.get("size", 0) or 0
    text = content.get("text", "") or ""
    if not text:
        return {"status": status, "text": "", "size": size, "is_binary": False}
    try:
        if content.get("encoding") == "base64":
            raw = base64.b64decode(text, validate=False)
        else:
            raw = text.encode("utf-8", errors="replace")
    except Exception as exc:  # malformed base64 etc.
        return {"status": status, "text": f"<decode error: {exc}>",
                "size": size, "is_binary": True}

    content_enc = get_header(resp.get("headers", []), "content-encoding") or ""
    raw = _decompress(raw, content_enc)

    if _looks_binary(raw):
        return {"status": status, "text": "", "size": len(raw), "is_binary": True}
    try:
        decoded = raw.decode("utf-8", errors="replace")
    except Exception as exc:
        return {"status": status, "text": f"<decode error: {exc}>",
                "size": len(raw), "is_binary": True}
    return {"status": status, "text": decoded, "size": len(decoded), "is_binary": False}


def parse_request(entry: dict) -> dict:
    """Decoded request: method, url, query, headers, body. Never raises."""
    req = entry.get("request", {}) or {}
    url = req.get("url", "")
    parsed = urlparse(url)
    query = [{"name": k, "value": v} for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    post = req.get("postData", {}) or {}
    body = post.get("text", "") or ""
    params = post.get("params") or []
    return {
        "method": req.get("method", ""),
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path,
        "query": query,
        "headers": req.get("headers", []) or [],
        "body": body,
        "params": [{"name": p.get("name", ""), "value": p.get("value", "")} for p in params],
    }


def friendly_short(url: str) -> str:
    """Apply config-driven friendly shortening to the URL/path tail."""
    base = urlparse(url).path.rsplit("/", 1)[-1] or url
    for long, short in FRIENDLY_SHORTEN.items():
        if long in base:
            base = base.replace(long, short)
    return base


# --------------------------------------------------------------------------- #
# Filesystem safety                                                             #
# --------------------------------------------------------------------------- #
def _safe_resolve(path: str) -> dict:
    """Resolve + single stat. Returns {ok, real, size} or {ok:False, error}."""
    try:
        real = os.path.realpath(path)
    except Exception as exc:
        return {"ok": False, "error": f"bad path: {exc}"}
    if not os.path.exists(real):
        return {"ok": False, "error": "file not found"}
    if not os.path.isfile(real):
        return {"ok": False, "error": "not a file"}
    if not real.lower().endswith(".har"):
        return {"ok": False, "error": "not a .har file (expected .har extension)"}
    try:
        size = os.path.getsize(real)
    except OSError as exc:
        return {"ok": False, "error": f"cannot stat file: {exc}"}
    if size > MAX_FILE_BYTES:
        return {"ok": False, "error": f"file too large ({size} bytes > {MAX_FILE_BYTES})"}
    return {"ok": True, "real": real, "size": size}


# --------------------------------------------------------------------------- #
# URL fetch safety (SSRF guards)                                               #
# --------------------------------------------------------------------------- #
URL_FETCH_TIMEOUT = 20  # seconds


def _is_private_ip(host: str) -> bool:
    """True if host resolves to a private/loopback/link-local/reserved address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True  # unresolvable → treat as unsafe
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False


def _fetch_url(url: str) -> dict:
    """Fetch a HAR over http(s) with SSRF + size guards. Returns {ok, text} | {error}."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": "url must be http:// or https://"}
    host = parsed.hostname
    if not host:
        return {"ok": False, "error": "url has no host"}
    if _is_private_ip(host):
        return {"ok": False,
                "error": "refusing to fetch from a private/loopback/internal address"}
    req = urllib.request.Request(url, headers={"User-Agent": "har-mcp/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=URL_FETCH_TIMEOUT) as resp:
            clen = resp.headers.get("Content-Length")
            if clen and int(clen) > MAX_FILE_BYTES:
                return {"ok": False,
                        "error": f"remote file too large ({clen} bytes > {MAX_FILE_BYTES})"}
            # Read at most MAX_FILE_BYTES+1 to detect overflow without chunked Content-Length.
            raw = resp.read(MAX_FILE_BYTES + 1)
    except (urllib.error.URLError, ValueError, OSError) as exc:
        return {"ok": False, "error": f"fetch failed: {exc}"}
    if len(raw) > MAX_FILE_BYTES:
        return {"ok": False, "error": f"remote file too large (> {MAX_FILE_BYTES} bytes)"}
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return {"ok": False, "error": f"remote content not valid UTF-8: {exc}"}
    return {"ok": True, "text": text}


# --------------------------------------------------------------------------- #
# HarStore — thread-safe singleton. Lock guards the dict ONLY.                  #
# --------------------------------------------------------------------------- #
class HarStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._hars: dict[str, dict] = {}

    def _unique_name(self, base: str) -> str:
        # caller holds the lock
        if base not in self._hars:
            return base
        i = 2
        while f"{base}-{i}" in self._hars:
            i += 1
        return f"{base}-{i}"

    def _ingest(self, raw: str, source: str, base: str) -> dict:
        """Parse + validate + store HAR text. Heavy work runs OUTSIDE the lock."""
        try:
            data = json.loads(raw)
        except (ValueError, TypeError) as exc:
            return {"ok": False, "error": f"invalid JSON: {exc}"}

        entries = (((data or {}).get("log") or {}).get("entries"))
        if not isinstance(entries, list):
            return {"ok": False, "error": "invalid HAR: log.entries missing or not a list"}
        if len(entries) > MAX_ENTRIES:
            return {"ok": False,
                    "error": f"too many entries ({len(entries)} > {MAX_ENTRIES})"}

        record = {"entries": entries, "path": source,
                  "entry_count": len(entries), "_index": None}
        with self._lock:
            final = self._unique_name(base)
            self._hars[final] = record
        return {"ok": True, "name": final, "entry_count": len(entries)}

    def load(self, path: str, name: str = "") -> dict:
        resolved = _safe_resolve(path)
        if not resolved.get("ok"):
            return {"ok": False, "error": resolved["error"]}
        real = resolved["real"]
        try:
            with open(real, "r", encoding="utf-8-sig") as fh:
                raw = fh.read()
        except UnicodeDecodeError as exc:
            return {"ok": False, "error": f"not valid UTF-8 text: {exc}"}
        except OSError as exc:
            return {"ok": False, "error": f"cannot read file: {exc}"}
        base = name.strip() or os.path.splitext(os.path.basename(real))[0]
        return self._ingest(raw, real, base)

    def load_url(self, url: str, name: str = "") -> dict:
        fetched = _fetch_url(url)
        if not fetched.get("ok"):
            return {"ok": False, "error": fetched["error"]}
        if name.strip():
            base = name.strip()
        else:
            tail = os.path.basename(urlparse(url).path)
            base = os.path.splitext(tail)[0] if tail else (urlparse(url).hostname or "remote")
        return self._ingest(fetched["text"], url, base)

    def get(self, name: str) -> Optional[dict]:
        with self._lock:
            return self._hars.get(name)

    def get_entries(self, name: str) -> Optional[list]:
        rec = self.get(name)
        return rec["entries"] if rec else None

    def get_entry(self, name: str, i: int) -> dict:
        rec = self.get(name)
        if rec is None:
            return {"error": f"no HAR named '{name}' (loaded: {self.names()})"}
        entries = rec["entries"]
        try:
            i = int(i)
        except (TypeError, ValueError):
            return {"error": f"index must be an integer, got {i!r}"}
        if i < 0 or i >= len(entries):
            return {"error": f"index {i} out of range (0-{len(entries) - 1})"}
        return {"ok": True, "entry": entries[i]}

    def names(self) -> list[str]:
        with self._lock:
            return list(self._hars.keys())

    def list(self) -> list[dict]:
        with self._lock:
            return [{"name": n, "entry_count": r["entry_count"], "path": r["path"]}
                    for n, r in self._hars.items()]

    def unload(self, name: str) -> bool:
        with self._lock:
            return self._hars.pop(name, None) is not None


store = HarStore()
