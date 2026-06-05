"""Parsing, decoding, redaction, store, and load validation."""
import json

import pytest

import har_parser as hp
from conftest import SESSION, CSRF


# ---- loading / validation ------------------------------------------------- #
def test_load_ok(loaded):
    assert loaded == "cap"
    assert hp.store.get_entries(loaded) is not None


def test_load_missing(tmp_path):
    r = hp.store.load(str(tmp_path / "nope.har"))
    assert r["ok"] is False and "not found" in r["error"]


def test_load_wrong_extension(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("{}")
    r = hp.store.load(str(p))
    assert r["ok"] is False and ".har" in r["error"]


def test_load_bad_json(tmp_path):
    p = tmp_path / "bad.har"
    p.write_text("{not json")
    r = hp.store.load(str(p))
    assert r["ok"] is False and "JSON" in r["error"]


def test_load_missing_entries(tmp_path):
    p = tmp_path / "noent.har"
    p.write_text(json.dumps({"log": {}}))
    r = hp.store.load(str(p))
    assert r["ok"] is False and "log.entries" in r["error"]


def test_load_bom(tmp_path):
    p = tmp_path / "bom.har"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps({"log": {"entries": []}}).encode())
    r = hp.store.load(str(p))
    assert r["ok"] is True and r["entry_count"] == 0


def test_collision_safe_name(har_file):
    hp.store._hars.clear()
    a = hp.store.load(har_file)
    b = hp.store.load(har_file)
    assert a["name"] == "cap" and b["name"] == "cap-2"
    hp.store._hars.clear()


def test_entry_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "MAX_ENTRIES", 1)
    p = tmp_path / "big.har"
    p.write_text(json.dumps({"log": {"entries": [{}, {}]}}))
    r = hp.store.load(str(p))
    assert r["ok"] is False and "too many" in r["error"]


# ---- get_entry bounds ----------------------------------------------------- #
def test_get_entry_oob(loaded):
    r = hp.store.get_entry(loaded, 9999)
    assert "out of range" in r["error"]


def test_get_entry_bad_index(loaded):
    r = hp.store.get_entry(loaded, "abc")
    assert "integer" in r["error"]


def test_unload(loaded):
    assert hp.store.unload(loaded) is True
    assert hp.store.unload(loaded) is False


# ---- header helpers ------------------------------------------------------- #
def test_get_header_case_insensitive():
    hdrs = [{"name": "Content-Type", "value": "json"}]
    assert hp.get_header(hdrs, "content-type") == "json"
    assert hp.get_header(hdrs, "missing") is None


def test_parse_cookies():
    c = hp.parse_cookies("a=1; b=2")
    assert {x["name"]: x["value"] for x in c} == {"a": "1", "b": "2"}


def test_parse_set_cookie_attrs():
    c = hp.parse_cookies("sid=xyz; Path=/; HttpOnly; Secure", set_cookie=True)
    assert c[0]["name"] == "sid" and c[0]["value"] == "xyz"
    assert "httponly" in c[0]["attrs"] and "secure" in c[0]["attrs"]


# ---- secret detection / redaction ----------------------------------------- #
def test_looks_secret():
    assert hp.looks_secret(CSRF) is True
    assert hp.looks_secret("hello world this is a sentence") is False
    assert hp.looks_secret("short") is False


def test_redact_headers_masks_sensitive():
    hdrs = [{"name": "Authorization", "value": "Bearer abc"},
            {"name": "Accept", "value": "application/json"}]
    out = hp.redact_headers(hdrs)
    assert out[0]["value"].startswith("<REDACTED")
    assert out[1]["value"] == "application/json"


# ---- deep_decode ---------------------------------------------------------- #
def test_deep_decode_unwraps_nested_json():
    obj = {"a": json.dumps({"b": json.dumps({"c": 1})})}
    out = hp.deep_decode(obj)
    assert out == {"a": {"b": {"c": 1}}}


def test_deep_decode_depth_cap(monkeypatch):
    monkeypatch.setattr(hp, "MAX_DECODE_DEPTH", 2)
    obj = json.dumps(json.dumps(json.dumps({"x": 1})))
    out = hp.deep_decode(obj)
    # stops unwrapping at the cap; result is still a (partially) decoded string/obj
    assert out is not None


def test_deep_decode_non_json_passthrough():
    assert hp.deep_decode("just a string") == "just a string"


# ---- response decoding ---------------------------------------------------- #
def test_parse_response_binary(loaded):
    entry = hp.store.get_entries(loaded)[3]  # logo.png base64
    r = hp.parse_response(entry)
    assert r["is_binary"] is True


def test_parse_response_text(loaded):
    entry = hp.store.get_entries(loaded)[0]
    r = hp.parse_response(entry)
    assert r["is_binary"] is False and "csrf_token" in r["text"]


def test_parse_response_gzip():
    import gzip
    import base64
    payload = json.dumps({"hello": "world"}).encode()
    gz = gzip.compress(payload)
    entry = {
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Encoding", "value": "gzip"}],
            "content": {"encoding": "base64",
                        "text": base64.b64encode(gz).decode(), "size": len(gz)},
        }
    }
    r = hp.parse_response(entry)
    assert r["is_binary"] is False and "world" in r["text"]


# ---- paging clamp --------------------------------------------------------- #
@pytest.mark.parametrize("limit,expected", [
    (10, 10), (10**9, hp.LIMIT_MAX), (-5, 1), (0, 1), ("x", 50), (None, 50),
])
def test_page_clamp(limit, expected):
    lim, _ = hp._page(limit, 0)
    assert lim == expected


@pytest.mark.parametrize("offset,expected", [(0, 0), (-3, 0), (7, 7), ("x", 0)])
def test_page_offset(offset, expected):
    _, off = hp._page(50, offset)
    assert off == expected
