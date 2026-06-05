"""Provenance tracing — the flagship. Covers cookies AND non-cookie values."""
import provenance as prov
from conftest import SESSION, CSRF


def test_trace_cookie_value(loaded):
    t = prov.trace_value(loaded, SESSION)
    assert any(s["where"] == "response.set_cookie" for s in t["set_by"])
    assert any(u["where"] == "request.cookie" for u in t["used_in"])
    assert t["origin"]["where"] == "response.set_cookie"


def test_trace_non_cookie_body_value(loaded):
    """CSRF token lives in a response BODY and is reused in a request header+body."""
    t = prov.trace_value(loaded, CSRF)
    # produced by a response body (with JSON path), not a cookie
    set_body = [s for s in t["set_by"] if s["where"] == "response.body"]
    assert set_body and set_body[0]["key"] == "csrf_token"
    # used in both a request header and a request body
    wheres = {u["where"] for u in t["used_in"]}
    assert "request.header" in wheres
    assert "request.body" in wheres


def test_trace_too_short(loaded):
    r = prov.trace_value(loaded, "ab")
    assert "too short" in r["error"]


def test_trace_unknown_har():
    r = prov.trace_value("nope", "somevalue")
    assert "no HAR named" in r["error"]


def test_trace_timeline_ordered(loaded):
    t = prov.trace_value(loaded, SESSION)
    assert t["timeline"] == sorted(t["timeline"])


def test_json_path_resolution(loaded):
    t = prov.trace_value(loaded, CSRF)
    # the body field key is reported as a JSON path
    body_hits = [u for u in t["used_in"] if u["where"] == "request.body"]
    assert any(u["key"] == "token" for u in body_hits)


# ---- cookie_map ----------------------------------------------------------- #
def test_cookie_map(loaded):
    m = prov.cookie_map(loaded)
    sess = next(c for c in m["cookies"] if c["name"] == "sessionid")
    assert 0 in sess["set_in"]
    assert 1 in sess["used_in"] and 2 in sess["used_in"]
    assert "httponly" in sess["attrs"]


# ---- token_map ------------------------------------------------------------ #
def test_token_map_finds_shared_secrets(loaded):
    m = prov.token_map(loaded)
    # session + csrf are reused → should surface
    assert m["count"] >= 1
    previews = " ".join(t["preview"] for t in m["tokens"])
    assert "redacted" in previews


def test_token_map_counts_accurate(loaded):
    m = prov.token_map(loaded, all_tokens=True)
    for t in m["tokens"]:
        # true totals are >= the (capped) example-list lengths
        assert t["set_count"] >= len(t["set_by"])
        assert t["used_count"] >= len(t["used_in"])
        # capped example lists never exceed 20
        assert len(t["set_by"]) <= 20 and len(t["used_in"]) <= 20


def test_token_map_filtering(loaded):
    filt = prov.token_map(loaded)
    allt = prov.token_map(loaded, all_tokens=True)
    assert filt["filtered"] is True
    assert allt["count"] >= filt["count"]


# ---- index caching -------------------------------------------------------- #
def test_index_built_once(loaded):
    prov.build_index(loaded)
    assert hp_index_present(loaded)


def hp_index_present(name):
    import har_parser as hp
    return hp.store.get(name)["_index"] is not None


def test_trace_header(loaded):
    r = prov.trace_header(loaded, "X-CSRF-Token")
    assert r["header"] == "X-CSRF-Token"
    sent = r["sent_in"]
    assert sent and sent[0]["entry"] == 2
    # value originated in response #0 body
    assert sent[0]["origin"] is not None
    assert sent[0]["origin"]["entry"] == 0
