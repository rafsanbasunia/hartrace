"""Search / discovery toolkit."""
import search as srch
from conftest import CSRF


def test_search_regex_in_body(loaded):
    r = srch.search_regex(loaded, "csrf_token", scope="resp_body")
    assert r["total"] >= 1
    assert any(h["scope"] == "resp_body" for h in r["items"])


def test_search_regex_in_headers(loaded):
    r = srch.search_regex(loaded, "X-CSRF-Token", scope="req_headers")
    assert r["total"] == 1


def test_search_regex_bad_pattern(loaded):
    r = srch.search_regex(loaded, "(", scope="all")
    assert "bad regex" in r["error"]


def test_search_regex_bad_scope(loaded):
    r = srch.search_regex(loaded, "x", scope="nonsense")
    assert "scope must be" in r["error"]


def test_search_regex_clamped(loaded):
    r = srch.search_regex(loaded, ".", scope="url", limit=10**9)
    assert r["limit"] == 200


def test_find_header(loaded):
    r = srch.find_header(loaded, "Cookie")
    assert r["total"] == 2
    assert all(i["side"] == "request" for i in r["items"])


def test_find_header_raw_value(loaded):
    """find_header returns RAW values (for feeding into trace_value)."""
    r = srch.find_header(loaded, "X-CSRF-Token")
    assert r["items"][0]["value"] == CSRF  # not redacted


def test_find_urls(loaded):
    r = srch.find_urls(loaded, "/action")
    assert r["total"] == 1 and r["items"][0]["method"] == "POST"


def test_find_urls_bad_regex(loaded):
    r = srch.find_urls(loaded, "(")
    assert "bad regex" in r["error"]


def test_list_endpoints(loaded):
    r = srch.list_endpoints(loaded)
    assert r["total"] == 4
    endpoints = {i["endpoint"] for i in r["items"]}
    assert any("/login" in e for e in endpoints)


def test_list_endpoints_group_by_host(loaded):
    r = srch.list_endpoints(loaded, group_by="host")
    hosts = {i["endpoint"] for i in r["items"]}
    assert "api.example.com" in hosts and "cdn.example.com" in hosts


def test_list_endpoints_bad_group(loaded):
    r = srch.list_endpoints(loaded, group_by="bogus")
    assert "group_by" in r["error"]


def test_get_query_params(loaded):
    r = srch.get_query_params(loaded, 1)
    assert r["query"] == [{"name": "ref", "value": "login"}]


def test_search_unknown_har():
    r = srch.search_regex("nope", "x")
    assert "no HAR named" in r["error"]
