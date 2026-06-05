"""Integration: drive tools through the actual FastMCP call path."""
import asyncio

import pytest

import har_mcp
import har_parser as hp
from conftest import CSRF


def call(name, args):
    r = asyncio.run(har_mcp.mcp.call_tool(name, args))
    return r.structured_content


@pytest.fixture
def mcp_loaded(har_file):
    hp.store._hars.clear()
    out = call("load_har", {"path": har_file})
    assert out["ok"]
    yield out["name"]
    hp.store._hars.clear()


def test_all_tools_registered():
    tools = asyncio.run(har_mcp.mcp.list_tools())
    names = {t.name for t in tools}
    expected = {
        "list_har_files", "load_har", "load_har_url", "list_hars", "unload_har",
        "list_requests", "get_request", "get_response", "get_headers",
        "search_regex", "find_header", "find_urls", "list_endpoints",
        "get_query_params", "trace_value", "trace_header", "cookie_map",
        "token_map", "diff_hars",
    }
    assert expected <= names


def test_every_tool_has_rich_description():
    tools = asyncio.run(har_mcp.mcp.list_tools())
    for t in tools:
        assert t.description and len(t.description) > 80, f"{t.name} doc too thin"


def test_load_and_trace_via_mcp(mcp_loaded):
    t = call("trace_value", {"har_name": mcp_loaded, "value": CSRF})
    assert t["set_by"] and t["used_in"]


def test_get_request_redacts(mcp_loaded):
    r = call("get_request", {"har_name": mcp_loaded, "index": 2})
    csrf_hdr = next(h for h in r["headers"] if h["name"].lower() == "x-csrf-token")
    assert csrf_hdr["value"].startswith("<REDACTED")


def test_get_response_truncates(mcp_loaded):
    r = call("get_response", {"har_name": mcp_loaded, "index": 0, "max_chars": 10})
    assert r["truncated"] is True and len(r["body"]) <= 10


def test_get_response_binary(mcp_loaded):
    r = call("get_response", {"har_name": mcp_loaded, "index": 3})
    assert r["is_binary"] is True


def test_list_requests_clamped(mcp_loaded):
    r = call("list_requests", {"har_name": mcp_loaded, "limit": 10**9})
    assert r["limit"] == 200


def test_error_is_structured_not_raised(mcp_loaded):
    r = call("get_request", {"har_name": mcp_loaded, "index": 99999})
    assert "out of range" in r["error"]


def test_diff_hars(har_file):
    hp.store._hars.clear()
    a = call("load_har", {"path": har_file, "name": "a"})["name"]
    b = call("load_har", {"path": har_file, "name": "b"})["name"]
    d = call("diff_hars", {"har_a": a, "har_b": b})
    # identical captures → nothing unique, all unchanged
    assert d["only_in_a_total"] == 0 and d["only_in_b_total"] == 0
    assert d["unchanged_count"] == 4
    hp.store._hars.clear()
