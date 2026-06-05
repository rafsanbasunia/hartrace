"""Shared fixtures: a synthetic HAR with a real set→used provenance chain."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import har_parser as hp  # noqa: E402


# A capture where:
#   #0 POST /login  -> Set-Cookie sessionid=...  + body has csrf_token + nested JSON
#   #1 GET  /home   -> sends sessionid cookie
#   #2 POST /action -> sends sessionid cookie + X-CSRF header + token in body
#   #3 GET  logo.png-> binary (base64) response
SESSION = "Zx9KdpQ4mNvR7sLwT2bYhJ8cF1gA6eU3"
CSRF = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"

_HAR = {
    "log": {
        "version": "1.2",
        "entries": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/login",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {"text": json.dumps({"user": "alice", "pass": "hunter2"})},
                },
                "response": {
                    "status": 200,
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "Set-Cookie",
                         "value": f"sessionid={SESSION}; Path=/; HttpOnly"},
                    ],
                    "content": {
                        "size": 100,
                        "text": json.dumps({
                            "ok": True, "csrf_token": CSRF,
                            "nested": json.dumps({"inner": "deep_value_xyz"}),
                        }),
                    },
                },
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/home?ref=login",
                    "headers": [{"name": "Cookie", "value": f"sessionid={SESSION}"}],
                },
                "response": {"status": 200,
                             "headers": [{"name": "Content-Type", "value": "text/html"}],
                             "content": {"size": 17, "text": "<html>home</html>"}},
            },
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/action",
                    "headers": [
                        {"name": "Cookie", "value": f"sessionid={SESSION}"},
                        {"name": "X-CSRF-Token", "value": CSRF},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "postData": {"text": json.dumps({"do": "thing", "token": CSRF})},
                },
                "response": {"status": 200,
                             "headers": [{"name": "Content-Type", "value": "application/json"}],
                             "content": {"size": 15, "text": '{"result":"ok"}'}},
            },
            {
                "request": {"method": "GET", "url": "https://cdn.example.com/logo.png",
                            "headers": [{"name": "Accept", "value": "image/png"}]},
                "response": {"status": 200,
                             "headers": [{"name": "Content-Type", "value": "image/png"}],
                             "content": {"size": 8, "encoding": "base64",
                                         "text": "iVBORw0KAAA="}},
            },
        ],
    }
}


@pytest.fixture
def har_file(tmp_path):
    """Write the synthetic HAR to disk and return its path."""
    p = tmp_path / "cap.har"
    p.write_text(json.dumps(_HAR), encoding="utf-8")
    return str(p)


@pytest.fixture
def loaded(har_file):
    """Load the HAR into a fresh store and return its name. Cleans up after."""
    # isolate the global store between tests
    hp.store._hars.clear()
    res = hp.store.load(har_file)
    assert res["ok"], res
    yield res["name"]
    hp.store._hars.clear()
