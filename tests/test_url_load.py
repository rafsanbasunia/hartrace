"""URL loading: SSRF guards + a mocked successful fetch."""
import io
import json

import pytest

import har_parser as hp


def test_reject_non_http():
    r = hp.store.load_url("ftp://example.com/x.har")
    assert r["ok"] is False and "http" in r["error"]


def test_reject_no_host():
    r = hp.store.load_url("http:///nohost")
    assert r["ok"] is False


@pytest.mark.parametrize("url", [
    "http://localhost/x.har",
    "http://127.0.0.1/x.har",
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://10.0.0.1/x.har",
    "http://192.168.1.1/x.har",
])
def test_reject_private_addresses(url, monkeypatch):
    # Force resolution to the literal address so the guard is exercised
    # even where DNS would differ.
    r = hp.store.load_url(url)
    assert r["ok"] is False
    assert "private" in r["error"] or "internal" in r["error"]


def test_successful_fetch_mocked(monkeypatch):
    """Bypass the SSRF check + urlopen to prove the happy path ingests correctly."""
    har = json.dumps({"log": {"entries": [
        {"request": {"method": "GET", "url": "https://x/y", "headers": []},
         "response": {"status": 200, "headers": [], "content": {"size": 0, "text": ""}}}
    ]}}).encode()

    class FakeResp(io.BytesIO):
        headers = {"Content-Length": str(len(har))}
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(hp, "_is_private_ip", lambda host: False)
    monkeypatch.setattr(hp.urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResp(har))
    hp.store._hars.clear()
    r = hp.store.load_url("https://example.com/cap.har")
    assert r["ok"] is True and r["entry_count"] == 1
    assert r["name"] == "cap"
    hp.store._hars.clear()


def test_fetch_too_large(monkeypatch):
    monkeypatch.setattr(hp, "_is_private_ip", lambda host: False)
    monkeypatch.setattr(hp, "MAX_FILE_BYTES", 10)

    class FakeResp(io.BytesIO):
        headers = {"Content-Length": "999"}
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(hp.urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResp(b"x" * 999))
    r = hp.store.load_url("https://example.com/big.har")
    assert r["ok"] is False and "too large" in r["error"]
