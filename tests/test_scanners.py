"""The scanner adapters' parsing. httpx.MockTransport answers in place of the
real services, so nothing leaves the machine."""
import json

import httpx
import pytest

from asma.scanners import common, hibs, opensquat, shodan


def answer(monkeypatch, handler):
    """The scanners' HTTP client gets every response from handler(request)."""
    monkeypatch.setattr(common, "client",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler)))


def test_opensquat(monkeypatch):
    answer(monkeypatch, lambda r: httpx.Response(200, json={"results": [{"domain": "Examp1e.com."}]}))
    findings, raw = opensquat.run("example", "key", lambda: None)
    assert findings == {"examp1e.com": {}}  # key normalised


def hibs_stream(*kinds):
    lines = [{"permutation": {"domain": {"fqdn": "examp1e.com"}, "kind": "Typo"}}]
    lines += [{"op": "Meta", "data": {"kind": kind}} for kind in kinds]
    return "\n".join(json.dumps(line) for line in lines)


def test_hibs(monkeypatch):
    answer(monkeypatch, lambda r: httpx.Response(200, text=hibs_stream("Done")))
    findings, raw = hibs.run("example.com", "key", lambda: None)
    assert findings == {"examp1e.com": {"kinds": ["Typo"]}}


def test_hibs_stream_without_done_fails(monkeypatch):
    answer(monkeypatch, lambda r: httpx.Response(200, text=hibs_stream()))
    with pytest.raises(common.ScanError):
        hibs.run("example.com", "key", lambda: None)


def test_shodan(monkeypatch):
    monkeypatch.setattr(shodan, "DELAY", 0)
    host = {"data": [{"port": 443, "transport": "tcp", "data": "banner"}]}
    # Only .1 gets sent to Shodan, the other addresses get skipped.
    answer(monkeypatch, lambda r: httpx.Response(200, json=host) if r.url.path.endswith(".1")
           else httpx.Response(404))
    findings, raw = shodan.run("198.51.100.0/30", "key", lambda: None)
    assert findings == {"198.51.100.1": {"ports": [{"port": 443, "transport": "tcp", "banner": "banner"}]}}
