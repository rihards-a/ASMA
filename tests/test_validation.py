"""Input checks in validation.py. Pure functions: no application needed."""
import pytest

from conftest import validation


def rejects(func, *args):
    """True when func(*args) raises InputError."""
    with pytest.raises(validation.InputError):
        func(*args)
    return True


def test_text():
    assert validation.text("  hello ", "Label", 10) == "hello"
    assert validation.text("  ", "Notes", 10, required=False) is None
    for bad in ("   ", None, "x" * 11, 42):
        assert rejects(validation.text, bad, "Label", 10)


def test_username_and_password():
    assert validation.username(" Anna.K_1 ") == "Anna.K_1"
    for bad in ("an", "anna k", "x" * 51):
        assert rejects(validation.username, bad)
    assert validation.password(" twelve chars ", "anna") == " twelve chars "  # not trimmed
    for bad in ("short", "x" * 129, None):
        assert rejects(validation.password, bad, "anna")
    assert rejects(validation.password, "AnnaAnnaAnna", "annaannaanna")  # equals username


def test_domain():
    assert validation.domain("Example.COM") == "example.com"
    assert validation.domain("xn--bcher-kva.de") == "xn--bcher-kva.de"
    for bad in ("localhost", "example.com.", "a..b", "-bad.com", "ex_ample.com", "example.c",
                "bücher.de"):
        assert rejects(validation.domain, bad)


def test_keyword():
    assert validation.keyword("Example-2") == "example-2"
    for bad in ("ex.ample", "brand_x", "x" * 64):
        assert rejects(validation.keyword, bad)


def test_network_canonical_forms():
    cases = {
        "198.51.100.7": "198.51.100.7/32",
        "198.51.100.0/24": "198.51.100.0/24",
        "198.51.100.0-198.51.100.255": "198.51.100.0/24",
        "198.51.100.10-40": "198.51.100.10-198.51.100.40",
        "10.0.0.0/22": "10.0.0.0/22",  # exactly 1024 addresses
    }
    for value, expected in cases.items():
        assert validation.network(value, 1024) == expected


def test_network_rejected():
    for bad in ("10.0.0.0/21",                          # too large
                "127.0.0.1", "224.0.0.0/24",            # reserved
                "198.51.100.5/24", "198.51.100.40-10",  # host bits set, reversed range
                "2001:db8::/64", "example.com"):        # not IPv4
        assert rejects(validation.network, bad, 1024)


def test_key_prefix():
    assert validation.key_prefix("N8N-Prod") == "n8n-prod"
    for bad in ("ab", "n8n_x", "-n8n", "x" * 33):
        assert rejects(validation.key_prefix, bad)
