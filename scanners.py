"""Shared helpers for the scanners, and the contract every scanner follows.

Each scanner is one module in adapters/ and is listed in adapters.SCANNERS.
A scanner module defines:
  TARGET_KIND  the kind of target it scans (keyword, domain or network);
  API_KEY      configuration key holding the external service's API key;
  ARTIFACT, MEDIA_TYPE  file name and content type of its raw output;
  run(value, api_key, checkpoint) returning (findings, raw):
    value       the target's value - a domain, network or keyword;
    api_key     the service's key, from the configuration;
    checkpoint  called between requests; raises Cancelled when the job is no
                longer running (cancelled, or its target deleted);
    findings    {finding_key: details}, keys normalised by finding_key();
    raw         the service's responses as bytes, kept as the job's artifact.

Scanner modules call the helpers through the module (scanners.client()), so
later the tests can replace them. Failures are raised as exceptions; the job 
runner (jobs.py) turns them into the job's error.
"""
import json
import logging

import httpx

# httpx logs every request URL at INFO level, and Shodan's URL carries the API key.
logging.getLogger("httpx").setLevel(logging.WARNING)

# Longest findings.details text, in characters (the CHECK in the schema).
MAX_DETAILS = 16384


class Cancelled(Exception):
    """The job is no longer running; the scan stops and its results are dropped."""


class ScanError(Exception):
    """A failure whose message can be shown to the user as is."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def client():
    """HTTP client for one scan. Added so tests can replace it easily.

    Redirects are not followed (httpx default), so API keys sent in headers
    never reach another host. Each request sets its own timeout.
    """
    return httpx.Client()


def json_body(response, service):
    """The response's JSON object, or ScanError when the service sent something else."""
    try:
        data = response.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise ScanError(f"{service} returned an unexpected response.")
    return data


def finding_key(text):
    """Lowercase key without a trailing dot; None when outside the schema's 1 to 300 characters."""
    key = str(text).strip().lower().rstrip(".")
    return key if 0 < len(key) <= 300 else None


def canonical(value):
    """JSON text with sorted keys and no spaces, so equal values give equal text."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def cut(value, limit):
    """value with every string longer than limit characters cut to limit."""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, list):
        return [cut(v, limit) for v in value]
    if isinstance(value, dict):
        return {k: cut(v, limit) for k, v in value.items()}
    return value


def details_json(details):
    """Canonical JSON of a finding's details, made to fit MAX_DETAILS.

    Too long details get their strings (e.g. banners) cut shorter until the
    text fits, plus "truncated": true. The cut is the same on every run, so
    it never shows up as a change between two jobs.
    """
    text = canonical(details)
    for limit in (1000, 200, 50):
        if len(text) <= MAX_DETAILS:
            break
        text = canonical({**cut(details, limit), "truncated": True})
    return text if len(text) <= MAX_DETAILS else canonical({"truncated": True})
