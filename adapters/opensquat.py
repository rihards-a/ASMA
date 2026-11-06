"""openSquat: newly registered domains resembling a keyword (NRD look-alike API).

One request. Details are everything the API reports on the domain
(e.g. tld, first-seen date, risk, similarity).
"""
from .. import scanners

TARGET_KIND = "keyword"
API_KEY = "OPENSQUAT_API_KEY"
ARTIFACT = "opensquat.json"
MEDIA_TYPE = "application/json"


def run(keyword, api_key, checkpoint):
    with scanners.client() as http:
        response = http.post(
            f"https://api.opensquat.com/v1/nrd/lookalike/{keyword}",  # keyword: [a-z0-9-] only
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            params={"risk": "true", "similarity": "true", "fuzziness": "high", "format": "json"},
            timeout=120)  # the service searches its feed before answering
        response.raise_for_status()
        data = scanners.json_body(response, "openSquat")
    findings = {}
    for entry in data.get("results") or []:
        key = scanners.finding_key(entry.get("domain") or "") if isinstance(entry, dict) else None
        if key:
            findings[key] = {k: v for k, v in entry.items() if k != "domain"}
    return findings, response.content
