"""Have I Been Squatted: typosquatting permutations of a domain (lookup API).

The API streams one JSON object per line: Meta messages (progress,
heartbeats, the stored result's ID, done) and enrichment messages about
one permutation each (DNS, GeoIP, WHOIS, ...). Every permutation line is
kept as raw output; the finding only records the permutation kinds, the
rest stays in the artifact. The scan is complete when the StoredResult or
Done message arrives: a stream ending without one is a failed scan, not
a shorter result.
"""
import json

from .. import scanners

TARGET_KIND = "domain"
API_KEY = "HIBS_API_KEY"
ARTIFACT = "hibs.jsonl"
MEDIA_TYPE = "application/x-ndjson"


def run(domain, api_key, checkpoint):
    kinds, lines, finished = {}, [], False
    url = f"https://api.haveibeensquatted.com/v2/squat/{domain}"
    headers = {"Authorization": f"Bearer {api_key}"}
    # The read timeout applies between lines; the service sends heartbeats meanwhile.
    with scanners.client() as http, http.stream("GET", url, headers=headers,
                                                timeout=30) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            checkpoint()
            try:
                message = json.loads(line)
            except ValueError:
                continue  # blank or broken line
            if not isinstance(message, dict):
                continue
            meta = message.get("data") if message.get("op") == "Meta" else None
            if isinstance(meta, dict):
                kind = meta.get("kind")
                if kind == "Error":
                    detail = meta.get("data")
                    raise scanners.ScanError("Have I Been Squatted reported an error"
                                             + (f": {detail}" if detail else "."))
                if kind == "Timeout":
                    # The service gave up before checking every permutation.
                    raise scanners.ScanError("The Have I Been Squatted scan timed out; "
                                             "the results are incomplete.")
                if kind == "Done":
                    finished = True
                    break
                continue  # Progress, Heartbeat, StoredResult: nothing to keep
            permutation = message.get("permutation")
            if not isinstance(permutation, dict):
                continue
            lines.append(line)
            name = permutation.get("domain")
            key = scanners.finding_key(name.get("fqdn") or "") if isinstance(name, dict) else None
            if key:
                # One domain can come from several permutation kinds.
                kinds.setdefault(key, set()).add(str(permutation.get("kind") or "unknown"))
    if not finished:
        raise scanners.ScanError("The Have I Been Squatted stream ended before the scan finished.")
    findings = {key: {"kinds": sorted(k)} for key, k in kinds.items()}
    return findings, "".join(line + "\n" for line in lines).encode()
