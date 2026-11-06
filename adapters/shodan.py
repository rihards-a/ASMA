"""Shodan: stored data on every address of a network (host API).

One request per address, DELAY seconds apart, so a /22 takes about
17 minutes. Only addresses Shodan has data on become findings, with their
ports and banners.
"""
import ipaddress
import json
import time

from .. import scanners

TARGET_KIND = "network"
API_KEY = "SHODAN_API_KEY"
ARTIFACT = "shodan.json"
MEDIA_TYPE = "application/json"

# Seconds between host lookups; Shodan allows about one per second.
DELAY = 1.0


def run(network, api_key, checkpoint):
    # Target values are canonical: a CIDR block or first-last (validation.network).
    if "-" in network:
        first, last = (int(ipaddress.IPv4Address(a)) for a in network.split("-"))
    else:
        block = ipaddress.IPv4Network(network)
        first, last = int(block.network_address), int(block.broadcast_address)
    findings, raw = {}, {}
    with scanners.client() as http:
        for number in range(first, last + 1):
            checkpoint()
            ip = str(ipaddress.IPv4Address(number))
            response = http.get(f"https://api.shodan.io/shodan/host/{ip}",
                                params={"key": api_key}, timeout=30)
            # 404 means Shodan has no information on the address.
            if response.status_code != 404:
                response.raise_for_status() # 4xx and 5xx are failures.
                host = raw[ip] = scanners.json_body(response, "Shodan")
                # Sorted, so the same services always give the same details.
                ports = sorted((int(item.get("port") or 0), str(item.get("transport") or ""),
                                str(item.get("data") or ""))
                               for item in host.get("data") or [] if isinstance(item, dict))
                findings[ip] = {"ports": [{"port": p, "transport": t, "banner": b}
                                          for p, t, b in ports]}
            if number < last:
                time.sleep(DELAY)
    return findings, json.dumps(raw).encode()
