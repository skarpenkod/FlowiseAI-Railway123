"""Subdomain enrichment through crt.sh (historical CT search) for a list of apex domains."""
from __future__ import annotations

import json
import sys
import time
import urllib.parse

from .ctlog import http_get
from .filters import normalize


def subdomains(apex: str, include_expired: bool = False, timeout: float = 90) -> set[str]:
    q = urllib.parse.quote(f"%.{apex}")
    url = f"https://crt.sh/?q={q}&output=json"
    if not include_expired:
        url += "&exclude=expired"
    data = json.loads(http_get(url, timeout=timeout, retries=4) or b"[]")
    out = set()
    for row in data:
        for raw in (row.get("name_value", "") + "\n" + row.get("common_name", "")).splitlines():
            n = normalize(raw)
            if n and (n == apex or n.endswith("." + apex)):
                out.add(n)
    return out


def enrich(store, matcher, apexes, include_expired: bool, delay: float):
    total_new = 0
    for i, a in enumerate(apexes, 1):
        try:
            hosts = subdomains(a, include_expired)
        except Exception as e:
            print(f"[{i}] {a}: failed ({e})", file=sys.stderr)
            continue
        rows = [(h, matcher.match_host(h) or "crtsh") for h in hosts]
        new = store.add_hosts(rows, "crt.sh")
        store.commit()
        total_new += new
        print(f"[{i}] {a}: {len(hosts)} names, {new} new", file=sys.stderr)
        time.sleep(delay)
    return total_new
