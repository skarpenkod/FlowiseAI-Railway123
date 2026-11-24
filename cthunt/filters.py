"""Decide which hostnames are "Chinese": .cn zones, brand domains/keywords, C=CN certificates."""
from __future__ import annotations

import re
from pathlib import Path

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")

# Public second-level zones under .cn (CNNIC + provincial), so apex detection is right.
CN_SLD = {
    "com", "net", "org", "gov", "edu", "ac", "mil",
    "ah", "bj", "cq", "fj", "gd", "gs", "gz", "gx", "ha", "hb", "he", "hi", "hk", "hl", "hn",
    "jl", "js", "jx", "ln", "mo", "nm", "nx", "qh", "sc", "sd", "sh", "sn", "sx", "tj", "tw",
    "xj", "xz", "yn", "zj",
}
# Common multi-label suffixes elsewhere (for brand domains such as alibaba.com.hk).
OTHER_SLD = {"com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "com.tw", "org.tw", "com.sg",
             "co.uk", "com.au", "co.jp", "co.kr", "com.br", "com.my", "co.id", "com.ru"}

DEFAULT_SUFFIXES = (
    "cn",            # .cn and every *.com.cn / *.gov.cn / *.bj.cn ...
    "xn--fiqs8s",    # .中国
    "xn--fiqz9s",    # .中國
)


def normalize(name: str) -> str | None:
    n = name.strip().lower().rstrip(".")
    while n.startswith("*."):
        n = n[2:]
    if not HOST_RE.match(n):
        return None
    return n


def apex(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3:
        last2 = ".".join(labels[-2:])
        if (labels[-1] == "cn" and labels[-2] in CN_SLD) or last2 in OTHER_SLD:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class Matcher:
    """Returns a reason string ('tld', 'brand', 'kw', 'org') or None."""

    def __init__(self, suffixes=DEFAULT_SUFFIXES, brands_file: str | None = None,
                 use_brands: bool = True, country_cn: bool = True):
        self.suffixes = tuple("." + s.strip(".").lower() for s in suffixes)
        self.brand_domains: set[str] = set()
        self.keywords: list[str] = []
        self.country_cn = country_cn
        if use_brands:
            path = Path(brands_file) if brands_file else Path(__file__).with_name("brands.txt")
            self._load_brands(path)
        self._kw_re = re.compile("|".join(map(re.escape, self.keywords))) if self.keywords else None

    def _load_brands(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if not line:
                continue
            if line.startswith("kw:"):
                self.keywords.append(line[3:].strip())
            else:
                self.brand_domains.add(line)

    def match_host(self, host: str) -> str | None:
        h = "." + host
        if h.endswith(self.suffixes):
            return "tld"
        if self.brand_domains:
            labels = host.split(".")
            for i in range(len(labels) - 1):
                if ".".join(labels[i:]) in self.brand_domains:
                    return "brand"
        if self._kw_re and self._kw_re.search(apex(host)):
            return "kw"
        return None

    def match_cert(self, names: dict):
        """Yield (host, reason) for every interesting hostname in a parsed certificate."""
        hosts = {n for n in map(normalize, names["san"] + names["cn"]) if n}
        cert_is_cn = self.country_cn and names.get("country") == "CN"
        for h in hosts:
            reason = self.match_host(h)
            if reason is None and cert_is_cn:
                reason = "org"   # OV/EV certificate issued to a company with C=CN
            if reason:
                yield h, reason
