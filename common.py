"""Shared pieces for ct_collect / cc_collect / crux_collect: normalization, "Chinese" test, output schema."""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
import urllib.request
from pathlib import Path

import pyarrow as pa

CHINA_LIST_URL = ("https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/"
                  "master/accelerated-domains.china.conf")
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
CACHE = Path(os.environ.get("CNDOMAINS_CACHE", Path(__file__).with_name(".cache")))

CN_TLDS = ("cn", "xn--fiqs8s")  # .cn, .中国
REASONS = ("cn_tld", "china_list", "lang_zho", "crux_cn")
SOURCES = ("ct", "cc", "crux")

SCHEMA = pa.schema([
    ("domain", pa.string()),
    ("host", pa.string()),
    ("source", pa.string()),
    ("reason", pa.string()),
    ("first_seen", pa.date32()),
    ("last_seen", pa.date32()),
    ("hits", pa.int64()),
    ("extra", pa.string()),  # JSON text; written with the Parquet JSON logical type
])

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

log = logging.getLogger("cndomains")


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")


def download(url: str, dest: Path, timeout: float = 120) -> bool:
    """Download to dest atomically; keep the old copy if the download fails."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cndomains/1.0"})
        data = urllib.request.urlopen(req, timeout=timeout).read()
        fd, tmp = tempfile.mkstemp(dir=dest.parent)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, dest)
        return True
    except Exception as e:  # noqa: BLE001
        if dest.exists():
            log.warning("download %s failed (%s), using cached %s", url, e, dest)
            return False
        raise


# --------------------------------------------------------------------------- normalization

def normalize(name: str) -> str | None:
    """lower-case, no '*.', no trailing dot, IDN -> punycode. None if not a valid hostname."""
    n = name.strip().lower().rstrip(".")
    while n.startswith("*."):
        n = n[2:]
    if not n:
        return None
    if not n.isascii():
        try:
            n = n.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return n if HOST_RE.match(n) else None


class Registrable:
    """eTLD+1 via tldextract on a local PSL copy (refreshed from publicsuffix.org when possible)."""

    def __init__(self, psl_path: str | None = None, refresh: bool = True):
        import tldextract
        if psl_path is None:
            path = CACHE / "public_suffix_list.dat"
            if refresh or not path.exists():
                try:
                    download(PSL_URL, path)
                except Exception as e:  # noqa: BLE001
                    log.warning("PSL download failed (%s); using tldextract's bundled snapshot", e)
            psl_path = str(path) if path.exists() else None
        urls = (Path(psl_path).resolve().as_uri(),) if psl_path else ()
        self._ex = tldextract.TLDExtract(suffix_list_urls=urls, cache_dir=str(CACHE / "tldextract"),
                                         fallback_to_snapshot=True, include_psl_private_domains=False)
        self._cache: dict[str, str] = {}

    def __call__(self, host: str) -> str:
        d = self._cache.get(host)
        if d is None:
            r = self._ex(host)
            d = r.top_domain_under_public_suffix if hasattr(r, "top_domain_under_public_suffix") else r.registered_domain
            d = d or host
            if len(self._cache) < 2_000_000:
                self._cache[host] = d
        return d


# --------------------------------------------------------------------------- "Chinese" test

def load_china_list(path: str | None = None) -> set[str]:
    """dnsmasq-china-list accelerated-domains, downloaded fresh on every start (cached fallback)."""
    p = Path(path) if path else CACHE / "accelerated-domains.china.conf"
    if not path:
        download(CHINA_LIST_URL, p)
    out = set()
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("server=/"):
            d = normalize(line.split("/")[1])
            if d:
                out.add(d)
    log.info("china-list: %d domains", len(out))
    return out


class ChinaTest:
    def __init__(self, china_list: set[str]):
        self.china = china_list

    def __call__(self, host: str) -> str | None:
        """'cn_tld', 'china_list' or None."""
        tld = host.rsplit(".", 1)[-1]
        if tld in CN_TLDS:
            return "cn_tld"
        if self.china:
            i = 0
            while True:
                if host[i:] in self.china:
                    return "china_list"
                i = host.find(".", i) + 1
                if i == 0:
                    break
        return None


# --------------------------------------------------------------------------- output

def write_output(con, select_sql: str, out: str) -> int:
    """Run an aggregate query in DuckDB and write it to Parquet in the common schema."""
    tmp = out + ".tmp"
    con.execute(f"""
        COPY (
            SELECT domain::VARCHAR AS domain, host::VARCHAR AS host, source::VARCHAR AS source,
                   reason::VARCHAR AS reason, first_seen::DATE AS first_seen, last_seen::DATE AS last_seen,
                   hits::BIGINT AS hits, extra::JSON AS extra
            FROM ({select_sql}) ORDER BY domain, host
        ) TO '{tmp}' (FORMAT parquet, COMPRESSION zstd)
    """)
    os.replace(tmp, out)
    return con.execute(f"SELECT count(*) FROM read_parquet('{out}')").fetchone()[0]


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def atomic_write_parquet(table: pa.Table, path: Path) -> None:
    import pyarrow.parquet as pq
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, path)


def jdump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
