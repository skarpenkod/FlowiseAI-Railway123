#!/usr/bin/env python3
"""Common Crawl -> cc_domains.parquet

For every crawl, reads the URL-index Parquet files (columnar, only 5 columns via HTTP range
requests), keeps fetch_status=200 rows whose host is in .cn/.中国, in dnsmasq-china-list, or whose
primary content language is zho, and aggregates per host.

Checkpoint: <work>/cc/<crawl>/done.txt lists finished index files; each file's result is an
aggregated part Parquet, so an interrupted run resumes without losing or double-counting pages.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import io
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from common import (CN_TLDS, ChinaTest, Registrable, atomic_write_parquet, load_china_list, log,
                    normalize, setup_logging, write_output)

BASE = "https://data.commoncrawl.org/"
COLLINFO = "https://index.commoncrawl.org/collinfo.json"
COLUMNS = ["url_host_name", "url_host_registered_domain", "url_host_tld", "content_languages", "fetch_status"]


def http(url: str, headers=None, timeout=120, retries=8) -> bytes:
    delay = 2
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cndomains/1.0", **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 404) and i >= 2:
                raise
            if i == retries - 1:
                raise
        except Exception:  # noqa: BLE001
            if i == retries - 1:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 120)  # CC answers 503 "slow down" under load
    raise RuntimeError


class HTTPRangeFile(io.RawIOBase):
    """Seekable read-only file over HTTP range requests, so pyarrow fetches only needed column chunks."""

    def __init__(self, url: str):
        super().__init__()
        self.url, self.pos, self.fetched = url, 0, 0
        last = http(url, {"Range": "bytes=-8"})
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "cndomains/1.0"})
        self.size = int(urllib.request.urlopen(req, timeout=60).headers["Content-Length"])
        assert last[-4:] == b"PAR1", "not a parquet file"

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.size + off
        return self.pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        if n == 0 or self.pos >= self.size:
            return b""
        end = min(self.pos + n, self.size) - 1
        data = http(self.url, {"Range": f"bytes={self.pos}-{end}"})
        self.pos += len(data)
        self.fetched += len(data)
        return data

    def readinto(self, b):
        d = self.read(len(b))
        b[:len(d)] = d
        return len(d)


def to_arrow(res) -> pa.Table:
    """DuckDB result -> Arrow table (DuckDB 2.x: to_arrow_table, 1.x: fetch_arrow_table)."""
    fn = getattr(res, "to_arrow_table", None) or res.fetch_arrow_table
    return fn()


def crawl_date(crawl: str) -> dt.date:
    """CC-MAIN-2026-43 -> Monday of ISO week 43 of 2026."""
    _, _, y, w = crawl.split("-")
    return dt.date.fromisocalendar(int(y), int(w), 1)


def list_crawls(n: int) -> list[str]:
    """Latest crawls: collinfo.json, falling back to the crawl-data index page."""
    try:
        ids = [c["id"] for c in json.loads(http(COLLINFO, timeout=60, retries=3))]
    except Exception as e:  # noqa: BLE001
        log.warning("collinfo.json unavailable (%s), using crawl-data/index.html", e)
        page = http(BASE + "crawl-data/index.html").decode("utf-8", "replace")
        ids = list(dict.fromkeys(re.findall(r"CC-MAIN-20\d\d-\d\d", page)))
    ids = sorted({i for i in ids if re.fullmatch(r"CC-MAIN-20\d\d-\d\d", i)}, reverse=True)
    return ids[:n]


def index_files(crawl: str) -> list[str]:
    raw = gzip.decompress(http(f"{BASE}crawl-data/{crawl}/cc-index-table.paths.gz"))
    return [l for l in raw.decode().split() if "/subset=warc/" in l]


def process_file(path: str, crawl: str, china: ChinaTest, regdom: Registrable, threads: int) -> tuple[pa.Table, int, int]:
    f = HTTPRangeFile(BASE + path)
    pf = pq.ParquetFile(f, pre_buffer=True)
    tb = pf.read(columns=COLUMNS, use_threads=True)
    con = duckdb.connect()
    con.execute(f"SET threads={threads}")
    con.register("t", tb)
    # one row per host in this file; china-list matching needs suffix tests, done in Python on
    # distinct hosts (hundreds of thousands, not millions of rows)
    hosts = con.sql(f"""
        SELECT url_host_name AS host,
               any_value(url_host_tld) AS tld,
               count(*) AS pages,
               count(*) FILTER (WHERE content_languages LIKE 'zho%') AS zho_pages
        FROM t WHERE fetch_status = 200
        GROUP BY 1
    """)
    hosts = to_arrow(hosts)
    out_host, out_dom, out_reason, out_hits, out_zho = [], [], [], [], []
    for h, tld, pages, zho in zip(*(hosts.column(c).to_pylist() for c in ("host", "tld", "pages", "zho_pages"))):
        n = normalize(h)
        if not n:
            continue
        reason = "cn_tld" if (tld or "").lower() in CN_TLDS or tld == "中国" else china(n)
        if reason is None and zho:
            reason = "lang_zho"
        if reason is None:
            continue
        out_host.append(n)
        out_dom.append(regdom(n))
        out_reason.append(reason)
        out_hits.append(pages)
        out_zho.append(zho)
    part = pa.table({"host": out_host, "domain": out_dom, "reason": out_reason,
                     "hits": pa.array(out_hits, pa.int64()), "zho_pages": pa.array(out_zho, pa.int64()),
                     "crawl": pa.array([crawl] * len(out_host), pa.string())})
    return part, tb.num_rows, f.fetched


def run_crawl(crawl: str, work: Path, china: ChinaTest, regdom: Registrable, threads: int, limit: int | None):
    d = work / "cc" / crawl
    d.mkdir(parents=True, exist_ok=True)
    done_file = d / "done.txt"
    done = set(done_file.read_text().split()) if done_file.exists() else set()
    files = index_files(crawl)
    if limit:
        files = files[:limit]
    todo = [p for p in files if p.rsplit("/", 1)[-1] not in done]
    log.info("%s: %d index files, %d done, %d to go", crawl, len(files), len(files) - len(todo), len(todo))
    lock = threading.Lock()
    t0, rows_total, bytes_total, n_ok = time.time(), 0, 0, 0
    inner = max(1, 4 // threads) if threads < 4 else 1
    with ThreadPoolExecutor(threads) as pool:
        futs = {pool.submit(process_file, p, crawl, china, regdom, inner): p for p in todo}
        for fut in as_completed(futs):
            p = futs[fut]
            name = p.rsplit("/", 1)[-1]
            try:
                part, nrows, nbytes = fut.result()
            except Exception as e:  # noqa: BLE001
                log.error("%s %s failed: %s (will retry on next run)", crawl, name, e)
                continue
            # part first, then mark done: a crash in between only redoes this file (same part name)
            atomic_write_parquet(part, d / (name.replace(".parquet", "") + ".part.parquet"))
            with lock:
                with open(done_file, "a") as fh:
                    fh.write(name + "\n")
                n_ok += 1
                rows_total += nrows
                bytes_total += nbytes
                el = time.time() - t0
                log.info("%s [%d/%d] %s: %d rows -> %d hosts | %.1f MB/s, %.0f rows/s",
                         crawl, n_ok, len(todo), name[:14], nrows, part.num_rows,
                         bytes_total / 1e6 / el, rows_total / el)
    return n_ok == len(todo)


def aggregate(work: Path, crawls: list[str], out: str) -> int:
    con = duckdb.connect()
    globs = [str(work / "cc" / c / "*.part.parquet") for c in crawls if list((work / "cc" / c).glob("*.part.parquet"))]
    if not globs:
        log.error("nothing to aggregate")
        return 0
    dates = ", ".join(f"('{c}', DATE '{crawl_date(c)}')" for c in crawls)
    rank = "CASE reason WHEN 'cn_tld' THEN 1 WHEN 'china_list' THEN 2 ELSE 3 END"
    sql = f"""
        WITH p AS (
            SELECT p.*, d.dt FROM read_parquet({globs!r}) p JOIN (VALUES {dates}) d(crawl, dt) USING (crawl)
        )
        SELECT any_value(domain) AS domain, host, 'cc' AS source,
               arg_min(reason, {rank}) AS reason,
               min(dt) AS first_seen, max(dt) AS last_seen,
               sum(hits) AS hits,
               json_object('crawls', count(DISTINCT crawl), 'zho_pages', sum(zho_pages)) AS extra
        FROM p GROUP BY host
    """
    n = write_output(con, sql, out)
    stats = con.execute(f"""SELECT reason, count(*), count(DISTINCT domain) FROM read_parquet('{out}')
                            GROUP BY 1 ORDER BY 2 DESC""").fetchall()
    log.info("wrote %s: %d hosts; by reason (hosts, domains): %s", out, n, stats)
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--crawls", default="6",
                    help="number of latest crawls (default 6) or comma-separated ids, e.g. CC-MAIN-2026-43")
    ap.add_argument("--threads", type=int, default=8, help="index files processed in parallel")
    ap.add_argument("--out", default="cc_domains.parquet")
    ap.add_argument("--work", default="work", help="checkpoint directory")
    ap.add_argument("--limit-files", type=int, help="only the first N index files per crawl (testing)")
    ap.add_argument("--china-list", help="local accelerated-domains.china.conf instead of downloading")
    ap.add_argument("--psl", help="local public_suffix_list.dat")
    ap.add_argument("--aggregate-only", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    setup_logging(a.verbose)

    crawls = list_crawls(int(a.crawls)) if a.crawls.isdigit() else [c.strip() for c in a.crawls.split(",")]
    log.info("crawls: %s", ", ".join(crawls))
    work = Path(a.work)
    ok = True
    if not a.aggregate_only:
        china = ChinaTest(load_china_list(a.china_list))
        regdom = Registrable(a.psl)
        for c in crawls:
            ok &= run_crawl(c, work, china, regdom, a.threads, a.limit_files)
    aggregate(work, crawls, a.out)
    if not ok:
        log.warning("some index files failed; rerun the same command to finish them")
        sys.exit(2)


if __name__ == "__main__":
    main()
