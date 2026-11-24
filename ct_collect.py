#!/usr/bin/env python3
"""Certificate Transparency logs -> ct_domains.parquet

Reads RFC 6962 logs (get-sth / get-entries) and static-ct-api tiled logs (checkpoint / tile/data)
listed in log_list.json, takes SAN + CN names from every certificate and precertificate, keeps the
Chinese ones (.cn/.中国 or dnsmasq-china-list) and aggregates per host.

Every log runs in its own process (parsing is CPU-bound) with --workers HTTP fetchers. Results are
flushed into part files under <work>/ct/<log>/ and only then the checkpoint (next index) is moved, so
an interrupted run resumes without loss. hits = number of distinct certificates (issuer + serial), so
precert/final-cert pairs and the same certificate in several logs are counted once.

Scale: all current shards hold tens of billions of entries. Measure on one log first:
    python ct_collect.py --logs sycamore2027h1 --tail 2000000
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import logging
import multiprocessing as mp
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pyarrow as pa

from common import (ChinaTest, Registrable, atomic_write_parquet, atomic_write_text, download,
                    load_china_list, log, normalize, setup_logging, write_output)
from cthunt import ctlog
from cthunt.der import parse_names

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
OK_STATES = ("usable", "qualified", "readonly")


# --------------------------------------------------------------------------- log selection

def iso(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def select_logs(log_list: dict, names: str, since_months: int, exclude: str | None = None) -> list[dict]:
    """Current shards: they hold every certificate that is still valid or was logged in the window."""
    now = dt.datetime.now(dt.timezone.utc)
    horizon = now + dt.timedelta(days=31 * since_months)
    wanted = [w.strip().lower() for w in names.split(",")] if names and names != "all" else None
    skip = [w.strip().lower() for w in exclude.split(",")] if exclude else []
    out = []
    for op in log_list["operators"]:
        for kind, url_key in (("logs", "url"), ("tiled_logs", "monitoring_url")):
            for lg in op.get(kind, []):
                state = next(iter(lg.get("state", {})), "")
                if state not in OK_STATES:
                    continue
                ti = lg.get("temporal_interval")
                if ti and (iso(ti["end_exclusive"]) <= now or iso(ti["start_inclusive"]) > horizon):
                    continue
                desc = f'{op["name"]} {lg["description"]}'
                url = lg[url_key]
                key = desc.lower().replace(" ", "") + " " + url.lower()
                if wanted and not any(w in key for w in wanted):
                    continue
                if any(w in key for w in skip):
                    continue
                out.append({"name": desc, "url": url, "kind": "static" if kind == "tiled_logs" else "rfc6962"})
    return out


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def make(cfg: dict, batch: int):
    if cfg["kind"] == "static":
        return ctlog.StaticLog(cfg["url"], cfg["name"])
    return ctlog.RFC6962Log(cfg["url"], cfg["name"], batch)


def first_index_since(lg, size: int, cutoff_ms: int) -> int:
    """Binary search for the first entry logged at/after cutoff (timestamps are ~monotonic)."""
    def ts(i):
        e = lg.fetch(i, i + 1)
        return e[0].ts if e else 0
    if size == 0 or ts(0) >= cutoff_ms:
        return 0
    lo, hi = 0, size  # ts(lo) < cutoff
    while hi - lo > 1024:
        mid = (lo + hi) // 2
        if ts(mid) < cutoff_ms:
            lo = mid
        else:
            hi = mid
    return lo


# --------------------------------------------------------------------------- per-log worker (own process)

PART_SCHEMA = pa.schema([("host", pa.string()), ("domain", pa.string()), ("reason", pa.string()),
                         ("cert", pa.int64()), ("ts", pa.int64()), ("issuer", pa.string()),
                         ("log", pa.string())])


def cert_id(names: dict) -> int:
    h = hashlib.blake2b(names["issuer_raw"] + b"|" + names["serial"], digest_size=8).digest()
    return int.from_bytes(h, "big", signed=True)


def scan_log(cfg: dict, opts: dict) -> dict:
    setup_logging(opts["verbose"])
    name = cfg["name"]
    lg = make(cfg, opts["batch"])
    d = Path(opts["work"]) / "ct" / slug(name)
    d.mkdir(parents=True, exist_ok=True)
    state_file = d / "state.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else None

    try:
        size = lg.tree_size()
    except Exception as e:  # noqa: BLE001
        log.error("[%s] unreachable: %s", name, e)
        return {"log": name, "error": str(e)}

    if state is None:
        cutoff = int((time.time() - opts["since"] * 31 * 86400) * 1000)
        start = first_index_since(lg, size, cutoff)
        if opts["tail"]:
            start = max(start, size - opts["tail"])
        state = {"name": name, "url": cfg["url"], "start": start, "next": start}
        atomic_write_text(state_file, json.dumps(state))
    pos = state["next"]
    end = size if not opts["max_entries"] else min(size, pos + opts["max_entries"])
    log.info("[%s] tree_size=%s start=%s next=%s -> %s (%s entries to read)",
             name, f"{size:,}", f"{state['start']:,}", f"{pos:,}", f"{end:,}", f"{end - pos:,}")

    china = ChinaTest(load_china_list(opts["china_list_path"]))
    regdom = Registrable(opts["psl"], refresh=False)
    cols = {k: [] for k in PART_SCHEMA.names}
    chunk_start, t0, seen = pos, time.time(), 0
    window = opts["workers"] * lg.batch * 4
    parse_err = 0

    def flush(upto: int):
        nonlocal chunk_start, cols
        if upto > chunk_start:
            tb = pa.table({k: pa.array(v, PART_SCHEMA.field(k).type) for k, v in cols.items()}, schema=PART_SCHEMA)
            atomic_write_parquet(tb, d / f"{chunk_start:012d}-{upto:012d}.parquet")
        state["next"] = upto
        atomic_write_text(state_file, json.dumps(state))
        cols = {k: [] for k in PART_SCHEMA.names}
        chunk_start = upto

    with ThreadPoolExecutor(opts["workers"]) as pool:
        while pos < end:
            if opts["deadline"] and time.time() > opts["deadline"]:
                flush(pos)
                log.info("[%s] time limit reached at %s; rerun to continue", name, f"{pos:,}")
                break
            wend = min(pos + window, end)
            ranges, a = [], pos
            while a < wend:
                b = min((a // lg.batch + 1) * lg.batch, wend)
                ranges.append((a, b))
                a = b
            for attempt in range(5):
                try:
                    batches = list(pool.map(lambda r: lg.fetch(*r), ranges))
                    got = sum(len(x) for x in batches)
                    if got < wend - pos:
                        raise IOError(f"short read {got}/{wend - pos}")
                    break
                except Exception as e:  # noqa: BLE001
                    log.warning("[%s] window %s-%s failed (%s), retry %d", name, pos, wend, e, attempt + 1)
                    time.sleep(10 * (attempt + 1))
            else:
                flush(pos)
                log.error("[%s] giving up at %s; rerun to resume from here", name, f"{pos:,}")
                return {"log": name, "error": "fetch failed", "next": pos}
            for batch in batches:
                for ent in batch:
                    try:
                        nm = parse_names(ent.der, ent.is_tbs)
                    except Exception:  # noqa: BLE001
                        parse_err += 1
                        continue
                    cid = None
                    for raw in set(nm["san"] + nm["cn"]):
                        h = normalize(raw)
                        if not h:
                            continue
                        reason = china(h)
                        if not reason:
                            continue
                        if cid is None:
                            cid = cert_id(nm)
                        cols["host"].append(h)
                        cols["domain"].append(regdom(h))
                        cols["reason"].append(reason)
                        cols["cert"].append(cid)
                        cols["ts"].append(ent.ts)
                        cols["issuer"].append(nm["issuer"])
                        cols["log"].append(name)
            seen += wend - pos
            pos = wend
            if pos - chunk_start >= opts["chunk"] or pos >= end:
                flush(pos)
                el = time.time() - t0
                rate = seen / el
                eta = (end - pos) / rate if rate else 0
                log.info("[%s] %s/%s  %.0f entries/s  ETA %s  parse_errors=%d", name, f"{pos:,}", f"{end:,}",
                         rate, str(dt.timedelta(seconds=int(eta))), parse_err)
    return {"log": name, "next": pos, "read": seen, "seconds": time.time() - t0}


# --------------------------------------------------------------------------- aggregation

def aggregate(work: Path, out: str) -> int:
    import duckdb
    parts = list((work / "ct").glob("*/*.parquet"))
    if not parts:
        log.error("no CT parts to aggregate")
        return 0
    con = duckdb.connect()
    con.execute(f"SET temp_directory='{work / 'duckdb_tmp'}'")
    glob = str(work / "ct" / "*" / "*.parquet")
    sql = f"""
        SELECT any_value(domain) AS domain, host, 'ct' AS source,
               arg_min(reason, CASE reason WHEN 'cn_tld' THEN 1 ELSE 2 END) AS reason,
               CAST(to_timestamp(min(ts) / 1000) AS DATE) AS first_seen,
               CAST(to_timestamp(max(ts) / 1000) AS DATE) AS last_seen,
               count(DISTINCT cert) AS hits,
               json_object('issuers', list_slice(list(DISTINCT issuer) FILTER (WHERE issuer IS NOT NULL), 1, 5),
                           'logs', count(DISTINCT log)) AS extra
        FROM read_parquet('{glob}') GROUP BY host
    """
    n = write_output(con, sql, out)
    stats = con.execute(f"SELECT reason, count(*), count(DISTINCT domain) FROM read_parquet('{out}') GROUP BY 1").fetchall()
    log.info("wrote %s: %d hosts; by reason (hosts, domains): %s", out, n, stats)
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logs", default="all",
                    help="'all' or comma-separated parts of log names/URLs, e.g. 'sycamore2027h1,argon'")
    ap.add_argument("--exclude", help="comma-separated parts of log names/URLs to skip, e.g. 'argon,xenon'")
    ap.add_argument("--since", type=int, default=13, help="months back (default 13 = every valid certificate)")
    ap.add_argument("--workers", type=int, default=16, help="parallel HTTP requests per log")
    ap.add_argument("--procs", type=int, default=mp.cpu_count(), help="logs processed at once (one process each)")
    ap.add_argument("--out", default="ct_domains.parquet")
    ap.add_argument("--work", default="work", help="checkpoint directory")
    ap.add_argument("--log-list", default=LOG_LIST_URL, help="log_list.json URL or path")
    ap.add_argument("--tail", type=int, help="first run only: read just the newest N entries of each log")
    ap.add_argument("--max-entries", type=int, help="stop each log after N entries in this run")
    ap.add_argument("--hours", type=float, help="stop every log after this many hours (checkpoint kept)")
    ap.add_argument("--chunk", type=int, default=1_000_000, help="entries per checkpoint")
    ap.add_argument("--batch", type=int, default=256, help="get-entries page size for RFC 6962 logs")
    ap.add_argument("--china-list", help="local accelerated-domains.china.conf instead of downloading")
    ap.add_argument("--psl", help="local public_suffix_list.dat")
    ap.add_argument("--aggregate-only", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    setup_logging(a.verbose)
    work = Path(a.work)

    if not a.aggregate_only:
        if a.log_list.startswith("http"):
            path = work / "log_list.json"
            download(a.log_list, path)
        else:
            path = Path(a.log_list)
        logs = select_logs(json.loads(path.read_text()), a.logs, a.since, a.exclude)
        if not logs:
            sys.exit("no logs matched --logs")
        log.info("%d logs: %s", len(logs), ", ".join(l["name"] for l in logs))
        # download china-list and PSL once, workers reuse the cached files
        load_china_list(a.china_list)
        Registrable(a.psl)
        from common import CACHE
        opts = dict(work=str(work), workers=a.workers, since=a.since, tail=a.tail, max_entries=a.max_entries,
                    chunk=a.chunk, batch=a.batch,
                    deadline=time.time() + a.hours * 3600 if a.hours else None, verbose=a.verbose, psl=a.psl,
                    china_list_path=a.china_list or str(CACHE / "accelerated-domains.china.conf"))
        ctx = mp.get_context("spawn")
        with ctx.Pool(min(a.procs, len(logs))) as pool:
            results = pool.starmap(scan_log, [(c, opts) for c in logs])
        for r in results:
            log.info("result: %s", r)
    aggregate(work, a.out)


if __name__ == "__main__":
    main()
