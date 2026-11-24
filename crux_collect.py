#!/usr/bin/env python3
"""Chrome UX Report (BigQuery) -> crux_domains.parquet

Takes every origin from the public dataset `chrome-ux-report.country_cn.YYYYMM` for the last
--months months, only the `origin` column and `experimental.popularity.rank` (if present), so the scan
stays inside the BigQuery free tier. A dry run prints the bytes to be scanned before anything runs.

All origins are kept: CrUX for China contains many foreign sites, so `reason` says why a host counts as
Chinese (cn_tld / china_list) or is just `crux_cn`, and extra.chinese is the flag.
hits = number of months the origin appeared; extra.rank = best (smallest) popularity rank bucket.

Checkpoint: one part file per month under <work>/crux/; finished months are not queried again.

Auth: Application Default Credentials (`gcloud auth application-default login`) or
GOOGLE_APPLICATION_CREDENTIALS pointing to a service-account key; --project is billed for the query.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

import pyarrow as pa

from common import (ChinaTest, Registrable, atomic_write_parquet, load_china_list, log, normalize,
                    setup_logging, write_output)

DATASET = "chrome-ux-report.country_cn"
MAX_BYTES = 1 << 40  # 1 TiB, acceptance limit


def month_ids(n: int, latest: str | None) -> list[str]:
    if latest:
        y, m = int(latest[:4]), int(latest[4:])
    else:
        t = dt.date.today()
        y, m = t.year, t.month
    out = []
    for _ in range(n):
        out.append(f"{y:04d}{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return out


def available_months(client) -> set[str]:
    rows = client.query(f"SELECT table_name FROM `{DATASET}.INFORMATION_SCHEMA.TABLES`").result()
    return {r.table_name for r in rows if r.table_name.isdigit()}


def has_rank(client, table: str) -> bool:
    q = (f"SELECT 1 FROM `{DATASET}.INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` "
         f"WHERE table_name = '{table}' AND field_path = 'experimental.popularity.rank' LIMIT 1")
    return bool(list(client.query(q).result()))


def month_sql(table: str, rank: bool) -> str:
    r = "MIN(experimental.popularity.rank)" if rank else "CAST(NULL AS INT64)"
    return f"SELECT origin, {r} AS rank FROM `{DATASET}.{table}` GROUP BY origin"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="GCP project that pays for the query")
    ap.add_argument("--months", type=int, default=12)
    ap.add_argument("--latest", help="newest month YYYYMM (default: newest available)")
    ap.add_argument("--out", default="crux_domains.parquet")
    ap.add_argument("--work", default="work")
    ap.add_argument("--dry-run", action="store_true", help="only print the scan size")
    ap.add_argument("--max-bytes", type=int, default=MAX_BYTES, help="refuse to run above this scan size")
    ap.add_argument("--china-list")
    ap.add_argument("--psl")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    setup_logging(a.verbose)

    from google.cloud import bigquery
    client = bigquery.Client(project=a.project)
    avail = available_months(client)
    if not avail:
        sys.exit(f"no tables in {DATASET}")
    latest = a.latest or max(avail)
    months = [m for m in month_ids(a.months, latest) if m in avail]
    log.info("months: %s (missing: %s)", ", ".join(months),
             ", ".join(sorted(set(month_ids(a.months, latest)) - avail)) or "none")

    work = Path(a.work) / "crux"
    work.mkdir(parents=True, exist_ok=True)
    todo = [m for m in months if not (work / f"{m}.parquet").exists()]
    rank_cols = {m: has_rank(client, m) for m in todo}
    if todo:
        # one dry run over everything still to do: what the real queries will scan
        union = " UNION ALL ".join(month_sql(m, rank_cols[m]) for m in todo)
        job = client.query(union, job_config=bigquery.QueryJobConfig(dry_run=True, use_query_cache=False))
        scan = job.total_bytes_processed
        log.info("dry run: %d months to query, %.2f GB to scan (limit %.0f GB)", len(todo), scan / 1e9, a.max_bytes / 1e9)
        if a.dry_run:
            return
        if scan > a.max_bytes:
            sys.exit("scan exceeds --max-bytes, aborting")
    elif a.dry_run:
        log.info("dry run: nothing to query, all months are cached")
        return

    china = ChinaTest(load_china_list(a.china_list))
    regdom = Registrable(a.psl)
    for m in todo:
        job = client.query(month_sql(m, rank_cols[m]),
                           job_config=bigquery.QueryJobConfig(maximum_bytes_billed=a.max_bytes))
        rows = job.result()
        cols = {"host": [], "domain": [], "reason": [], "chinese": [], "rank": [], "origin": [], "month": []}
        for r in rows:
            origin = r.origin
            host = normalize(origin.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0])
            if not host:
                continue
            why = china(host)
            cols["host"].append(host)
            cols["domain"].append(regdom(host))
            cols["reason"].append(why or "crux_cn")
            cols["chinese"].append(why is not None)
            cols["rank"].append(r.rank)
            cols["origin"].append(origin)
            cols["month"].append(dt.date(int(m[:4]), int(m[4:]), 1))
        tb = pa.table({k: pa.array(v, pa.int64() if k == "rank" else pa.date32() if k == "month" else None)
                       for k, v in cols.items()})
        atomic_write_parquet(tb, work / f"{m}.parquet")
        log.info("%s: %d origins, %d chinese, billed %.2f GB", m, tb.num_rows, sum(cols["chinese"]),
                 (job.total_bytes_billed or 0) / 1e9)

    import duckdb
    con = duckdb.connect()
    parts = [str(work / f"{m}.parquet") for m in months if (work / f"{m}.parquet").exists()]
    rank = "CASE reason WHEN 'cn_tld' THEN 1 WHEN 'china_list' THEN 2 ELSE 3 END"
    sql = f"""
        SELECT any_value(domain) AS domain, host, 'crux' AS source,
               arg_min(reason, {rank}) AS reason,
               min(month) AS first_seen, max(month) AS last_seen,
               count(DISTINCT month) AS hits,
               json_object('rank', min(rank), 'chinese', bool_or(chinese),
                           'origins', list_slice(list(DISTINCT origin), 1, 3)) AS extra
        FROM read_parquet({parts!r}) GROUP BY host
    """
    n = write_output(con, sql, a.out)
    stats = con.execute(f"SELECT reason, count(*) FROM read_parquet('{a.out}') GROUP BY 1").fetchall()
    log.info("wrote %s: %d hosts %s", a.out, n, stats)


if __name__ == "__main__":
    main()
