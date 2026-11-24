#!/usr/bin/env python3
"""Check ct/cc/crux Parquet files against the common schema and the 20-domain control list.

    python validate.py data/ct_domains.parquet data/cc_domains.parquet data/crux_domains.parquet
Exit code 1 if a schema rule fails. Control-list misses are reported, not fatal (see --strict-control).
"""
from __future__ import annotations

import argparse
import sys

import duckdb

from common import REASONS, SOURCES

EXPECTED = {"domain": "VARCHAR", "host": "VARCHAR", "source": "VARCHAR", "reason": "VARCHAR",
            "first_seen": "DATE", "last_seen": "DATE", "hits": "BIGINT", "extra": "JSON"}

CONTROL = ["baidu.com", "qq.com", "sina.com.cn", "taobao.com", "tmall.com", "jd.com", "163.com",
           "weibo.com", "bilibili.com", "zhihu.com", "sohu.com", "alipay.com", "aliyun.com",
           "douyin.com", "meituan.com", "ctrip.com", "xiaomi.com", "huawei.com", "12306.cn", "people.com.cn"]


def check(path: str, strict_control: bool) -> bool:
    con = duckdb.connect()
    t = f"read_parquet('{path}')"
    ok = True

    def fail(msg):
        nonlocal ok
        ok = False
        print(f"  FAIL {msg}")

    cols = {r[0]: r[1] for r in con.execute(f"DESCRIBE SELECT * FROM {t}").fetchall()}
    if list(cols) != list(EXPECTED):
        fail(f"columns {list(cols)} != {list(EXPECTED)}")
    for c, typ in EXPECTED.items():
        if c in cols and cols[c] != typ and not (c == "extra" and cols[c] == "VARCHAR"):
            fail(f"{c}: {cols[c]} != {typ}")
    if not ok:
        return ok

    q = lambda sql: con.execute(sql.format(t=t)).fetchone()[0]  # noqa: E731
    n = q("SELECT count(*) FROM {t}")
    print(f"  rows {n:,}, domains {q('SELECT count(DISTINCT domain) FROM {t}'):,}")
    rules = {
        "duplicate host": "SELECT count(*) - count(DISTINCT host) FROM {t}",
        "null in required column": "SELECT count(*) FROM {t} WHERE domain IS NULL OR host IS NULL OR source IS NULL "
                                   "OR reason IS NULL OR first_seen IS NULL OR last_seen IS NULL OR hits IS NULL",
        "bad source": f"SELECT count(*) FROM {{t}} WHERE source NOT IN {SOURCES!r}",
        "bad reason": f"SELECT count(*) FROM {{t}} WHERE reason NOT IN {REASONS!r}",
        "not normalized (case/*./trailing dot/non-ascii)":
            "SELECT count(*) FROM {t} WHERE host <> lower(host) OR host LIKE '*.%' OR host LIKE '%.' "
            "OR regexp_matches(host, '[^a-z0-9._-]')",
        "host not under domain": "SELECT count(*) FROM {t} WHERE host <> domain AND NOT ends_with(host, '.' || domain)",
        "first_seen > last_seen": "SELECT count(*) FROM {t} WHERE first_seen > last_seen",
        "hits < 1": "SELECT count(*) FROM {t} WHERE hits < 1",
        "extra not valid json": "SELECT count(*) FROM {t} WHERE extra IS NOT NULL AND NOT json_valid(extra::VARCHAR)",
    }
    for name, sql in rules.items():
        bad = q(sql)
        if bad:
            fail(f"{name}: {bad:,} rows")
    print("  by reason:", con.execute(f"SELECT reason, count(*), count(DISTINCT domain) FROM {t} GROUP BY 1 ORDER BY 2 DESC").fetchall())
    cn = q("SELECT count(DISTINCT domain) FROM {t} WHERE ends_with(domain, '.cn') OR domain = 'cn'")
    print(f"  domains in .cn: {cn:,}")

    found = {r[0] for r in con.execute(
        f"SELECT DISTINCT domain FROM {t} WHERE domain IN ({','.join(repr(d) for d in CONTROL)})").fetchall()}
    missing = [d for d in CONTROL if d not in found]
    print(f"  control list: {len(CONTROL) - len(missing)}/{len(CONTROL)} found"
          + (f"; missing: {', '.join(missing)}" if missing else ""))
    if missing and strict_control:
        fail("control list incomplete")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--strict-control", action="store_true")
    a = ap.parse_args()
    ok = True
    for f in a.files:
        print(f)
        ok &= check(f, a.strict_control)
    print("OK" if ok else "SCHEMA CHECK FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
