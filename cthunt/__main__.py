"""cthunt — collect Chinese domains (.cn, .com.cn, Chinese brands) from Certificate Transparency logs."""
from __future__ import annotations

import argparse
import re
import sys

from . import ctlog
from .filters import DEFAULT_SUFFIXES, Matcher
from .store import Store


def build_matcher(a) -> Matcher:
    return Matcher(suffixes=a.suffix or DEFAULT_SUFFIXES, brands_file=a.brands,
                   use_brands=not a.no_brands, country_cn=not a.no_country)


def select_logs(a):
    if a.log:
        logs = [ctlog.make_log(u, a.batch) for u in a.log]
    else:
        logs = ctlog.load_log_list(a.log_list, all_shards=a.all_shards, rfc6962_batch=a.batch)
    if a.only:
        rx = re.compile(a.only, re.I)
        logs = [lg for lg in logs if rx.search(lg.name) or rx.search(lg.url)]
    return logs


def cmd_logs(a):
    for lg in select_logs(a):
        size = ""
        if a.sizes:
            try:
                size = f"{lg.tree_size():>15,}"
            except Exception as e:
                size = f"{'error: ' + type(e).__name__:>15}"
        print(f"{lg.kind:8} {size} {lg.name}  {lg.url}")


def cmd_run(a):
    from .runner import run
    logs = select_logs(a)
    if not logs:
        sys.exit("no logs selected")
    store = Store(a.db)
    print(f"{len(logs)} logs, db={a.db}", file=sys.stderr)
    stats, new = run(logs, store, build_matcher(a), tail=a.tail, from_start=a.from_start,
                     follow=a.follow, poll=a.poll, workers=a.workers,
                     parallel_logs=a.parallel_logs, max_entries=a.max_entries)
    hosts, apexes = store.count()
    print(f"done: entries={stats.entries:,} matched={stats.matched:,} new={new:,} "
          f"total_hosts={hosts:,} apexes={apexes:,}", file=sys.stderr)


def cmd_export(a):
    store = Store(a.db)
    out = open(a.output, "w", encoding="utf-8") if a.output and a.output != "-" else sys.stdout
    n = 0
    for h in store.iter_hosts(apex_only=a.apex, reasons=a.reason):
        out.write(h + "\n")
        n += 1
    if out is not sys.stdout:
        out.close()
    print(f"exported {n:,} lines", file=sys.stderr)


def cmd_stats(a):
    store = Store(a.db)
    hosts, apexes = store.count()
    print(f"hosts:   {hosts:,}\napexes:  {apexes:,}")
    for reason, c in store.stats():
        print(f"  {reason:8} {c:,}")
    rows = store.db.execute("SELECT log, next_index, tree_size FROM progress ORDER BY log").fetchall()
    if rows:
        print("progress:")
        for log, nxt, size in rows:
            pct = f"{100 * nxt / size:5.1f}%" if size else "  ?"
            print(f"  {pct} {nxt:>14,} / {size or 0:<14,} {log}")


def cmd_crtsh(a):
    from .crtsh import enrich
    store = Store(a.db)
    if a.domains:
        apexes = [l.strip().lower() for l in open(a.domains, encoding="utf-8") if l.strip()]
    else:
        apexes = list(store.iter_hosts(apex_only=True, reasons=a.reason))
    if a.limit:
        apexes = apexes[:a.limit]
    new = enrich(store, build_matcher(a), apexes, a.include_expired, a.delay)
    print(f"crt.sh: {new:,} new hosts", file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(prog="cthunt", description=__doc__)
    p.add_argument("--db", default="cthunt.db", help="SQLite file (default: cthunt.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def log_opts(sp):
        sp.add_argument("--log", action="append", help="explicit log URL (repeatable); prefix 'static:' for a tiled log")
        sp.add_argument("--log-list", help="log list JSON (path or URL); default: Google's all_logs_list.json")
        sp.add_argument("--only", help="regex on log name/URL, e.g. 'argon|xenon'")
        sp.add_argument("--all-shards", action="store_true", help="include past/future year shards too")
        sp.add_argument("--batch", type=int, default=256, help="get-entries page size for RFC 6962 logs")

    def filter_opts(sp):
        sp.add_argument("--suffix", action="append", help="zone to keep (repeatable). Default: cn, xn--fiqs8s, xn--fiqz9s")
        sp.add_argument("--brands", help="brand list file (default: built-in brands.txt)")
        sp.add_argument("--no-brands", action="store_true", help="only zones, ignore the brand list")
        sp.add_argument("--no-country", action="store_true", help="ignore certificates with subject C=CN")

    sp = sub.add_parser("logs", help="list CT logs that would be scanned")
    log_opts(sp)
    sp.add_argument("--sizes", action="store_true", help="also fetch the current tree size")
    sp.set_defaults(fn=cmd_logs)

    sp = sub.add_parser("run", help="scan CT logs and store matching hosts")
    log_opts(sp)
    filter_opts(sp)
    sp.add_argument("--tail", type=int, default=1_000_000, help="first run: start this many entries before the head (default 1M)")
    sp.add_argument("--from-start", action="store_true", help="first run: start at entry 0 (full backfill, billions of entries)")
    sp.add_argument("--max-entries", type=int, help="stop each log after this many entries per pass")
    sp.add_argument("--follow", action="store_true", help="keep running and pick up new certificates")
    sp.add_argument("--poll", type=float, default=30, help="seconds between head checks in --follow")
    sp.add_argument("--workers", type=int, default=4, help="parallel HTTP requests per log")
    sp.add_argument("--parallel-logs", type=int, default=8, help="logs scanned at once")
    sp.set_defaults(fn=cmd_run)

    sp = sub.add_parser("export", help="write hosts to a text file")
    sp.add_argument("-o", "--output", default="-")
    sp.add_argument("--apex", action="store_true", help="registrable domains only")
    sp.add_argument("--reason", action="append", choices=["tld", "brand", "kw", "org", "crtsh"])
    sp.set_defaults(fn=cmd_export)

    sp = sub.add_parser("stats", help="counts and per-log progress")
    sp.set_defaults(fn=cmd_stats)

    sp = sub.add_parser("crtsh", help="pull every known subdomain of apexes from crt.sh")
    filter_opts(sp)
    sp.add_argument("--domains", help="file with apex domains (default: apexes already in the db)")
    sp.add_argument("--reason", action="append", choices=["tld", "brand", "kw", "org"], help="which db apexes to enrich")
    sp.add_argument("--limit", type=int)
    sp.add_argument("--include-expired", action="store_true")
    sp.add_argument("--delay", type=float, default=2.0, help="seconds between crt.sh queries")
    sp.set_defaults(fn=cmd_crtsh)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
