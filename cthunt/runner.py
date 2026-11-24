"""Pulls entries from many CT logs in parallel, filters names, and feeds one SQLite writer."""
from __future__ import annotations

import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .der import parse_names
from .filters import Matcher
from .store import Store


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries = 0
        self.matched = 0
        self.errors = 0

    def add(self, entries=0, matched=0, errors=0):
        with self.lock:
            self.entries += entries
            self.matched += matched
            self.errors += errors


def _ranges(start: int, end: int, step: int):
    # align to the log's page size so tile/batch boundaries line up with server pages
    pos = start
    while pos < end:
        nxt = min((pos // step + 1) * step, end)
        yield pos, nxt
        pos = nxt


def scan_log(log, matcher: Matcher, out: queue.Queue, stats: Stats, start: int, end: int,
             workers: int, stop: threading.Event, log_fn) -> int:
    """Scan [start, end) of one log; returns the index reached."""
    window = workers * log.batch * 4
    pos = start
    with ThreadPoolExecutor(workers) as pool:
        while pos < end and not stop.is_set():
            wend = min(pos + window, end)
            futs = [pool.submit(log.fetch, a, b) for a, b in _ranges(pos, wend, log.batch)]
            rows: list[tuple[str, str]] = []
            n = errs = 0
            for f in futs:
                try:
                    entries = f.result()
                except Exception as e:  # one bad page must not kill the whole log
                    log_fn(f"[{log.name}] fetch failed: {e}")
                    errs += 1
                    continue
                for ent in entries:
                    n += 1
                    try:
                        rows.extend(matcher.match_cert(parse_names(ent.der, ent.is_tbs)))
                    except Exception:
                        errs += 1
            stats.add(entries=n, matched=len(rows), errors=errs)
            out.put((rows, log.key, wend, end))
            pos = wend
    return pos


def run(logs, store: Store, matcher: Matcher, *, tail: int, from_start: bool, follow: bool,
        poll: float, workers: int, parallel_logs: int, max_entries: int | None, quiet: bool = False):
    out: queue.Queue = queue.Queue(maxsize=256)
    stats = Stats()
    stop = threading.Event()
    lock = threading.Lock()

    def log_fn(msg):
        if not quiet:
            with lock:
                print(msg, file=sys.stderr, flush=True)

    # SQLite is touched only from this thread (reads of progress happen before workers start).
    starts = {}
    for lg in logs:
        starts[lg.key] = store.get_progress(lg.key)

    def worker(lg):
        try:
            size = lg.tree_size()
        except Exception as e:
            log_fn(f"[{lg.name}] skipped: cannot read tree size ({e})")
            return
        pos = starts[lg.key]
        if pos is None:
            pos = 0 if from_start else max(0, size - tail)
        log_fn(f"[{lg.name}] tree_size={size:,} start={pos:,} ({lg.kind})")
        while not stop.is_set():
            end = size if max_entries is None else min(size, pos + max_entries)
            if pos < end:
                pos = scan_log(lg, matcher, out, stats, pos, end, workers, stop, log_fn)
            if not follow:
                return
            stop.wait(poll)
            try:
                size = lg.tree_size()
            except Exception as e:
                log_fn(f"[{lg.name}] get tree size failed: {e}")

    pool = ThreadPoolExecutor(max(1, parallel_logs))
    futs = [pool.submit(worker, lg) for lg in logs]

    new_total = 0
    last_commit = last_print = time.time()
    t0 = time.time()
    try:
        while True:
            try:
                rows, key, nxt, size = out.get(timeout=1)
                new_total += store.add_hosts(rows, key)
                store.set_progress(key, nxt, size)
            except queue.Empty:
                if all(f.done() for f in futs) and out.empty():
                    break
            now = time.time()
            if now - last_commit > 5:
                store.commit()
                last_commit = now
            if not quiet and now - last_print > 10:
                rate = stats.entries / max(now - t0, 1e-9)
                hosts, apexes = store.count()
                log_fn(f"entries={stats.entries:,} ({rate:,.0f}/s) matched={stats.matched:,} "
                       f"new={new_total:,} db_hosts={hosts:,} apexes={apexes:,} errors={stats.errors}")
                last_print = now
    except KeyboardInterrupt:
        log_fn("stopping… (progress is saved, rerun to resume)")
        stop.set()
        # drain what the workers still hand over so progress stays consistent
        while any(not f.done() for f in futs) or not out.empty():
            try:
                rows, key, nxt, size = out.get(timeout=1)
                new_total += store.add_hosts(rows, key)
                store.set_progress(key, nxt, size)
            except queue.Empty:
                pass
    finally:
        store.commit()
        pool.shutdown(wait=False)
    return stats, new_total
