"""Clients for CT logs: classic RFC 6962 and the newer static-ct-api (tiled logs, Sunlight)."""
from __future__ import annotations

import base64
import gzip
import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

USER_AGENT = "cthunt/1.0 (+certificate-transparency domain collector)"
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

X509_ENTRY = 0
PRECERT_ENTRY = 1


@dataclass
class Entry:
    index: int
    der: bytes
    is_tbs: bool  # True for precert entries (bare TBSCertificate)


def http_get(url: str, timeout: float = 30, retries: int = 6) -> bytes:
    delay = 1.0
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip" or data[:2] == b"\x1f\x8b":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as e:
            if e.code == 404 or attempt == retries - 1:
                raise
            ra = e.headers.get("Retry-After") if e.headers else None
            wait = float(ra) if ra and ra.isdigit() else delay
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            if attempt == retries - 1:
                raise
            wait = delay
        time.sleep(wait + random.random())
        delay = min(delay * 2, 60)
    raise RuntimeError("unreachable")


# --------------------------------------------------------------------------- binary readers

class Reader:
    __slots__ = ("b", "o")

    def __init__(self, b: bytes, o: int = 0):
        self.b, self.o = b, o

    def u(self, n: int) -> int:
        v = int.from_bytes(self.b[self.o:self.o + n], "big")
        self.o += n
        return v

    def raw(self, n: int) -> bytes:
        v = self.b[self.o:self.o + n]
        if len(v) != n:
            raise ValueError("truncated entry")
        self.o += n
        return v

    def vec(self, lenbytes: int) -> bytes:
        return self.raw(self.u(lenbytes))

    def done(self) -> bool:
        return self.o >= len(self.b)


def parse_merkle_leaf(leaf: bytes) -> tuple[bytes, bool]:
    """RFC 6962 MerkleTreeLeaf -> (der, is_tbs)."""
    r = Reader(leaf)
    r.u(1)  # version
    r.u(1)  # leaf type
    r.u(8)  # timestamp
    et = r.u(2)
    if et == X509_ENTRY:
        return r.vec(3), False
    if et == PRECERT_ENTRY:
        r.raw(32)  # issuer_key_hash
        return r.vec(3), True
    raise ValueError(f"unknown entry type {et}")


def parse_tile_leaves(data: bytes):
    """static-ct-api data tile -> iterator of (der, is_tbs)."""
    r = Reader(data)
    while not r.done():
        r.u(8)  # timestamp
        et = r.u(2)
        if et == X509_ENTRY:
            der = r.vec(3)
            r.vec(2)  # extensions
            r.vec(2)  # chain fingerprints
            yield der, False
        elif et == PRECERT_ENTRY:
            r.raw(32)
            der = r.vec(3)
            r.vec(2)  # extensions
            r.vec(3)  # pre_certificate
            r.vec(2)  # chain fingerprints
            yield der, True
        else:
            raise ValueError(f"unknown entry type {et}")


# --------------------------------------------------------------------------- logs

class RFC6962Log:
    kind = "rfc6962"

    def __init__(self, url: str, name: str | None = None, batch: int = 256):
        self.url = url.rstrip("/") + "/"
        self.name = name or self.url
        self.batch = batch

    @property
    def key(self) -> str:
        return self.url

    def tree_size(self) -> int:
        return int(json.loads(http_get(self.url + "ct/v1/get-sth"))["tree_size"])

    def fetch(self, start: int, end: int) -> list[Entry]:
        """Entries in [start, end). Servers may return fewer than asked, so loop."""
        out: list[Entry] = []
        pos = start
        while pos < end:
            body = json.loads(http_get(f"{self.url}ct/v1/get-entries?start={pos}&end={end - 1}"))
            got = body.get("entries", [])
            if not got:
                break
            for e in got:
                try:
                    der, tbs = parse_merkle_leaf(base64.b64decode(e["leaf_input"]))
                    out.append(Entry(pos, der, tbs))
                except Exception:
                    pass
                pos += 1
        return out


def tile_path(n: int) -> str:
    s = f"{n:03d}"
    s = "0" * (-len(s) % 3) + s
    parts = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])


class StaticLog:
    kind = "static"
    TILE = 256

    def __init__(self, monitoring_url: str, name: str | None = None):
        self.url = monitoring_url.rstrip("/") + "/"
        self.name = name or self.url
        self.batch = self.TILE

    @property
    def key(self) -> str:
        return self.url

    def tree_size(self) -> int:
        lines = http_get(self.url + "checkpoint").decode().splitlines()
        return int(lines[1])

    def fetch(self, start: int, end: int) -> list[Entry]:
        out: list[Entry] = []
        t = start // self.TILE
        while t * self.TILE < end:
            base = t * self.TILE
            width = min(self.TILE, end - base)
            # A partial tile only exists at the tree's right edge; prefer the full tile.
            try:
                data = http_get(f"{self.url}tile/data/{tile_path(t)}")
            except urllib.error.HTTPError as e:
                if e.code != 404 or width == self.TILE:
                    raise
                data = http_get(f"{self.url}tile/data/{tile_path(t)}.p/{width}")
            for i, (der, tbs) in enumerate(parse_tile_leaves(data)):
                idx = base + i
                if start <= idx < end:
                    out.append(Entry(idx, der, tbs))
            t += 1
        return out


# --------------------------------------------------------------------------- log list

def _active(log: dict, now: datetime, all_shards: bool) -> bool:
    state = log.get("state", {})
    if not any(k in state for k in ("usable", "qualified", "readonly")):
        return False
    if all_shards:
        return True
    ti = log.get("temporal_interval")
    if not ti:
        return True
    end = datetime.fromisoformat(ti["end_exclusive"].replace("Z", "+00:00"))
    start = datetime.fromisoformat(ti["start_inclusive"].replace("Z", "+00:00"))
    # certs expiring in the current shard window and the next one are the live ones
    return end > now and start < now.replace(year=now.year + 1)


def load_log_list(source: str | None = None, all_shards: bool = False, rfc6962_batch: int = 256):
    raw = open(source, "rb").read() if source and not source.startswith("http") else http_get(source or LOG_LIST_URL)
    data = json.loads(raw)
    now = datetime.now(timezone.utc)
    logs = []
    for op in data.get("operators", []):
        for lg in op.get("logs", []):
            if _active(lg, now, all_shards):
                logs.append(RFC6962Log(lg["url"], f'{op["name"]}: {lg["description"]}', rfc6962_batch))
        for lg in op.get("tiled_logs", []):
            if _active(lg, now, all_shards):
                logs.append(StaticLog(lg["monitoring_url"], f'{op["name"]}: {lg["description"]}'))
    return logs


def make_log(url: str, rfc6962_batch: int = 256):
    """Build a log from a URL given on the command line. ``static:`` prefix forces tiled mode."""
    if url.startswith("static:"):
        return StaticLog(url[len("static:"):])
    return RFC6962Log(url, batch=rfc6962_batch)
