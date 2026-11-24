"""End-to-end tests: synthetic certificates served by a fake RFC 6962 log and a fake tiled log."""
import base64
import datetime as dt
import json
import os
import struct
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cthunt import ctlog
from cthunt.der import parse_names
from cthunt.filters import Matcher, apex
from cthunt.runner import run
from cthunt.store import Store

KEY = ec.generate_private_key(ec.SECP256R1())


def make_cert(cn, sans, country=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if country:
        attrs.insert(0, x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    now = dt.datetime(2026, 1, 1)
    b = (x509.CertificateBuilder().subject_name(x509.Name(attrs))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
         .public_key(KEY.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
    return b.sign(KEY, hashes.SHA256())


CERTS = [
    make_cert("www.example.com", ["www.example.com", "example.com"]),           # no match
    make_cert("shop.taobao.com", ["*.taobao.com", "shop.taobao.com"]),          # brand
    make_cert("a.b.gov.cn", ["a.b.gov.cn", "*.mail.Example.COM.CN"]),           # tld
    make_cert("acme.com", ["acme.com", "www.acme.com"], country="CN"),         # org (C=CN)
    make_cert("x.huaweicloud-partner.net", ["x.huaweicloud-partner.net"]),      # kw
    make_cert("xn--fiqs8s-test.xn--fiqs8s", []),                                # .中国 via CN only
] * 3   # 18 entries -> crosses page boundaries with small batches


def cert_der(c):
    from cryptography.hazmat.primitives.serialization import Encoding
    return c.public_bytes(Encoding.DER)


def tbs_der(c):
    return c.tbs_certificate_bytes


def u24(b):
    return len(b).to_bytes(3, "big") + b


# even indexes are x509 entries, odd ones precert entries (bare TBS)
def merkle_leaf(i, c):
    if i % 2 == 0:
        body = struct.pack(">H", 0) + u24(cert_der(c))
    else:
        body = struct.pack(">H", 1) + b"\0" * 32 + u24(tbs_der(c))
    return b"\x00\x00" + struct.pack(">Q", 1700000000000) + body + b"\x00\x00"


def tile_leaf(i, c):
    ts = struct.pack(">Q", 1700000000000)
    if i % 2 == 0:
        return ts + struct.pack(">H", 0) + u24(cert_der(c)) + b"\0\0" + b"\0\x20" + b"\1" * 32
    return (ts + struct.pack(">H", 1) + b"\0" * 32 + u24(tbs_der(c)) + b"\0\0"
            + u24(cert_der(c)) + b"\0\0")


class Handler(BaseHTTPRequestHandler):
    MAX_PAGE = 5     # server returns fewer entries than asked, like real logs
    TILE = 4         # tiny tiles so the test covers full + partial tiles

    def log_message(self, *a):
        pass

    def send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        n = len(CERTS)
        if self.path.startswith("/rfc/ct/v1/get-sth"):
            return self.send(json.dumps({"tree_size": n}).encode())
        if self.path.startswith("/rfc/ct/v1/get-entries"):
            q = dict(p.split("=") for p in self.path.split("?")[1].split("&"))
            s, e = int(q["start"]), min(int(q["end"]), n - 1, int(q["start"]) + self.MAX_PAGE - 1)
            ents = [{"leaf_input": base64.b64encode(merkle_leaf(i, CERTS[i])).decode(), "extra_data": ""}
                    for i in range(s, e + 1)]
            return self.send(json.dumps({"entries": ents}).encode())
        if self.path == "/tiled/checkpoint":
            return self.send(f"test.log\n{n}\nAAAA\n".encode())
        if self.path.startswith("/tiled/tile/data/"):
            p = self.path[len("/tiled/tile/data/"):]
            width = None
            if ".p/" in p:
                p, width = p.split(".p/")
                width = int(width)
            t = int(p.replace("x", "").replace("/", ""))
            base = t * self.TILE
            full = min(self.TILE, n - base)
            if width is None and full < self.TILE:
                return self.send(b"", 404)
            w = width or self.TILE
            import gzip
            return self.send(gzip.compress(b"".join(tile_leaf(i, CERTS[i]) for i in range(base, base + w))))
        self.send(b"", 404)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"
        os.environ["NO_PROXY"] = "127.0.0.1"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_der_cert_and_tbs(self):
        c = CERTS[3]
        for names in (parse_names(cert_der(c)), parse_names(tbs_der(c), is_tbs=True)):
            self.assertEqual(names["cn"], ["acme.com"])
            self.assertEqual(names["san"], ["acme.com", "www.acme.com"])
            self.assertEqual(names["country"], "CN")

    def test_tile_path(self):
        self.assertEqual(ctlog.tile_path(5), "005")
        self.assertEqual(ctlog.tile_path(1234067), "x001/x234/067")

    def test_apex(self):
        self.assertEqual(apex("a.b.mail.example.com.cn"), "example.com.cn")
        self.assertEqual(apex("www.foo.cn"), "foo.cn")
        self.assertEqual(apex("cdn.alibaba.com.hk"), "alibaba.com.hk")

    def test_matcher(self):
        m = Matcher()
        self.assertEqual(m.match_host("x.y.com.cn"), "tld")
        self.assertEqual(m.match_host("img.alicdn.com"), "brand")
        self.assertEqual(m.match_host("huaweicloud-partner.net"), "kw")
        self.assertIsNone(m.match_host("cnn.com"))
        self.assertIsNone(m.match_host("qqq.com"))

    def _scan(self, log):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "t.db"))
            stats, new = run([log], store, Matcher(), tail=10**9, from_start=False, follow=False,
                             poll=1, workers=3, parallel_logs=1, max_entries=None, quiet=True)
            hosts = dict(store.db.execute("SELECT name, reason FROM hosts").fetchall())
            prog = store.get_progress(log.key)
            store.db.close()
        self.assertEqual(stats.entries, len(CERTS))
        self.assertEqual(stats.errors, 0)
        self.assertEqual(prog, len(CERTS))
        self.assertEqual(hosts, {
            "taobao.com": "brand", "shop.taobao.com": "brand",
            "a.b.gov.cn": "tld", "mail.example.com.cn": "tld",
            "acme.com": "org", "www.acme.com": "org",
            "x.huaweicloud-partner.net": "kw",
            "xn--fiqs8s-test.xn--fiqs8s": "tld",
        })

    def test_rfc6962_log(self):
        self._scan(ctlog.RFC6962Log(self.base + "/rfc/", batch=7))

    def test_static_log(self):
        log = ctlog.StaticLog(self.base + "/tiled/")
        log.TILE = log.batch = Handler.TILE
        self._scan(log)


if __name__ == "__main__":
    unittest.main()
