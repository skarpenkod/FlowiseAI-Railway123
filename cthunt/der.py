"""Minimal DER walker: pulls hostnames out of an X.509 Certificate or TBSCertificate.

No dependencies and no full ASN.1 parse, so it stays fast on millions of certificates.
"""
from __future__ import annotations

OID_CN = bytes.fromhex("550403")        # 2.5.4.3  commonName
OID_C = bytes.fromhex("550406")         # 2.5.4.6  countryName
OID_O = bytes.fromhex("55040a")         # 2.5.4.10 organizationName
OID_SAN = bytes.fromhex("551d11")       # 2.5.29.17 subjectAltName


class DERError(ValueError):
    pass


def tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) for the element at ``off``."""
    if off + 2 > len(buf):
        raise DERError("truncated")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise DERError("multi-byte tags not supported")
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or off + n > len(buf):
            raise DERError("bad length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    end = off + ln
    if end > len(buf):
        raise DERError("length overflow")
    return tag, off, end


def children(buf: bytes, start: int, end: int):
    off = start
    while off < end:
        tag, cs, ce = tlv(buf, off)
        yield tag, cs, ce
        off = ce


def _decode_str(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    return raw.decode("utf-8", "replace")


def _parse_issuer(buf: bytes, s: int, e: int, out: dict) -> None:
    out["issuer_raw"] = buf[s:e]
    tmp = {"cn": [], "country": None, "org": None}
    _parse_name(buf, s, e, tmp)
    out["issuer"] = tmp["org"] or (tmp["cn"][0] if tmp["cn"] else None)


def _parse_name(buf: bytes, s: int, e: int, out: dict) -> None:
    # Name ::= SEQUENCE OF SET OF AttributeTypeAndValue
    for _, rs, re_ in children(buf, s, e):
        for _, as_, ae in children(buf, rs, re_):
            it = children(buf, as_, ae)
            _, os_, oe = next(it)
            vtag, vs, ve = next(it)
            oid = buf[os_:oe]
            if oid == OID_CN:
                out["cn"].append(_decode_str(vtag, buf[vs:ve]))
            elif oid == OID_C:
                out["country"] = _decode_str(vtag, buf[vs:ve]).upper()
            elif oid == OID_O:
                out["org"] = _decode_str(vtag, buf[vs:ve])


def _parse_extensions(buf: bytes, s: int, e: int, out: dict) -> None:
    # [3] EXPLICIT Extensions ::= SEQUENCE OF Extension
    _, ss, se = tlv(buf, s)
    for _, xs, xe in children(buf, ss, se):
        parts = list(children(buf, xs, xe))
        if not parts or buf[parts[0][1]:parts[0][2]] != OID_SAN:
            continue
        _, vs, ve = parts[-1]               # OCTET STRING with GeneralNames
        _, gs, ge = tlv(buf, vs)
        for gtag, ns, ne in children(buf, gs, ge):
            if gtag == 0x82:                # dNSName [2] IA5String
                out["san"].append(buf[ns:ne].decode("ascii", "replace"))


def parse_names(der: bytes, is_tbs: bool = False) -> dict:
    """Extract subject CN/C/O, SAN dNSNames, serial number and issuer (O, else CN).

    ``der`` is a full Certificate, or a bare TBSCertificate when ``is_tbs`` (CT precert entries).
    """
    out = {"cn": [], "san": [], "country": None, "org": None,
           "serial": b"", "issuer": None, "issuer_raw": b""}
    _, s, e = tlv(der, 0)
    if not is_tbs:
        _, s, e = tlv(der, s)               # tbsCertificate
    idx = 0
    for tag, cs, ce in children(der, s, e):
        if idx == 0 and tag == 0xA0:        # optional explicit version
            continue
        # 0 serial, 1 signature, 2 issuer, 3 validity, 4 subject, 5 spki, then optional [1] [2] [3]
        if idx == 0:
            out["serial"] = der[cs:ce]
        elif idx == 2:
            _parse_issuer(der, cs, ce, out)
        elif idx == 4:
            _parse_name(der, cs, ce, out)
        elif tag == 0xA3:
            _parse_extensions(der, cs, ce, out)
        idx += 1
    return out
