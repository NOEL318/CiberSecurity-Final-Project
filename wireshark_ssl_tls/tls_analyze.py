#!/usr/bin/env python3
"""
Extracts everything the SSL/TLS Wireshark lab asks for from a .pcap/.pcapng file (no Wireshark needed).

usage: python tls_analyze.py capture.pcapng [--sni amazon] [--json out.json]

Reports, for the chosen TLS connection (first one whose SNI contains --sni, else the first full handshake):
  - first 8 frames carrying TLS records: frame number, direction, number of records, record types
  - record header fields, ClientHello (version, random, session id, cipher suites, extensions)
  - ServerHello (random, session id, chosen suite, negotiated version, key share)
  - Certificate / ServerKeyExchange / ClientKeyExchange (TLS 1.2), ChangeCipherSpec, encrypted handshake,
    application data records
Frame numbers follow Wireshark's numbering (1 = first packet in the file).
"""
import argparse
import json
import struct
import sys
from collections import defaultdict

CT = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}
HS = {0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 8: "Encrypted Extensions",
      11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request", 14: "Server Hello Done",
      15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished"}
VER = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",
}
GROUPS = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048",
          257: "ffdhe3072", 0x11EC: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00", 0x11EB: "SecP256r1MLKEM768"}
EXT = {0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
       13: "signature_algorithms", 16: "application_layer_protocol_negotiation", 18: "signed_certificate_timestamp",
       21: "padding", 23: "extended_master_secret", 27: "compress_certificate", 35: "session_ticket",
       41: "pre_shared_key", 43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share",
       17513: "application_settings", 17613: "application_settings", 65037: "encrypted_client_hello",
       65281: "renegotiation_info"}


def grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def suite_name(v):
    if grease(v):
        return f"Reserved (GREASE) 0x{v:04x}"
    return SUITES.get(v, f"Unknown 0x{v:04x}")


# ------------------------------------------------------------------ capture readers
def read_packets(path):
    """Yields (frame_no, linktype, ts, data) for pcap and pcapng."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    n = 0
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        e = "<" if le else ">"
        linktype = struct.unpack(e + "I", data[20:24])[0]
        off = 24
        while off + 16 <= len(data):
            sec, frac, incl, _ = struct.unpack(e + "IIII", data[off:off + 16])
            off += 16
            n += 1
            yield n, linktype, sec + frac / (1e9 if nano else 1e6), data[off:off + incl]
            off += incl
        return
    if magic != b"\x0a\x0d\x0d\x0a":
        raise SystemExit("Not a pcap/pcapng file")
    off, e, ifaces = 0, "<", []
    while off + 12 <= len(data):
        btype = struct.unpack(e + "I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:
            bom = data[off + 8:off + 12]
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        blen = struct.unpack(e + "I", data[off + 4:off + 8])[0]
        body = data[off + 8:off + blen - 4]
        if btype == 1:  # IDB: link type + if_tsresol option (code 9), default microseconds
            res, o = 1e6, 8
            while o + 4 <= len(body):
                code, ol = struct.unpack(e + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9 and ol >= 1:
                    v = body[o + 4]
                    res = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                o += 4 + ((ol + 3) // 4) * 4
            ifaces.append((struct.unpack(e + "H", body[:2])[0], res))
        elif btype == 6:  # EPB
            iface, th, tl, cap = struct.unpack(e + "IIII", body[:16])
            lt, res = ifaces[iface] if iface < len(ifaces) else (1, 1e6)
            n += 1
            yield n, lt, ((th << 32) | tl) / res, body[20:20 + cap]
        elif btype == 3:  # SPB
            n += 1
            yield n, ifaces[0][0] if ifaces else 1, 0.0, body[4:]
        if blen < 12:
            break
        off += blen


def ip_payload(linktype, pkt):
    if linktype == 1:  # Ethernet
        et, o = struct.unpack(">H", pkt[12:14])[0], 14
        while et in (0x8100, 0x88A8):
            et, o = struct.unpack(">H", pkt[o + 2:o + 4])[0], o + 4
        return pkt[o:] if et in (0x0800, 0x86DD) else None
    if linktype in (101, 228, 229, 12, 14):
        return pkt
    if linktype == 113:  # Linux cooked
        return pkt[16:]
    if linktype == 276:  # SLL2
        return pkt[20:]
    if linktype in (0, 108):  # loopback
        return pkt[4:]
    return None


def parse_tcp(ip):
    if not ip:
        return None
    v = ip[0] >> 4
    if v == 4:
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:
            return None
        total = struct.unpack(">H", ip[2:4])[0]
        src, dst, seg = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20])), ip[ihl:total]
    elif v == 6:
        if ip[6] != 6:
            return None
        plen = struct.unpack(">H", ip[4:6])[0]
        import ipaddress
        src, dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
        seg = ip[40:40 + plen]
    else:
        return None
    if len(seg) < 20:
        return None
    sp, dp, seq = struct.unpack(">HHI", seg[:8])
    off = (seg[12] >> 4) * 4
    flags = seg[13]
    return src, sp, dst, dp, seq, flags, seg[off:]


# ------------------------------------------------------------------ reassembly + TLS parsing
class Stream:
    def __init__(self):
        self.isn = None
        self.buf = bytearray()
        self.frames = []  # (stream_offset_start, stream_offset_end, frame)
        self.pending = {}

    def add(self, seq, payload, frame, syn):
        if syn:
            self.isn = (seq + 1) & 0xFFFFFFFF
            return
        if not payload:
            return
        if self.isn is None:
            self.isn = seq
        rel = (seq - self.isn) & 0xFFFFFFFF
        self.pending.setdefault(rel, (payload, frame))
        while True:
            nxt = len(self.buf)
            hit = None
            for r, (p, fr) in self.pending.items():
                if r <= nxt < r + len(p):
                    hit = r
                    break
            if hit is None:
                break
            p, fr = self.pending.pop(hit)
            new = p[nxt - hit:]
            self.frames.append((nxt, nxt + len(new), fr))
            self.buf += new

    def frame_at(self, off):
        for a, b, fr in self.frames:
            if a <= off < b:
                return fr
        return None


def parse_records(st):
    recs, off, b = [], 0, bytes(st.buf)
    while off + 5 <= len(b):
        ct, ver, ln = b[off], struct.unpack(">H", b[off + 1:off + 3])[0], struct.unpack(">H", b[off + 3:off + 5])[0]
        if ct not in CT or (ver >> 8) != 3:
            break
        if off + 5 + ln > len(b):
            break
        recs.append({"type": ct, "version": ver, "length": ln, "start": off, "frame": st.frame_at(off),
                     "end_frame": st.frame_at(off + 4 + ln), "body": b[off + 5:off + 5 + ln]})
        off += 5 + ln
    return recs


def parse_exts(data):
    out, o = [], 0
    while o + 4 <= len(data):
        t, l = struct.unpack(">HH", data[o:o + 4])
        out.append((t, data[o + 4:o + 4 + l]))
        o += 4 + l
    return out


def parse_client_hello(m):
    o = 0
    ver = struct.unpack(">H", m[o:o + 2])[0]; o += 2
    rnd = m[o:o + 32]; o += 32
    sl = m[o]; sid = m[o + 1:o + 1 + sl]; o += 1 + sl
    cl = struct.unpack(">H", m[o:o + 2])[0]; o += 2
    suites = [struct.unpack(">H", m[o + i:o + i + 2])[0] for i in range(0, cl, 2)]; o += cl
    o += 1 + m[o]
    exts = parse_exts(m[o + 2:]) if o + 2 <= len(m) else []
    info = {"legacy_version": VER.get(ver, hex(ver)), "random": rnd.hex(), "session_id_length": sl,
            "session_id": sid.hex(), "cipher_suites": [suite_name(s) for s in suites],
            "cipher_suite_count": len(suites), "extensions": [EXT.get(t, f"unknown({t})") for t, _ in exts]}
    for t, d in exts:
        if t == 0 and len(d) > 5:
            info["sni"] = d[5:5 + struct.unpack(">H", d[3:5])[0]].decode(errors="replace")
        elif t == 43:
            info["supported_versions"] = [("GREASE" if grease(struct.unpack(">H", d[i:i + 2])[0])
                                           else VER.get(struct.unpack(">H", d[i:i + 2])[0], "?"))
                                          for i in range(1, 1 + d[0], 2)]
        elif t == 16:
            ps, i = [], 2
            while i < len(d):
                ps.append(d[i + 1:i + 1 + d[i]].decode(errors="replace")); i += 1 + d[i]
            info["alpn"] = ps
        elif t == 10:
            gl = struct.unpack(">H", d[:2])[0]
            info["supported_groups"] = [("GREASE" if grease(g) else GROUPS.get(g, hex(g)))
                                        for g in (struct.unpack(">H", d[2 + i:4 + i])[0] for i in range(0, gl, 2))]
        elif t == 51:
            ks, i = [], 2
            while i + 4 <= len(d):
                g, l = struct.unpack(">HH", d[i:i + 4])
                ks.append(f"{'GREASE' if grease(g) else GROUPS.get(g, hex(g))} ({l} bytes)"); i += 4 + l
            info["key_share"] = ks
    return info


def parse_server_hello(m):
    o = 0
    ver = struct.unpack(">H", m[:2])[0]; o += 2
    rnd = m[o:o + 32]; o += 32
    sl = m[o]; sid = m[o + 1:o + 1 + sl]; o += 1 + sl
    suite = struct.unpack(">H", m[o:o + 2])[0]; o += 3
    exts = parse_exts(m[o + 2:]) if o + 2 <= len(m) else []
    info = {"legacy_version": VER.get(ver, hex(ver)), "random": rnd.hex(), "session_id_length": sl,
            "session_id": sid.hex(), "cipher_suite": suite_name(suite), "extensions": [EXT.get(t, str(t)) for t, _ in exts],
            "negotiated_version": VER.get(ver, hex(ver))}
    for t, d in exts:
        if t == 43 and len(d) == 2:
            info["negotiated_version"] = VER.get(struct.unpack(">H", d)[0], "?")
        elif t == 51 and len(d) >= 4:
            g, l = struct.unpack(">HH", d[:4])
            info["key_share"] = f"{GROUPS.get(g, hex(g))} ({l} bytes)"
        elif t == 16:
            info["alpn"] = d[3:3 + d[2]].decode(errors="replace")
    if rnd[-8:] in (b"DOWNGRD\x01", b"DOWNGRD\x00"):
        info["downgrade_sentinel"] = True
    return info


def cert_cns(chain):
    cns, i = [], 0
    while i + 3 <= len(chain):
        l = int.from_bytes(chain[i:i + 3], "big")
        der = chain[i + 3:i + 3 + l]
        j = der.find(bytes([0x06, 0x03, 0x55, 0x04, 0x03]))
        last = None
        while j != -1:
            sl = der[j + 6]
            last = der[j + 7:j + 7 + sl].decode(errors="replace")
            j = der.find(bytes([0x06, 0x03, 0x55, 0x04, 0x03]), j + 1)
            if j != -1 and len(cns) == 0 and last:
                pass
        cns.append({"bytes": l, "subject_cn_last": last})
        i += 3 + l
    return cns


def analyze(path, sni_filter=None, want_version=None):
    streams, conn_first, all_frames = defaultdict(Stream), {}, 0
    for n, lt, ts, pkt in read_packets(path):
        all_frames = n
        t = parse_tcp(ip_payload(lt, pkt))
        if not t:
            continue
        src, sp, dst, dp, seq, flags, payload = t
        if 443 not in (sp, dp):
            continue
        key = (src, sp, dst, dp)
        conn = tuple(sorted([(src, sp), (dst, dp)]))
        conn_first.setdefault(conn, n)
        streams[key].add(seq, payload, n, bool(flags & 0x02))

    conns = []
    for conn, first in sorted(conn_first.items(), key=lambda x: x[1]):
        (a, b) = conn
        c2s = s2c = None
        for (src, sp, dst, dp) in streams:
            if (src, sp) in conn and (dst, dp) in conn:
                if dp == 443:
                    c2s = streams[(src, sp, dst, dp)]
                else:
                    s2c = streams[(src, sp, dst, dp)]
        if not c2s or not s2c:
            continue
        cr, sr = parse_records(c2s), parse_records(s2c)
        if not cr or cr[0]["type"] != 22 or not cr[0]["body"] or cr[0]["body"][0] != 1:
            continue
        conns.append((conn, cr, sr))
    if not conns:
        raise SystemExit("No complete TLS handshake on port 443 found")

    chosen = None
    summary = []
    for conn, cr, sr in conns:
        ch = parse_client_hello(cr[0]["body"][4:])
        shv = None
        for r in sr:
            if r["type"] == 22 and r["body"] and r["body"][0] == 2:
                shv = parse_server_hello(r["body"][4:])["negotiated_version"]
                break
        summary.append({"client_port": [e for e in conn if e[1] != 443][0][1], "sni": ch.get("sni"), "version": shv,
                        "first_frame": cr[0]["frame"]})
        if chosen is None and sni_filter and sni_filter.lower() in ch.get("sni", "").lower() and sr \
                and (want_version is None or shv == want_version):
            chosen = (conn, cr, sr, ch)
    if not chosen:
        conn, cr, sr = conns[0]
        chosen = (conn, cr, sr, parse_client_hello(cr[0]["body"][4:]))
    conn, cr, sr, ch = chosen
    client = [e for e in conn if e[1] != 443][0]
    server = [e for e in conn if e[1] == 443][0]

    # TLS 1.3 detection and handshake message decoding
    sh = None
    for r in sr:
        if r["type"] == 22 and r["body"] and r["body"][0] == 2:
            sh = parse_server_hello(r["body"][4:])
            break
    tls13 = sh and sh["negotiated_version"] == "TLS 1.3"

    def describe(recs, side):
        out, seen_ccs = [], False
        for r in recs:
            d = {"frame": r["frame"], "end_frame": r["end_frame"], "dir": side, "content_type": r["type"],
                 "type": CT[r["type"]], "version": VER.get(r["version"], hex(r["version"])), "length": r["length"]}
            if r["type"] == 22:
                if seen_ccs or (tls13 and side == "S" and r["body"][:1] not in (b"\x02",)):
                    d["type"] = "Handshake (Encrypted Handshake Message)"
                else:
                    msgs, o = [], 0
                    b = r["body"]
                    while o + 4 <= len(b):
                        ht, hl = b[o], int.from_bytes(b[o + 1:o + 4], "big")
                        msgs.append(HS.get(ht, f"type {ht}"))
                        if ht == 11 and side == "S":
                            d["certificate_bytes"] = hl
                            d["certificates"] = cert_cns(b[o + 7:o + 4 + hl])
                        if ht == 16:
                            d["client_key_exchange_bytes"] = hl
                        if ht == 12:
                            sk = b[o + 4:o + 4 + hl]
                            if sk[:1] == b"\x03":
                                d["server_key_exchange"] = {"curve": GROUPS.get(struct.unpack(">H", sk[1:3])[0], "?"),
                                                            "public_key_bytes": sk[3]}
                        o += 4 + hl
                    d["type"] = "Handshake: " + ", ".join(msgs)
            if r["type"] == 20:
                seen_ccs = True
            if r["type"] == 23 and tls13 and side == "C" and not any(x["content_type"] == 23 for x in out):
                d["note"] = "first client Application Data in TLS 1.3 = encrypted Finished"
            out.append(d)
        return out

    recs = sorted(describe(cr, "C") + describe(sr, "S"), key=lambda x: (x["frame"] or 0))
    frames = []
    for r in recs:
        if not frames or frames[-1]["frame"] != r["frame"]:
            frames.append({"frame": r["frame"], "source": "client" if r["dir"] == "C" else "server", "records": []})
        frames[-1]["records"].append(r["type"])
    for f in frames:
        f["n_records"] = len(f["records"])

    return {"file": path, "total_frames": all_frames, "tls_connections": len(conns), "connections": summary,
            "client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}",
            "client_hello": ch, "server_hello": sh, "tls13": bool(tls13),
            "first_8_frames": frames[:8], "records": recs[:40]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--sni", default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--version", default=None, help='e.g. "TLS 1.2" to pick a TLS 1.2 connection')
    a = ap.parse_args()
    res = analyze(a.pcap, a.sni, a.version)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=2, default=str)
    ch, sh = res["client_hello"], res["server_hello"]
    print(f"File: {res['file']}  frames={res['total_frames']}  TLS connections={res['tls_connections']}")
    for c in res["connections"]:
        print("   connection:", c)
    print(f"Chosen connection: client {res['client']}  ->  server {res['server']}  SNI={ch.get('sni')}")
    print("\nFirst 8 frames with TLS records:")
    for f in res["first_8_frames"]:
        print(f"  frame {f['frame']:>5}  {f['source']:6}  {f['n_records']} record(s): {'; '.join(f['records'])}")
    print("\nClientHello:", json.dumps({k: v for k, v in ch.items() if k != 'cipher_suites'}, indent=1))
    print("  cipher suites:", ch["cipher_suites"])
    print("\nServerHello:", json.dumps(sh, indent=1))
    print("\nRecords:")
    for r in res["records"]:
        extra = {k: v for k, v in r.items() if k in ("certificate_bytes", "client_key_exchange_bytes",
                                                     "server_key_exchange", "note", "end_frame")}
        print(f"  frame {r['frame']:>5} {r['dir']} {r['type']:<55} ct={r['content_type']} ver={r['version']} len={r['length']} {extra if extra else ''}")


if __name__ == "__main__":
    main()
