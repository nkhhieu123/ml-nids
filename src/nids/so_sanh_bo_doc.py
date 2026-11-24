"""So sánh bộ đọc gói tự viết với Scapy, dpkt và PyShark trên cùng một file PCAP (căn cứ cho QĐ-013, QĐ-014).

Mỗi công cụ đọc cùng file và lấy đúng các trường pipeline cần: thời điểm, IP nguồn/đích, giao thức, độ dài gói,
cổng và cờ TCP. Đo thời gian, tốc độ (gói/giây), số gói IP đọc được, và so từng gói với bộ đọc của đề tài để
biết các công cụ có cho cùng kết quả không. PyShark gọi TShark (Wireshark) nên cần cài Wireshark.

    cd src
    python -m nids.so_sanh_bo_doc ../output/pcap/fri_binh_thuong.pcap --out ../docs/hinh/so_sanh_bo_doc.json
"""

import argparse
import json
import socket
import sys
import time
from pathlib import Path


def ours(path, limit):
    from .packets import extract_packets
    out = []
    for r in extract_packets(path):
        out.append((r.src_ip, r.dst_ip, r.protocol, r.src_port, r.dst_port, r.ip_len))
        if len(out) >= limit:
            break
    return out


def with_dpkt(path, limit):
    import dpkt
    out = []
    with open(path, "rb") as f:
        for _ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                src, dst, ln = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.len
            elif isinstance(ip, dpkt.ip6.IP6):
                src, dst = socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
                ln = 40 + ip.plen
            else:
                continue
            l4 = ip.data
            first = not isinstance(ip, dpkt.ip.IP) or ip.offset == 0
            sp = getattr(l4, "sport", None) if first and isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)) else None
            dp = getattr(l4, "dport", None) if first and isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)) else None
            out.append((src, dst, ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt, sp, dp, ln))
            if len(out) >= limit:
                break
    return out


def with_scapy(path, limit):
    from scapy.all import IP, IPv6, TCP, UDP, PcapReader
    out = []
    with PcapReader(str(path)) as r:
        for p in r:
            if IP in p:
                ip = p[IP]
                src, dst, proto, ln = ip.src, ip.dst, ip.proto, ip.len
            elif IPv6 in p:
                ip = p[IPv6]
                src, dst, proto, ln = ip.src, ip.dst, ip.nh, 40 + ip.plen
            else:
                continue
            l4 = p[TCP] if TCP in p else p[UDP] if UDP in p else None
            out.append((src, dst, proto, l4.sport if l4 else None, l4.dport if l4 else None, ln))
            if len(out) >= limit:
                break
    return out


def with_pyshark(path, limit):
    import pyshark
    out = []
    cap = pyshark.FileCapture(str(path), keep_packets=False)
    try:
        for p in cap:
            if hasattr(p, "ip"):
                src, dst, proto, ln = p.ip.src, p.ip.dst, int(p.ip.proto), int(p.ip.len)
            elif hasattr(p, "ipv6"):
                src, dst, proto, ln = p.ipv6.src, p.ipv6.dst, int(p.ipv6.nxt), 40 + int(p.ipv6.plen)
            else:
                continue
            l4 = getattr(p, "tcp", None) or getattr(p, "udp", None)
            out.append((src, dst, proto, int(l4.srcport) if l4 else None, int(l4.dstport) if l4 else None, ln))
            if len(out) >= limit:
                break
    finally:
        cap.close()
    return out


TOOLS = {"tu_viet": ours, "dpkt": with_dpkt, "scapy": with_scapy, "pyshark": with_pyshark}


def main(argv=None):
    ap = argparse.ArgumentParser(description="So sánh bộ đọc gói tự viết với Scapy, dpkt, PyShark.")
    ap.add_argument("pcap")
    ap.add_argument("--so-goi", type=int, default=50000, help="đọc tối đa chừng này gói IP với mỗi công cụ")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    res, ref = {}, None
    for name, fn in TOOLS.items():
        t0 = time.perf_counter()
        try:
            rows = fn(a.pcap, a.so_goi)
        except Exception as exc:                      # công cụ chưa cài hoặc lỗi: ghi lại, không dừng
            res[name] = {"loi": f"{type(exc).__name__}: {exc}"}
            continue
        dt = time.perf_counter() - t0
        if ref is None:
            ref = rows
        same = sum(x == y for x, y in zip(rows, ref))
        res[name] = {"so_goi_ip": len(rows), "giay": round(dt, 2), "goi_moi_giay": round(len(rows) / dt),
                     "khop_bo_doc_de_tai": same, "ty_le_khop": round(same / max(len(ref), 1), 4)}
        print(name, res[name], flush=True)
    import platform
    out = {"file": Path(a.pcap).name, "so_goi_toi_da": a.so_goi, "ket_qua": res,
           "phien_ban": {"python": platform.python_version(),
                         **{m: __import__(m).__version__ for m in ("scapy", "dpkt") if _has(m)}}}
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def _has(m):
    try:
        __import__(m)
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    sys.exit(main())
