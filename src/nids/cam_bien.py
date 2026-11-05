"""Xác minh vị trí cảm biến thấy traffic hai chiều (C10-T02, B13).

Đọc một bản bắt thử trên card giám sát (ví dụ ``sudo tcpdump -i eth1 -c 20000 -w thu.pcap``) và đo:

- phần flow TCP có gói theo **cả hai chiều**;
- phần kết nối TCP thấy SYN của client mà cũng thấy phản hồi của server (SYN+ACK hoặc RST), tính riêng cho
  máy chủ trong mạng giám sát (máy ngoài Internet có thể không trả lời);
- cặp host chỉ thấy một chiều;
- phần gói **bị nhân đôi** (mirror gửi cả bản vào và bản ra của cùng một gói);
- các máy lab (``lab.hosts``) đã xuất hiện.

    python -m nids.cam_bien thu.pcap [--net 192.168.50.0/24] [--out output/cam_bien.json]

Kết luận ``dat`` / ``canh_bao`` / ``loi`` theo ngưỡng ở ``THRESHOLDS`` (docs/60_cam_bien_hai_chieu.md).
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from .flows import FlowAssigner, FlowSettings

# Ngưỡng kết luận
THRESHOLDS = {"hai_chieu_dat": 0.9, "hai_chieu_loi": 0.5, "nhan_doi_canh_bao": 0.05, "min_flow_tcp": 20,
              "cap_mot_chieu_min_goi": 10}
DUP_WINDOW_NS = 1_000_000          # 1 ms


def ip_digest(raw) -> bytes | None:
    """Băm nội dung gói IP, bỏ TTL/hop limit và checksum header IPv4 (hai trường đổi khi gói qua router).

    Hai bản mirror của cùng một gói cho cùng giá trị; hai gói khác nhau (khác IP ID, số thứ tự, ACK,
    dữ liệu) cho giá trị khác. None nếu không tìm được header IP.
    """
    import hashlib

    from .packets import network_offset
    found = network_offset(raw.linktype, raw.data)
    if found is None:
        return None
    off, version = found
    ip = bytearray(raw.data[off:])
    if version == 4 and len(ip) >= 20:
        ip[8] = 0                       # TTL
        ip[10:12] = bytes(2)             # checksum header
    elif version == 6 and len(ip) >= 40:
        ip[7] = 0                       # hop limit
    return hashlib.blake2b(bytes(ip), digest_size=12).digest()


def read_with_digest(path):
    """(PacketRecord, mã băm nội dung IP) của các gói IP đọc được trong một PCAP/PCAPNG."""
    from .packets import inspect_packet
    from .pcap_reader import PcapReader
    with PcapReader(path) as reader:
        for raw in reader:
            rec = inspect_packet(raw).record
            if rec is not None:
                yield rec, ip_digest(raw)


def analyze(packets, networks=None, lab_hosts=None, settings=None) -> dict:
    """Số liệu hai chiều từ dãy (``PacketRecord``, mã băm nội dung IP) theo thứ tự bắt.

    Mã băm có thể là None (khi đó không xét nhân đôi cho gói đó).
    """
    from ipaddress import ip_address, ip_network

    nets = [ip_network(n) for n in networks or []]
    inside = lambda ip: not nets or any(ip_address(ip) in n for n in nets if ip_address(ip).version == n.version)
    assigner = FlowAssigner(settings or FlowSettings(), keep_finished=True)
    pairs = defaultdict(Counter)            # (a, b) với a < b -> số gói theo chiều "a>b", "b>a"
    last_seen = {}
    dup = n = 0
    seen_hosts = set()
    first = last = None
    for rec, s in packets:
        n += 1
        if rec.ts_ns is not None:
            first = rec.ts_ns if first is None else min(first, rec.ts_ns)
            last = rec.ts_ns if last is None else max(last, rec.ts_ns)
        if rec.ts_ns is not None and s is not None:
            prev = last_seen.get(s)
            if prev is not None and 0 <= rec.ts_ns - prev <= DUP_WINDOW_NS:
                dup += 1
                continue                    # bản sao không tính vào flow
            last_seen[s] = rec.ts_ns
            if len(last_seen) > 200_000:    # giữ bộ nhớ nhỏ: chỉ cần các gói rất gần
                last_seen = {k: v for k, v in last_seen.items() if rec.ts_ns - v <= DUP_WINDOW_NS}
        seen_hosts.update((rec.src_ip, rec.dst_ip))
        a, b = sorted((rec.src_ip, rec.dst_ip))
        pairs[(a, b)]["a>b" if rec.src_ip == a else "b>a"] += 1
        assigner.add(rec)
    assigner.finish_all()
    flows = [f for f in assigner.flows() if f.key.protocol == 6 and (inside(f.fwd_endpoint[0]) or inside(f.bwd_endpoint[0]))]
    two_way = [f.bwd_packets > 0 and f.fwd_packets > 0 for f in flows]
    syn = [f for f in flows if (f.fwd_endpoint, "syn") in f.handshake_seq]
    answered = lambda f: f.synack_ts_ns is not None or f.server_rst_ts_ns is not None
    syn_in = [f for f in syn if inside(f.bwd_endpoint[0])]
    one_sided = sorted(((a, b, c["a>b"], c["b>a"]) for (a, b), c in pairs.items()
                        if (inside(a) or inside(b)) and min(c["a>b"], c["b>a"]) == 0
                        and max(c["a>b"], c["b>a"]) >= THRESHOLDS["cap_mot_chieu_min_goi"]),
                       key=lambda x: -max(x[2], x[3]))
    res = {
        "so_goi": n, "goi_nhan_doi": dup, "ty_le_nhan_doi": round(dup / n, 4) if n else 0.0,
        "thoi_luong_s": round((last - first) / 1e9, 1) if first is not None else 0.0,
        "flow_tcp": len(flows), "ty_le_flow_tcp_hai_chieu": round(sum(two_way) / len(flows), 4) if flows else None,
        "ket_noi_co_syn": len(syn), "ty_le_co_phan_hoi": round(sum(map(answered, syn)) / len(syn), 4) if syn else None,
        "ket_noi_toi_may_trong_mang": len(syn_in),
        "ty_le_co_phan_hoi_trong_mang": round(sum(map(answered, syn_in)) / len(syn_in), 4) if syn_in else None,
        "cap_mot_chieu": [{"a": a, "b": b, "goi_a_sang_b": x, "goi_b_sang_a": y} for a, b, x, y in one_sided[:20]],
        "so_cap_mot_chieu": len(one_sided),
    }
    if lab_hosts:
        res["may_lab"] = {h: h in seen_hosts for h in lab_hosts}
    res["ket_luan"], res["ly_do"] = verdict(res)
    return res


def verdict(res, t=THRESHOLDS) -> tuple:
    reasons = []
    if res["flow_tcp"] < t["min_flow_tcp"]:
        return "canh_bao", [f"chỉ có {res['flow_tcp']} flow TCP: bắt lâu hơn hoặc tạo traffic thử rồi chạy lại"]
    tw = res["ty_le_flow_tcp_hai_chieu"]
    sa = res["ty_le_co_phan_hoi_trong_mang"]
    level = "dat"
    if tw < t["hai_chieu_loi"] or (sa is not None and sa < t["hai_chieu_loi"]):
        level = "loi"
        reasons.append("phần lớn kết nối chỉ thấy một chiều: cổng mirror chỉ sao chép một hướng (TX hoặc RX) "
                       "hoặc cảm biến đặt sai chỗ")
    elif tw < t["hai_chieu_dat"] or (sa is not None and sa < t["hai_chieu_dat"]):
        level = "canh_bao"
        reasons.append("một phần kết nối chỉ thấy một chiều: kiểm tra cấu hình mirror cả hai hướng, hoặc kết nối "
                       "tới máy không trả lời")
    if res["ty_le_nhan_doi"] > t["nhan_doi_canh_bao"]:
        level = "canh_bao" if level == "dat" else level
        reasons.append(f"{res['ty_le_nhan_doi']:.1%} gói bị nhân đôi: mirror sao chép cả cổng vào và cổng ra của cùng "
                       "gói; đặc trưng đếm gói sẽ bị gấp đôi")
    if res.get("may_lab") and not all(res["may_lab"].values()):
        missing = [h for h, ok in res["may_lab"].items() if not ok]
        reasons.append(f"không thấy traffic của: {', '.join(missing)} (máy chưa phát traffic, hoặc không nằm trên "
                       "cổng được mirror)")
    return level, reasons or ["thấy traffic hai chiều"]


def main(argv=None):
    from .config import load_config
    ap = argparse.ArgumentParser(description="Xác minh cảm biến thấy traffic hai chiều.")
    ap.add_argument("pcap", help="bản bắt thử trên card giám sát")
    ap.add_argument("--net", action="append", help="mạng giám sát; mặc định lab.subnet")
    ap.add_argument("--out", help="ghi báo cáo JSON")
    ap.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    nets = a.net or [cfg["lab"]["subnet"]]
    lab_hosts = list((cfg.get("lab") or {}).get("hosts") or {}) if not a.net else None
    res = analyze(read_with_digest(a.pcap), nets, lab_hosts, FlowSettings.from_config(cfg))
    print(json.dumps(res, ensure_ascii=False, indent=1))
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"dat": 0, "canh_bao": 0, "loi": 1}[res["ket_luan"]]


if __name__ == "__main__":
    sys.exit(main())
