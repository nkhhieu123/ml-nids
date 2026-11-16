"""Phát hiện dấu hiệu giả mạo ARP (ARP spoofing) bằng quy tắc, trên file PCAP.

Bộ trích xuất của ba module bỏ qua gói ARP vì chúng không chở IP (docs/14). Module này đọc riêng các gói ARP
(Ethernet hoặc Linux cooked, có thể có thẻ VLAN) và giữ bảng "địa chỉ IP → địa chỉ MAC" học được từ trường người
gửi của gói ARP. Ba dấu hiệu được báo:

- ``doi_mac``: một IP đã gắn với MAC A, nay một gói ARP nói IP đó thuộc MAC B. Đây là dấu hiệu chính của giả mạo
  ARP (kẻ tấn công nhận mình là cổng mạng hoặc máy khác). Cũng xảy ra khi thay card mạng hoặc máy ảo đổi MAC, nên
  cảnh báo ghi rõ MAC cũ, MAC mới và thời điểm lần cuối thấy MAC cũ.
- ``mot_mac_nhieu_ip``: một MAC nhận là chủ của từ ``nhieu_ip`` IP trở lên. Kẻ giả mạo nhiều máy cùng lúc có dấu
  hiệu này; bộ định tuyến làm proxy ARP cũng vậy, nên mức này chỉ là nghi vấn.
- ``khung_khong_khop``: MAC nguồn của khung Ethernet khác MAC người gửi ghi trong gói ARP.

Gói ARP thăm dò (IP người gửi 0.0.0.0) không được dùng để học bảng. Module không phát gói nào; chỉ đọc PCAP.

    cd src
    python -m nids.arp_gia_mao ../data/pcap/lab/*.pcap --out ../docs/hinh/arp_lab.json
"""

import argparse
import ipaddress
import json
import struct
import sys
from pathlib import Path

from .pcap_reader import PcapReader

LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2 = 1, 113, 276
ETHERTYPE_ARP = 0x0806
VLAN = (0x8100, 0x88A8, 0x9100)


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_arp(linktype: int, data: bytes):
    """Trả về (MAC nguồn của khung hoặc None, phép toán, MAC gửi, IP gửi, MAC đích, IP đích) hoặc None."""
    frame_src = None
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        frame_src, pos = data[6:12], 12
        et = struct.unpack_from("!H", data, pos)[0]
        while et in VLAN and len(data) >= pos + 6:
            pos += 4
            et = struct.unpack_from("!H", data, pos)[0]
        pos += 2
    elif linktype == LINKTYPE_LINUX_SLL and len(data) >= 16:
        halen = struct.unpack_from("!H", data, 4)[0]
        frame_src = data[6:6 + min(halen, 6)] if halen == 6 else None
        et, pos = struct.unpack_from("!H", data, 14)[0], 16
    elif linktype == LINKTYPE_LINUX_SLL2 and len(data) >= 20:
        frame_src = data[12:18] if data[11] == 6 else None
        et, pos = struct.unpack_from("!H", data, 0)[0], 20
    else:
        return None
    if et != ETHERTYPE_ARP or len(data) < pos + 28:
        return None
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, pos)
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
        return None
    b = data[pos + 8:pos + 28]
    return (mac(frame_src) if frame_src else None, op, mac(b[0:6]), str(ipaddress.IPv4Address(b[6:10])),
            mac(b[10:16]), str(ipaddress.IPv4Address(b[16:20])))


class ArpWatch:
    """Bảng IP → MAC và các cảnh báo; dùng được cho từng gói theo thứ tự thời gian (offline hoặc realtime)."""

    def __init__(self, nhieu_ip=3):
        self.nhieu_ip = nhieu_ip
        self.bang = {}                 # ip -> [mac, lần đầu thấy, lần cuối thấy]
        self.ip_cua_mac = {}           # mac -> tập IP đã nhận
        self.canh_bao = []
        self.so_goi_arp = 0
        self._da_bao_nhieu_ip = set()

    def add(self, ts, parsed):
        frame_src, op, smac, sip, _tmac, _tip = parsed
        self.so_goi_arp += 1
        if frame_src and frame_src != smac:
            self.canh_bao.append({"loai": "khung_khong_khop", "thoi_diem": ts, "ip": sip, "mac_arp": smac,
                                  "mac_khung": frame_src, "phep_toan": op})
        if sip == "0.0.0.0":           # gói thăm dò, chưa ai nhận IP này
            return
        cu = self.bang.get(sip)
        if cu and cu[0] != smac:
            self.canh_bao.append({"loai": "doi_mac", "thoi_diem": ts, "ip": sip, "mac_cu": cu[0], "mac_moi": smac,
                                  "mac_cu_thay_lan_cuoi": cu[2], "phep_toan": op})
        if not cu or cu[0] != smac:
            self.bang[sip] = [smac, ts, ts]
        else:
            cu[2] = ts
        ips = self.ip_cua_mac.setdefault(smac, set())
        ips.add(sip)
        if len(ips) >= self.nhieu_ip and smac not in self._da_bao_nhieu_ip:
            self._da_bao_nhieu_ip.add(smac)
            self.canh_bao.append({"loai": "mot_mac_nhieu_ip", "thoi_diem": ts, "mac": smac, "ip": sorted(ips)})


def scan_pcap(path, watch=None) -> ArpWatch:
    watch = watch or ArpWatch()
    with PcapReader(path) as r:
        for pkt in r:
            p = parse_arp(pkt.linktype, pkt.data)
            if p:
                watch.add(pkt.ts, p)
    return watch


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phát hiện dấu hiệu giả mạo ARP trên file PCAP.")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--nhieu-ip", type=int, default=3, help="một MAC nhận từ chừng này IP trở lên thì báo")
    ap.add_argument("--out", help="file JSON kết quả")
    a = ap.parse_args(argv)
    res = {}
    for p in a.pcap:
        w = scan_pcap(p, ArpWatch(a.nhieu_ip))           # mỗi bản thu một bảng riêng: lần chạy lab độc lập nhau
        res[Path(p).name] = {"so_goi_arp": w.so_goi_arp, "so_ip": len(w.bang), "canh_bao": w.canh_bao}
        if w.canh_bao:
            print(Path(p).name, w.canh_bao[:3])
    tong = {"so_ban_thu": len(res), "so_goi_arp": sum(v["so_goi_arp"] for v in res.values()),
            "so_canh_bao": sum(len(v["canh_bao"]) for v in res.values())}
    print(json.dumps(tong, ensure_ascii=False))
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps({"tong": tong, "ban_thu": res}, ensure_ascii=False, indent=2),
                               encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
