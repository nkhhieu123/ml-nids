"""Bóc lớp đường hầm trước khi đọc gói: IP trong IP, IPv6 trong IPv4, GRE, VXLAN (QĐ-086).

Mặc định bộ đọc chỉ đọc header ngoài cùng (docs/17 mục 3.2): flow của traffic trong đường hầm là flow giữa hai đầu
đường hầm. Khi ``capture.giai_duong_ham`` bật, mỗi gói đường hầm được thay bằng gói **bên trong** trước khi đọc, nên
flow và cửa sổ host là của các máy thật trong đường hầm. Gói không phải đường hầm giữ nguyên.

Nhận diện:

- IPv4 giao thức 4 (IP trong IP) hoặc 41 (IPv6 trong IPv4); IPv6 tiêu đề kế 4 hoặc 41;
- GRE (giao thức 47) phiên bản 0, chở IPv4 (0x0800), IPv6 (0x86DD) hoặc Ethernet (0x6558);
- VXLAN: UDP cổng đích 4789, cờ I bật, bên trong là khung Ethernet.

Chỉ bóc gói không phân mảnh (gói đường hầm bị phân mảnh giữ nguyên). Bóc tối đa ``MAX_DEPTH`` lớp.
"""

import struct

from .pcap_reader import RawPacket

LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6 = 1, 228, 229
VXLAN_PORT = 4789
MAX_DEPTH = 2


def _inner(linktype, data):
    """(linktype mới, dữ liệu mới) của gói bên trong, hoặc None nếu không phải đường hầm bóc được."""
    from .packets import network_offset

    found = network_offset(linktype, data)
    if found is None:
        return None
    off, ver = found
    if ver == 4:
        if len(data) < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        flags_frag = struct.unpack_from("!H", data, off + 6)[0]
        if flags_frag & 0x3FFF:                      # mảnh: không bóc
            return None
        proto, payload = data[off + 9], off + ihl
    else:
        if len(data) < off + 40:
            return None
        proto, payload = data[off + 6], off + 40     # không đi qua tiêu đề mở rộng
    if proto == 4:
        return LINKTYPE_IPV4, data[payload:]
    if proto == 41:
        return LINKTYPE_IPV6, data[payload:]
    if proto == 47 and len(data) >= payload + 4:
        flags, ptype = struct.unpack_from("!HH", data, payload)
        if flags & 0x0007:                           # chỉ GRE phiên bản 0
            return None
        hlen = 4 + 4 * bool(flags & 0x8000) + 4 * bool(flags & 0x2000) + 4 * bool(flags & 0x1000)
        body = data[payload + hlen:]
        return {0x0800: (LINKTYPE_IPV4, body), 0x86DD: (LINKTYPE_IPV6, body),
                0x6558: (LINKTYPE_ETHERNET, body)}.get(ptype)
    if proto == 17 and len(data) >= payload + 16:
        dport = struct.unpack_from("!H", data, payload + 2)[0]
        if dport == VXLAN_PORT and data[payload + 8] & 0x08:
            return LINKTYPE_ETHERNET, data[payload + 16:]
    return None


def decapsulate(raw: RawPacket) -> RawPacket:
    """Gói bên trong (tối đa ``MAX_DEPTH`` lớp) hoặc chính ``raw`` nếu không phải đường hầm."""
    linktype, data = raw.linktype, raw.data
    for _ in range(MAX_DEPTH):
        got = _inner(linktype, data)
        if got is None or not got[1]:
            break
        linktype, data = got
    if data is raw.data:
        return raw
    return RawPacket(raw.index, raw.ts_ns, len(data), len(data), linktype, data, raw.interface)


def enabled(cfg) -> bool:
    return bool(((cfg or {}).get("capture") or {}).get("giai_duong_ham"))
