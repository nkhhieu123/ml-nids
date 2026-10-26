"""Đặc trưng cơ bản của flow: số gói, số byte, thời lượng, tỷ lệ gửi/nhận (C04-T03).

Mọi giá trị chỉ dựa vào các gói của chính flow đó, nên tính được ngay khi flow
kết thúc, kể cả khi chạy realtime. Công thức, đơn vị và trường hợp biên ở
docs/20_dac_trung_flow_co_ban.md (QĐ-018).

    for flow in assign_flows(extract_packets(path)).flows():
        print(basic_features(flow))
"""

from .packets import PROTO_TCP, PROTO_UDP

# Tên đặc trưng -> (đơn vị, mô tả). Thứ tự này là thứ tự cột khi xuất bảng.
BASIC_FEATURES = {
    "packets": ("gói", "Tổng số gói của flow"),
    "fwd_packets": ("gói", "Số gói chiều forward (client → server)"),
    "bwd_packets": ("gói", "Số gói chiều backward (server → client)"),
    "bytes": ("byte", "Tổng độ dài gói theo header IP (ip_len)"),
    "fwd_bytes": ("byte", "Tổng ip_len chiều forward"),
    "bwd_bytes": ("byte", "Tổng ip_len chiều backward"),
    "payload_bytes": ("byte", "Tổng dữ liệu TCP/UDP, không tính header; trống nếu không phải TCP/UDP"),
    "fwd_payload_bytes": ("byte", "Dữ liệu TCP/UDP chiều forward"),
    "bwd_payload_bytes": ("byte", "Dữ liệu TCP/UDP chiều backward"),
    "duration_s": ("giây", "Thời điểm gói cuối trừ gói đầu; 0 nếu flow có một gói"),
    "fwd_packet_share": ("tỷ lệ 0–1", "fwd_packets / packets"),
    "fwd_byte_share": ("tỷ lệ 0–1", "fwd_bytes / bytes"),
}

SHARE_DIGITS = 6


def _duration_s(flow):
    if flow.first_ts_ns is None or flow.last_ts_ns is None:
        return None
    ns = flow.last_ts_ns - flow.first_ts_ns
    return f"{ns // 10**9}.{ns % 10**9:09d}"


def basic_features(flow) -> dict:
    """Đặc trưng cơ bản của một flow (đối tượng Flow của flows.py).

    ``duration_s`` là chuỗi số thập phân đủ 9 chữ số (nano giây) để không mất độ
    chính xác khi ghi CSV. Hai tỷ lệ luôn xác định vì mọi flow có ít nhất một gói
    và mỗi gói IP dài ít nhất 20 byte.
    """
    packets = flow.fwd_packets + flow.bwd_packets
    total_bytes = flow.fwd_bytes + flow.bwd_bytes
    has_payload = flow.key.protocol in (PROTO_TCP, PROTO_UDP)
    return {
        "packets": packets,
        "fwd_packets": flow.fwd_packets,
        "bwd_packets": flow.bwd_packets,
        "bytes": total_bytes,
        "fwd_bytes": flow.fwd_bytes,
        "bwd_bytes": flow.bwd_bytes,
        "payload_bytes": flow.fwd_payload_bytes + flow.bwd_payload_bytes if has_payload else None,
        "fwd_payload_bytes": flow.fwd_payload_bytes if has_payload else None,
        "bwd_payload_bytes": flow.bwd_payload_bytes if has_payload else None,
        "duration_s": _duration_s(flow),
        "fwd_packet_share": round(flow.fwd_packets / packets, SHARE_DIGITS),
        "fwd_byte_share": round(flow.fwd_bytes / total_bytes, SHARE_DIGITS) if total_bytes else None,
    }
