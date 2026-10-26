# C03-T03 — Trích xuất port và cờ TCP

Mã nguồn: `src/nids/packets.py` (cùng hàm `parse_packet()` của C03-T02).
Kiểm thử: `tests/test_packets.py`, lớp `PortFlagTest`.

## 1. Trường mới của `PacketRecord`

| Trường | Ý nghĩa |
|---|---|
| `src_port`, `dst_port` | Cổng nguồn và đích của TCP, UDP, SCTP. `None` khi giao thức không có cổng hoặc khi 4 byte đầu header tầng trên không có trong gói |
| `tcp_flags` | 9 bit cờ TCP dạng số nguyên (FIN 0x001 … CWR 0x080, AE 0x100). `None` khi không phải TCP hoặc khi gói bị cắt trước byte cờ |
| `tcp_seq` | Số thứ tự TCP (sequence number), thêm ở C04-T02 để phân biệt gói bắt tay gửi lại với kết nối mới ([19_ket_thuc_flow.md](19_ket_thuc_flow.md)). Chỉ có khi có `tcp_flags`, giống Wireshark; không có trong CSV |
| `tcp_flag_names` | Thuộc tính: tên các cờ đang bật, theo thứ tự cố định `SYN,ACK,FIN,RST,PSH,URG,ECE,CWR,AE`; chuỗi rỗng nếu không có cờ |

Các hằng `TCP_SYN`, `TCP_ACK`, ... dùng để kiểm tra cờ trong mã, ví dụ
`rec.tcp_flags & TCP_SYN and not rec.tcp_flags & TCP_ACK` là gói mở kết nối.
Hàm `tcp_flag_names(flags)` đổi một giá trị cờ bất kỳ thành chuỗi tên.

Bit AE (Accurate ECN, trước đây gọi là NS) là bit thấp nhất của byte 12 trong
header TCP. Ba bit dự trữ còn lại không phải cờ nên bị bỏ qua.

## 2. Khi nào trường "tồn tại"

| Trường hợp | Cổng | Cờ TCP |
|---|---|---|
| TCP đủ 14 byte đầu header | Có | Có |
| TCP bị `snaplen` cắt, còn 4 đến 13 byte | Có | `None` |
| UDP, SCTP | Có | `None` |
| ICMP, ICMPv6, IGMP, GRE, ... | `None` | `None` |
| Mảnh IP không phải mảnh đầu (`l4_offset` là `None`) | `None` | `None` |
| Header tầng trên nằm ngoài gói IP, ví dụ gói IP rỗng được đệm cho đủ khung Ethernet 60 byte | `None` | `None` |

Chỉ đọc byte trong phạm vi `ip_len`, nên phần đệm của khung Ethernet không bị
đọc nhầm thành cổng. Gói lỗi ICMP (ví dụ port unreachable) có chép lại header
của gói gốc, nhưng bản thân gói ICMP không có cổng nên trả về `None`.

Không kiểm tra checksum và không kiểm tra trường Data Offset của TCP, vì chỉ cần
4 byte cổng và 2 byte cờ ở vị trí cố định.

## 3. Cách dùng

```python
from nids.packets import TCP_ACK, TCP_SYN, extract_packets

syn = 0
for rec in extract_packets("data/pcap/k2-quet-cong-train-01.pcap"):
    if rec.tcp_flags is not None and rec.tcp_flags & TCP_SYN and not rec.tcp_flags & TCP_ACK:
        syn += 1
```

Dòng lệnh không đổi so với C03-T02; phần in ra có thêm cổng và cờ, ví dụ
`192.168.50.20:51234 -> 192.168.50.30:443  TCP [SYN,ACK]`. CSV có thêm bốn cột
`src_port`, `dst_port`, `tcp_flags` (số thập phân), `tcp_flag_names`; ô để trống
khi trường không tồn tại.

## 4. Kiểm tra

**Kiểm thử tự động** (8 ca mới, tổng 50 ca của dự án): cổng và cờ TCP qua IPv4,
bit AE và bit dự trữ, UDP, ICMP không có cổng, TCP sau header mở rộng IPv6, gói
bị cắt ở hai mức, phần đệm Ethernet, mảnh IP sau; CSV có cột mới.

**Đối chiếu với Wireshark** (ngày 20/10/2026): so `tcp.srcport`, `tcp.dstport`,
`tcp.flags`, `udp.*port`, `sctp.*port` của `tshark` với từng gói IP.

| File | Gói IP | TCP khớp | UDP khớp | Khác | Lệch |
|---|---|---|---|---|---|
| CTU-13 scenario 6, `donbot.pcap` (cả bản PCAPNG) | 24 407 | 24 240 | 147 | 20 ICMP | 0 |
| CTU-13 scenario 7, `sogou.pcap` | 20 614 | 20 512 | 92 | 10 ICMP | 0 |
| File tổng hợp: TCP qua IPv6, cờ ECE/CWR/AE, SCTP, gói bị cắt, phần đệm | 8 | 5 | 1 | 1 SCTP, 1 không cổng | 0 |

Với các gói lỗi ICMP, `tshark` hiển thị cổng UDP của gói được chép lại bên
trong; bộ trích xuất trả về `None`. Đây là khác biệt có chủ ý (mục 2), không
tính là lệch.

Phân bố cờ trên `donbot.pcap`: SYN 15 346, ACK 4 891, ACK+PSH 2 949, ACK+FIN
397, SYN+ACK 275, ACK+RST 197. Số SYN lớn hơn nhiều SYN+ACK cho thấy bot thử
kết nối hàng loạt; tỉ lệ này là ứng viên đặc trưng ở chặng 4.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Cổng (port) | Số 0–65535 chỉ chương trình nhận dữ liệu trên máy; cổng nguồn của client thường là số ngẫu nhiên lớn |
| TCP / UDP / SCTP | Ba giao thức tầng 4 có cổng; SCTP ít gặp, dùng trong mạng viễn thông |
| Cờ TCP | Các bit trong header TCP đánh dấu vai trò của gói |
| SYN | Xin mở kết nối |
| ACK | Xác nhận đã nhận dữ liệu |
| FIN | Xin đóng kết nối một cách bình thường |
| RST | Cắt ngang kết nối, thường do cổng đóng hoặc lỗi |
| PSH | Yêu cầu đẩy dữ liệu lên ứng dụng ngay |
| URG | Đánh dấu dữ liệu khẩn; hầu như không còn dùng |
| ECE, CWR, AE | Ba cờ báo nghẽn mạng (ECN); AE trước đây gọi là NS |
| Bit dự trữ | Bit chưa được giao nhiệm vụ trong chuẩn, phải bằng 0 |
| Data Offset | Trường cho biết header TCP dài bao nhiêu |
| Checksum | Số kiểm tra lỗi của gói |
| Bắt tay ba bước | Cách mở kết nối TCP: SYN → SYN+ACK → ACK |
| Gói lỗi ICMP (port unreachable) | Gói ICMP báo cổng đích không mở; nó chép lại phần đầu của gói gốc |
| snaplen | Số byte tối đa được lưu cho mỗi gói |
| Số thứ tự TCP (sequence number) | Số trong header TCP đánh dấu vị trí byte dữ liệu; gói gửi lại giữ nguyên số này |
