# C03-T02 — Trích xuất timestamp, IP, giao thức, độ dài

Mã nguồn: `src/nids/packets.py`. Kiểm thử: `tests/test_packets.py`. Quyết định
liên quan: QĐ-014.

## 1. Chức năng

`parse_packet()` nhận một `RawPacket` từ bộ đọc PCAP
([11_bo_doc_pcap.md](11_bo_doc_pcap.md)), bóc header tầng liên kết, đọc header
IPv4 hoặc IPv6 và trả về một `PacketRecord`. Gói không phải IP, hoặc header IP
bị cắt hay sai, cho kết quả `None`.

| Trường | Ý nghĩa |
|---|---|
| `index` | Thứ tự packet trong file, khớp với số frame của Wireshark trừ 1 |
| `ts_ns` | Thời điểm bắt, nano giây từ epoch UTC |
| `src_ip`, `dst_ip` | Địa chỉ nguồn và đích; IPv6 ở dạng rút gọn chuẩn (`fe80::1`) |
| `ip_version` | 4 hoặc 6 |
| `protocol` | Số hiệu giao thức tầng trên: 1 ICMP, 6 TCP, 17 UDP, 58 ICMPv6, ... |
| `protocol_name` | Tên giao thức; số hiệu lạ thì là chính con số |
| `frame_len` | Độ dài gói trên đường truyền (`orig_len`), gồm header tầng liên kết |
| `ip_len` | Độ dài gói IP theo header IP: IPv4 là Total Length, IPv6 là 40 + Payload Length |
| `caplen` | Số byte đã lưu trong file |
| `is_fragment` | Gói thuộc một datagram IP bị phân mảnh |
| `l4_offset` | Vị trí header tầng trên trong byte của gói; `None` với mảnh không phải mảnh đầu. Dùng cho task C03-T03 |
| `frag_id` | Identification của datagram bị phân mảnh (IPv4: trường Identification; IPv6: header Fragment); `None` nếu gói không phân mảnh. Thêm ở C04-T01 để gắn các mảnh vào cùng flow ([18_flow_hai_chieu.md](18_flow_hai_chieu.md)); không có trong CSV |

Cổng và cờ TCP (C03-T03) mô tả ở [13_port_co_tcp.md](13_port_co_tcp.md).

**Chọn độ dài nào.** `frame_len` gồm header Ethernet và phần đệm của khung
ngắn (khung Ethernet tối thiểu 60 byte), nên phụ thuộc kiểu tầng liên kết lúc
bắt. `ip_len` không phụ thuộc vào cách bắt và không bị ảnh hưởng khi gói bị cắt
bởi `snaplen`. Đã chốt ở C04-T03 (QĐ-018): đặc trưng về byte dùng `ip_len`, kèm
trường `payload_len` (dữ liệu TCP/UDP) thêm vào bản ghi packet; xem
[20_dac_trung_flow_co_ban.md](20_dac_trung_flow_co_ban.md).

## 2. Phạm vi hỗ trợ

| Tầng | Hỗ trợ |
|---|---|
| Ethernet (LINKTYPE 1), kể cả thẻ VLAN 802.1Q và QinQ 802.1ad | Có |
| Linux cooked v1 và v2 (LINKTYPE 113, 276), khi bắt bằng `tcpdump -i any` | Có |
| Loopback BSD (LINKTYPE 0), IP thô (LINKTYPE 101, 228, 229) | Có |
| IPv4, kể cả header có option | Có |
| IPv6, đi qua header mở rộng Hop-by-Hop, Routing, Fragment, Destination Options, AH để tìm giao thức tầng trên | Có |
| Phân mảnh IP | Ghi nhận `is_fragment`; không ghép lại datagram |
| Đường hầm (IP trong IP, GRE, VXLAN) | Chỉ đọc header IP ngoài cùng |
| ARP, 802.11 và các kiểu khác | Trả về `None` |

Phân loại và đếm các gói trả về `None` theo lý do (C03-T04) mô tả ở
[14_goi_bo_qua.md](14_goi_bo_qua.md).

## 3. Cách dùng

```python
from nids.packets import extract_packets

for rec in extract_packets("data/pcap/k1-binh-thuong-train-01.pcap"):
    print(rec.ts_ns, rec.src_ip, rec.dst_ip, rec.protocol_name, rec.ip_len)
```

Từ dòng lệnh, in 10 gói IP đầu, thống kê theo giao thức, và ghi bảng ra CSV:

```bash
python -m nids.packets data/pcap/<file>.pcap -n 10 --csv output/packets.csv
```

Các cột của CSV: `index`, `ts`, `src_ip`, `dst_ip`, `ip_version`, `protocol`,
`protocol_name`, `frame_len`, `ip_len`, `caplen`, `is_fragment`. Cột `ts` ghi
dạng `giây.nano giây` giống trường `frame.time_epoch` của Wireshark.

## 4. Kiểm tra

**Kiểm thử tự động** (`tests/test_packets.py`, 15 ca): IPv4 qua Ethernet, khung
có phần đệm, option IPv4, VLAN và QinQ, phân mảnh, gói bị cắt bởi `snaplen`,
header hỏng, gói không phải IP; IPv6 có và không có header mở rộng, mảnh IPv6;
Linux cooked, loopback, IP thô; đọc cả file và ghi CSV.

**Đối chiếu với Wireshark** (ngày 19/10/2026): so từng gói với kết quả `tshark`
về timestamp, `frame.len`, địa chỉ nguồn/đích, số hiệu giao thức và độ dài IP.

| File | Số packet | Gói IP khớp | Không phải IP (cả hai bên đồng ý) | Lệch |
|---|---|---|---|---|
| CTU-13 scenario 6, `botnet-capture-20110816-donbot.pcap` | 24 764 | 24 407 | 357 | 0 |
| Cùng file, chuyển sang PCAPNG | 24 764 | 24 407 | 357 | 0 |
| CTU-13 scenario 7, `botnet-capture-20110816-sogou.pcap` | 20 663 | 20 614 | 49 | 0 |
| File tổng hợp: VLAN, QinQ, IPv6, header mở rộng, phân mảnh | 7 | 7 | 0 | 0 |

Hai file CTU-13 chỉ có IPv4, nên phần IPv6 mới được kiểm tra trên file tổng
hợp. Cần kiểm tra lại khi có PCAP lab thật.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Trích xuất | Lấy ra các trường cần dùng từ byte thô của gói |
| Tầng liên kết, header | Tầng thấp nhất như Ethernet; header là phần đầu chứa thông tin điều khiển |
| IPv4 / IPv6 | Hai phiên bản giao thức địa chỉ Internet |
| Identification | Số trong header IP mà mọi mảnh của cùng một gói gốc đều mang giống nhau |
| Dạng rút gọn IPv6 | Cách viết ngắn bỏ các nhóm số 0, ví dụ `fe80:0:0:0:0:0:0:1` thành `fe80::1` |
| Số hiệu giao thức | Số trong header IP cho biết bên trong là gì: 1 ICMP, 6 TCP, 17 UDP, 58 ICMPv6 |
| ICMP / ICMPv6 | Giao thức báo lỗi và kiểm tra kết nối (lệnh ping) của IPv4 / IPv6 |
| Total Length, Payload Length | Trường độ dài trong header IPv4 (cả gói IP) / IPv6 (phần sau header 40 byte) |
| Phân mảnh (fragment) | Gói IP quá lớn bị chia thành nhiều mảnh nhỏ; chỉ mảnh đầu có header TCP/UDP |
| l4_offset | Vị trí bắt đầu của header tầng 4 (TCP/UDP) trong gói |
| Phần đệm (padding) | Byte 0 thêm vào cho khung Ethernet đủ tối thiểu 60 byte |
| VLAN, QinQ | Thẻ chia mạng logic; QinQ là hai thẻ VLAN lồng nhau |
| Linux cooked | Header giả của Linux khi bắt trên mọi card mạng (`tcpdump -i any`) |
| Loopback, IP thô | Card ảo cho máy nói chuyện với chính nó / file chỉ có gói IP, không có tầng liên kết |
| Header mở rộng IPv6 | Các header phụ có thể nằm giữa header IPv6 và TCP/UDP (Hop-by-Hop, Routing, Fragment, ...) |
| Đường hầm (tunnel) | Gói IP được bọc trong một gói khác (IP trong IP, GRE, VXLAN) |
| ARP, 802.11 | Giao thức hỏi địa chỉ MAC / chuẩn Wi-Fi |
| frame.time_epoch | Tên trường thời điểm bắt gói trong Wireshark |
