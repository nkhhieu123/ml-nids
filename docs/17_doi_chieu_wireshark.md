# C03-T07 — Đối chiếu kết quả đọc packet với Wireshark

Mã nguồn: `src/nids/wireshark_compare.py`. Kiểm thử:
`tests/test_wireshark_compare.py`. Các phần được đối chiếu:
[11_bo_doc_pcap.md](11_bo_doc_pcap.md), [12_trich_xuat_packet.md](12_trich_xuat_packet.md),
[13_port_co_tcp.md](13_port_co_tcp.md), [14_goi_bo_qua.md](14_goi_bo_qua.md).

## 1. Cách đối chiếu

Các task C03-T01 đến C03-T04 đã so từng phần với `tshark` bằng script tạm.
C03-T07 gom lại thành một công cụ trong dự án, so **mọi trường** của **mọi
packet** trong một lần chạy, để chạy lại được trên PCAP của CIC-IDS2017 và của
lab khi có:

```bash
python -m nids.wireshark_compare data/pcap/<file>.pcap [file khác ...] --report output/ws_compare.json
```

Công cụ chạy `tshark` (bản dòng lệnh của Wireshark) trên cùng file, đọc song
song đầu ra của `tshark` và bộ đọc PCAP của dự án, rồi so từng packet:

| Trường của dự án | Trường của Wireshark |
|---|---|
| `ts_ns` | `frame.time_epoch` |
| `frame_len`, `caplen` | `frame.len`, `frame.cap_len` |
| `src_ip`, `dst_ip`, `ip_version` | `ip.src`/`ip.dst` hoặc `ipv6.src`/`ipv6.dst` của header ngoài cùng |
| `protocol` | `ip.proto`; với IPv6 là một trong các giá trị "next header" của chuỗi header mở rộng |
| `ip_len` | `ip.len`; với IPv6 là 40 + `ipv6.plen` |
| `is_fragment` | `ip.flags.mf`, `ip.frag_offset`, hoặc có header Fragment của IPv6 |
| `src_port`, `dst_port` | `tcp.*port`, `udp.*port`, `sctp.*port` |
| `tcp_flags` | `tcp.flags` (bỏ 3 bit dự trữ) |
| `tcp_seq` | `tcp.seq_raw` (thêm ở C04-T02) |
| Gói bị bỏ qua | `tshark` cũng không thấy IPv4/IPv6; cột giao thức của `tshark` được ghi lại để biết đó là gì |

`tshark` được chạy với ghép mảnh IP và ghép đoạn TCP **tắt**, để mỗi dòng đầu
ra ứng đúng một packet trong file như bộ đọc của dự án. Hai luồng được đọc song
song nên dùng được cho file nhiều GB. Lệnh trả mã thoát 1 nếu có lệch.

**Khác biệt có chủ ý** được đếm riêng, không tính là lệch:

| Mã | Trường hợp | Wireshark | Dự án |
|---|---|---|---|
| `icmp_chep_header_goc` | Gói lỗi ICMP (ví dụ port unreachable) chép lại header của gói gốc | Báo cổng của header được chép bên trong | Gói ICMP không có cổng |
| `ip_len_bang_0_tso` | IPv4 Total Length bằng 0 do card mạng chia đoạn (TSO) | Giữ 0 | Lấy theo số byte đã bắt |
| `duong_ham_ip` | IP bọc trong IP | Báo cổng của gói bên trong | Chỉ đọc header ngoài cùng |
| `header_ip_bi_cat_mat_dia_chi` | Gói bị cắt khi bắt giữa header IP, mất địa chỉ đích | Hiện phần đọc được, ví dụ chỉ có địa chỉ nguồn | Bỏ gói (`header_ip_bi_cat`) vì không dùng được cho flow |

## 2. Dữ liệu đối chiếu

Ngày 23/10/2026, Wireshark/TShark 4.6.8 trên máy phát triển.

| File | Nguồn | Vì sao chọn |
|---|---|---|
| `botnet-capture-20110816-donbot.pcap` | CTU-13 scenario 6, chỉ traffic bot | Quét cổng: nhiều SYN, RST |
| Cùng file đổi sang PCAPNG và PCAP nano giây | Tạo bằng `editcap` | Thử ba kiểu file với cùng nội dung |
| `botnet-capture-20110816-sogou.pcap` | CTU-13 scenario 7, chỉ traffic bot | HTTP |
| `botnet-capture-20110815-fast-flux.pcap` | CTU-13 scenario 5 (Virut), chỉ traffic bot | Spam, HTTP, IGMP |
| `capture20110815-2.truncated.pcap` | CTU-13 scenario 5, **toàn mạng trường**, mỗi gói đã bị cắt còn phần header | Bản thu lớn, traffic hỗn hợp thật, mọi gói bị cắt bởi snaplen |
| `wsl.pcapng` và bản PCAP | Tự bắt bằng `dumpcap` trên card ảo giữa Windows và WSL Ubuntu | Hệ điều hành Linux hiện đại: phân mảnh IPv4 thật, ICMPv6, HTTP, TCP RST, ICMP port unreachable |
| `synthetic.pcap`, `l4.pcap` | Tự tạo bằng mã | Những gì dữ liệu thật chưa có: VLAN, QinQ, header mở rộng IPv6, SCTP, cờ ECE/CWR/AE, gói bị cắt giữa header TCP |

Bản thu WSL được bắt trên card ảo chỉ nối Windows với WSL. Ngoài traffic do
nhóm tự sinh, nó có gói NTP và một kết nối TCP của Ubuntu tới máy chủ của
Canonical (hệ điều hành tự đồng bộ giờ). Các file thu chỉ lưu trong thư mục tạm,
không đưa lên git.

## 3. Kết quả

| File | Packet | Gói IP khớp | Không phải IP (hai bên đồng ý) | Khác biệt có chủ ý | Lệch |
|---|---|---|---|---|---|
| donbot (PCAP, PCAPNG, PCAP nano giây; mỗi bản) | 24 764 | 24 407 | 357 ARP | 20 ICMP | 0 |
| sogou | 20 663 | 20 614 | 49 ARP | 10 ICMP | 0 |
| Virut fast-flux | 45 853 | 45 784 | 69 ARP | 14 ICMP | 0 |
| CTU-13 scenario 5, PCAP toàn mạng đã cắt | 4 479 658 | 4 479 656 | 0 | 5 719 ICMP; 2 IPv6 bị cắt mất địa chỉ đích | 0 |
| WSL (PCAPNG và PCAP; mỗi bản) | 197 | 197 | 0 | 0 | 0 |
| synthetic | 7 | 7 | 0 | 0 | 0 |
| l4 | 8 | 8 | 0 | 0 | 0 |

Theo giao thức, các gói IP khớp gồm:
- PCAP toàn mạng scenario 5: TCP 4 074 304, UDP 397 607, ICMP 7 745; mọi gói
  đều bị cắt còn phần header. Chạy mất khoảng 14 phút.
- WSL: TCP 147, UDP 40, ICMP 9, ICMPv6 1; có 6 mảnh IPv4 thật.
- Ba file bot của CTU-13: TCP 90 281, UDP 476, ICMP 44, IGMP 4.
- Hai file tổng hợp: thêm IPv6 TCP/UDP/ICMPv6, SCTP, VLAN, phân mảnh IPv6.

Ngày 26/10/2026 (C04-T02) công cụ được bổ sung trường `tcp_seq` và chạy lại trên
mọi file ở bảng trên, gồm cả PCAP toàn mạng scenario 5: vẫn 0 lệch.

## 4. Nhận xét

- Mọi trường của mọi packet đều khớp với Wireshark trên các file trên, gồm cả
  ba kiểu file (PCAP micro giây, PCAP nano giây, PCAPNG).
- Mọi gói bộ trích xuất bỏ qua đều là gói Wireshark cũng không thấy IP (trên
  dữ liệu thật là ARP), trừ 2 gói IPv6 của PCAP cắt ngắn scenario 5.
- Hai gói đó là gói IPv6 multicast bị cắt còn 42 byte: header IPv6 chỉ còn 28/40
  byte, có địa chỉ nguồn nhưng địa chỉ đích bị cắt dở. Wireshark vẫn hiện phần
  đọc được; bộ trích xuất bỏ gói vì không dùng được cho flow. Lần chạy đầu công
  cụ báo 2 lệch; sau khi xem từng byte, trường hợp này được thêm vào danh sách
  khác biệt có chủ ý (`header_ip_bi_cat_mat_dia_chi`) và chạy lại cả file.
- Khác biệt có chủ ý gặp trên dữ liệu thật: gói lỗi ICMP và gói IPv6 bị cắt.
  Chưa gặp TSO và đường hầm IP trong dữ liệu thật; hai trường hợp này mới được
  thử bằng kiểm thử tự động.
- IPv6 thật mới có 1 gói đầy đủ (ICMPv6 Router Solicitation của WSL) và 2 gói bị cắt. Phần IPv6 còn lại
  được kiểm tra bằng dữ liệu tổng hợp. Cần chạy lại công cụ trên PCAP lab và
  CIC-IDS2017 khi có.

**Kiểm thử tự động** (11 ca, tổng 103 ca của dự án): đọc dòng `tshark` cho
IPv4, gói không phải IP, gói ICMP lỗi có hai header IP, IPv6 có header mở rộng;
so khớp, **phát hiện** trường bị lệch (độ dài IP, cổng, cờ), gói bị bỏ qua sai,
ba loại khác biệt có chủ ý; và một ca chạy `tshark` thật trên file tổng hợp
(tự bỏ qua nếu máy không cài Wireshark).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Wireshark, tshark | Công cụ xem gói tin phổ biến nhất; tshark là bản dòng lệnh của nó. Dùng làm "đáp án" để kiểm tra bộ đọc của dự án |
| dumpcap, editcap | Công cụ đi kèm Wireshark: bắt gói ra file / chuyển đổi định dạng file |
| Trường (field) của Wireshark | Tên một giá trị Wireshark đọc được từ gói, ví dụ `ip.src` là IP nguồn |
| Header ngoài cùng | Header IP đầu tiên của gói; gói ICMP lỗi hay đường hầm có thêm header IP bên trong |
| Next header | Trường của IPv6 cho biết phần tiếp theo là header mở rộng hay TCP/UDP/ICMPv6 |
| Ghép mảnh, ghép đoạn TCP | Wireshark có thể nối các mảnh IP hoặc các đoạn TCP thành một; tắt đi để so từng gói |
| Gói lỗi ICMP, port unreachable | Gói ICMP báo cổng đích không mở; nó chép lại phần đầu của gói gốc |
| TSO | Card mạng tự chia gói lớn khi gửi; bắt trên chính máy gửi thấy Total Length bằng 0 |
| Đường hầm IP trong IP | Gói IP được bọc trong một gói IP khác |
| ARP, IGMP, NTP | Hỏi địa chỉ MAC; đăng ký nhận multicast; đồng bộ giờ qua mạng |
| ICMPv6 Router Solicitation | Gói IPv6 máy gửi để tìm router khi vừa bật mạng |
| WSL | Windows Subsystem for Linux: chạy Ubuntu bên trong Windows, nối với Windows qua một card mạng ảo |
| PCAP toàn mạng đã cắt | Bản thu cả mạng trường của CTU-13, mỗi gói chỉ giữ phần header để bảo vệ riêng tư |
| Fast-flux | Kỹ thuật botnet đổi liên tục địa chỉ IP sau một tên miền để khó bị chặn |
| Mã thoát | Số chương trình trả về: 0 là khớp hết, 1 là có lệch |
| Đọc song song hai luồng | Đọc từng gói từ bộ đọc PCAP và từng dòng từ tshark cùng lúc, không nạp hết file vào bộ nhớ |
| Bit dự trữ | Bit chưa được dùng trong header TCP, phải bằng 0 |
| SCTP, VLAN, QinQ | Giao thức tầng 4 ít gặp; thẻ chia mạng logic; hai thẻ VLAN lồng nhau |
| Số thứ tự TCP (sequence number) | Số trong header TCP đánh dấu vị trí byte dữ liệu; gói gửi lại giữ nguyên số này |
