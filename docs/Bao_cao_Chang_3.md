# Báo cáo Chặng 3 — Chuyển PCAP và log thành dữ liệu có cấu trúc

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 17/10/2026 – 23/10/2026 |
| Trạng thái | Xong 7/7 task |
| Chặng trước | [Bao_cao_Chang_2.md](Bao_cao_Chang_2.md) |

## 1. Tóm tắt

Chặng 3 viết phần mã **đọc dữ liệu thô và chuyển thành bảng**, theo hai nhánh:

```
File PCAP/PCAPNG ──> bộ đọc PCAP ──> bóc header Ethernet/IP/TCP/UDP ──> bảng packet (CSV)
                     (C03-T01)        (C03-T02, T03, T04)                + thống kê gói bỏ qua
                                                  └── đối chiếu với Wireshark (C03-T07)

Access log Nginx ──> parser log ──> bảng log (CSV) ──> đối chiếu với dòng gốc
                     (C03-T05)       (C03-T06)
```

Tiêu chí nghiệm thu của chặng — *có cả ví dụ PCAP → bản ghi packet và log text →
bảng dữ liệu* — đã đạt:

- Bảng packet khớp Wireshark ở **mọi trường của mọi packet** trên 5 bản thu
  thật (4 571 135 packet, lớn nhất là bản thu toàn mạng 4,48 triệu packet của
  CTU-13) và 2 file tổng hợp.
- Bảng log khớp **mọi ô** khi đối chiếu toàn bộ 470 dòng log do Nginx thật ghi.

Mã đọc PCAP tự viết bằng thư viện chuẩn của Python, không dùng Scapy hay dpkt
(QĐ-013, QĐ-014). Chưa có flow, đặc trưng hay mô hình nào; đó là việc của
Chặng 4 trở đi.

## 2. Các task

| Task | Nội dung | Trạng thái | Mã nguồn | Tài liệu |
|---|---|---|---|---|
| C03-T01 | Viết bộ đọc PCAP theo từng packet | Xong | `src/nids/pcap_reader.py` | [11_bo_doc_pcap.md](11_bo_doc_pcap.md) |
| C03-T02 | Trích xuất timestamp, IP, giao thức, độ dài | Xong | `src/nids/packets.py` | [12_trich_xuat_packet.md](12_trich_xuat_packet.md) |
| C03-T03 | Trích xuất port và cờ TCP khi tồn tại | Xong | `src/nids/packets.py` | [13_port_co_tcp.md](13_port_co_tcp.md) |
| C03-T04 | Xử lý packet không hỗ trợ, lỗi và thống kê bỏ qua | Xong | `src/nids/packets.py` | [14_goi_bo_qua.md](14_goi_bo_qua.md) |
| C03-T05 | Viết parser cho log dịch vụ đã chọn | Xong | `src/nids/service_log.py` | [15_parser_log.md](15_parser_log.md) |
| C03-T06 | Xuất dữ liệu log thành bảng; đối chiếu một số dòng với bản gốc | Xong | `src/nids/service_log.py`, `src/nids/log_compare.py` | [16_xuat_doi_chieu_log.md](16_xuat_doi_chieu_log.md) |
| C03-T07 | Đối chiếu kết quả đọc packet với Wireshark | Xong | `src/nids/wireshark_compare.py` | [17_doi_chieu_wireshark.md](17_doi_chieu_wireshark.md) |

## 3. Kết quả từng task

### 3.1. C03-T01 — Bộ đọc PCAP

`PcapReader` mở file PCAP hoặc PCAPNG và trả về lần lượt từng packet: thời điểm
bắt (nano giây, số nguyên nên không mất độ chính xác), số byte đã lưu, độ dài
gốc, kiểu tầng liên kết và byte thô.

- Đọc theo luồng, không nạp cả file vào bộ nhớ: khoảng 300 000 packet/giây.
- PCAP micro giây và nano giây, cả hai thứ tự byte; PCAPNG nhiều giao diện,
  nhiều section, độ phân giải thời gian riêng của từng giao diện.
- Nhận định dạng qua 4 byte đầu file, không tin phần mở rộng.
- File cụt (tcpdump bị dừng đột ngột): giữ các packet trước đó và cảnh báo.
  File hỏng: báo lỗi rõ ràng.

### 3.2. C03-T02 — Timestamp, IP, giao thức, độ dài

`parse_packet()` bóc header tầng liên kết rồi đọc header IP:

| Đọc được | Chi tiết |
|---|---|
| Tầng liên kết | Ethernet (kể cả VLAN, QinQ), Linux cooked v1/v2 (`tcpdump -i any`), loopback, IP thô |
| IP | IPv4 có option; IPv6 đi qua các header mở rộng để tìm giao thức thật |
| Trường | Thời điểm, IP nguồn/đích, phiên bản, số hiệu giao thức, độ dài khung, độ dài IP, có phân mảnh hay không |

Đề xuất: đặc trưng về byte ở Chặng 4 dùng **độ dài theo header IP** (`ip_len`),
vì nó không phụ thuộc kiểu bắt gói hay việc gói bị cắt; chốt ở C04-T03.

### 3.3. C03-T03 — Port và cờ TCP

Thêm cổng nguồn/đích (TCP, UDP, SCTP) và 9 cờ TCP (SYN, ACK, FIN, RST, PSH,
URG, ECE, CWR, AE). Trường nào không có trong gói thì để trống: giao thức không
có cổng, mảnh IP không phải mảnh đầu, gói bị cắt trước header TCP. Byte đệm của
khung Ethernet không bị đọc nhầm thành cổng.

Trên bản thu bot donbot của CTU-13: 15 346 gói SYN nhưng chỉ 275 gói SYN+ACK,
dấu hiệu bot thử kết nối hàng loạt; tỷ lệ này là ứng viên đặc trưng ở Chặng 4.

### 3.4. C03-T04 — Gói không hỗ trợ, lỗi, thống kê bỏ qua

Không gói nào bị bỏ mà không được đếm.

| Gói bị bỏ qua | Ví dụ |
|---|---|
| `khong_phai_ip` | ARP, LLDP, khung 802.3/LLC |
| `linktype_khong_ho_tro` | Bản thu Wi-Fi 802.11 |
| `header_lien_ket_bi_cat`, `header_ip_bi_cat` | Gói quá ngắn |
| `header_ip_sai` | Sai phiên bản, IHL, Total Length |

Gói vẫn dùng được nhưng có điểm bất thường thì giữ và ghi chú: bị cắt khi bắt,
thiếu cổng/cờ, phân mảnh, Total Length bằng 0 do TSO, không có thời điểm. File
hỏng giữa chừng: giữ phần đã đọc, ghi lỗi, lệnh trả mã thoát 1. Thống kê xuất
ra JSON (`--stats`) để lưu vào nhật ký lần chạy (QĐ-015).

### 3.5. C03-T05 — Parser access log Nginx

`read_log()` đọc access log định dạng `nids` (12 trường) thành bản ghi: thời
điểm (cùng đơn vị nano giây với packet), IP và cổng client, dòng yêu cầu tách
thành phương thức/đường dẫn/phiên bản, mã trạng thái, số byte, thời gian phục
vụ, số kết nối, User-Agent.

- Giải mã `\xHH` mà Nginx dùng để ghi `"`, `\`, chữ tiếng Việt, byte lạ.
- Dòng sai định dạng bị bỏ có lý do và dòng mẫu; dòng yêu cầu rác (byte TLS,
  `HELP`, `OPTIONS / RTSP/1.0` của `nmap -sV`) được **giữ** kèm ghi chú vì đó
  là dấu vết quét dò.
- Đọc cả file đã nén `.gz`, cả kiểu xuống dòng Windows và Linux; khoảng
  45 000 dòng/giây.

Kiểm tra bằng Nginx 1.26.3 thật cài tạm trên máy phát triển, gửi 11 tình huống
(keep-alive, thiếu User-Agent, tiếng Việt, byte TLS, yêu cầu dở 408, lệnh lạ
400, upstream lỗi 502, client ngắt 499, ...).

### 3.6. C03-T06 — Bảng log và đối chiếu với bản gốc

`--csv` xuất bảng 18 cột, thêm `start_ts` (thời điểm bắt đầu yêu cầu) để ghép
với flow. `nids.log_compare` đọc lại dòng gốc bằng một cách **độc lập** với
parser (duyệt từng ký tự, giải mã bằng codec có sẵn của Python) và so từng ô.

| Log Nginx thật | Dòng | Đối chiếu mẫu | Đối chiếu toàn bộ |
|---|---|---|---|
| Log tình huống | 13 | — | 13/13 khớp |
| Log 8 client song song | 457 | 28/28 khớp | 457/457 khớp |

Kiểm thử xác nhận công cụ phát hiện được ô bị sửa, dòng lệch số, dòng bị mất.
Phát hiện từ log thật: thời điểm ghi log luôn tăng, nhưng thời điểm **bắt đầu**
yêu cầu bị đảo thứ tự 90/457 lần, nên khi ghép với flow phải sắp xếp lại.

### 3.7. C03-T07 — Đối chiếu với Wireshark

`nids.wireshark_compare` chạy `tshark` và so mọi trường của mọi packet (thời
điểm, độ dài, IP, giao thức, độ dài IP, phân mảnh, cổng, cờ TCP); gói bị bỏ qua
phải là gói Wireshark cũng không thấy IP.

| File | Packet | Lệch |
|---|---|---|
| CTU-13 donbot (PCAP, PCAPNG, PCAP nano giây) | 24 764 mỗi bản | 0 |
| CTU-13 sogou | 20 663 | 0 |
| CTU-13 Virut fast-flux | 45 853 | 0 |
| CTU-13 scenario 5, PCAP toàn mạng đã cắt | 4 479 658 | 0 |
| Tự bắt Windows ↔ WSL (PCAPNG và PCAP) | 197 mỗi bản | 0 |
| Hai file tổng hợp | 15 | 0 |

Khác biệt có chủ ý gặp trên dữ liệu thật: gói lỗi ICMP (Wireshark báo cổng của
header được chép bên trong, bộ trích xuất không gán cổng cho gói ICMP) và 2 gói
IPv6 bị cắt mất địa chỉ đích (Wireshark hiện phần đọc được, bộ trích xuất bỏ
gói). Hai gói IPv6 này lần đầu được báo là lệch; sau khi xem từng byte mới xác
định là khác biệt có chủ ý.

## 4. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-013 | Tự viết bộ đọc file PCAP/PCAPNG bằng thư viện chuẩn | Tạm thời |
| QĐ-014 | Tự viết phần đọc header Ethernet/IP, không dùng dpkt | Đã chốt |
| QĐ-015 | Gói không đọc được bị bỏ qua có thống kê; file hỏng giữ phần đã đọc | Đã chốt |

## 5. Kiểm thử

`python -m unittest discover -s tests`: **103/103 ca đạt**.

| File | Số ca | Nội dung |
|---|---|---|
| `tests/test_pcap_reader.py` | 12 | PCAP/PCAPNG các biến thể, file cụt, file hỏng |
| `tests/test_packets.py` | 37 | IPv4/IPv6, tầng liên kết, cổng và cờ, lý do bỏ qua, ghi chú, thống kê, CSV, JSON |
| `tests/test_service_log.py` | 16 | 12 dòng log Nginx thật, giải mã, dòng hỏng, file `.gz` |
| `tests/test_log_compare.py` | 12 | Bảng CSV, đối chiếu, phát hiện ô bị sửa |
| `tests/test_wireshark_compare.py` | 11 | Đọc đầu ra tshark, phát hiện lệch, chạy tshark thật |
| Chặng 1–2 (`alerts`, `config`, `manifest`) | 15 | |

## 6. Cách chạy

```bash
python -m nids.pcap_reader data/pcap/<file>.pcap -n 10
python -m nids.packets data/pcap/<file>.pcap --csv output/packets.csv --stats output/packets_stats.json
python -m nids.wireshark_compare data/pcap/<file>.pcap
python -m nids.service_log data/service_logs/<run_id>/access_nids.log --csv output/log.csv
python -m nids.log_compare data/service_logs/<run_id>/access_nids.log output/log.csv -k 20
```

## 7. Điểm cần lưu ý

1. **Dữ liệu thật của đồ án mới có một phần.** Lúc kết thúc chặng chỉ có bản thu
   CTU-13, bản tự bắt Windows ↔ WSL, log Nginx cài tạm và dữ liệu tổng hợp. Ngày
   27/10/2026 đã chạy trên PCAP CIC-IDS2017 thứ Hai và thứ Sáu: đọc hết cả hai
   file không lỗi, 1 triệu gói đầu mỗi file khớp Wireshark 0 lệch (docs/06, mục 7).
   Lab chưa dựng; phải chạy lại `wireshark_compare` và `log_compare` khi có.
2. **IPv6 thật rất ít** (1 gói đầy đủ và 2 gói bị cắt); phần IPv6 còn lại kiểm tra bằng dữ liệu tổng hợp.
3. **TSO và đường hầm IP** chưa gặp trên dữ liệu thật, mới thử bằng kiểm thử.
4. **Tốc độ.** Đo trên file nhỏ lúc làm chặng: bộ đọc khoảng 300 000 packet/giây.
   Đo lại trên 2 triệu gói đầu của PCAP CIC thứ Sáu (27/10/2026, máy đang bận tải
   file khác): đọc thô khoảng 100 000 gói/giây, trích xuất khoảng 24 000, trích
   xuất kèm ghép flow khoảng 10 600. Khảo sát trọn một file 10 GB mất khoảng
   26 phút. Đủ cho lab 7 máy, nhưng cần đo lại khi máy rảnh và trước khi chạy
   realtime.
5. Log Nginx được sinh trên Windows (xuống dòng CRLF, một worker); cần đọc lại
   log của máy chủ dịch vụ Linux khi lab dựng xong.

## 8. Việc tiếp theo

**Chặng 4 — Xây dựng flow và đặc trưng:** định nghĩa flow hai chiều, xử lý
timeout và FIN/RST, tính packet/byte/thời lượng, thống kê kích thước và khoảng
cách giữa gói, cửa sổ host, số đích và cổng đích, entropy, tỷ lệ kết nối không
hoàn tất.

Song song: tải phần còn lại của CIC-IDS2017 (PCAP thứ Tư, hai CSV có nhãn) và 11
file `.binetflow` còn lại của CTU-13; dựng mạng lab và cài Nginx với định dạng
`nids`.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Dữ liệu thô / có cấu trúc | Byte hoặc dòng chữ nguyên bản / bảng có cột rõ ràng, máy tính xử lý được ngay |
| PCAP, PCAPNG | Hai định dạng file lưu gói tin bắt được |
| Packet, header | Một gói tin; phần đầu của gói chứa thông tin điều khiển như địa chỉ, độ dài |
| Bộ đọc, parser | Phần mã mở file và tách ra từng bản ghi / từng trường |
| Đọc theo luồng | Đọc từng phần của file, không nạp cả file vào bộ nhớ |
| Thứ tự byte | Cách xếp byte của một số nhiều byte (little-endian, big-endian) |
| Section, giao diện | Một phần của file PCAPNG; một card mạng |
| Tầng liên kết | Tầng thấp nhất như Ethernet; quyết định gói bắt đầu bằng header nào |
| Ethernet, VLAN, QinQ | Chuẩn mạng có dây; thẻ chia mạng logic; hai thẻ VLAN lồng nhau |
| Linux cooked, loopback, IP thô | Header giả khi bắt trên mọi card (`tcpdump -i any`); card ảo cho máy nói với chính nó; file chỉ có gói IP |
| IPv4, IPv6, header mở rộng | Hai phiên bản địa chỉ Internet; các header phụ có thể nằm giữa IPv6 và TCP/UDP |
| Phân mảnh (fragment) | Gói IP lớn bị chia nhỏ; chỉ mảnh đầu có cổng |
| Độ dài khung / độ dài IP | Độ dài cả gói trên dây / độ dài phần IP theo header IP |
| Cổng (port) | Số chỉ chương trình nhận dữ liệu trên máy |
| TCP, UDP, SCTP, ICMP | Các giao thức: có kết nối; không kết nối; ít gặp; báo lỗi và ping |
| Cờ TCP SYN, ACK, FIN, RST | Mở kết nối, xác nhận, đóng kết nối, cắt ngang kết nối |
| ARP, LLDP, 802.3/LLC | Các giao thức tầng liên kết không chở IP |
| IHL, Total Length | Độ dài header IPv4 / độ dài cả gói IPv4 |
| snaplen, bị cắt | Số byte tối đa lưu mỗi gói; gói dài hơn thì chỉ giữ phần đầu |
| TSO | Card mạng tự chia gói lớn khi gửi; bắt trên máy gửi thấy Total Length bằng 0 |
| Gói lỗi ICMP | Gói ICMP báo lỗi (ví dụ cổng không mở), chép lại phần đầu của gói gốc |
| Mã thoát | Số chương trình trả về: 0 là ổn, khác 0 là có lỗi hoặc lệch |
| CSV, JSON | File bảng dạng chữ; file chữ lưu dữ liệu dạng `{"khóa": giá trị}` |
| Nginx, access log, `log_format` | Máy chủ web; file ghi mỗi yêu cầu; lệnh quy định trường của dòng log |
| Escape `\xHH` | Nginx thay ký tự đặc biệt bằng `\x` và hai chữ số hệ 16 |
| Keep-alive, User-Agent | Giữ một kết nối cho nhiều yêu cầu; chuỗi client tự giới thiệu |
| Mã 400, 408, 499, 502 | Yêu cầu sai; hết thời gian chờ; client tự ngắt; máy chủ phía sau lỗi |
| Upstream, worker | Máy chủ phía sau Nginx; tiến trình con của Nginx xử lý yêu cầu |
| `nmap -sV` | Lệnh Nmap dò phiên bản dịch vụ, để lại dòng log lạ |
| Wireshark, tshark, dumpcap, editcap | Công cụ xem gói tin; bản dòng lệnh; công cụ bắt gói; công cụ chuyển đổi file |
| WSL | Chạy Ubuntu bên trong Windows, nối với Windows qua card mạng ảo |
| Đối chiếu độc lập | Kiểm tra lại bằng một cách đọc khác hẳn; hai cách cùng kết quả thì đáng tin |
| Khác biệt có chủ ý | Chỗ dự án cố ý xử lý khác Wireshark, được đếm riêng, không tính là lỗi |
| Flow, đặc trưng, entropy | Toàn bộ gói của một kết nối; con số đưa vào mô hình; độ đa dạng (ví dụ của các cổng đích) |
| Nhật ký lần chạy | File ghi mỗi lần thử nghiệm trong lab; căn cứ gán nhãn |
