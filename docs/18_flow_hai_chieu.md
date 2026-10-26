# C04-T01 — Flow hai chiều và quy tắc forward/backward

Mã nguồn: `src/nids/flows.py`. Kiểm thử: `tests/test_flows.py`. Quyết định:
QĐ-016 trong [03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md). Đầu vào là
bảng packet của [12_trich_xuat_packet.md](12_trich_xuat_packet.md) và
[13_port_co_tcp.md](13_port_co_tcp.md).

```bash
python -m nids.flows data/pcap/<file>.pcap --csv output/flows.csv --stats output/flows_stats.json
```

Tài liệu này định nghĩa **flow là gì** và **chiều nào là forward**. Việc cắt
flow theo thời gian nhàn rỗi, FIN/RST và khi 5-tuple được dùng lại làm ở C04-T02,
xem [19_ket_thuc_flow.md](19_ket_thuc_flow.md). Số liệu ở mục 7 đo lúc C04-T01,
khi mỗi khóa flow còn ứng một flow trong cả file.

## 1. Flow hai chiều

Một flow hai chiều gồm mọi packet có cùng:

| Thành phần | Ghi chú |
|---|---|
| Phiên bản IP | IPv4 và IPv6 không bao giờ chung flow |
| Giao thức tầng trên | Số hiệu trong header IP: 6 TCP, 17 UDP, 1 ICMP, ... |
| Hai đầu mút (IP, cổng) | Không phân biệt nguồn hay đích, nên gói đi và gói về chung một flow |

**Khóa flow** (`FlowKey`) xếp hai đầu mút theo thứ tự cố định: đầu mút `a` là
đầu có IP nhỏ hơn khi so **dạng số** (không so chuỗi, vì theo chuỗi
`10.0.0.10` < `10.0.0.9`), cùng IP thì so cổng. Nhờ đó gói A→B và B→A cho cùng
một khóa. Thứ tự này chỉ để tra cứu; nó **không** nói bên nào là client.

| Trường hợp | Đầu mút gồm |
|---|---|
| TCP, UDP, SCTP | IP và cổng |
| ICMP, ICMPv6, IGMP và giao thức khác | Chỉ IP (cổng để trống). Mọi gói ICMP giữa hai máy là một flow |
| TCP/UDP bị cắt trước khi tới cổng | Chỉ IP; tách khỏi flow có cổng và được đếm ở `flow_khong_co_cong` |
| Mảnh IP không phải mảnh đầu | Không có cổng; được gắn vào flow của mảnh đầu (mục 4) |

Gói lỗi ICMP (ví dụ port unreachable) thuộc flow ICMP giữa hai máy, không
thuộc flow TCP/UDP mà nó báo lỗi, vì bộ trích xuất chỉ đọc header ngoài cùng
([17_doi_chieu_wireshark.md](17_doi_chieu_wireshark.md)).

## 2. Forward và backward

- **Forward**: chiều từ **bên mở kết nối** (client) sang bên kia.
- **Backward**: chiều ngược lại, từ server về client.

Mọi đặc trưng có chữ "fwd"/"bwd" ở C04-T03, C04-T04 (số gói, byte, tỷ lệ
gửi/nhận) đều dựa vào quy tắc này. CICFlowMeter, công cụ tạo CSV của
CIC-IDS2017, lấy bên gửi gói đầu tiên làm forward. Dự án dùng cùng ý đó nhưng
sửa cho các trường hợp gói đầu tiên không phải gói mở kết nối.

## 3. Cách xác định bên mở kết nối

Chiều được chọn **một lần, từ gói đầu tiên của flow**, theo thứ tự ưu tiên dưới
đây, và không đổi về sau. Vì chỉ dùng gói đã tới nên cách làm giống hệt nhau khi
huấn luyện và khi chạy realtime, và không dùng dữ liệu tương lai.

| Thứ tự | Mã (`direction_basis`) | Gói đầu tiên của flow | Client là |
|---|---|---|---|
| 0 | `cung_dau_mut` | Hai đầu mút trùng nhau (cùng IP, cùng cổng) | Không phân biệt được; mọi gói tính là forward |
| 1 | `syn` | TCP có SYN, không có ACK | Bên gửi |
| 2 | `syn_ack` | TCP có SYN và ACK (đã lỡ mất gói SYN) | Bên nhận |
| 3 | `cong_dich_vu` | TCP khác (bắt giữa chừng kết nối), một bên dùng cổng < 1024, bên kia ≥ 1024 | Bên dùng cổng ≥ 1024 |
| 4 | `goi_dau` | Mọi trường hợp còn lại | Bên gửi |

Lý do của từng quy tắc:
- **SYN và SYN+ACK** là cách chắc chắn nhất để biết ai mở kết nối TCP. Bắt đầu
  bắt gói lúc kết nối đang mở, hay file bị sắp xếp sai thời gian, đều có thể
  làm gói SYN+ACK đứng trước.
- **Cổng dịch vụ** chỉ dùng cho TCP bắt giữa chừng. Nếu gói đầu tiên là dữ liệu
  server gửi về cổng 80 → 40000 thì theo "gói đầu" server sẽ thành client, các
  đặc trưng fwd/bwd bị đảo. Cổng < 1024 gần như luôn là phía server. Nếu cả hai
  cổng cùng < 1024 hoặc cùng ≥ 1024 (P2P, BitTorrent) thì không đoán, quay về
  `goi_dau`.
- **UDP và giao thức khác dùng `goi_dau`**, không đoán theo cổng. UDP không có
  bắt tay nên gói đầu thường chính là yêu cầu của client. Đoán theo cổng sẽ đảo
  chiều sai với traffic tấn công cố ý dùng cổng nguồn thấp (ví dụ `nmap -g 53`)
  hoặc flood dùng cổng ngẫu nhiên.
- Một gói SYN tới **sau** trên cùng 5-tuple không làm đổi chiều của flow đang
  có. Gói đó báo hiệu một kết nối mới và mở flow mới, có chiều riêng
  ([19_ket_thuc_flow.md](19_ket_thuc_flow.md)).

Mỗi gói được đánh dấu forward nếu (IP nguồn, cổng nguồn) của nó trùng đầu mút
client của flow, ngược lại là backward.

## 4. Mảnh IP

Mảnh đầu của một datagram bị phân mảnh mang header TCP/UDP nên có cổng; các mảnh
sau thì không. Nếu chỉ dựa vào cổng, các mảnh sau sẽ rơi vào một flow riêng
không cổng, làm số gói và byte của flow thật bị thiếu.

Vì vậy bộ trích xuất packet giờ ghi thêm trường `frag_id`: Identification của
IPv4, hoặc của header Fragment trong IPv6. Bộ ghép flow nhớ mảnh đầu theo
(IP nguồn, IP đích, giao thức, `frag_id`) và gắn các mảnh sau vào **cùng flow
và cùng chiều**. Mảnh đầu chỉ được nhớ 30 giây (`flow.fragment_timeout_s` trong
`config/default.yaml`), bằng thời gian chờ ghép mảnh mặc định của Linux
(`net.ipv4.ipfrag_time`).

Mảnh không tìm thấy mảnh đầu (mảnh đầu bị mất, tới sau, hoặc quá 30 giây) được
gọi là **mảnh mồ côi**: nó vào flow không cổng của cặp IP và được đếm ở
`manh_mo_coi`. Không ghép lại nội dung mảnh (xem
[12_trich_xuat_packet.md](12_trich_xuat_packet.md)).

## 5. Thứ tự gói

Gói được xử lý **theo thứ tự trong file**, giống như khi bắt realtime. Nếu một gói
có thời điểm nhỏ hơn gói đứng trước, chương trình đếm vào
`goi_sai_thu_tu_thoi_gian` và in cảnh báo, không sắp xếp lại. File donbot và
sogou của CTU-13 có 2 và 4 gói như vậy (chênh nhau dưới 1 mili giây).

## 6. Đầu ra

Bảng CSV, mỗi dòng một flow, theo thứ tự gói đầu tiên:

| Cột | Ý nghĩa |
|---|---|
| `first_index` | Chỉ số packet đầu tiên của flow trong file (khung `first_index + 1` trong Wireshark) |
| `first_ts`, `last_ts` | Thời điểm gói đầu và gói cuối, giây từ epoch UTC |
| `ip_version`, `protocol` | Phiên bản IP, số hiệu giao thức |
| `fwd_ip`, `fwd_port` | Đầu mút client |
| `bwd_ip`, `bwd_port` | Đầu mút server |
| `direction_basis` | Quy tắc đã dùng để chọn client (mục 3) |
| `fwd_packets`, `bwd_packets` | Số gói mỗi chiều; từ C04-T03 là đặc trưng, cùng các cột byte và thời lượng ([20_dac_trung_flow_co_ban.md](20_dac_trung_flow_co_ban.md)) |
| `fragments_attached` | Số mảnh không mang cổng đã gắn vào flow |

Thống kê JSON có số flow theo `direction_basis` và theo giao thức, số mảnh đã
gắn, số mảnh mồ côi, số flow không có cổng, số gói sai thứ tự thời gian, kèm
thống kê bỏ qua của bộ trích xuất packet.

## 7. Kiểm tra

**So với Wireshark.** Một script tạm chạy `tshark` (tắt ghép mảnh và ghép đoạn),
lấy số `tcp.stream`/`udp.stream` của từng gói, rồi kiểm tra:
1. Mọi gói cùng một stream của Wireshark nằm trong cùng một flow của dự án.
2. Với mỗi stream TCP có gói SYN, gói đi từ bên gửi SYN đầu tiên phải là
   forward, gói ngược lại phải là backward.

| File | Packet IP | Flow | Stream Wireshark | Stream bị chia sang 2 flow | Gói kiểm tra chiều theo SYN | Sai chiều |
|---|---|---|---|---|---|---|
| donbot | 24 407 | 4 540 | 4 565 | 0 | 24 234 | 0 |
| sogou | 20 614 | 47 | 46 | 0 | 20 512 | 0 |
| Virut fast-flux | 45 784 | 873 | 1 446 | 0 | 45 527 | 0 |
| WSL | 197 | 84 | 82 | 0 | 147 | 0 |
| CTU-13 scenario 5, PCAP toàn mạng đã cắt | 4 479 656 | 118 853 | 119 444 | 0 | 3 204 767 | 4 |
| l4 (tự tạo) | 8 | 8 | 3 | 0 | 1 | 0 |

Ba điều rút ra từ bảng:
- **Flow ít hơn stream** ở donbot (26 flow chứa 2 stream) và Virut (291 flow chứa 3
  stream). Wireshark tách stream mới khi cùng 5-tuple được dùng lại sau khi kết
  nối đóng; lúc C04-T01 dự án chưa tách. Bot Virut mở lại cùng cổng nguồn
  tới cùng máy chủ nhiều lần. Sau C04-T02 không còn flow nào chứa hai stream.
- **Flow nhiều hơn stream** là các flow ICMP và giao thức khác mà Wireshark không
  đánh số stream.
- **4 gói sai chiều** ở bản thu toàn mạng đều thuộc một flow BitTorrent
  (cổng 6881 ↔ 1567). Flow bắt đầu giữa chừng, cả hai cổng ≥ 1024 nên chiều
  chọn theo `goi_dau`: máy ngoài là client. Sau đó máy trong mạng gửi SYN mở một
  kết nối **mới** trên cùng 5-tuple; Wireshark coi đó là stream mới với client
  là máy trong mạng. Theo QĐ-016 chiều của flow đang có không đổi, nên 2 gói SYN
  và 2 gói tiếp theo bị tính là backward. C04-T02 tách flow mới tại gói SYN
  này nên 4 gói đã đúng chiều. Bản thu này chạy mất 83 giây.
- Ở WSL có 6 mảnh IPv4 thật: 2 mảnh đầu, 4 mảnh sau được gắn đúng flow; không có
  mảnh mồ côi.

**Cơ sở xác định chiều trên dữ liệu thật:**

| File | `syn` | `syn_ack` | `cong_dich_vu` | `goi_dau` |
|---|---|---|---|---|
| donbot | 4 505 | 1 | 1 | 33 |
| sogou | 40 | 0 | 0 | 7 |
| Virut | 850 | 0 | 0 | 23 |
| WSL | 62 | 0 | 0 | 22 |
| Scenario 5 toàn mạng | 29 164 | 863 | 1 104 | 87 722 |

Flow `syn_ack` duy nhất của donbot là kết nối HTTP mà file không lưu gói SYN
của bot; chương trình vẫn nhận đúng bot là client. Các flow `goi_dau` là DNS,
NetBIOS broadcast, NTP, ICMP và SNMP. Ở bản thu toàn mạng, `goi_dau` gồm 85 755
flow UDP, 1 234 flow ICMP và 733 flow TCP; 730 trong số flow TCP đó có cả hai
cổng ≥ 1024 (chủ yếu P2P). Bản thu này có 14 mảnh đã gắn và 4 mảnh mồ côi
(UDP từ máy ngoài Internet, không thấy mảnh đầu).

**Kiểm thử tự động** (24 ca, tổng 127 ca của dự án): khóa giống nhau ở hai chiều,
so IP dạng số, IPv6; năm quy tắc chọn client, gồm bắt giữa chừng, RST/FIN đầu
tiên, UDP trả lời trước; tách theo giao thức, cổng, gói bị cắt cổng; gắn mảnh
chiều đi và chiều về, mảnh mồ côi, quá hạn 30 giây, Identification trùng ở hai
máy khác nhau; đếm gói sai thứ tự; dòng lệnh ghi CSV và JSON.

## 8. Giới hạn

- `cong_dich_vu` có thể sai nếu cả client dùng cổng < 1024 (ví dụ `rsh`, một số
  dịch vụ cũ) và kết nối bị bắt giữa chừng; khi đó kết quả giống `goi_dau`.
- Flow ICMP gộp mọi loại ICMP giữa hai máy (ping, báo lỗi), vì bảng packet chưa
  có trường type/code.
- Đường hầm IP trong IP chỉ có flow của header ngoài cùng.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Flow hai chiều | Mọi gói qua lại giữa hai đầu của một kết nối, gộp cả chiều đi và chiều về |
| Đầu mút | Một phía của kết nối: địa chỉ IP cùng số cổng |
| 5-tuple | Năm giá trị nhận diện một kết nối: IP nguồn, IP đích, cổng nguồn, cổng đích, giao thức |
| Khóa flow | Giá trị dùng để tra flow của một gói; gói hai chiều cho cùng khóa |
| Forward / backward | Chiều từ client sang server / chiều từ server về client |
| Client / server | Bên mở kết nối / bên nhận kết nối |
| SYN, SYN+ACK | Gói đầu tiên của bắt tay TCP do client gửi / gói server trả lời đồng ý |
| Bắt giữa chừng | Bắt đầu thu gói khi kết nối đã mở, nên không thấy bắt tay |
| Cổng dịch vụ (well-known port) | Cổng dưới 1024, dành cho dịch vụ như 22 SSH, 53 DNS, 80 HTTP |
| BitTorrent | Phần mềm chia sẻ file kiểu P2P, hay dùng cổng 6881 |
| P2P | Mạng ngang hàng, hai bên cùng là client và server, thường dùng cổng cao |
| CICFlowMeter | Công cụ tạo file flow CSV của CIC-IDS2017 |
| Mảnh IP, mảnh đầu | Một gói IP lớn bị chia nhỏ; chỉ mảnh đầu chứa header TCP/UDP |
| Identification (`frag_id`) | Số trong header IP giúp biết các mảnh nào thuộc cùng một gói gốc |
| Mảnh mồ côi | Mảnh không tìm thấy mảnh đầu nên không biết thuộc flow nào |
| `tcp.stream`, `udp.stream` | Số thứ tự kết nối Wireshark gán cho từng gói |
| Dữ liệu tương lai | Thông tin của gói tới sau; dùng nó khi tính đặc trưng là gian lận vì realtime không có |
| SNMP, NetBIOS | Giao thức quản lý thiết bị mạng; giao thức chia sẻ tên máy trong mạng Windows |
| Cấu hình (config) | Tham số chỉnh được mà không sửa mã, nằm trong `config/default.yaml` |
| Epoch UTC | Mốc 00:00 ngày 1/1/1970 giờ quốc tế; thời điểm được tính bằng giây kể từ mốc này |
