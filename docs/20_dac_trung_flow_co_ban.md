# C04-T03 — Số gói, số byte, thời lượng và tỷ lệ gửi/nhận của flow

Mã nguồn: `src/nids/flow_features.py` (công thức), `src/nids/flows.py` (cộng dồn
theo từng gói), `src/nids/packets.py` (trường `payload_len`). Kiểm thử:
`tests/test_flow_features.py`, `tests/test_packets.py`. Quyết định: QĐ-018 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md). Flow được ghép và kết thúc
theo [18_flow_hai_chieu.md](18_flow_hai_chieu.md) và
[19_ket_thuc_flow.md](19_ket_thuc_flow.md).

```bash
python -m nids.flows data/pcap/<file>.pcap --csv output/flows.csv
```

Bảng CSV của lệnh trên có thêm các cột ở mục 2.

## 1. Đo độ dài bằng gì

Có ba cách đo độ dài một gói:

| Độ dài | Gồm | Phụ thuộc cách bắt gói | Dùng |
|---|---|---|---|
| `frame_len` | Cả khung trên dây: header Ethernet, phần đệm khung ngắn | Có: khác nhau giữa Ethernet, Linux cooked, VLAN | Không dùng cho đặc trưng |
| `ip_len` | Gói IP: header IP, header TCP/UDP, dữ liệu | Không; đúng cả khi gói bị cắt bởi snaplen | Đặc trưng `*_bytes` |
| `payload_len` | Chỉ dữ liệu TCP/UDP | Không | Đặc trưng `*_payload_bytes` |

**Chốt: `ip_len` là độ dài chính** (đề xuất từ Chặng 3,
[12_trich_xuat_packet.md](12_trich_xuat_packet.md)). CIC-IDS2017, CTU-13 và
PCAP lab được bắt bằng cách khác nhau. Dùng `frame_len` thì cùng một gói sẽ dài
khác nhau tùy kiểu tầng liên kết, nên đặc trưng của ba nguồn không so được với
nhau.

**Thêm payload** vì CICFlowMeter tính "Total Length of Fwd Packets" theo dữ liệu,
không theo cả gói. Có payload thì so được với CSV của CIC, và gói chỉ có header
(SYN, ACK rỗng) có payload bằng 0. Đó là dấu hiệu rõ của quét cổng và SYN flood.

`payload_len` tính bằng ip_len trừ header IP (gồm header mở rộng IPv6) trừ
header TCP (theo Data Offset) hoặc 8 byte UDP. Vì lấy từ ip_len nên vẫn đúng với
PCAP chỉ giữ header, như bản thu toàn mạng của CTU-13. Các trường hợp đặc biệt:

| Trường hợp | `payload_len` |
|---|---|
| Mảnh IP không phải mảnh đầu | ip_len trừ header IP (toàn bộ là dữ liệu) |
| Mảnh đầu | Phần dữ liệu trong mảnh đó; cộng các mảnh lại ra dữ liệu của cả datagram |
| TCP bị cắt trước byte Data Offset | Không biết (None); flow đếm ở `payload_unknown` |
| Data Offset < 5 (sai) hoặc kết quả âm | None |
| ICMP, IGMP, giao thức khác | None; cột payload của flow để trống |

## 2. Đặc trưng

| Cột | Công thức | Đơn vị |
|---|---|---|
| `packets` | `fwd_packets + bwd_packets` | gói |
| `fwd_packets`, `bwd_packets` | Số gói mỗi chiều | gói |
| `bytes` | `fwd_bytes + bwd_bytes` | byte |
| `fwd_bytes`, `bwd_bytes` | Tổng `ip_len` mỗi chiều | byte |
| `payload_bytes` | `fwd_payload_bytes + bwd_payload_bytes` | byte |
| `fwd_payload_bytes`, `bwd_payload_bytes` | Tổng `payload_len` mỗi chiều; trống nếu flow không phải TCP/UDP | byte |
| `duration_s` | Thời điểm lớn nhất trừ thời điểm nhỏ nhất của các gói | giây, 9 chữ số thập phân |
| `fwd_packet_share` | `fwd_packets / packets` | tỷ lệ 0–1 |
| `fwd_byte_share` | `fwd_bytes / bytes` | tỷ lệ 0–1 |

Cột kiểm tra (không phải đặc trưng): `payload_unknown` là số gói TCP/UDP không tính
được payload.

Chiều forward là chiều client → server theo QĐ-016. Ví dụ: gửi yêu cầu HTTP nhỏ
rồi nhận trang lớn thì `fwd_byte_share` nhỏ, còn tải file lên thì lớn.

## 3. Tỷ lệ gửi/nhận

Đặc trưng "tỷ lệ gửi/nhận" được biểu diễn bằng **phần của chiều forward trong
tổng** (`fwd_packet_share`, `fwd_byte_share`), không bằng phép chia hai chiều
cho nhau:

- Phép chia `bwd / fwd` hay `fwd / bwd` cho kết quả vô hạn khi một chiều không có
  gói. Đây là trường hợp rất thường gặp: SYN quét cổng không được trả lời (4 249
  trong 4 588 flow của bản thu donbot), flow UDP một chiều, phần sau của kết nối bị active
  timeout cắt. CSV của CIC-IDS2017 có giá trị vô hạn và trống trong các cột
  dạng này, phải xử lý riêng trước khi huấn luyện.
- Phần trong tổng luôn nằm trong [0, 1] và luôn xác định, vì mọi flow có ít nhất
  một gói và mỗi gói IP dài ít nhất 20 byte. Có thể đổi qua lại với tỷ lệ chia:
  `fwd / bwd = share / (1 − share)`.
- `fwd_packet_share` = 1 nghĩa là không có trả lời; = 0 là chỉ thấy chiều server,
  ví dụ khi chiều đi không được bắt.

Không có tỷ lệ theo payload, vì nhiều flow có payload bằng 0 cả hai chiều (quét,
bắt tay không dữ liệu). Mô hình dùng trực tiếp `fwd_payload_bytes` và
`bwd_payload_bytes`.

## 4. Thời lượng

`duration_s` = thời điểm lớn nhất trừ thời điểm nhỏ nhất của các gói trong flow.

| Trường hợp | Giá trị |
|---|---|
| Flow một gói | 0 |
| File sai thứ tự thời gian (gói tới sau có thời điểm nhỏ hơn) | Vẫn không âm, vì dùng lớn nhất/nhỏ nhất. Từ task này `first_ts`/`last_ts` của flow cũng là nhỏ nhất/lớn nhất |
| Gói không có thời điểm | Bỏ qua khi tính; nếu flow không có gói nào có thời điểm thì để trống |
| Kết nối dài | Tối đa khoảng 120 giây (active timeout, QĐ-017); phần sau là flow khác có `continuation = 1` |
| Flow kết thúc vì nhàn rỗi | Không tính thời gian chờ 60 giây; chỉ tính tới gói cuối |

Thời lượng được ghi dạng chuỗi thập phân 9 chữ số (nano giây) để CSV không làm
tròn. Không có đặc trưng tốc độ (byte/giây, gói/giây) ở task này: flow một gói
có thời lượng 0, chia ra vô hạn. Đây cũng là lỗi có trong cột "Flow Bytes/s" của
CSV CIC.

## 5. Đối chiếu với tên cột của CIC-IDS2017

Chỉ để tra cứu khi so với CSV của CIC. Dự án không đọc trực tiếp các cột này
(QĐ-009).

| Dự án | CICFlowMeter | Khác biệt |
|---|---|---|
| `fwd_packets`, `bwd_packets` | Total Fwd Packets, Total Backward Packets | Cách chọn chiều và cắt flow khác (QĐ-016, QĐ-017) |
| `fwd_payload_bytes`, `bwd_payload_bytes` | Total Length of Fwd Packets, Total Length of Bwd Packets | Cùng ý nghĩa (dữ liệu, không header) |
| `duration_s` | Flow Duration | CIC tính bằng micro giây |
| `fwd_packet_share` | Down/Up Ratio | CIC lấy phần nguyên của bwd/fwd (một số nguyên); dự án dùng phần trong tổng |

## 6. Kiểm tra

**So với Wireshark, từng gói.** Công cụ `nids.wireshark_compare` so thêm
`payload_len` với `tcp.len` (TCP) và `udp.length − 8` (UDP), bỏ qua mảnh IP:

| File | Gói IP | Lệch |
|---|---|---|
| donbot (PCAP, PCAPNG, nano giây) | 24 407 mỗi bản | 0 |
| sogou | 20 614 | 0 |
| Virut | 45 784 | 0 |
| WSL (hai bản) | 197 | 0 |
| l4, synthetic (tự tạo) | 8, 7 | 0 |
| Scenario 5 toàn mạng (PCAP đã cắt) | 4 479 656 | 0 |

Gói UDP có trường Length trong header UDP khác với độ dài suy từ header IP được
đếm riêng là khác biệt có chủ ý `udp_length_khac_ip`: dự án tin header IP.
Trường hợp này gặp ở 3 gói tự tạo sai định dạng và **1 gói thật** trong bản thu
toàn mạng (khung 624 494). Gói đó khai Length 18 688 byte trong khi cả gói IP chỉ
dài 124 byte, và hai cổng 17152, 18432 (0x4300, 0x4800) trông như byte rác; đây
là gói hỏng hoặc giả. Theo header IP thì gói có 96 byte dữ liệu, là con số hợp
lý.

**So với Wireshark, từng flow.** Script tạm lấy các flow ứng đúng một stream TCP/UDP của
Wireshark (flow không bị cắt khác Wireshark, không có mảnh IP). Với mỗi flow như vậy,
script tính lại số gói, tổng `ip.len` và tổng `tcp.len`/`udp.length − 8` mỗi chiều,
và thời lượng từ `frame.time_epoch`. Đồng thời kiểm tra tổng byte của mọi flow
bằng tổng `ip_len` của mọi gói, tức là không gói nào bị mất hay đếm hai lần.

| File | Flow | Flow so được với một stream | Lệch | Tổng byte bảo toàn |
|---|---|---|---|---|
| donbot | 4 588 | 4 560 | 0 | Đúng (4 501 451 byte) |
| sogou | 77 | 17 | 0 | Đúng (18 171 519 byte) |
| Virut | 1 487 | 1 437 | 0 | Đúng (29 450 007 byte) |
| WSL | 84 | 82 | 0 | Đúng (24 666 byte) |
| l4 | 8 | 4 | 0 | Đúng |
| Scenario 5 toàn mạng | 163 588 | — (*) | — | Đúng (4 479 656 gói, 3 677 028 804 byte, 3 474 316 946 byte payload) |

(*) Với bản thu toàn mạng chỉ kiểm tra bảo toàn và miền giá trị, không so từng
flow với Wireshark, vì script so từng flow cần giữ thông tin của 4,5 triệu gói
trong bộ nhớ (lần chạy kiểu này ở C04-T02 đã bị dừng vì máy thiếu bộ nhớ). Kết
quả: không có thời lượng âm, mọi tỷ lệ nằm trong [0, 1], không có gói TCP/UDP nào
thiếu payload (header TCP luôn còn tới Data Offset), 11 507 flow có payload bằng 0.

Ở sogou chỉ 17 flow so được, vì phần lớn kết nối của sogou bị cắt bởi timeout
nhàn rỗi hoặc active timeout (docs/19, mục 7).

**Kiểm thử tự động** (18 ca mới, tổng 169 ca của dự án):
- `payload_len`: TCP và UDP có dữ liệu, TCP có option, gói bị cắt bởi snaplen vẫn
  tính theo ip_len, cắt trước Data Offset, phần đệm Ethernet không bị tính, mảnh
  đầu và mảnh sau, header mở rộng IPv6, ICMP, Data Offset sai.
- Đặc trưng: trao đổi kiểu HTTP, SYN không trả lời, flow chỉ có gói server, ICMP
  không có payload, payload không biết, sai thứ tự thời gian, thiếu thời điểm,
  mảnh IP, gói đọc từ byte thật; mọi đặc trưng có đơn vị và có trong CSV.

## 7. Giới hạn

- Tổng payload là tổng theo từng gói, nên gói TCP gửi lại được đếm hai lần. Đây là
  số byte đã đi trên mạng, không phải số byte ứng dụng nhận được; CICFlowMeter
  cũng tính như vậy.
- Gói TSO (Total Length bằng 0) lấy độ dài theo số byte đã bắt (QĐ-015).
- Đường hầm IP trong IP: độ dài là của gói ngoài cùng.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Đặc trưng (feature) | Một con số mô tả flow, là đầu vào của mô hình học máy |
| `ip_len`, `frame_len` | Độ dài gói theo header IP / độ dài cả khung trên dây, gồm header Ethernet |
| Payload | Phần dữ liệu ứng dụng trong gói TCP/UDP, không tính các header |
| Header, Data Offset | Phần đầu chứa thông tin điều khiển; Data Offset là trường cho biết header TCP dài bao nhiêu |
| Option TCP | Phần mở rộng tùy chọn của header TCP, làm header dài hơn 20 byte |
| snaplen | Số byte tối đa được lưu cho mỗi gói khi bắt |
| Mảnh IP, datagram | Gói IP lớn bị chia nhỏ / gói IP gốc trước khi chia |
| Forward / backward | Chiều client → server / chiều server → client |
| Tỷ lệ gửi/nhận, phần trong tổng | So sánh lượng dữ liệu hai chiều; dự án dùng phần của chiều forward trong tổng, từ 0 tới 1 |
| Vô hạn (Infinity), giá trị trống | Kết quả của phép chia cho 0, mô hình học máy không dùng được nếu không xử lý |
| Thời lượng (duration) | Khoảng thời gian từ gói đầu tới gói cuối của flow |
| Active timeout | Độ dài tối đa của một flow (120 giây); kết nối dài hơn bị cắt thành nhiều flow |
| CICFlowMeter, Down/Up Ratio | Công cụ tạo CSV của CIC-IDS2017; cột tỷ lệ số gói về / số gói đi của nó |
| Bảo toàn byte | Kiểm tra tổng byte của mọi flow bằng tổng byte của mọi gói: không mất, không trùng |
| TSO | Card mạng tự chia gói lớn khi gửi; bắt trên chính máy gửi thấy Total Length bằng 0 |
| Gói gửi lại (retransmission) | Gói TCP được gửi lại vì bên kia chưa xác nhận đã nhận |
| Quét cổng, SYN flood | Gửi gói tới nhiều cổng để dò / gửi rất nhiều SYN để làm nghẽn server |
