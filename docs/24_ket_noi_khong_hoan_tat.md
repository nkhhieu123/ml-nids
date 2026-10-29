# C04-T07 — Tỷ lệ kết nối không hoàn tất sau thời gian quan sát

Mã nguồn: `src/nids/window_features.py` (`attempt_outcome`, các cột `*_out`, `*_in`
mới), thời điểm bắt tay ghi trong `src/nids/flows.py`, thời gian chờ trả cửa sổ
trong `src/nids/host_windows.py`. Kiểm thử: `tests/test_window_features.py`,
`tests/test_host_windows.py`. Quyết định: QĐ-023 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

```bash
python -m nids.window_features data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/windows.csv
```

Quét cổng và SYN flood để lại nhiều kết nối TCP **không hoàn tất**: gửi SYN nhưng
không bắt tay xong. Task này đếm các lần thử kết nối trong mỗi cửa sổ host và xếp
loại từng lần sau một **thời gian quan sát** cố định.

## 1. Lần thử kết nối

Một lần thử là một flow TCP:
- mở bằng gói SYN không ACK của client (`direction_basis = syn`, QĐ-016);
- không phải phần tiếp nối (`continuation = 0`, QĐ-017).

Flow bắt giữa chừng hoặc mở bằng SYN+ACK không được tính, vì không thấy lúc bắt
đầu. SYN gửi lại cùng số thứ tự vẫn là một lần thử; SYN với số thứ tự mới là lần
thử mới (QĐ-017). Lần thử được tính cho các cửa sổ chứa gói SYN đầu, cho client
(`*_out`) và cho server (`*_in`).

## 2. Xếp loại sau thời gian quan sát

Thời gian quan sát **T = 3 giây** (`flow.handshake_observe_s` trong
`config/default.yaml`, tạm thời). Chỉ xét các gói tới trong vòng T kể từ SYN đầu:

| Loại | Điều kiện trong vòng T | Ví dụ |
|---|---|---|
| `hoan_tat` | Server gửi SYN+ACK, sau đó client gửi gói ACK (không SYN, không RST) | Kết nối bình thường |
| `do_dang` | Có SYN+ACK nhưng client không ACK trong T | `nmap -sS` gặp cổng mở (client gửi RST); client chậm |
| `bi_tu_choi` | Không có SYN+ACK; server gửi RST | Cổng đóng |
| `khong_phan_hoi` | Không có SYN+ACK lẫn RST | Tường lửa chặn, máy không tồn tại, SYN flood làm server quá tải |

Không hoàn tất = ba loại sau. Tỷ lệ = số không hoàn tất / số lần thử.

**Vì sao 3 giây.** Lần gửi lại SYN đầu tiên của TCP là sau 1 giây (RFC 6298); bản
cũ là 3 giây. Trong mạng lab và mạng nội bộ của CIC, thời gian trả lời chỉ vài mili
giây, nên 3 giây đủ dư cho kết nối bình thường mà vẫn kết luận sớm. Giá trị này
chỉnh trên tập validation như các tham số thời gian khác (QĐ-006).

**Không dùng dữ liệu tương lai.** Kết quả chỉ phụ thuộc các gói trong T giây sau
SYN: gói SYN+ACK tới sau T không làm lần thử thành `hoan_tat`. Vì vậy cửa sổ
`[start, end)` phải **chờ thêm T** rồi mới trả ra, tức khi "bây giờ" (thời điểm gói
lớn nhất đã thấy) ≥ `end + T`. Lần thử có SYN sát cuối cửa sổ khi đó đã đủ thời
gian quan sát. Mọi cột khác của cửa sổ vẫn chỉ dùng gói trong `[start, end)`.

## 3. Đặc trưng

| Cột | Ý nghĩa | Đơn vị |
|---|---|---|
| `tcp_attempts_out` | Số lần thử host mở | lần thử |
| `incomplete_out` | Số lần thử host mở không hoàn tất | lần thử |
| `no_reply_out`, `rejected_out`, `half_open_out` | Tách theo loại | lần thử |
| `incomplete_ratio_out` | `incomplete_out / tcp_attempts_out`; trống nếu không có lần thử | tỷ lệ 0–1 |
| `tcp_attempts_in` | Số lần thử tới host | lần thử |
| `incomplete_in` | Số lần thử tới host không hoàn tất | lần thử |
| `incomplete_ratio_in` | `incomplete_in / tcp_attempts_in`; trống nếu không có | tỷ lệ 0–1 |

Phía `out` cho thấy máy đang quét; phía `in` cho thấy máy đang bị quét hoặc bị SYN
flood.

## 4. Chỉ là dấu hiệu nghi vấn

Theo nghiệm thu của Chặng 4, **SYN thiếu phản hồi là dấu hiệu nghi vấn, không tự
động gán nhãn scan**. Các cột ở đây là đặc trưng cho mô hình; nhãn vẫn gán theo nhật
ký lần chạy và lịch tấn công (Chặng 5). Dữ liệu thật cho thấy vì sao không được gán
nhãn chỉ từ tỷ lệ này. Trên đoạn PCAP CIC thứ Sáu 14:51–14:57 (port scan), mạng
192.168.10.0/24:

| Host | Lần thử trong một cửa sổ 10 giây (cửa sổ nhiều nhất) | Tỷ lệ không hoàn tất |
|---|---|---|
| `172.16.0.1` (bên quét, sau NAT) | 7 977 ra | 0,995 (7 887 bị từ chối, 50 không trả lời) |
| `192.168.10.50` (nạn nhân) | 7 981 vào | 0,999 |
| Các host bình thường | 629 cửa sổ có lần thử | Trung vị 0, nhưng 97 cửa sổ có tỷ lệ trên 0,5 |

Host bình thường cũng có cửa sổ với tỷ lệ cao: vài lần thử tới máy ngoài Internet
không trả lời là đủ. Khác biệt nằm ở **số lần thử** đi kèm tỷ lệ, nên mô hình cần cả
hai cột.

## 5. Kiểm tra

**Tính lại từ Wireshark.** Một script tạm đọc từng gói TCP bằng tshark. Với mỗi
`tcp.stream` mở bằng SYN, script tự ghi thời điểm SYN+ACK của server, ACK của client
và RST của server. Sau đó xếp loại theo bảng ở mục 2 với T = 3 giây, cộng vào cửa sổ
vét cạn và so 7 cột đếm với CSV của dự án:

| File | Cửa sổ so | Lệch | Tổng lần thử (cộng mọi cửa sổ) |
|---|---|---|---|
| CIC thứ Sáu, đoạn port scan (host `172.16.0.1`, `192.168.10.50`) | 294 | 0 | 697 950 ra, 698 110 vào |
| donbot (mọi host) | 26 937 | 0 | 22 655 |
| WSL (mọi host) | 86 | 0 | 310 |

Mỗi lần thử nằm trong 5 cửa sổ chồng nhau nên tổng cộng mọi cửa sổ lớn gấp 5 lần
số lần thử thật.

**Kiểm thử tự động** (8 ca mới, tổng 220 ca của dự án): bốn loại trong một cửa sổ
(cả phía nạn nhân); trả lời sau T bị bỏ qua và đổi khi T dài hơn; ACK sau hạn là
`do_dang`; không có lần thử thì tỷ lệ trống; flow bắt giữa chừng và phần tiếp nối
không phải lần thử; cửa sổ chờ đủ T mới trả ra; thời gian chờ của `HostWindower`;
gói trễ sau khoảng lặng vẫn giữ thứ tự cửa sổ.

## 6. Giới hạn

- Chỉ TCP. Quét UDP (`nmap -sU`) nhận về ICMP port unreachable. Dấu hiệu này đã có ở
  `dst_ports` và entropy (C04-T06), chưa có tỷ lệ riêng.
- Tường lửa gửi RST thay cho máy đích thì bị tính là `bi_tu_choi` như cổng đóng.
- Cửa sổ trả ra chậm thêm 3 giây, tức cảnh báo realtime chậm nhất `10 + 3` giây sau
  gói đầu của cửa sổ.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Bắt tay ba bước | Cách TCP mở kết nối: client gửi SYN, server trả SYN+ACK, client gửi ACK |
| Lần thử kết nối | Một flow TCP mở bằng SYN của client |
| Không hoàn tất | Lần thử không đi hết bắt tay ba bước trong thời gian quan sát |
| Thời gian quan sát | Khoảng chờ trả lời sau SYN trước khi kết luận lần thử có hoàn tất hay không |
| Half-open (`do_dang`) | Server đã đồng ý (SYN+ACK) nhưng client không gửi ACK |
| RST | Cờ TCP hủy kết nối; server gửi khi cổng đóng |
| SYN flood | Gửi rất nhiều SYN để server giữ quá nhiều kết nối dở dang |
| `nmap -sS`, `nmap -sU` | Quét SYN (không hoàn tất bắt tay) / quét UDP của Nmap |
| RFC 6298 | Tiêu chuẩn quy định thời gian chờ gửi lại của TCP |
| Dữ liệu tương lai | Gói tới sau thời điểm đang xét; dùng nó là gian lận vì realtime không có |
| Dấu hiệu nghi vấn | Đặc trưng gợi ý có thể là tấn công, không phải kết luận hay nhãn |
| ICMP port unreachable | Gói báo cổng UDP không mở |
