# C04-T04 — Thống kê kích thước gói, inter-arrival time và cờ TCP

Mã nguồn: `src/nids/flow_features.py` (`RunningStats`, `PacketStats`,
`stat_features`), cộng dồn trong `FlowAssigner.add` của `src/nids/flows.py`.
Kiểm thử: `tests/test_flow_features.py`. Quyết định: QĐ-020 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md). Các đặc trưng cơ bản (số
gói, byte, thời lượng) ở [20_dac_trung_flow_co_ban.md](20_dac_trung_flow_co_ban.md).

```bash
python -m nids.flows data/pcap/<file>.pcap --csv output/flows.csv
```

## 1. Đặc trưng

Với mỗi nhóm gói, tính bốn số: nhỏ nhất (`_min`), lớn nhất (`_max`), trung bình
(`_mean`), độ lệch chuẩn (`_std`).

| Nhóm cột | Tính trên | Đơn vị |
|---|---|---|
| `pkt_len_*` | `ip_len` của mọi gói trong flow | byte |
| `fwd_pkt_len_*`, `bwd_pkt_len_*` | `ip_len` các gói chiều forward / backward | byte |
| `iat_*` | Khoảng cách thời gian giữa hai gói liên tiếp của flow | giây |
| `fwd_iat_*`, `bwd_iat_*` | Khoảng cách giữa hai gói liên tiếp **cùng chiều** | giây |
| `syn_count`, `fin_count`, `rst_count`, `psh_count`, `ack_count`, `urg_count`, `ece_count`, `cwr_count` | Số gói TCP có cờ đó bật | gói |

Tổng cộng 32 cột, thêm vào bảng flow sau các cột của C04-T03.

Ý nghĩa với ba module:
- **Kích thước:** quét cổng và SYN flood có gói nhỏ đều nhau (`pkt_len_std` gần
  0); tải trang web có gói backward lớn.
- **Inter-arrival time:** slowloris giữ kết nối bằng cách gửi rất chậm (`fwd_iat`
  lớn); flood gửi dày đặc (`iat_mean` rất nhỏ); beaconing botnet có khoảng cách đều
  (`iat_std` nhỏ so với `iat_mean`).
- **Cờ TCP:** nhiều `rst_count` so với số gói là dấu hiệu quét vào cổng đóng; quét
  kiểu FIN/Xmas/Null của Nmap có cờ lạ (FIN, URG, PSH không kèm ACK).

## 2. Công thức

- **Kích thước** dùng `ip_len` như các đặc trưng byte (QĐ-018), không dùng
  `frame_len`.
- **Độ lệch chuẩn** là của tổng thể, chia cho n chứ không chia n − 1:
  `std = sqrt(Σ(x − mean)² / n)`. Flow chỉ có một gói vẫn có `std = 0`, không trống.
- Tính **dần từng gói** bằng thuật toán Welford: mỗi nhóm chỉ giữ n, min, max,
  trung bình và tổng bình phương độ lệch. Bộ nhớ của một flow không tăng theo số
  gói, cần cho flow dài và cho chạy realtime.
- **Inter-arrival time** của n gói gồm n − 1 khoảng: `iat_i = ts_i − ts_(i−1)`, theo
  thứ tự gói tới. `fwd_iat` chỉ xét các gói forward, bỏ qua gói backward xen giữa;
  `bwd_iat` tương tự.
- **Cờ:** mỗi gói có cờ bật được đếm một lần cho cờ đó. Gói SYN+ACK được đếm vào cả
  `syn_count` và `ack_count`.

## 3. Trường hợp biên

| Trường hợp | Kết quả |
|---|---|
| Flow một gói (SYN quét không trả lời) | `pkt_len_*` có giá trị, `std = 0`; mọi cột `iat_*` trống |
| Một chiều không có gói (`bwd_packets = 0`) | `bwd_pkt_len_*`, `bwd_iat_*` trống |
| Một chiều có đúng một gói | `*_pkt_len_*` của chiều đó có giá trị; `*_iat_*` của chiều đó trống |
| File sai thứ tự thời gian | Khoảng âm được tính là 0. File donbot có 2, sogou 4, CIC thứ Hai 3 219, CIC thứ Sáu 7 085 gói như vậy |
| Gói không có thời điểm | Không tham gia khoảng cách; vẫn tính kích thước và cờ |
| Flow không phải TCP | Mọi cột cờ bằng 0 |
| Mảnh IP không mang header TCP | Tính kích thước và khoảng cách, không có cờ |
| Kết nối dài bị active timeout cắt (QĐ-017) | Mỗi đoạn tối đa 120 giây có thống kê riêng; khoảng cách giữa hai đoạn không tính vào đoạn nào |

**Giá trị trống** thay cho số 0 ở các cột `iat_*` và `*_pkt_len_*` khi không có dữ
liệu. Nếu ghi 0, mô hình sẽ hiểu nhầm "flow một gói" là "các gói tới cùng một lúc".
Chặng 5 xử lý cột trống khi tiền xử lý, chỉ fit trên train. CICFlowMeter ghi 0 ở
các trường hợp này.

## 4. Khác với CICFlowMeter

| Dự án | CICFlowMeter | Khác biệt |
|---|---|---|
| `fwd_pkt_len_*` | Fwd Packet Length Min/Max/Mean/Std | CIC tính trên payload, dự án trên `ip_len` |
| `iat_*`, `fwd_iat_*`, `bwd_iat_*` | Flow IAT, Fwd IAT, Bwd IAT (Min/Max/Mean/Std) | CIC tính bằng micro giây và ghi 0 khi không có khoảng nào |
| `pkt_len_std` | Packet Length Std | CIC dùng độ lệch chuẩn mẫu (chia n − 1) |
| `syn_count` … `cwr_count` | SYN Flag Count … | CIC có cột Fwd/Bwd PSH Flags riêng; dự án đếm chung hai chiều |

## 5. Kiểm tra

**So với Wireshark.** Script tạm của C04-T03 được mở rộng. Với mỗi flow ứng đúng
một stream TCP/UDP, script tính lại 39 cột: số gói, byte, payload, thời lượng và 32
cột thống kê. Kích thước lấy từ `ip.len`, thời điểm từ `frame.time_epoch`, cờ từ
`tcp.flags`; trung bình và độ lệch chuẩn tính bằng module `statistics` của Python.
Sai số cho phép là 10⁻⁶ (tương đối).

| File | Flow so được | Lệch |
|---|---|---|
| donbot | 4 560 | 0 |
| sogou | 17 | 0 |
| Virut | 1 437 | 0 |
| WSL | 82 | 0 |
| l4 (tự tạo) | 4 | 0 |

Để chắc script không bỏ sót, đã cố ý cộng 1 giây vào `iat_mean` của dự án: script
báo lệch ở cả 82/82 flow WSL.

**Kiểm thử tự động** (11 ca mới, tổng 187 ca của dự án): Welford so với
`statistics.fmean`/`pstdev` trên 500 giá trị ngẫu nhiên; một giá trị có std = 0;
kích thước, khoảng cách và cờ theo từng chiều của một trao đổi kiểu HTTP; flow một
gói; sai thứ tự thời gian; UDP không có cờ; thiếu thời điểm; mọi cột có đơn vị và
có trong CSV.

## 6. Giới hạn

- Khoảng cách dùng thời điểm do máy bắt gói ghi lại. Trên PCAP CIC có hàng nghìn
  gói sai thứ tự (mục 3), nên `iat_min` có thể bằng 0 do sai thứ tự chứ không phải
  do gói tới cùng lúc.
- Chưa có đặc trưng "thời gian hoạt động / nghỉ" (Active/Idle của CICFlowMeter) và
  tốc độ (byte/giây); chưa cần cho ba module. Nếu cần thì thêm ở bước chọn đặc trưng.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Inter-arrival time (IAT) | Khoảng thời gian giữa hai gói tới liên tiếp |
| Trung bình, độ lệch chuẩn | Giá trị điển hình / mức độ phân tán quanh giá trị đó; độ lệch chuẩn 0 nghĩa là mọi giá trị bằng nhau |
| Độ lệch chuẩn tổng thể / mẫu | Chia cho n / chia cho n − 1; khác nhau nhiều khi n nhỏ |
| Welford | Cách tính trung bình và độ lệch chuẩn dần từng giá trị mà không cần giữ lại các giá trị |
| Cờ TCP: SYN, FIN, RST, PSH, ACK, URG, ECE, CWR | Bit trong header TCP: mở kết nối, đóng, hủy, đẩy dữ liệu ngay, xác nhận, khẩn, và hai cờ báo nghẽn mạng |
| Quét FIN/Xmas/Null | Kiểu quét Nmap gửi gói có tổ hợp cờ lạ để dò cổng mà không mở kết nối |
| Beaconing | Máy nhiễm gọi về máy chủ điều khiển theo chu kỳ đều |
| Slowloris, flood | DoS giữ kết nối bằng cách gửi rất chậm / gửi ồ ạt thật nhiều gói |
| Giá trị trống | Ô không có số vì không có dữ liệu để tính; khác với số 0 |
| Fit trên train | Tham số tiền xử lý (ví dụ giá trị điền vào ô trống) chỉ được học từ tập huấn luyện |
| Active timeout | Độ dài tối đa của một flow; kết nối dài hơn bị cắt thành nhiều đoạn |
| CICFlowMeter | Công cụ tạo CSV đặc trưng flow của CIC-IDS2017 |
