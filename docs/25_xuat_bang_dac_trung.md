# C04-T08 — Xuất bảng đặc trưng cùng schema và metadata

Mã nguồn: `src/nids/feature_export.py` (`export`, `read_table`, `table_schemas`).
Kiểm thử: `tests/test_feature_export.py`. Quyết định: QĐ-024 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

```bash
python -m nids.feature_export data/pcap/<file>.pcap --net 192.168.10.0/24 --out output/features
```

Lệnh đọc PCAP **một lượt**: ghép flow (C04-T01–T04) và lập cửa sổ host (C04-T05–T07)
cùng lúc, ghi bảng ra đĩa ngay khi flow và cửa sổ kết thúc. Bộ nhớ không tăng theo
độ dài file, nên chạy được với PCAP CIC 13 GB. Đây là đầu vào của Chặng 5 (gán nhãn,
chia dữ liệu, tiền xử lý).

## 1. Bốn file kết quả

| File | Nội dung |
|---|---|
| `<tên>.flows.csv` | Một dòng một flow: 14 cột định danh và ngữ cảnh, 12 đặc trưng cơ bản (C04-T03), 32 đặc trưng thống kê (C04-T04) |
| `<tên>.windows.csv` | Một dòng một cặp (host, cửa sổ 10 giây): 9 cột của C04-T05 và 16 đặc trưng của C04-T06, T07 |
| `<tên>.schema.json` | Mô tả từng cột của hai bảng (mục 2) |
| `<tên>.meta.json` | Bảng được tạo từ đâu, như thế nào (mục 3) |

`<tên>` mặc định là tên file PCAP; đổi bằng `--name`. Dòng của bảng flow theo thứ tự
flow **kết thúc** (ghi ngay khi kết thúc). Muốn theo thứ tự thời gian thì sắp theo
`first_ts` hoặc `first_index`. Dòng của bảng cửa sổ theo `window_start` tăng dần.

## 2. Schema

Mỗi cột có:

| Trường | Ý nghĩa |
|---|---|
| `ten` | Tên cột, đúng thứ tự trong CSV |
| `kieu` | `int`, `float`, `str`, hoặc `thoi_diem` (giây từ epoch UTC, chuỗi 9 chữ số thập phân) |
| `don_vi` | gói, byte, giây, bit, tỷ lệ 0–1, ... |
| `vai_tro` | Dùng cột vào việc gì (bảng dưới) |
| `co_the_trong` | Ô có thể trống không. Ô trống là **không có dữ liệu để tính**, khác 0 |
| `mo_ta` | Giải thích ngắn |

**Vai trò** cho Chặng 5 biết cột nào được đưa vào mô hình:

| Vai trò | Cột | Dùng |
|---|---|---|
| `dac_trung` | Mọi đặc trưng của C04-T03, T04, T06, T07; số gói, byte vào/ra của cửa sổ | Đưa vào mô hình |
| `dinh_danh` | IP, cổng client và server, chỉ số packet, thời điểm, đầu và cuối cửa sổ | Chỉ để gán nhãn, chia train/test theo thời gian, truy vết cảnh báo. **Không** đưa vào mô hình: mô hình sẽ học thuộc "IP này, cổng này là tấn công" (docs/06, mục 6) |
| `ngu_canh` | `ip_version`, `protocol`, `continuation`, `end_reason` | Thuộc tính phân loại; chỉ dùng khi chứng minh được không rò rỉ nhãn |
| `kiem_tra` | `direction_basis`, `fragments_attached`, `payload_unknown` | Kiểm tra chất lượng dữ liệu, không dùng cho mô hình |

Schema được sinh từ cùng các bảng tên cột mà mã dùng để tính đặc trưng
(`BASIC_FEATURES`, `STAT_FEATURES`, `WINDOW_FEATURES`). Thêm cột mà quên mô tả thì
lệnh xuất báo lỗi ngay. Phiên bản schema hiện là `1.0`; đổi cột thì phải tăng phiên
bản.

## 3. Metadata

| Mục | Nội dung |
|---|---|
| `phien_ban_schema`, `tao_luc_utc`, `thoi_gian_chay_s` | Phiên bản schema, lúc tạo, thời gian chạy |
| `nguon` | Đường dẫn và kích thước PCAP; SHA-256 lấy từ manifest (`nguon_ma_bam: manifest:<id>`), hoặc tính lại với `--hash` |
| `ma_nguon` | Commit git của mã đã dùng và có sửa chưa commit không (`co_sua_chua_commit`); phiên bản Python |
| `tham_so` | Mọi tham số flow (QĐ-006, QĐ-016, QĐ-017), kích thước và bước cửa sổ, thời gian quan sát (QĐ-023), dải mạng `--net` |
| `bang` | Tên file và số dòng của hai bảng |
| `thong_ke` | Thống kê gói bỏ qua, flow (lý do kết thúc, cơ sở xác định chiều, mảnh IP) và cửa sổ (gói trễ) |

Nhờ đó mọi bảng đặc trưng dùng để huấn luyện đều truy ngược được về đúng file PCAP,
đúng tham số và đúng phiên bản mã (yêu cầu B12: huấn luyện và realtime dùng cùng cách
tính). Bảng tạo từ mã có sửa chưa commit thì `co_sua_chua_commit = true`; không nên
dùng bảng đó cho kết quả cuối.

## 4. Đọc lại bảng

```python
from nids.feature_export import read_table
flows = read_table("output/features/cic17_wednesday.flows.csv")
```

`read_table` đọc schema cùng tên, đổi mỗi ô sang đúng kiểu (ô trống thành `None`).
Hàm **báo lỗi** khi phiên bản schema khác, cột không khớp schema (thiếu, thừa, sai thứ
tự), hoặc ô trống ở cột không được trống. Chặng 5 dùng hàm này thay vì đọc CSV trực
tiếp.

## 5. Kiểm tra

| Kiểm tra | Kết quả |
|---|---|
| Bảng xuất ra giống từng dòng bảng của `nids.flows` và `nids.window_features` (so như tập hợp) | donbot: 4 588 flow, 26 937 cửa sổ; WSL: 84 flow, 86 cửa sổ: giống hết |
| Đoạn CIC thứ Sáu 14:51–14:57 (344 181 gói), mạng 192.168.10.0/24 và 172.16.0.1 | 143 900 flow, 2 061 cửa sổ, 30,5 giây; `read_table` đọc lại không lỗi; tổng gói trong bảng flow bằng số gói đã đọc |
| PCAP CIC thứ Tư đầy đủ (13,4 GB) | Xem mục 6 |

**Kiểm thử tự động** (8 ca mới, tổng 228 ca của dự án): schema có mọi cột đúng thứ
tự, vai trò và kiểu hợp lệ; IP, cổng, thời điểm không phải đặc trưng; xuất đủ bốn
file với metadata (mã băm, số dòng, tham số); đọc lại đúng kiểu, ô trống thành
`None`; từ chối bảng đổi tên cột, ô bắt buộc bị trống, phiên bản schema khác; dòng
lệnh.

## 6. Chạy trên CIC thứ Tư

Ngày 29/10/2026, toàn bộ `Wednesday-workingHours.pcap` (13,4 GB, 13 788 878 gói), cửa
sổ cho host trong `192.168.10.0/24` và `172.16.0.0/24`:

| | Kết quả |
|---|---|
| Thời gian chạy | 24 phút (1 436 giây), một lượt đọc |
| Bảng flow | 506 163 dòng, 179 MB (bằng số flow của lần khảo sát ở docs/06, mục 7.2) |
| Bảng cửa sổ | 163 431 dòng, 24 MB; 0 gói trễ |
| Mã băm nguồn | Lấy từ manifest (`manifest:cic17-wed-pcap`) |
| Đọc lại bằng `read_table` | 39 giây, không lỗi; tổng `packets` của bảng flow = 13 732 433 = số gói IP đã đọc |

Cửa sổ của web server `192.168.10.50` (giờ địa phương UTC−3):

| Thời điểm | `packets_in` | `new_conn_in` | `src_hosts` | `incomplete_ratio_in` |
|---|---|---|---|---|
| 09:30, bình thường | 50 | 1 | 1 | 0 |
| 10:00, slowloris | 235 | 15 | 1 | 0,4 |
| 10:50, Hulk | 19 412 | 2 508 | 1 | 0,03 |

Hulk mở hàng nghìn kết nối hoàn tất (tỷ lệ không hoàn tất thấp), slowloris mở ít kết
nối và giữ lâu. Hai kiểu DoS tầng HTTP khác hẳn SYN flood, kiểu sẽ có tỷ lệ không hoàn
tất cao. `src_hosts = 1` vì mọi traffic tấn công đi qua NAT `172.16.0.1`.

Bảng này được tạo trước khi commit C04-T08 nên metadata ghi `co_sua_chua_commit: true`.
Các bảng dùng cho kết quả cuối phải tạo lại từ mã đã commit.

## 7. Giới hạn

- CSV không nén; bảng flow của một ngày CIC khoảng vài trăm MB. Có thể chuyển sang
  định dạng cột (Parquet) ở Chặng 5 nếu cần đọc nhanh.
- Hai bảng tách rời. Bảng cửa sổ không trỏ tới flow cụ thể; gán nhãn cửa sổ theo
  host và khung giờ (Chặng 5).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Bảng đặc trưng | Bảng mỗi dòng một mẫu (flow hoặc cửa sổ host), mỗi cột một đặc trưng; đầu vào của mô hình |
| Schema | Mô tả cấu trúc bảng: tên, kiểu, đơn vị, ý nghĩa của từng cột |
| Metadata | Thông tin về bảng: tạo từ đâu, khi nào, bằng tham số và phiên bản mã nào |
| Vai trò cột | Cột dùng làm đặc trưng, định danh, ngữ cảnh hay kiểm tra |
| Định danh | Cột cho biết mẫu là của ai, lúc nào (IP, cổng, thời điểm); không phải hành vi |
| Rò rỉ nhãn | Mô hình nhìn thấy thông tin gắn trực tiếp với nhãn, cho kết quả đẹp giả |
| Học thuộc địa chỉ | Mô hình nhớ "IP này là kẻ tấn công" thay vì học hành vi |
| Commit git | Một phiên bản mã đã lưu, có mã định danh duy nhất |
| Epoch UTC | Mốc 00:00:00 ngày 1/1/1970 giờ quốc tế |
| Parquet | Định dạng file bảng theo cột, nén tốt, đọc nhanh hơn CSV |
| B12 | Yêu cầu huấn luyện và realtime dùng cùng cách tính đặc trưng (docs/01) |
