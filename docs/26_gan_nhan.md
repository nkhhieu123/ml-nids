# C05-T01 — Ghép nhãn từ nguồn và metadata

Mã nguồn: `src/nids/labeling.py`. Nguồn nhãn: `config/label_schedule.csv`. Kiểm thử:
`tests/test_labeling.py`. Quyết định: QĐ-025 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

```bash
python -m nids.labeling output/features/cic17_wednesday.flows.csv
```

Lệnh ghi `<tên>.flows.labels.csv` (và `<tên>.windows.labels.csv` nếu có bảng cửa sổ,
xem [28_nhan_cua_so.md](28_nhan_cua_so.md)), nối với bảng đặc trưng bằng khóa
`first_index` (flow) hoặc (`host`, `window_start`) (cửa sổ). Bảng đặc trưng không bị
sửa.

## 1. Nguồn nhãn: lịch tấn công

Theo QĐ-009 và QĐ-010, nhãn của đồ án gán **theo lịch tấn công và địa chỉ IP**, không
lấy cột nhãn của CSV CIC (CSV có lỗi nhãn, docs/06 mục 6 và 7.5). Lịch nằm ở
`config/label_schedule.csv`, mỗi dòng một đợt tấn công:

| Cột | Ý nghĩa |
|---|---|
| `id` | Mã đợt, ghi vào `rule_id` của mẫu khớp |
| `ngay`, `bat_dau`, `ket_thuc`, `utc_offset_h` | Ngày và khung giờ **địa phương** theo lịch gốc, độ lệch múi giờ. `ket_thuc` là phút cuối, tính hết phút đó |
| `nhan_goc` | Nhãn của nguồn (ví dụ `DoS Hulk`) |
| `nhan_attack` | Nhãn đồ án: `dos`, `port_scan`, hoặc `loai` (tấn công bị loại khỏi phân loại) |
| `ben_tan_cong`, `nan_nhan` | IP **như thấy trong PCAP** (sau NAT), nhiều IP cách nhau bằng `;` |
| `cong_nan_nhan` | Cổng dịch vụ bị tấn công phía nạn nhân (trống: mọi cổng) |
| `khoi` | Khối thời gian dùng khi chia dữ liệu (C05-T04); trống với đợt bị loại |

Lịch CIC-IDS2017 (9 dòng, giờ UTC−3, docs/06 mục 7.3):

| Đợt | Giờ địa phương | Cặp IP | `nhan_attack` |
|---|---|---|---|
| DoS slowloris, Slowhttptest, Hulk, GoldenEye (thứ Tư) | 09:47–10:10, 10:14–10:35, 10:43–11:00, 11:10–11:23 | `172.16.0.1` ↔ `192.168.10.50`:80 | `dos` |
| Heartbleed (thứ Tư) | 15:12–15:32 | `172.16.0.1` ↔ `192.168.10.51`:444 | `loai` |
| Port scan, tường lửa bật / tắt (thứ Sáu) | 13:55–14:35, 14:51–15:29 | `172.16.0.1` ↔ `192.168.10.50` (mọi cổng) | `port_scan` |
| DDoS LOIT (thứ Sáu) | 15:56–16:16 | `172.16.0.1` ↔ `192.168.10.50`:80 | `loai` |
| Botnet ARES (thứ Sáu) | Cả ngày | `205.174.165.73` ↔ 5 máy bot | `loai` |

- Các đợt bị loại khỏi phân loại (QĐ-009) **vẫn phải có trong lịch**: nếu không, flow của
  chúng sẽ thành `benign`, làm bẩn lớp bình thường. Với module anomaly chúng vẫn là
  `anomaly`.
- IP các máy bot lấy từ CSV có nhãn buổi sáng thứ Sáu (lịch gốc không ghi). Bot gọi về
  máy điều khiển tới khoảng 13:00, muộn hơn khung 10:02–11:02 của lịch, nên đợt này áp
  cho cả ngày.
- Dữ liệu lab sau này dùng cùng định dạng: mỗi dòng lấy từ nhật ký lần chạy.

## 2. Quy tắc ghép

Một mẫu có hai đầu (a, b) và khoảng thời gian [đầu, cuối] (flow: `first_ts`, `last_ts`).
Với mỗi đợt:
- **Cặp IP**: một đầu thuộc `ben_tan_cong`, đầu kia thuộc `nan_nhan`, theo chiều bất
  kỳ (gói trả lời của nạn nhân cũng thuộc tấn công). Nếu đợt có `cong_nan_nhan`, phía
  nạn nhân phải dùng đúng cổng đó.
- **Thời gian**: khoảng của mẫu chạm khung giờ đã nới `tolerance_s` = 60 giây mỗi đầu
  (`labeling.tolerance_s`). Lịch CIC khớp dữ liệu tới phút, nên nới 1 phút đủ bắt lượt
  quét đầu và cuối mà không lan sang đợt khác (các đợt cách nhau ít nhất 3 phút).

Kết quả mỗi mẫu:

| `label_status` | Khi nào | `label_attack` | `label_anomaly` |
|---|---|---|---|
| `khop` | Khớp một đợt `dos`/`port_scan` | nhãn của đợt | `anomaly` |
| `loai` | Khớp một đợt bị loại | trống | `anomaly` |
| `mo_ho` | Đúng cặp IP của một đợt, cùng ngày, nhưng ngoài mọi khung giờ; hoặc chạm hai đợt khác nhãn (`rule_id = nhieu_quy_tac`) | trống | trống |
| `khong_khop` | Không thuộc trường hợp nào ở trên | `benign` | `normal` |

"Cùng ngày" là 00:00–24:00 giờ địa phương của ngày trong lịch. Flow giữa `172.16.0.1`
và `192.168.10.50` vào thứ Hai (không có đợt nào) là `khong_khop`.

Mẫu `mo_ho` không được đoán nhãn: có thể là thử nghiệm của bên tấn công ngoài lịch,
cũng có thể là traffic thường đi qua NAT. Chặng sau bỏ chúng khỏi huấn luyện và đánh
giá, và báo số lượng (C05-T02).

## 3. Kết quả trên CIC-IDS2017

Bảng flow thứ Tư (xuất từ commit `84640e3`, ngày 29/10/2026; thứ Sáu và thứ Hai bổ sung
ở [27_bao_cao_nhan.md](27_bao_cao_nhan.md)):

| `label_status` | Flow | Gói |
|---|---|---|
| `khong_khop` (benign) | 325 096 | 11 242 469 |
| `khop` (dos) | 180 768 | 2 439 842 |
| `mo_ho` | 288 | 826 |
| `loai` (Heartbleed) | 11 | 49 296 |

| Đợt | Flow | Gói |
|---|---|---|
| Hulk | 159 014 | 2 246 818 |
| GoldenEye | 8 786 | 106 177 |
| slowloris | 6 997 | 47 591 |
| Slowhttptest | 5 971 | 39 256 |
| Heartbleed | 11 | 49 296 |

**Vì sao cần cột cổng.** Lần chạy đầu (chưa có `cong_nan_nhan`) có 2 616 flow mơ hồ:
2 322 trong số đó là `192.168.10.51` gọi HTTPS (cổng 443) tới `172.16.0.1` suốt cả ngày,
trùng cặp IP với Heartbleed. Heartbleed chỉ nhắm cổng 444 của `.51`; thêm cổng vào lịch
thì còn 288 flow mơ hồ, và mức đồng ý với CSV CIC tăng từ 98,0% lên 99,0%.

**288 flow mơ hồ còn lại** là traffic giữa `172.16.0.1` và nạn nhân nằm ngay ngoài khung
giờ: 150 flow lúc 11:06–11:07 giờ địa phương (giữa Hulk và GoldenEye; CSV CIC ghi Hulk
kéo tới 11:07), 127 flow lúc 10:37 (giữa Slowhttptest và Hulk), vài flow buổi chiều. Đó
là đuôi của các đợt tấn công vượt lịch; không gán nhãn vì lịch không xác nhận.

Lúc xuất bảng, metadata ghi `co_sua_chua_commit: true` vì các module Chặng 5 và ba mục
cấu hình mới (`labeling`, `split`, `preprocess`) chưa commit. Lệnh xuất không đọc các
mục đó; số flow và số cửa sổ giống hệt lần xuất trước (506 163 và 163 431).

## 4. Kiểm thử

Kiểm thử tự động (`tests/test_labeling.py`, phần C05-T01, 10 ca): đổi giờ địa phương sang
UTC và tính hết phút cuối; từ chối nhãn lạ; lịch của dự án đọc được (9 đợt); bốn trạng
thái trong một bảng, cả chiều ngược; cổng nạn nhân (trường hợp `.51` ở trên); nới khung
giờ; flow dài chạm hai đợt khác nhãn; ngày khác là bình thường; dòng lệnh ghi file nhãn
đúng cột.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Gán nhãn | Ghi cho mỗi mẫu biết nó là bình thường hay loại tấn công nào |
| Lịch tấn công | Danh sách các đợt tấn công: lúc nào, ai tấn công ai |
| Metadata | Thông tin đi kèm dữ liệu, ở đây là lịch và IP để suy ra nhãn |
| Cặp IP tấn công | Hai địa chỉ bên tấn công và nạn nhân của một đợt |
| Nới khung giờ (tolerance) | Mở rộng khung giờ thêm một khoảng mỗi đầu để bù sai lệch đồng hồ, làm tròn phút |
| NAT | Tường lửa thay địa chỉ thật bằng địa chỉ của nó; ở CIC mọi tấn công hiện là `172.16.0.1` |
| Mơ hồ | Mẫu không đủ căn cứ để gán nhãn chắc chắn |
| `loai` | Tấn công không thuộc ba lớp phân loại (DDoS, Heartbleed, botnet); vẫn là bất thường |
| UTC−3 | Giờ địa phương nơi CIC thu dữ liệu, chậm hơn giờ quốc tế 3 tiếng |
