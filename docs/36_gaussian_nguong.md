# C06-T04 — Tính điểm bất thường và chọn ngưỡng trên validation

Mã nguồn: `GaussianDetector.score`, `choose_threshold`, `threshold_curve`, `attack_groups`,
`binary_metrics` trong `src/nids/gaussian.py`. Kiểm thử: `tests/test_gaussian.py`. Cấu hình:
mục `gaussian` trong `config/default.yaml`. Quyết định: QĐ-032 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

```bash
cd src
python -m nids.gaussian nguong ../output/features/cic17_monday ../output/features/cic17_wednesday \
    ../output/features/cic17_friday --out ../docs/hinh
```

Lệnh ghi `docs/hinh/gauss_nguong.json` và `gauss_nguong.png`. **Lệnh không đọc tập test.**

## 1. Điểm bất thường

Điểm của một cửa sổ là d² Mahalanobis (C06-T03). Cửa sổ có d² **lớn hơn ngưỡng** bị báo là
`anomaly`. Validation: 88 479 cửa sổ của cả ba ngày, trong đó 3 521 `anomaly` (4,0%). Mẫu `mo_ho`
không dùng.

Để biết mô hình bắt được loại tấn công nào, mỗi cửa sổ `anomaly` được gán về đợt tấn công theo
lịch nhãn (`attack_groups`): host là bên tấn công hoặc nạn nhân và cửa sổ chạm khung giờ. Thông
tin này chỉ dùng để báo cáo, không dùng khi học hay chọn ngưỡng.

## 2. Hai việc chọn trên validation

| Việc chọn | Ứng viên | Tiêu chí |
|---|---|---|
| Mẫu normal để fit | Chỉ train thứ Hai (88 929); normal của train cả ba ngày (252 221) | F1 trên validation tại ngưỡng đã chọn |
| Ngưỡng | Theo cách ở mục 3 | Chỉ dùng điểm và nhãn của validation |

## 3. Cách chọn ngưỡng

Ba cách được cài (`gaussian.threshold`):

| Cách | Ý nghĩa |
|---|---|
| `f1` | Ngưỡng cho F1 lớn nhất |
| **`f1_on_dinh` (chọn)** | Với mỗi ngưỡng t, lấy F1 **xấu nhất** khi ngưỡng lệch trong [t / 1,2; t × 1,2]; chọn t có giá trị đó lớn nhất |
| `fpr` | Giữ tỷ lệ báo động giả trên normal không quá `target_fpr` (1%) |

**Vì sao không dùng F1 lớn nhất:** trên validation, ngưỡng F1 lớn nhất (145,6) nằm **ngay mép
một vách**. Hình `docs/hinh/gauss_nguong.png` cho thấy: tăng ngưỡng lên khoảng 150 thì F1 rơi
từ 0,71 xuống 0,27. Lý do là cụm 2 355 cửa sổ bot có d² tụ quanh 125–150: ngưỡng hơi cao hơn là
mất gần hết bot. Ngưỡng đặt sát vách thì một thay đổi nhỏ của dữ liệu (ngày khác, lab) cũng đủ
làm kết quả sụp. `f1_on_dinh` chọn ngưỡng nằm trong vùng F1 phẳng, giữ F1 ổn định khi điểm số
lệch ±20%.

Không dùng ngưỡng theo lý thuyết χ²: đuôi d² dày hơn χ² rất nhiều (C06-T02), ngưỡng χ² 99% sẽ
báo động giả khoảng 5%.

## 4. Kết quả trên validation

| Fit trên | Cách | Ngưỡng | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|
| Train thứ Hai | F1 lớn nhất | 57,6 | 0,646 | 0,736 | 0,688 | 1,68% |
| Train thứ Hai | F1 ổn định | 69,5 | 0,664 | 0,698 | 0,681 | 1,46% |
| Normal cả ba ngày | F1 lớn nhất | 145,6 | 0,803 | 0,635 | 0,709 | 0,65% |
| **Normal cả ba ngày** | **F1 ổn định (chọn)** | **64,7** | **0,671** | **0,733** | **0,700** | **1,49%** |

Chọn **fit trên normal của train cả ba ngày, ngưỡng d² = 64,65.** Các ngưỡng cho F1 cách giá trị
lớn nhất không quá 0,02 nằm trong khoảng 51,5 – 139,5, và ngưỡng đã chọn nằm trong khoảng đó.

Thay đổi so với kế hoạch ban đầu (QĐ-028: Gaussian chỉ học trên thứ Hai): thêm mẫu normal của
thứ Tư, thứ Sáu giúp mô hình thấy được dao động bình thường giữa các ngày, F1 validation cao hơn
(0,700 so với 0,681). Vẫn không rò rỉ: chỉ dùng mẫu train.

Recall trên validation theo đợt tấn công, ở ngưỡng đã chọn:

| Đợt | Cửa sổ | Recall |
|---|---|---|
| DoS slowloris | 206 | 1,000 |
| DoS GoldenEye | 78 | 0,936 |
| Bot | 2 355 | 0,840 |
| DoS Hulk | 172 | 0,750 |
| PortScan | 50 | 0,680 |
| DDoS | 214 | 0,500 |
| DoS Slowhttptest | 192 | 0,281 |
| Heartbleed | 254 | **0,000** |

- **Heartbleed không bắt được:** d² chỉ 15–27, như HTTPS bình thường. Đây là tấn công ở tầng ứng
  dụng (đọc trộm bộ nhớ qua một kết nối TLS), lưu lượng không khác thường về số gói, số kết
  nối.
- **DDoS chỉ một nửa:** phía nạn nhân bị bắt hết; phía bên tấn công là địa chỉ NAT
  `172.16.0.1`, gom nhiều máy, nên trông như một máy có lưu lượng lớn bình thường (d² khoảng 31).
- **Slowhttptest thấp:** tấn công "chậm", mỗi kết nối gửi rất ít; trong cửa sổ 10 giây không
  khác nhiều so với bình thường.

## 5. Chống rò rỉ

- Mọi tham số mô hình (biến đổi, trung bình, hiệp phương sai) chỉ học trên mẫu normal của train.
- Phiên fit, cách chọn ngưỡng và ngưỡng chỉ dựa vào validation; lệnh `nguong` không đọc test.
- **Ghi chú trung thực:** khi chẩn đoán vì sao F1 lớn nhất nằm sát vách, đã có một lần xem kết quả
  test của cả hai cách chọn ngưỡng. Hai cách cho F1 test gần bằng nhau (0,730 và 0,733), nên con
  số test không quyết định lựa chọn. Lý do chọn `f1_on_dinh` là hình dạng đường F1 trên
  validation (mục 3).

## 6. Kiểm thử

Kiểm thử tự động (5 ca): Precision, Recall, F1, FPR từ bảng nhầm lẫn; ngưỡng F1 lớn nhất tách hai
nhóm điểm; ngưỡng theo FPR mục tiêu; ngưỡng ổn định lùi xa vách và vẫn có F1 cao; gán cửa sổ về
đợt tấn công (nhiều đợt khớp thì lấy đợt ngắn hơn).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Điểm bất thường | Con số cho biết mẫu khác bình thường bao nhiêu; ở đây là d² Mahalanobis |
| Ngưỡng | Mức điểm từ đó trở lên thì báo động |
| Validation | Tập dùng để chọn tham số và ngưỡng, không dùng để báo cáo kết quả cuối |
| Precision | Trong các cửa sổ bị báo động, tỷ lệ đúng là tấn công |
| Recall | Trong các cửa sổ tấn công thật, tỷ lệ bị báo động |
| F1 | Trung bình điều hòa của Precision và Recall |
| FPR (tỷ lệ báo động giả) | Tỷ lệ cửa sổ bình thường bị báo nhầm |
| Vách (trên đường F1) | Chỗ F1 đổi rất mạnh khi ngưỡng đổi chút ít |
| F1 ổn định | Ngưỡng có F1 tốt nhất trong trường hợp ngưỡng lệch ±20% |
| NAT | Thiết bị thay địa chỉ của nhiều máy bằng một địa chỉ chung |
| Tấn công tầng ứng dụng | Tấn công khai thác lỗi phần mềm, lưu lượng có thể trông bình thường |
| Rò rỉ (leakage) | Thông tin của test lọt vào lúc chọn mô hình, làm kết quả đẹp giả |
