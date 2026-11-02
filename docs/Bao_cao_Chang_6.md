# Báo cáo Chặng 6 — Gaussian anomaly detection

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 02/11/2026 |
| Trạng thái | Xong 6/6 task |
| Chặng trước | [Bao_cao_Chang_5.md](Bao_cao_Chang_5.md) |

## 1. Tóm tắt

Chặng 6 xây module **phát hiện bất thường**: học phân bố của cửa sổ host bình thường bằng một
Gaussian đa biến, rồi báo các cửa sổ nằm quá xa phân bố đó.

```
Cửa sổ host ─> chọn 14 đặc trưng ─> Yeo-Johnson / log ─> Gaussian (μ, Σ Ledoit-Wolf) ─> d² ─> so ngưỡng ─> anomaly?
(Chặng 5)      (T01, train)          (T02, train)          (T03, normal của train)        (T04, validation)
                                                                                             đánh giá test (T05), lưu (T06)
```

Kết quả trên **test** CIC-IDS2017 (105 361 cửa sổ, 5,1% tấn công), ngưỡng chọn trên validation:

| Precision | Recall | F1 | Tỷ lệ báo động giả | AUC |
|---|---|---|---|---|
| 0,733 | 0,727 | 0,730 | 1,42% | 0,977 |

**Tiêu chí nghiệm thu:** nạp lại mô hình để dự đoán được; có kết quả test thật và phân tích hạn
chế của giả định Gaussian.

| Tiêu chí | Đáp ứng |
|---|---|
| Nạp lại mô hình để dự đoán | `models/gaussian_windows.joblib` chứa biến đổi, Gaussian và ngưỡng. Nạp lại ở tiến trình khác cho **đúng cùng** kết quả test; lệnh `du-doan` chạy trên bảng chưa nhãn (mục 3.6) |
| Kết quả test thật | Đo một lần trên tập test, bằng mô hình đã nạp lại: tổng, theo phiên, theo 8 đợt tấn công (mục 3.5) |
| Phân tích hạn chế của giả định Gaussian | Năm hạn chế có số liệu: đuôi dày, cột gần như toàn 0, một đỉnh (so với hỗn hợp 8 Gaussian), tấn công trông bình thường, ngưỡng nhạy với cụm điểm (mục 4) |

## 2. Các task

| Task | Nội dung | Tài liệu |
|---|---|---|
| C06-T01 | Chọn đặc trưng và lấy mẫu bình thường trong train | [33_gaussian_dac_trung.md](33_gaussian_dac_trung.md) |
| C06-T02 | Kiểm tra phân bố và xác định phép biến đổi cần thiết | [34_gaussian_phan_bo.md](34_gaussian_phan_bo.md) |
| C06-T03 | Huấn luyện Gaussian, xử lý covariance suy biến | [35_gaussian_huan_luyen.md](35_gaussian_huan_luyen.md) |
| C06-T04 | Tính điểm bất thường và chọn ngưỡng trên validation | [36_gaussian_nguong.md](36_gaussian_nguong.md) |
| C06-T05 | Đánh giá Precision, Recall, F1 và false positive rate | [37_gaussian_danh_gia.md](37_gaussian_danh_gia.md) |
| C06-T06 | Lưu mô hình, ngưỡng, tiền xử lý và notebook | [38_gaussian_luu_mo_hinh.md](38_gaussian_luu_mo_hinh.md) |

Mã nguồn: `src/nids/gaussian.py`. Notebook: `notebooks/06_gaussian.ipynb`. Kiểm thử:
`tests/test_gaussian.py`.

## 3. Kết quả từng task

### 3.1. C06-T01 — Đặc trưng và mẫu normal

- Đơn vị là **cửa sổ host** (10 giây, bước 2 giây). Bảng flow có quá nhiều mẫu trùng (docs/30).
- Chỉ học trên mẫu `normal` của train.
- 20 đặc trưng ứng viên được lọc bằng quy tắc chạy trên train:
  - bỏ 2 cột tỷ lệ trống > 70%;
  - bỏ `incomplete_out`, vì bằng tổng ba cột thành phần;
  - bỏ 3 cột tương quan Spearman ≥ 0,95 (`bytes_out`, `bytes_in`, `dst_host_ports`).
- Còn **14 đặc trưng**; fit trên thứ Hai hay trên cả ba ngày đều ra cùng danh sách.

### 3.2. C06-T02 — Phân bố và biến đổi

| Cách | \|skew\| trung vị | Chỉ số điều kiện | d² phân vị 99% (χ²: 29,1) |
|---|---|---|---|
| Giữ nguyên | 10,5 | 2 390 | 175,8 |
| log(1 + x) | 2,0 | 88 | 102,3 |
| **Yeo-Johnson + log (chọn)** | **1,0** | **63** | 97,9 |

Yeo-Johnson cho 9 cột liên tục; log(1 + x) cho 5 cột có ≥ 90% giá trị 0 (λ học từ vài chục mẫu
khác 0 không đáng tin). **Phần giữa khớp Gaussian, đuôi thì không**: d² phân vị 99% là 98 so với
29 của χ²(14).

### 3.3. C06-T03 — Huấn luyện, hiệp phương sai suy biến

- Điểm bất thường là d² = (z − μ)ᵀ Σ⁻¹ (z − μ).
- Σ được bảo vệ ba lớp:
  - không đưa cột thừa vào (T01);
  - co Ledoit-Wolf;
  - sàn trị riêng 10⁻⁶ × trị riêng lớn nhất.
- Trên trường hợp suy biến thật (đủ 20 cột, trị riêng nhỏ nhất = 0), Ledoit-Wolf cho chỉ số điều
  kiện 748, còn chỉ dùng sàn trị riêng là 10⁶.
- Với 14 cột đã chọn, hệ số co chỉ 0,006 nên gần như không đổi mô hình.
- Huấn luyện mất 1–2,5 giây.

### 3.4. C06-T04 — Ngưỡng trên validation

- **Fit trên normal của train cả ba ngày** (252 221 cửa sổ). Cách này cho F1 validation 0,700,
  so với 0,681 khi chỉ dùng thứ Hai. Quyết định này thay phần "Gaussian học trên thứ Hai" của
  QĐ-028.
- **Ngưỡng d² = 64,65**, chọn bằng "F1 ổn định": ngưỡng có F1 xấu nhất khi lệch ±20% là lớn nhất.
- Ngưỡng F1 lớn nhất (145,6) nằm sát một vách. Cụm cửa sổ bot có d² quanh 125–150, nên tăng
  ngưỡng nhẹ là F1 rơi từ 0,71 xuống 0,27.
- Lệnh chọn ngưỡng không đọc tập test.

### 3.5. C06-T05 — Kết quả trên test

| Phiên | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Thứ Hai (không tấn công) | — | — | — | 1,28% |
| Thứ Tư (DoS, Heartbleed) | 0,453 | 0,424 | 0,438 | 1,94% |
| Thứ Sáu (bot, quét, DDoS) | 0,891 | 0,809 | 0,848 | 1,12% |
| **Tổng** | **0,733** | **0,727** | **0,730** | **1,42%** |

| Đợt | Recall test | | Đợt | Recall test |
|---|---|---|---|---|
| DoS slowloris | 0,912 | | DDoS | 0,495 |
| Bot | 0,863 | | DoS Slowhttptest | 0,277 |
| DoS Hulk | 0,705 | | DoS GoldenEye (24 cửa sổ) | 0,125 |
| PortScan | 0,537 | | Heartbleed | **0,000** |

Báo động giả: khoảng **17 đợt mỗi giờ** trên toàn mạng (15–17 host), một đợt là các cửa sổ liền
nhau của cùng host.

### 3.6. C06-T06 — Lưu, nạp lại, notebook

- `huan-luyen` lưu `models/gaussian_windows.joblib` (6 KB) kèm `.json` ghi:
  - đặc trưng, λ, tham số chuẩn hóa, ngưỡng, phiên fit;
  - chỉ số validation, commit mã nguồn, phiên bản thư viện.
- Kiểm chứng trên dữ liệu thật:
  - mô hình nạp lại cho đúng cùng kết quả test;
  - d² validation trùng khớp tuyệt đối;
  - `du-doan --khong-nhan` chạy trên 152 513 cửa sổ chưa nhãn.
- `notebooks/06_gaussian.ipynb` chạy lại toàn bộ chặng và đã lưu sẵn kết quả. Notebook chỉ gọi
  hàm của `gaussian.py`, đánh giá test bằng mô hình đã nạp lại.

## 4. Hạn chế của giả định Gaussian (tóm tắt docs/37 mục 3)

1. **Đuôi dày.** Ngưỡng lý thuyết χ² 99% báo nhầm 4,26% thay vì 1%. Vì vậy ngưỡng phải chọn bằng
   dữ liệu có nhãn (validation).
2. **Cột gần như toàn 0** (kết nối không hoàn tất) không thể thành dạng chuông. Chúng gây phần
   lớn báo động giả, nhưng cũng là tín hiệu quét mạnh nhất.
3. **Một đỉnh không đủ.**
   - Hỗn hợp 8 Gaussian (cùng biến đổi, cùng cách chọn ngưỡng): báo động giả 0,41% thay vì 1,42%,
     AP 0,83 thay vì 0,74.
   - Gaussian bỏ tương quan kém hơn (AUC 0,925 so với 0,977), nên hiệp phương sai đầy đủ là đúng
     hướng.
4. **Tấn công trông bình thường về lưu lượng:**
   - Heartbleed: recall 0, d² 15–27;
   - phía bên tấn công sau NAT (DDoS, PortScan);
   - DoS chậm (Slowhttptest).
5. **Ngưỡng nhạy với cụm điểm:** phải dùng ngưỡng ổn định, đổi lấy báo động giả cao hơn.

## 5. Sửa ở chặng trước

Khi làm C06-T04, phát hiện **Heartbleed nằm trọn trong validation**. Đợt này và DDoS để trống cột
`khoi` của lịch nhãn, nên không được cắt 60/20/20 như các khối tấn công.

- Đã sửa (commit `3223448`): Heartbleed và DDoS có khối riêng.
- Đã chạy lại chia dữ liệu, tiền xử lý, kiểm tra chất lượng, EDA và cập nhật số liệu ở docs/26,
  29–33, 35, báo cáo Chặng 5 và QĐ-027.
- Số mẫu `dos`, `port_scan` không đổi.
- Không có mẫu nào của hai tập khác nhau chồng thời gian; khoảng cách nhỏ nhất vẫn là 22 giây
  (cửa sổ) và 20 giây (flow).

## 6. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-029 | Gaussian dùng cửa sổ host; chọn đặc trưng bằng quy tắc trên train | Đã chốt |
| QĐ-030 | Yeo-Johnson cho cột liên tục, log(1 + x) cho cột gần như toàn 0; ngưỡng không theo χ² | Đã chốt |
| QĐ-031 | Điểm là d² Mahalanobis; hiệp phương sai Ledoit-Wolf kèm sàn trị riêng | Đã chốt |
| QĐ-032 | Fit trên normal của train cả ba ngày; ngưỡng F1 ổn định chọn trên validation | Đã chốt |

Cấu hình mới: mục `gaussian` trong `config/default.yaml` gồm `covariance`, các cách lấy mẫu fit để
so, cách chọn ngưỡng, độ lệch ±20%, FPR mục tiêu.

## 7. Kiểm thử

`python -m unittest discover -s tests`: **295/295 ca đạt** (Chặng 5 kết thúc ở 274).
`tests/test_gaussian.py` có 21 ca:

| Task | Số ca | Nội dung |
|---|---|---|
| T01 | 4 | Các quy tắc bỏ cột; cột tổng giữ lại khi thiếu thành phần; điền 0; mẫu normal của train |
| T02 | 3 | Chia cột Yeo-Johnson / log; giảm độ lệch; tham số không đổi khi biến đổi dữ liệu khác |
| T03 | 3 | Ma trận suy biến vẫn nghịch đảo được; điểm của mẫu lệch quan hệ lớn; dự đoán cần ngưỡng |
| T04 | 5 | Precision/Recall/F1/FPR; ba cách chọn ngưỡng; ngưỡng ổn định lùi xa vách; gán đợt tấn công |
| T05 | 3 | Đếm đợt báo động; đánh giá theo phiên; ba biến thể mô hình |
| T06 | 3 | Lưu/nạp; từ chối thiếu cột hoặc ngưỡng; lưu bằng dòng lệnh, nạp ở tiến trình khác, dự đoán bằng dòng lệnh |

## 8. Cách chạy

```bash
cd src
F=../output/features
python -m nids.gaussian phan-bo $F/cic17_monday --fit-session cic17_monday --out ../docs/hinh
python -m nids.gaussian nguong $F/cic17_monday $F/cic17_wednesday $F/cic17_friday --out ../docs/hinh
python -m nids.gaussian huan-luyen $F/cic17_monday $F/cic17_wednesday $F/cic17_friday
python -m nids.gaussian danh-gia $F/cic17_monday $F/cic17_wednesday $F/cic17_friday \
    --model ../models/gaussian_windows.joblib --out ../docs/hinh --so-sanh
python -m nids.gaussian du-doan $F/cic17_monday --khong-nhan \
    --model ../models/gaussian_windows.joblib --out ../output/du_doan.csv
```

## 9. Điểm cần lưu ý

1. **Mới có kết quả trên CIC-IDS2017.** Train, validation, test cùng mạng, cùng đợt tấn công. Phải
   đo lại trên dữ liệu lab khi có (Chặng 11).
2. **Báo động giả khoảng 17 đợt mỗi giờ** trên khoảng 16 host là nhiều cho vận hành thật. Có thể
   giảm bằng hỗn hợp Gaussian (mục 4.3), hoặc chỉ báo khi nhiều cửa sổ liền nhau vượt ngưỡng
   (Chặng 9).
3. **Gaussian không thay được bộ phân loại:** Heartbleed, DoS chậm và phía bên tấn công sau NAT
   gần như không bị bắt. Chặng 7 (phân loại) và Chặng 9 (kết hợp) cần bù.
4. **Số mẫu nhỏ ở vài đợt** (GoldenEye 24 cửa sổ test, PortScan 50 cửa sổ validation): recall theo
   đợt của chúng dao động lớn.
5. **Đã có một lần xem kết quả test** khi chẩn đoán cách chọn ngưỡng (ghi rõ ở docs/36 mục 5). Hai
   cách cho F1 test gần bằng nhau, nên lựa chọn không dựa vào test.

## 10. Việc tiếp theo

**Chặng 7 — Phân loại tấn công** (Benign, PortScan, DoS), dùng bộ tiền xử lý `attack_classification`
của C05-T07:
- Logistic Regression làm mô hình đối chiếu, rồi Random Forest.
- Chọn tham số trên validation; báo macro-F1, chỉ số từng lớp và confusion matrix.

Song song:
- dựng lab;
- chốt scenario validation của CTU-13 cho Chặng 8.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Phát hiện bất thường | Học dữ liệu bình thường rồi báo mẫu khác xa nó, không cần biết trước loại tấn công |
| Gaussian đa biến | Mô hình dữ liệu bình thường bằng trung bình và ma trận hiệp phương sai |
| d² (Mahalanobis) | Điểm bất thường: khoảng cách tới trung bình có tính dao động và tương quan giữa các cột |
| Yeo-Johnson, λ | Phép biến đổi làm phân bố gần dạng chuông và tham số của nó |
| Hiệp phương sai, suy biến | Bảng đo các cột biến thiên cùng nhau; suy biến khi không nghịch đảo được |
| Ledoit-Wolf | Cách co hiệp phương sai về đường chéo để luôn nghịch đảo được |
| Ngưỡng, F1 ổn định | Mức d² để báo động; ngưỡng có F1 tốt nhất khi lệch ±20% |
| Precision, Recall, F1 | Tỷ lệ báo đúng / tỷ lệ bắt được / trung bình điều hòa của hai số |
| FPR, đợt báo động | Tỷ lệ cửa sổ bình thường bị báo nhầm; các cửa sổ bị báo liên tiếp của một host |
| AUC, AP | Khả năng xếp tấn công trên bình thường; diện tích dưới đường Precision–Recall |
| χ², đuôi dày | Phân bố lý thuyết của d² nếu đúng Gaussian; có nhiều giá trị cực lớn hơn dự đoán |
| Hỗn hợp Gaussian | Mô hình gồm nhiều Gaussian cho nhiều kiểu hành vi |
| joblib, notebook | Thư viện lưu đối tượng Python; file Jupyter gồm mã, kết quả và giải thích |
| NAT | Thiết bị thay địa chỉ của nhiều máy bằng một địa chỉ chung |
