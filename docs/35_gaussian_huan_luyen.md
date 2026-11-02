# C06-T03 — Huấn luyện Gaussian, xử lý hiệp phương sai suy biến

Mã nguồn: `fit_covariance`, `GaussianDetector` trong `src/nids/gaussian.py`. Kiểm thử:
`tests/test_gaussian.py`. Cấu hình: mục `gaussian` trong `config/default.yaml`. Quyết định:
QĐ-031 trong [03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

## 1. Mô hình

Sau biến đổi của C06-T02, mỗi cửa sổ là vector **z** 14 chiều. Gaussian đa biến học trên mẫu
normal của train:

- trung bình **μ**;
- ma trận hiệp phương sai **Σ** (14 × 14).

**Điểm bất thường** của một cửa sổ là khoảng cách Mahalanobis bình phương:

d²(z) = (z − μ)ᵀ Σ⁻¹ (z − μ)

d² càng lớn, cửa sổ càng xa hành vi bình thường. Nó xếp hạng **đúng ngược** với mật độ Gaussian
(`log_density`), nhưng dễ đọc hơn: với dữ liệu đúng Gaussian thì trung bình d² bằng số chiều.
Cửa sổ có d² vượt ngưỡng (chọn ở C06-T04) bị báo là `anomaly`.

Dùng d² thay vì mật độ theo từng cột độc lập: Gaussian đa biến biết quan hệ giữa các cột. Ví dụ
nhiều gói ra mà không có gói vào là bất thường, dù từng cột riêng lẻ trông bình thường.

## 2. Xử lý hiệp phương sai suy biến

Σ⁻¹ chỉ tồn tại khi Σ không suy biến. Ba lớp bảo vệ:

| Lớp | Cách | Ở đâu |
|---|---|---|
| 1. Không đưa cột thừa vào | Bỏ cột tổng, cột hằng số, cột tương quan ≥ 0,95 | C06-T01 |
| 2. Co hiệp phương sai (Ledoit-Wolf) | Σ = (1 − α)·S + α·(trung bình phương sai)·I, với S là hiệp phương sai mẫu; α chọn tự động từ dữ liệu | `fit_covariance(..., "ledoit_wolf")` |
| 3. Sàn trị riêng | Trị riêng nhỏ hơn 10⁻⁶ × trị riêng lớn nhất được nâng lên mức đó | `fit_covariance`, mọi phương pháp |

Lớp 2 và 3 đảm bảo Σ luôn nghịch đảo được, kể cả trên dữ liệu khác (lab) mà quy tắc của lớp 1
chưa lường trước.

**Thử trên trường hợp suy biến thật:** dùng cả 20 cột (giữ cả `incomplete_out` lẫn ba cột thành
phần), trị riêng nhỏ nhất của S là −2,8·10⁻¹⁷, tức đúng bằng 0.

| Cách | Kết quả |
|---|---|
| Chỉ sàn trị riêng | 1 trị riêng được nâng; chỉ số điều kiện 10⁶. Nghịch đảo được, nhưng một hướng gần như không có dao động: mẫu lệch nhẹ theo hướng đó bị cho d² rất lớn |
| Ledoit-Wolf | α = 0,0089; trị riêng nhỏ nhất 0,0089; chỉ số điều kiện 748. Không cần sàn |

Vì vậy **chọn Ledoit-Wolf làm mặc định** (`gaussian.covariance: ledoit_wolf`).

## 3. Kết quả trên CIC-IDS2017

Với 14 đặc trưng đã chọn, Σ không suy biến: hệ số co α chỉ khoảng 0,006 nên Ledoit-Wolf gần như
không đổi mô hình. AUC dưới đây chỉ để so sánh các cách fit, đo trên **validation**; ngưỡng và
kết quả cuối ở C06-T04, T05.

| Fit trên | Hiệp phương sai | Mẫu fit | Chỉ số điều kiện | α | AUC (validation) | AP (validation) |
|---|---|---|---|---|---|---|
| Train thứ Hai | Mẫu | 88 929 | 62,7 | — | 0,9619 | 0,574 |
| Train thứ Hai | Ledoit-Wolf | 88 929 | 58,3 | 0,0058 | 0,9623 | 0,576 |
| Normal của train cả ba ngày | Mẫu | 251 154 | 59,5 | — | 0,9673 | 0,624 |
| Normal của train cả ba ngày | Ledoit-Wolf | 251 154 | 55,6 | 0,0055 | 0,9674 | 0,624 |

Validation có 80 609 cửa sổ, trong đó 4 094 `anomaly` (5,1%). Huấn luyện mất khoảng 1–2,5 giây.

Nhận xét:
- Hai cách tính hiệp phương sai cho kết quả gần như nhau, vì Σ đã ổn định từ C06-T01, T02.
- Fit trên normal cả ba ngày tốt hơn rõ (AP 0,624 so với 0,574), vì mô hình thấy được dao động
  bình thường của thứ Tư, thứ Sáu. Cách nào được dùng sẽ chốt ở C06-T04 theo validation.

## 4. Kiểm thử

Kiểm thử tự động (3 ca):
- Ma trận có cột là tổng của hai cột khác: cả hai cách đều nghịch đảo được, chỉ số điều kiện
  ≤ 10⁶, sàn trị riêng nâng đúng 1 giá trị, Ledoit-Wolf có hệ số co dương.
- Mẫu gần trung tâm có d² nhỏ, mẫu phá quan hệ giữa hai cột có d² lớn; log mật độ xếp hạng ngược
  với d²; trung bình d² trên train gần bằng số chiều.
- Dự đoán báo lỗi khi chưa đặt ngưỡng.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Gaussian đa biến | Mô hình dữ liệu bình thường bằng trung bình và ma trận hiệp phương sai |
| Khoảng cách Mahalanobis (d²) | Khoảng cách tới trung bình có tính độ dao động và tương quan giữa các cột; dùng làm điểm bất thường |
| Mật độ | Mức "phổ biến" của một điểm theo mô hình; mật độ thấp là bất thường |
| Ma trận hiệp phương sai | Bảng đo từng cặp đặc trưng biến thiên cùng nhau ra sao |
| Suy biến | Ma trận không nghịch đảo được, khi có cột là tổ hợp của cột khác |
| Trị riêng | Độ dao động của dữ liệu theo từng hướng chính; bằng 0 là hướng không dao động |
| Chỉ số điều kiện | Tỷ lệ trị riêng lớn nhất trên nhỏ nhất; càng lớn càng gần suy biến |
| Ledoit-Wolf | Cách co hiệp phương sai mẫu về ma trận đường chéo, mức co tự chọn từ dữ liệu |
| Hệ số co (α) | Tỷ lệ co: 0 là giữ nguyên, 1 là chỉ còn đường chéo |
| Sàn trị riêng | Nâng các trị riêng quá nhỏ lên một mức tối thiểu |
| AUC | Xác suất mô hình cho một mẫu tấn công điểm cao hơn một mẫu bình thường ngẫu nhiên; 1 là hoàn hảo |
| AP (average precision) | Diện tích dưới đường Precision–Recall; nhạy với lớp hiếm hơn AUC |
| Ngưỡng | Mức d² từ đó trở lên thì báo động |
