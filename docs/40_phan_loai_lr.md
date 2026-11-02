# C07-T02 — Logistic Regression làm mô hình đối chiếu

Mã nguồn: `prepare_data`, `AttackClassifier`, `multiclass_metrics`, `fit_and_score`,
`lr_coefficients` trong `src/nids/classifier.py`. Kiểm thử: `tests/test_classifier.py`. Kết quả:
`docs/hinh/phan_loai_lr_validation.json`.

```bash
cd src
python -m nids.classifier thu logistic_regression ../output/features/cic17_wednesday ../output/features/cic17_friday --out ../docs/hinh
```

## 1. Cách làm

Logistic Regression (LR) là mô hình tuyến tính: mỗi lớp có một tổng có trọng số của các đặc
trưng, lớp có tổng lớn nhất thắng. Nó đơn giản, học nhanh và dễ giải thích qua hệ số, nên dùng làm
**mức chuẩn** cho Random Forest (C07-T03): Random Forest chỉ đáng dùng nếu hơn rõ LR.

Dữ liệu và tiền xử lý dùng chung cho cả hai mô hình (cùng bài toán):

1. Mẫu và nhãn như C07-T01 (cửa sổ host, ba lớp, thứ Tư và thứ Sáu).
2. Train: bỏ mẫu trùng hệt (166 233 → 85 956), rồi giảm mẫu mỗi lớp xuống tối đa 10 lần lớp ít
   nhất (QĐ-028): benign 4 450, dos 2 165, port_scan 445.
3. Bộ tiền xử lý của C05-T07 **fit trên train sau bỏ trùng** (trước giảm mẫu): log cho cột đếm,
   điền trung vị và thêm cột đánh dấu ô trống, chuẩn hóa. 20 đặc trưng thành 23 cột.
4. Validation và test giữ nguyên phân bố thật (khoảng 1,3% là tấn công).

`AttackClassifier` gói bộ tiền xử lý và mô hình: nhận bảng cửa sổ thô, trả nhãn. Tham số mặc định
trong `config/default.yaml` mục `classifier.logistic_regression`: `C = 1`, `class_weight =
balanced` (lớp ít mẫu được nhân trọng số), thuật toán lbfgs nhiều lớp.

## 2. Kết quả với tham số mặc định

| Tập | Macro-F1 | Accuracy |
|---|---|---|
| Train (đã cân bằng) | 0,897 | 0,939 |
| Validation | **0,418** | 0,870 |

| Lớp (validation) | Precision | Recall | F1 | Số mẫu |
|---|---|---|---|---|
| benign | 0,999 | 0,869 | 0,930 | 53 949 |
| port_scan | 0,008 | 0,660 | 0,015 | 50 |
| dos | 0,185 | 0,951 | 0,310 | 648 |

Confusion matrix trên validation (hàng: nhãn thật, cột: dự đoán):

| | benign | port_scan | dos |
|---|---|---|---|
| benign | 46 875 | 4 373 | 2 701 |
| port_scan | 9 | 33 | 8 |
| dos | 21 | 11 | 616 |

LR bắt được phần lớn tấn công (recall dos 0,95), nhưng **13% cửa sổ benign bị báo là tấn công**.
Vì benign nhiều gấp khoảng 80 lần tấn công trên validation, số báo nhầm (7 074) lớn hơn hẳn số
tấn công thật, nên precision của hai lớp tấn công rất thấp.

## 3. Vì sao: cân bằng lớp làm lệch xác suất

Train đã cân bằng có 37% tấn công, lại thêm `class_weight = balanced`, trong khi thực tế chỉ khoảng
1,3%. Mô hình học rằng tấn công "phổ biến", nên với mẫu nằm ở vùng giáp ranh nó nghiêng về tấn
công. Thử nhanh trên validation (C = 1):

| Giảm mẫu train | `class_weight` | Macro-F1 | Precision port_scan | Precision dos | Recall dos |
|---|---|---|---|---|---|
| Tối đa 10 lần | balanced | 0,418 | 0,008 | 0,19 | 0,95 |
| Tối đa 10 lần | không | 0,540 | 0,12 | 0,29 | 0,93 |
| Không giảm | không | 0,883 | 0,97 | 0,96 | 0,79 |

Bỏ cân bằng thì precision tăng mạnh, đổi lại recall dos giảm. Đây là đánh đổi phải chọn bằng
validation, nên **tỷ lệ giảm mẫu và `class_weight` trở thành tham số chọn ở C07-T04**, thay vì cố
định 10 như QĐ-028 (QĐ-034). Recall port_scan của LR chỉ khoảng 0,58–0,76 ở mọi cấu hình đã thử: một phần
cửa sổ quét không tách được bằng đường thẳng (C07-T06 phân tích).

## 4. Hệ số

Các hệ số lớn nhất (trên đặc trưng đã log và chuẩn hóa; dương là đẩy về lớp đó):

| Lớp | Hệ số lớn nhất |
|---|---|
| benign | `dst_host_ports` +4,8; `new_conn_in` +2,4; `dst_port_entropy` trống +2,3; `tcp_attempts_out` −1,7 |
| port_scan | `packets_in` −4,4; `dst_host_ports` −3,6; `dst_port_entropy` +2,2; `new_conn_in` +2,1 |
| dos | `new_conn_in` −4,5; `packets_in` +2,7; `tcp_attempts_in` +1,9; `packets_out` −1,5 |

Các đặc trưng bị log nên tương quan mạnh với nhau (gói vào, kết nối mới, cặp đích-cổng), hệ số chỉ
nên đọc theo hướng, không theo độ lớn tuyệt đối. Bên tấn công và nạn nhân cùng nhãn nhưng hướng
traffic ngược nhau, nên một mô hình tuyến tính phải "kẹp" hai cụm cách xa nhau vào một lớp: đây là
giới hạn chính của LR ở bài toán này.

## 5. Kiểm thử

- Bỏ trùng và giảm mẫu chỉ ở train; validation, test giữ nguyên số mẫu.
- Bộ tiền xử lý fit trên train sau bỏ trùng.
- `multiclass_metrics` đúng định nghĩa (confusion matrix, recall, macro-F1 trên ví dụ tính tay).
- LR học được dữ liệu giả lập có ba lớp tách biệt (macro-F1 validation > 0,9).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Logistic Regression | Mô hình tuyến tính cho xác suất từng lớp từ tổng có trọng số của đặc trưng |
| Hệ số | Trọng số của một đặc trưng cho một lớp |
| `C` | Tham số điều chỉnh: nhỏ thì hệ số bị ép nhỏ (mô hình đơn giản hơn) |
| `class_weight = balanced` | Nhân trọng số mẫu theo nghịch đảo tần suất lớp |
| Giảm mẫu (cân bằng) | Bỏ ngẫu nhiên bớt mẫu của lớp nhiều mẫu trong train |
| Macro-F1 | Trung bình F1 ba lớp, mỗi lớp nặng như nhau |
| Precision, Recall, F1 | Tỷ lệ báo đúng; tỷ lệ bắt được; trung bình điều hòa của hai số |
| Accuracy | Tỷ lệ mẫu đoán đúng; bị lớp đông nhất (benign) chi phối |
| Confusion matrix | Bảng đếm mẫu theo nhãn thật (hàng) và nhãn dự đoán (cột) |
| Mức chuẩn (baseline) | Mô hình đơn giản để so sánh; mô hình phức tạp phải hơn nó mới đáng dùng |
| lbfgs | Thuật toán tối ưu dùng để học hệ số |
