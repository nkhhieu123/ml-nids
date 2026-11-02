# C07-T03 — Random Forest

Mã nguồn: `make_estimator`, `AttackClassifier` trong `src/nids/classifier.py`. Kiểm thử:
`tests/test_classifier.py`. Kết quả: `docs/hinh/phan_loai_rf_validation.json`.

```bash
cd src
python -m nids.classifier thu random_forest ../output/features/cic17_wednesday ../output/features/cic17_friday --out ../docs/hinh
```

## 1. Cách làm

Random Forest (RF) gồm nhiều cây quyết định, mỗi cây học trên một mẫu lấy lại ngẫu nhiên của train
và chỉ xét một phần đặc trưng ở mỗi lần chia; dự đoán là lá phiếu trung bình của các cây. Khác LR,
RF chia được không gian thành nhiều vùng, nên một lớp có thể gồm nhiều cụm cách xa nhau (ví dụ bên
tấn công và nạn nhân cùng mang nhãn `dos`).

**Cùng bài toán với LR**: cùng mẫu, cùng train sau bỏ trùng và giảm mẫu, cùng bộ tiền xử lý (log,
điền trung vị, chuẩn hóa không ảnh hưởng RF nhưng giữ để hai mô hình nhận đúng một đầu vào).

Tham số mặc định (`config/default.yaml`, mục `classifier.random_forest`): 300 cây, cây mọc hết cỡ
(`max_depth = null`, `min_samples_leaf = 1`), mỗi lần chia xét √23 ≈ 4 đặc trưng, `class_weight =
balanced_subsample`. Seed cố định nên chạy lại cho đúng kết quả cũ.

## 2. Kết quả với tham số mặc định

| Tập | Macro-F1 | Accuracy |
|---|---|---|
| Train (đã cân bằng) | 1,000 | 1,000 |
| Validation | **0,421** | 0,904 |

| Lớp (validation) | Precision | Recall | F1 | Số mẫu |
|---|---|---|---|---|
| benign | 1,000 | 0,904 | 0,949 | 53 949 |
| port_scan | 0,054 | 0,680 | 0,101 | 50 |
| dos | 0,120 | 0,968 | 0,213 | 648 |

| Validation | benign | port_scan | dos |
|---|---|---|---|
| benign | 48 749 | 588 | 4 612 |
| port_scan | 9 | 34 | 7 |
| dos | 17 | 4 | 627 |

RF thuộc lòng train (macro-F1 1,0) nhưng **gặp đúng vấn đề của LR**: train chỉ còn 4 450 cửa sổ
benign (giảm mẫu tối đa 10 lần) nên không thấy đủ kiểu benign, lại được nhân trọng số tấn công;
9,6% benign validation bị báo tấn công, phần lớn thành `dos`.

## 3. Cân bằng lớp (thử nhanh trên validation, 300 cây)

| Giảm mẫu train | `class_weight` | Macro-F1 | Precision port_scan | Precision dos | Recall dos |
|---|---|---|---|---|---|
| Tối đa 10 lần | balanced_subsample | 0,421 | 0,05 | 0,12 | 0,97 |
| Tối đa 10 lần | không | 0,482 | 0,18 | 0,12 | 0,97 |
| Tối đa 100 lần | không | 0,750 | 0,71 | 0,41 | 0,93 |
| Không giảm | balanced_subsample | 0,700 | 0,45 | 0,41 | 0,91 |
| Không giảm | không | **0,911** | 0,97 | 0,94 | 0,93 |

So với LR ở cùng thiết lập "không giảm, không trọng số" (macro-F1 0,883), RF hơn chủ yếu nhờ
**recall dos 0,93 so với 0,79** mà precision vẫn 0,94. Với RF, giữ đủ benign quan trọng hơn với LR:
cây cần thấy nhiều kiểu benign mới không cắt nhầm vùng benign hiếm sang tấn công.

Recall port_scan dừng ở **0,68 (34/50)** ở mọi cấu hình của cả hai mô hình: 16 cửa sổ quét trên
validation giống benign về mọi đặc trưng đang có; C07-T06 xem chúng là gì.

Tham số chốt (tỷ lệ giảm mẫu, trọng số lớp, độ sâu, số đặc trưng mỗi lần chia) chọn ở C07-T04.

## 4. Độ quan trọng đặc trưng (mặc định, giảm Gini)

| Đặc trưng | Độ quan trọng | Đặc trưng | Độ quan trọng |
|---|---|---|---|
| `dst_hosts` | 0,092 | `bytes_out` | 0,060 |
| `tcp_attempts_in` | 0,088 | `new_conn_in` | 0,058 |
| `dst_port_entropy` | 0,077 | `dst_ports` | 0,053 |
| `bytes_in` | 0,069 | `dst_host_ports` | 0,045 |
| `packets_in` | 0,067 | `rejected_out` | 0,043 |
| `incomplete_ratio_in` trống | 0,062 | `packets_out` | 0,043 |

Không có đặc trưng nào áp đảo; RF dựa vào cả chiều vào (nạn nhân) lẫn chiều ra (bên tấn công).
Độ quan trọng Gini thiên về đặc trưng có nhiều giá trị; C07-T06 đo thêm bằng hoán vị trên validation.

## 5. Kiểm thử

- RF học được dữ liệu giả lập ba lớp (macro-F1 validation > 0,9); có độ quan trọng cho từng cột.
- Cùng seed thì cùng xác suất dự đoán.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Random Forest | Tập nhiều cây quyết định; dự đoán bằng biểu quyết của các cây |
| Cây quyết định | Chuỗi câu hỏi "đặc trưng x lớn hơn ngưỡng t?" dẫn tới một nhãn |
| `max_depth`, `min_samples_leaf` | Độ sâu tối đa của cây; số mẫu tối thiểu ở mỗi lá |
| `max_features` | Số đặc trưng xét ở mỗi lần chia (sqrt: căn bậc hai tổng số) |
| `balanced_subsample` | Trọng số lớp tính lại trên mẫu lấy lại của từng cây |
| Thuộc lòng (overfit) | Đúng hoàn toàn trên train nhưng kém hơn nhiều trên dữ liệu mới |
| Độ quan trọng Gini | Mức giảm độ lẫn lộn nhãn nhờ đặc trưng đó, cộng trên mọi cây |
| Hoán vị (permutation importance) | Xáo trộn một đặc trưng rồi đo chỉ số giảm bao nhiêu |
| Seed | Số khởi tạo ngẫu nhiên; cố định để chạy lại cho cùng kết quả |
| Macro-F1, Precision, Recall | Như docs/40 |
