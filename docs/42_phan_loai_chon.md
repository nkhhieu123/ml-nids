# C07-T04 — Chọn tham số và mô hình bằng validation

Mã nguồn: `search`, `select_models`, `paired_bootstrap` trong `src/nids/classifier.py`. Lưới tham
số: `config/default.yaml` mục `classifier.search`. Kiểm thử: `tests/test_classifier.py`. Kết quả:
`docs/hinh/phan_loai_chon.json` (mọi lần thử).

```bash
cd src
python -m nids.classifier chon ../output/features/cic17_wednesday ../output/features/cic17_friday --out ../docs/hinh
```

Chạy khoảng 20 phút trên máy phát triển. **Bước này không đọc tập test.**

## 1. Cách chọn

Chỉ số chọn: **macro-F1 trên validation**. Mỗi lớp nặng như nhau, nên mô hình không thể đạt điểm
cao chỉ nhờ đoán đúng benign (chiếm 98,7% validation).

Mỗi loại mô hình chọn theo hai bước, để không phải thử mọi tổ hợp (RF trên toàn bộ train mất
khoảng 30 giây mỗi lần):

1. **Tỷ lệ giảm mẫu train** (tối đa 10 lần, 100 lần, không giảm) × **`class_weight`**, các tham
   số khác để mặc định. C07-T02/T03 cho thấy đây là yếu tố ảnh hưởng nhiều nhất.
2. **Các tham số còn lại**, giữ tỷ lệ và `class_weight` tốt nhất của bước 1:
   - LR: `C` ∈ {0,01; 0,1; 1; 10; 100};
   - RF: `max_depth` ∈ {không giới hạn, 20, 10} × `min_samples_leaf` ∈ {1, 3, 10} ×
     `max_features` ∈ {sqrt, 0,5}; 300 cây.

Mô hình cuối là loại có macro-F1 validation cao hơn. Để biết chênh lệch có vượt nhiễu không (lớp
port_scan chỉ có 50 mẫu validation), dùng **bootstrap ghép cặp**: lấy lại 1 000 lần các mẫu
validation có hoàn lại, tính macro-F1 của cả hai mô hình trên cùng mẫu lấy lại.

## 2. Bước 1: cân bằng lớp

| Giảm mẫu train | `class_weight` | LR | RF |
|---|---|---|---|
| Tối đa 10 lần | balanced | 0,418 | 0,421 |
| Tối đa 10 lần | không | 0,540 | 0,482 |
| Tối đa 100 lần | balanced | 0,402 | 0,696 |
| Tối đa 100 lần | không | 0,842 | 0,750 |
| Không giảm | balanced | 0,404 | 0,700 |
| Không giảm | không | **0,883** | **0,911** |

Cả hai mô hình đều tốt nhất khi **giữ nguyên phân bố lớp của train**. Lớp tấn công không quá ít
(port_scan 445, dos 2 165 mẫu sau bỏ trùng) nên không cần cân bằng để học được chúng; còn cân bằng
thì làm mô hình đánh giá quá cao khả năng gặp tấn công (docs/40 mục 3).

## 3. Bước 2: tham số còn lại

**LR** (không giảm, không trọng số):

| C | 0,01 | 0,1 | 1 | 10 | 100 |
|---|---|---|---|---|---|
| Macro-F1 | 0,882 | 0,878 | **0,883** | 0,876 | 0,867 |

**RF** (không giảm, không trọng số), macro-F1 validation:

| `max_depth` | `min_samples_leaf` | sqrt | 0,5 |
|---|---|---|---|
| Không giới hạn | 1 | 0,911 | 0,906 |
| Không giới hạn | 3 | 0,909 | 0,902 |
| Không giới hạn | 10 | 0,909 | 0,906 |
| 20 | 1 | 0,911 | 0,907 |
| 20 | 3 | **0,913** | 0,902 |
| 20 | 10 | 0,909 | 0,903 |
| 10 | 1 | 0,906 | 0,912 |
| 10 | 3 | 0,904 | 0,912 |
| 10 | 10 | 0,891 | 0,911 |

Bề mặt **gần như phẳng** (0,89–0,913): các tham số cây hầu như không quan trọng bằng việc giữ đủ
benign. Chênh lệch 0,001–0,005 giữa các ô nhỏ hơn một mẫu port_scan validation (khoảng 0,007
macro-F1), nên cấu hình "tốt nhất" là một lựa chọn trong nhóm ngang nhau, không phải tối ưu rõ rệt.

## 4. Kết quả chọn

| | LR | RF |
|---|---|---|
| Tham số | C = 1, không giảm mẫu, không trọng số | 300 cây, `max_depth` 20, `min_samples_leaf` 3, `max_features` sqrt, không giảm mẫu, không trọng số |
| Macro-F1 train | 0,907 | 0,970 |
| **Macro-F1 validation** | 0,883 | **0,913** |
| F1 benign / port_scan / dos | 0,998 / 0,786 / 0,866 | 0,999 / 0,800 / 0,939 |
| Precision port_scan / dos | 0,971 / 0,955 | 0,971 / 0,980 |
| Recall port_scan / dos | 0,660 / 0,792 | 0,680 / 0,901 |
| Benign bị báo nhầm | 23 / 53 949 | 13 / 53 949 |

Confusion matrix validation:

| LR | benign | port_scan | dos | | RF | benign | port_scan | dos |
|---|---|---|---|---|---|---|---|---|
| benign | 53 926 | 1 | 22 | | benign | 53 936 | 1 | 12 |
| port_scan | 15 | 33 | 2 | | port_scan | 16 | 34 | 0 |
| dos | 135 | 0 | 513 | | dos | 64 | 0 | 584 |

**Bootstrap ghép cặp** (RF − LR): RF hơn LR ở **99,7%** số lần lấy lại; hiệu trung bình +0,029,
khoảng 95% [+0,010; +0,051]. Các cửa sổ liền nhau không độc lập nên khoảng thật rộng hơn, nhưng
chênh lệch chủ yếu đến từ lớp dos (648 mẫu, recall 0,90 so với 0,79), không phải từ vài mẫu port_scan.

**Chọn Random Forest** (QĐ-035). LR được giữ làm mức chuẩn và vẫn đánh giá trên test (C07-T05) để
có bảng so sánh.

Cả hai mô hình sai chủ yếu theo cùng một hướng: **tấn công bị đoán là benign** (bỏ sót), rất ít báo
nhầm benign thành tấn công. Mô hình đã "thận trọng", phù hợp với tỷ lệ tấn công thật thấp.

## 5. Hạn chế

- Port_scan validation chỉ 50 mẫu (docs/39): F1 port_scan trên validation thay đổi khoảng 0,01–0,02
  với mỗi mẫu đoán khác, nên macro-F1 validation có nhiễu cỡ ±0,007 từ lớp này.
- Không chọn lại tỷ lệ giảm mẫu sau bước 2; bước 1 chênh lệch quá lớn (0,91 so với ≤ 0,75) nên
  thứ tự hai bước khó làm đổi kết quả.
- Tham số khung cửa sổ (10 giây) và đặc trưng cố định từ Chặng 4, không chọn ở đây.

## 6. Kiểm thử

- Bước 1 thử đủ tỷ lệ × trọng số; bước 2 giữ tỷ lệ tốt nhất, không thử lại tổ hợp đã có.
- Kết quả tốt nhất là lần thử có macro-F1 validation cao nhất.
- Bootstrap nhận ra chênh lệch rõ (tỷ lệ 1,0, khoảng 95% dương) và cho hiệu 0 khi hai mô hình như nhau.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Lưới tham số | Danh sách các giá trị tham số được thử |
| Macro-F1 | Trung bình F1 ba lớp, mỗi lớp nặng như nhau |
| Bootstrap ghép cặp | Lấy lại mẫu nhiều lần, tính chỉ số của hai mô hình trên cùng mẫu lấy lại để so sánh |
| Khoảng 95% | Khoảng chứa 95% giá trị hiệu số qua các lần lấy lại |
| Giảm mẫu, `class_weight` | Bớt mẫu lớp đông trong train; nhân trọng số lớp ít mẫu |
| `C` | Tham số của LR: nhỏ thì mô hình đơn giản hơn |
| `max_depth`, `min_samples_leaf`, `max_features` | Độ sâu tối đa; số mẫu tối thiểu ở lá; số đặc trưng xét mỗi lần chia của cây |
| Bỏ sót | Tấn công bị đoán là benign |
| Báo nhầm | Benign bị đoán là tấn công |
