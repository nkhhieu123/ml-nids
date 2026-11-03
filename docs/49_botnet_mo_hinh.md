# C08-T05 — Huấn luyện và so sánh hai mô hình phát hiện botnet

Mã nguồn: `BotnetDetector`, `training_set`, `model_search`, `evaluate`, `save_model`, `load_model`
trong `src/nids/botnet.py`. Cấu hình: `botnet.max_background_alarm` trong `config/default.yaml`.
Kiểm thử: `tests/test_botnet.py`. Kết quả: `docs/hinh/botnet_mo_hinh.json`; mô hình trong `models/`
(không lên git).

```bash
cd src
python -m nids.botnet huan-luyen ../output/ctu13 --out ../docs/hinh        # khoảng 10 phút
```

Bước này chỉ dùng train và validation. Kết quả trên test ở C08-T08.

## 1. Hai mô hình

Cùng đầu vào: 24 đặc trưng của host–cửa sổ (19 đặc trưng đồ thị C08-T02 và 5 đặc trưng beaconing
C08-T03). Cùng tiền xử lý, fit trên train: log(1 + x) cho cột đếm, điền trung vị và thêm cột đánh dấu
ô trống, chuẩn hóa.

| Mô hình | Lưới thử |
|---|---|
| Logistic Regression | `C` ∈ {0,1; 1; 10} × `class_weight` ∈ {balanced, không} |
| Random Forest (300 cây) | `max_depth` ∈ {không giới hạn, 10}, `min_samples_leaf` 5 |

Cùng với tham số mô hình, chọn thêm trên validation:
- **ngưỡng xác suất** (0,05 tới 0,95, bước 0,05);
- **tỷ lệ cửa sổ Background của train dùng làm mẫu âm** (0; 0,1; 0,3; 1), xem mục 2.

## 2. Hai điều chỉnh khi chọn (QĐ-040)

**Lần thử đầu** chọn theo F1 validation, ngưỡng 0,5: LR đạt F1 0,627, RF 0,405. Cho chọn cả ngưỡng
thì ngưỡng rơi xuống 0,05 và F1 RF lên 0,96. Nhưng khi đó **84–93% cửa sổ Background validation bị
báo là bot**.

Cách đọc: với 4 máy bình thường **giống nhau ở mọi tập** (docs/48 mục 5), mô hình học "khác bốn máy
quen thuộc thì là bot", tức là học danh tính máy chứ không học hành vi bot. F1 trên validation không
thấy được điều này, vì validation cũng chỉ có đúng bốn máy đó.

Hai điều chỉnh, đều chỉ dùng train và validation:

1. **Ràng buộc khi chọn**: chỉ nhận cấu hình (tham số, ngưỡng) có tỷ lệ cửa sổ **Background validation
   bị báo ≤ 5%** (`max_background_alarm`). Phần lớn host Background là máy lành, nên đây là giới hạn
   hợp lý cho báo động trên máy lạ. Với ràng buộc này, RF chỉ còn F1 0,265.
2. **Background làm mẫu âm yếu khi học**: thêm một phần cửa sổ Background của **train** với nhãn
   `normal_host`, để mô hình thấy nhiều kiểu máy khác ngoài bốn máy bình thường. Tỷ lệ chọn trên
   validation. Background **không bao giờ** là lớp dương, và không dùng khi tính Precision/Recall.
   Điều này sửa một phần quy định ở QĐ-039 (Background "không học").

## 3. Kết quả trên validation (scenario 4, 13), Background bị báo ≤ 5%

F1 của `suspect_host`, cấu hình tốt nhất của mỗi tỷ lệ Background:

| Background làm mẫu âm | LR | RF |
|---|---|---|
| 0 | không đạt ≤ 5% (gần nhất 8,8%) | 0,265 |
| 10% | 0,095 | 0,462 |
| 30% | 0,138 | 0,466 |
| 100% | 0,165 | **0,536** |

Cấu hình được chọn:

| | Logistic Regression | **Random Forest (chọn)** |
|---|---|---|
| Tham số | C = 10, không trọng số lớp | 300 cây, không giới hạn độ sâu, `min_samples_leaf` 5, không trọng số lớp |
| Background làm mẫu âm | 100% | 100% |
| Ngưỡng xác suất | 0,30 | 0,10 |
| Precision / Recall / F1 | 0,944 / 0,090 / 0,165 | 0,965 / 0,371 / **0,536** |
| Background validation bị báo | 4,6% | 4,1% |
| Scenario 4 (Rbot): P / R / F1 | 0,988 / 0,473 / 0,640 | 0,997 / 0,841 / 0,912 |
| Scenario 13 (Virut): P / R / F1 | 0,898 / 0,046 / 0,088 | 0,956 / 0,317 / 0,476 |
| Tỷ lệ báo nhầm máy bình thường | 0,1–0,5% | 0,1–1,3% |

**Chọn Random Forest.** LR không tách được bot khỏi máy lạ bằng một mặt phẳng: muốn giữ Background
≤ 5% thì nó gần như không báo gì.

Đặc trưng quan trọng nhất của RF (giảm Gini): `so_peer` 0,17, `tap_trung_ra` 0,15,
`ty_le_khong_tra_loi_ra` 0,11, `so_peer_ra` 0,10, `so_byte_ra` 0,08. Beaconing không nằm trong nhóm
đầu, khớp với nhận xét ở docs/47.

## 4. Đọc kết quả

- Bot **Rbot** (scenario 4) được bắt tốt: gửi tới nhiều đích, nhiều flow không được trả lời.
- Bot **Virut** (scenario 13) phần lớn **trông như một máy Background bình thường**: recall chỉ 0,32
  khi giữ báo động trên máy lạ thấp. Hạ ngưỡng thì bắt thêm Virut nhưng báo cả loạt máy Background.
- Precision cao (0,96) nhưng recall thấp: mô hình chỉ báo khi chắc chắn. Với module chỉ "thể hiện mức
  nghi vấn" (B25), đây là đánh đổi chấp nhận được; nên kết hợp với cảnh báo theo host trong nhiều cửa
  sổ (Chặng 9).
- Validation chỉ có **1 IP bot** (`.165`, hai lần nhiễm khác nhau) và 3 máy bình thường: các con số
  trên có sai số lớn.

## 5. Kiểm thử

- RF học dữ liệu tổng hợp (F1 > 0,9); ngưỡng cao hơn 1 thì không báo gì.
- Thêm Background làm mẫu âm: đúng số mẫu, luôn mang nhãn `normal_host`.
- Lưới thử đủ các tỷ lệ Background; cấu hình chọn có ngưỡng trong lưới và Background bị báo ≤ giới hạn.
- Đánh giá tách theo scenario, có tỷ lệ Background bị báo; lưu rồi nạp lại cho cùng điểm; từ chối file
  không phải mô hình botnet.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Ngưỡng xác suất | Mô hình báo bot khi xác suất ≥ ngưỡng |
| Mẫu âm yếu | Mẫu coi như bình thường khi học dù chưa được kiểm chứng chắc chắn |
| Background bị báo | Phần cửa sổ của host Background bị đoán là bot; không phải tỷ lệ báo nhầm vì có thể có bot thật |
| Học danh tính máy | Mô hình nhớ đặc điểm riêng của vài máy thay vì học hành vi chung |
| Rbot, Virut | Hai họ bot trong validation: điều khiển qua IRC và tấn công; lây file và spam |
| Precision, Recall, F1 | Tỷ lệ báo đúng; tỷ lệ bắt được; trung bình điều hòa |
| Giảm Gini | Độ quan trọng của đặc trưng trong Random Forest |
