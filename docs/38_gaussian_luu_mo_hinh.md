# C06-T06 — Lưu mô hình, ngưỡng, tiền xử lý và notebook

Mã nguồn: `save_model`, `load_model`, `model_metadata`, `GaussianDetector.predict_frame` trong
`src/nids/gaussian.py`. Notebook: `notebooks/06_gaussian.ipynb`. Kiểm thử:
`tests/test_gaussian.py`.

## 1. Lệnh

```bash
cd src
F=../output/features
# Fit trên normal của train, chọn phiên fit và ngưỡng trên validation, lưu models/
python -m nids.gaussian huan-luyen $F/cic17_monday $F/cic17_wednesday $F/cic17_friday

# Nạp mô hình đã lưu, đánh giá trên test
python -m nids.gaussian danh-gia $F/cic17_monday $F/cic17_wednesday $F/cic17_friday \
    --model ../models/gaussian_windows.joblib --out ../docs/hinh

# Nạp mô hình đã lưu, dự đoán một bảng cửa sổ chưa gán nhãn (ví dụ bản thu mới)
python -m nids.gaussian du-doan $F/cic17_monday --khong-nhan \
    --model ../models/gaussian_windows.joblib --out ../output/du_doan.csv
```

## 2. Những gì được lưu

`models/gaussian_windows.joblib` (6 KB) là một đối tượng `GaussianDetector` gồm đủ mọi thứ để dự
đoán từ bảng cửa sổ thô:

| Thành phần | Nội dung | Học từ |
|---|---|---|
| Đặc trưng | 14 cột (C06-T01) | Quy tắc trên train |
| Tiền xử lý | Điền 0 cho `dst_port_entropy` trống; Yeo-Johnson (λ từng cột) cho 9 cột; log(1 + x) cho 5 cột; trung bình và độ lệch chuẩn để chuẩn hóa | Train |
| Gaussian | Trung bình μ, hiệp phương sai Σ (Ledoit-Wolf), Σ⁻¹ | Normal của train |
| Ngưỡng | d² = 64,65 | Validation |

Gaussian **dùng phép biến đổi riêng** (`GaussianTransform`), không dùng bộ tiền xử lý chung của
C05-T07 (log, trung vị, chuẩn hóa): Gaussian cần phân bố gần dạng chuông nên cần Yeo-Johnson
(C06-T02). Phép biến đổi nằm **trong** file mô hình, nên không thể nạp nhầm mô hình với một phép
biến đổi khác.

File `models/gaussian_windows.json` đi kèm, đọc được không cần Python:
- danh sách đặc trưng, cột Yeo-Johnson và λ, cột log, tham số chuẩn hóa;
- ngưỡng, cách chọn ngưỡng, phiên fit, số mẫu fit, cột bị bỏ và lý do;
- thông tin hiệp phương sai (hệ số co, chỉ số điều kiện);
- Precision, Recall, F1, FPR trên validation;
- cấu hình mục `gaussian`;
- commit mã nguồn và cờ có sửa chưa commit;
- phiên bản Python, numpy, pandas, scikit-learn, scipy; thời điểm tạo.

Như dữ liệu, mô hình **không đưa lên git** (`models/*` trong `.gitignore`); chạy lại lệnh
`huan-luyen` để tạo.

## 3. Nạp lại để dự đoán

```python
from nids.gaussian import load_model
model = load_model("models/gaussian_windows.joblib")
pred = model.predict_frame(windows)      # cột host, window_start, d2, du_doan
```

Kiểm chứng trên dữ liệu thật:
- Mô hình nạp lại cho **đúng cùng kết quả test** như mô hình trong bộ nhớ (P 0,7334, R 0,727,
  F1 0,7302, FPR 1,42%).
- Điểm d² trên validation trùng khớp tuyệt đối với điểm trước khi lưu.
- Lệnh `du-doan --khong-nhan` chạy trên bảng cửa sổ thứ Hai chưa nhãn: 152 513 cửa sổ, 1,53% bị
  báo.

`load_model` từ chối file không phải `GaussianDetector`. `predict_frame` báo lỗi nếu bảng thiếu
cột đặc trưng hoặc mô hình chưa có ngưỡng; `save_model` không lưu mô hình chưa có ngưỡng.

Như bộ tiền xử lý (docs/32 mục 4), lệnh chạy bằng `python -m` gọi `main` của module đã import, để
joblib ghi lớp là `nids.gaussian.GaussianDetector` chứ không phải `__main__.GaussianDetector`; nhờ
vậy chương trình realtime (Chặng 10) nạp được.

## 4. Notebook

`notebooks/06_gaussian.ipynb` chạy lại toàn bộ Chặng 6 và đã lưu sẵn kết quả:

1. Mẫu normal của train và chọn đặc trưng (T01).
2. So sánh phép biến đổi, hình phân bố và QQ (T02).
3. Huấn luyện, chọn phiên fit và ngưỡng trên validation, đường F1 theo ngưỡng (T03, T04).
4. Lưu, nạp lại, kiểm tra điểm trùng khớp (T06).
5. Đánh giá trên test **bằng mô hình đã nạp lại**: tổng, theo phiên, theo đợt tấn công (T05).
6. Hạn chế của giả định Gaussian: ngưỡng χ², so với Gaussian đường chéo và hỗn hợp 8 Gaussian.

Notebook chỉ gọi hàm trong `src/nids/gaussian.py`, không có mã riêng, nên kết quả trùng với dòng
lệnh. Chạy lại: `pip install -e ".[notebook]"`, mở `notebooks/06_gaussian.ipynb` và chạy tất cả
(khoảng 2–3 phút); cần có bảng đặc trưng, nhãn và tập trong `output/features/`.

## 5. Kiểm thử

Kiểm thử tự động (3 ca):
- lưu rồi nạp lại cho cùng điểm và dự đoán; file `.json` có ngưỡng, đặc trưng, λ;
- từ chối khi thiếu cột hoặc chưa có ngưỡng;
- chạy `huan-luyen` bằng dòng lệnh trên phiên giả lập, nạp mô hình ở tiến trình khác (lớp thuộc
  `nids.gaussian`), rồi chạy `du-doan` bằng dòng lệnh.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| joblib | Thư viện lưu đối tượng Python ra file và nạp lại |
| Nạp lại (load) | Đọc mô hình đã lưu để dùng tiếp mà không cần huấn luyện lại |
| Metadata | Thông tin mô tả đi kèm mô hình: học từ đâu, tham số gì, phiên bản nào |
| Yeo-Johnson, λ | Phép biến đổi làm phân bố gần dạng chuông và tham số của nó |
| Ngưỡng | Mức d² từ đó trở lên thì báo động |
| Notebook | File Jupyter gồm mã, kết quả và giải thích xen kẽ |
| Realtime | Chạy trực tiếp trên lưu lượng đang đến |
| Commit | Một phiên bản mã nguồn đã ghi lại trong git |
