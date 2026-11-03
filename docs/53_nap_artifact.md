# C09-T01 — Bộ nạp artifact và kiểm tra schema

Mã nguồn: `load_artifacts`, `check_artifact`, `check_table`, `check_all` trong `src/nids/pipeline.py`.
Cấu hình: mục `pipeline.models` trong `config/default.yaml`. Kiểm thử: `tests/test_pipeline.py`.

```bash
cd src
python -m nids.pipeline kiem-tra [--out ../output/kiem_tra_artifact.json]
```

Mã thoát 0 nếu hợp lệ, 1 nếu có lỗi; pipeline (C09-T02) gọi cùng bước này trước khi chạy.

## 1. Artifact của ba module

| Module | File (mặc định) | Đầu vào | Gồm |
|---|---|---|---|
| `anomaly` | `models/gaussian_windows.joblib` | Cửa sổ host 10 giây (bảng `windows`) | Phép biến đổi, trung bình, hiệp phương sai, ngưỡng d² (Chặng 6) |
| `attack_classification` | `models/phan_loai_rf_windows.joblib` | Cửa sổ host 10 giây | Bộ tiền xử lý và Random Forest 3 lớp (Chặng 7) |
| `botnet_topology` | `models/botnet_rf.joblib` | Host–cửa sổ 120 giây (đặc trưng đồ thị và beaconing) | Tiền xử lý, Random Forest, ngưỡng xác suất (Chặng 8) |

Mỗi file `.joblib` có file `.json` cùng tên ghi đặc trưng, ngưỡng, tham số, commit mã nguồn và thời
điểm tạo. Bộ tiền xử lý nằm **trong** mô hình, nên không thể ghép nhầm mô hình với một phép biến đổi khác.

## 2. Kiểm tra gì

| Kiểm tra | Mức khi sai |
|---|---|
| File tồn tại, nạp được, đúng lớp của dự án (`load_model` của từng module từ chối lớp khác) | Dừng ngay |
| Mọi đặc trưng mô hình cần đều là cột đặc trưng của schema đầu vào: bảng `windows` theo `schema_document()` (QĐ-024), hoặc 24 đặc trưng của `nids.graph_features` | Lỗi |
| Có file `.json`; danh sách đặc trưng trong `.json` trùng với mô hình | Lỗi |
| Gaussian và botnet có ngưỡng | Lỗi |
| Lớp của bộ phân loại nằm trong tập nhãn đã chốt (`scope.ATTACK_LABELS`) | Lỗi |
| Mô hình tạo khi `src/` hoặc `config/` có sửa chưa commit | Cảnh báo |
| Metadata không ghi commit | Cảnh báo |

Khi chạy, `check_table` còn kiểm tra **bảng đầu vào thật** có đủ cột mô hình cần, trước khi tính
điểm (QĐ-043).

## 3. Kết quả trên artifact hiện có

| Module | Lớp | Đặc trưng | Ngưỡng | Vấn đề |
|---|---|---|---|---|
| `anomaly` | `GaussianDetector` | 14 | d² = 64,65 | Cảnh báo: tạo khi mã chưa commit |
| `attack_classification` | `AttackClassifier` | 20 | (lớp có xác suất lớn nhất) | Cảnh báo: như trên |
| `botnet_topology` | `BotnetDetector` | 24 | 0,10 | Cảnh báo: như trên |

Không có lỗi. Cả ba mô hình được huấn luyện lúc code của task đang viết chưa commit.

**Đã sửa (03/11/2026)**: huấn luyện lại cả ba từ commit `7536876` (cùng dữ liệu, cùng seed). Kết quả
trùng với trước (Gaussian ngưỡng 64,65, F1 validation 0,700; phân loại macro-F1 validation 0,913;
botnet F1 validation 0,536, ngưỡng 0,10). `kiem-tra` không còn cảnh báo nào.

## 4. Kiểm thử

- Artifact hợp lệ không có vấn đề.
- Cột lạ và thiếu ngưỡng là lỗi; mã chưa commit chỉ là cảnh báo; `.json` khác mô hình, lớp lạ, thiếu
  `.json` đều được báo.
- Bảng thiếu cột thì báo lỗi.
- Nạp mô hình thật từ đường dẫn cấu hình; file không tồn tại thì dừng.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Artifact | File kết quả đã lưu để dùng lại: mô hình, biến đổi, ngưỡng, metadata |
| Schema | Mô tả cột của bảng: tên, kiểu, vai trò |
| Pipeline | Chuỗi bước xử lý nối tiếp, từ PCAP tới cảnh báo |
| Metadata | Thông tin đi kèm mô hình: học từ đâu, tham số gì, mã nguồn nào |
| Commit | Một phiên bản mã nguồn đã ghi vào git |
| joblib | Thư viện lưu và nạp đối tượng Python |
