# C05-T07 — Tiền xử lý; chỉ fit và cân bằng lớp trên train

Mã nguồn: `src/nids/preprocessing.py`. Kiểm thử: `tests/test_preprocessing.py`. Quyết định:
QĐ-028 trong [03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

```bash
python -m nids.preprocessing --table windows --module attack_classification \
    output/features/cic17_monday output/features/cic17_wednesday output/features/cic17_friday
```

Lệnh lưu bộ tiền xử lý đã fit vào `models/preprocess_<bảng>_<module>.joblib`, kèm file `.json`
ghi thông tin (không lên git). Trong mã, `prepare(...)` trả về `X_train`, `y_train`,
`X_validation`, `y_validation`, `X_test`, `y_test` và bộ tiền xử lý.

## 1. Các bước

Thứ tự: **chọn mẫu → bỏ trùng trên train → fit trên train → biến đổi cả ba tập → cân bằng lớp
trên train.**

### 1.1. Chọn mẫu theo module

| Module | Phiên | Mẫu dùng | Nhãn |
|---|---|---|---|
| `attack_classification` | Thứ Tư, thứ Sáu (QĐ-009) | Trạng thái `khop` hoặc `khong_khop`, trong ba lớp | `label_attack` |
| `anomaly` | Thứ Hai, thứ Tư, thứ Sáu | Có nhãn `normal` hoặc `anomaly` | `label_anomaly` |

Với `anomaly`, bộ tiền xử lý (và Gaussian ở Chặng 6) **chỉ fit trên mẫu `normal` của train thứ
Hai** (`preprocess.anomaly_fit_sessions`, docs/08). Validation và test gồm cả ba phiên, có cả
`anomaly`. Mẫu `mo_ho`, `bo` không dùng; mẫu `loai` chỉ dùng cho `anomaly`.

Chỉ lấy cột có vai trò `dac_trung` trong schema (QĐ-024): 44 cột ở bảng flow, 20 cột ở bảng
cửa sổ. IP, cổng, thời điểm, giao thức không vào mô hình.

### 1.2. Bỏ mẫu trùng trên train (chỉ module phân loại)

Bỏ mẫu trùng hệt cả đặc trưng lẫn nhãn (`preprocess.drop_train_duplicates`). Lý do: 98,9% flow
`port_scan` là bản sao (docs/30 mục 5), nên nếu không bỏ, số lượng 104 614 chỉ là ảo và phép
cân bằng ở mục 1.5 không có tác dụng.

**Không bỏ trùng cho `anomaly`.** Gaussian ước lượng phân bố: tần suất là thông tin. Cửa sổ nhàn
rỗi lặp lại nhiều chính là trạng thái bình thường phổ biến nhất của mạng.

### 1.3. Biến đổi log

`sign(x) · log(1 + |x|)` cho các đặc trưng có đơn vị gói, byte, giây, host, cổng, kết nối, lần
thử: chúng lệch phải rất mạnh (docs/31). Tỷ lệ (0–1) và entropy giữ nguyên. Phép biến đổi này
không có tham số phải học.

### 1.4. Điền ô trống và chuẩn hóa

Dùng `Pipeline` của scikit-learn, **fit trên train**:

1. `SimpleImputer(strategy="median", add_indicator=True)`: điền **trung vị của train**, và thêm
   một cột 0/1 (`<tên>__trong`) cho mỗi cột có ô trống trong train. Ô trống có ý nghĩa (flow
   một gói không có khoảng cách, docs/21), nên phải giữ lại thông tin đó.
2. `StandardScaler`: trừ trung bình, chia độ lệch chuẩn **của train**.

Kết quả: bảng cửa sổ 23 cột (20 + 3 cột đánh dấu), bảng flow 67 cột (44 + 23).

### 1.5. Cân bằng lớp, chỉ trên train

- **Giảm mẫu ngẫu nhiên** mỗi lớp xuống tối đa `preprocess.balance_max_ratio` = 10 lần lớp ít
  nhất (seed lấy từ `random_seed`).
- **Trọng số lớp** kiểu `balanced` tính trên train sau khi giảm, ghi trong metadata, để Chặng 7
  truyền vào mô hình.

**Validation và test giữ nguyên phân bố thật**, vì chúng phải phản ánh tỷ lệ tấn công khi chạy
thật. Bước fit làm trước bước cân bằng, nên tham số chuẩn hóa phản ánh dữ liệu train đầy đủ.

Không dùng SMOTE (sinh mẫu giả): với các đặc trưng đếm rời rạc, mẫu nội suy không tương ứng hành
vi mạng có thật, và lớp ít nhất đã đủ vài trăm mẫu.

## 2. Kết quả trên CIC-IDS2017

| Bộ | Fit trên | Train trước → sau bỏ trùng | Train sau cân bằng | Validation | Test |
|---|---|---|---|---|---|
| Cửa sổ, phân loại | Thứ Tư, thứ Sáu | 165 166 → 86 396 | benign 4 450, dos 2 165, port_scan 445 | benign 45 506, dos 648, port_scan 50 | benign 79 077, dos 727, port_scan 462 |
| Flow, phân loại | Thứ Tư, thứ Sáu | 551 651 → 424 214 | benign 11 610, dos 11 610, port_scan 1 161 | benign 110 203, dos 30 768, port_scan 22 054 | benign 143 768, dos 33 320, port_scan 18 553 |
| Cửa sổ, anomaly | Thứ Hai (normal) | 88 929 (không bỏ trùng) | normal 88 929 | normal 76 515, anomaly 4 094 | normal 111 352, anomaly 5 858 |
| Flow, anomaly | Thứ Hai (normal) | 228 512 (không bỏ trùng) | normal 228 512 | normal 185 906, anomaly 76 614 | normal 220 000, anomaly 60 600 |

Trọng số lớp sau cân bằng: bảng cửa sổ benign 0,53, dos 1,09, port_scan 5,29; bảng flow benign
0,70, dos 0,70, port_scan 7,00.

Giảm mẫu bỏ nhiều benign: bảng cửa sổ còn 4 450 / 83 786 mẫu benign khác nhau. Tỷ lệ 10 chỉnh
được trong cấu hình; Chặng 7 sẽ kiểm tra có cần giữ nhiều hơn không.

## 3. Cách tránh rò rỉ giữa các tập

Tổng hợp mọi biện pháp của Chặng 4–5:

| Nguồn rò rỉ | Biện pháp | Cách kiểm chứng |
|---|---|---|
| Hai cửa sổ chồng nhau chung gói | Chia theo thời gian; mẫu vắt qua ranh giới bị bỏ; vùng đệm 10 giây (docs/29) | Trên cả ba ngày: **0** cặp mẫu ở hai tập khác nhau chồng thời gian; khoảng cách nhỏ nhất 22 giây (cửa sổ), 20 giây (flow) |
| Test nằm trước train | Trong mỗi khối, train trước, test sau | Theo cách dựng đoạn; có kiểm thử |
| Tham số học từ validation, test | Trung vị, trung bình, độ lệch chuẩn chỉ fit trên train | Tính tay từ train thứ Hai: trùng khớp tham số đã lưu (88 929 mẫu). Kiểm thử: sửa dữ liệu validation/test thì tham số không đổi |
| Cân bằng làm méo tập đánh giá | Chỉ giảm mẫu trên train | Kiểm thử: phân bố lớp test không đổi |
| Bản sao từ train nằm trong test | Bỏ trùng trên train không loại được; đo và báo cáo (docs/30 mục 5), lấy bảng cửa sổ làm đơn vị đánh giá chính | 98,3% flow `port_scan` test trùng train; ở cửa sổ chỉ 0,2% |
| Nhãn lộ qua đặc trưng | IP, cổng, thời điểm có vai trò `dinh_danh`, không vào mô hình; nhãn ở file riêng | Kiểm thử: cột đặc trưng không chứa các cột này |
| Nhìn test khi chọn đặc trưng | EDA chỉ vẽ trên train (docs/31) | Theo cách viết mã |
| Dữ liệu tương lai trong đặc trưng | Đặc trưng chỉ dùng gói đã tới; thời gian quan sát 3 giây có giới hạn (QĐ-021, QĐ-023) | Kiểm thử chạy dần bằng chạy một lần |
| Ngưỡng chọn trên test | Chọn trên validation (Chặng 6, 7) | Thực hiện ở chặng sau |

**Giới hạn không tránh được:**
- Train và test thuộc **cùng một đợt tấn công**, chỉ khác thời điểm, nên giống nhau hơn so với
  một đợt hoàn toàn mới. Kết quả test có thể cao hơn khi gặp công cụ chưa từng thấy; Chặng 7 sẽ
  đo riêng (bỏ hẳn một công cụ khỏi train).
- Cùng một mạng và cùng máy tấn công: kết quả trên CIC không suy ra được cho mạng khác. Kết quả
  CIC và lab báo cáo riêng (docs/06 mục 6).

## 4. Kiểm thử

Kiểm thử tự động (11 ca): sau chuẩn hóa, trung bình train bằng 0 còn test thì không; sửa
validation/test không đổi tham số fit; có cột đánh dấu ô trống, không còn NaN; đặc trưng có log
theo đơn vị; `anomaly` fit trên normal và đúng phiên chỉ định; lọc phiên; bỏ trùng chỉ tác động
train; cân bằng đúng tỷ lệ và không đổi test; hàm giảm mẫu; nạp lại file joblib cho cùng kết quả;
file do **dòng lệnh** lưu nạp được từ tiến trình khác.

Ca cuối được thêm sau khi kiểm tra trên dữ liệu thật phát hiện lỗi: chạy bằng `python -m`,
joblib ghi lớp là `__main__.Preprocessor`, chương trình khác không nạp được.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Tiền xử lý | Các bước đưa dữ liệu về dạng mô hình dùng được |
| Fit | Tính tham số từ dữ liệu, ví dụ trung bình để chuẩn hóa |
| Rò rỉ (leakage) | Thông tin của test lọt vào lúc huấn luyện, làm kết quả đẹp giả |
| Điền ô trống (imputer) | Thay ô trống bằng một giá trị, ở đây là trung vị của train |
| Cột đánh dấu ô trống | Cột 0/1 ghi ô đó vốn trống, để mô hình không mất thông tin |
| Chuẩn hóa (`StandardScaler`) | Đưa mỗi cột về trung bình 0, độ lệch chuẩn 1 |
| Cân bằng lớp | Giảm chênh lệch số mẫu giữa các lớp khi huấn luyện |
| Giảm mẫu (undersampling) | Bỏ ngẫu nhiên bớt mẫu của lớp đông |
| Trọng số lớp | Mô hình phạt nặng hơn khi đoán sai lớp ít mẫu |
| SMOTE | Cách sinh mẫu giả cho lớp ít bằng nội suy giữa các mẫu thật |
| Seed | Số khởi tạo của bộ sinh ngẫu nhiên, để chạy lại ra cùng kết quả |
| joblib | Thư viện lưu đối tượng Python ra file |
| Pipeline | Chuỗi các bước xử lý gộp thành một đối tượng |
| Phân bố thật | Tỷ lệ các lớp đúng như khi hệ thống chạy thật |
