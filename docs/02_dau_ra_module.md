# C01-T02 — Đầu ra ba module

Ba module: **anomaly**, **attack classification**, **botnet/topology**. Tên
module và tập nhãn được khai báo trong `src/nids/scope.py`; định dạng cảnh báo
nằm trong `src/nids/alerts.py`.

## 1. Ba module

| Module | Mã (`module`) | Phương pháp | Đầu ra |
|---|---|---|---|
| Anomaly | `anomaly` | Gaussian đa biến học từ traffic bình thường | Bình thường/bất thường và điểm bất thường |
| Attack classification | `attack_classification` | Random Forest, so sánh với Logistic Regression | Nhãn dự đoán: Benign, Port Scan, DoS |
| Botnet/topology | `botnet_topology` | Đặc trưng beaconing và đồ thị giao tiếp | Host nghi vấn; cấu trúc tập trung/ngang hàng |

Ba module chạy song song trên cùng luồng đặc trưng. Module anomaly **không**
là cổng lọc bắt buộc cho hai module còn lại.

Cập nhật 03/11/2026 (QĐ-047): pipeline mặc định chạy chế độ `ket_hop`. Anomaly và phân
loại vẫn chạy độc lập trên mọi cửa sổ; riêng module botnet chỉ kiểm tra host có bất
thường mà bộ phân loại cho là benign, vì khi chạy riêng nó gây phần lớn báo nhầm
(docs/57). Chế độ độc lập hoàn toàn vẫn chọn được (`--che-do doc_lap`).

## 2. Tập nhãn

| Module | Nhãn (`label`) | Nhãn sinh cảnh báo |
|---|---|---|
| `anomaly` | `normal`, `anomaly` | `anomaly` |
| `attack_classification` | `benign`, `port_scan`, `dos` | `port_scan`, `dos` |
| `botnet_topology` (host) | `normal_host`, `suspect_host` | `suspect_host` |
| `botnet_topology` (topology) | `centralized`, `p2p`, `none` | `centralized`, `p2p` |

- Module botnet/topology có hai nhóm đầu ra. Nhóm host đánh giá ở mức
  host–cửa sổ; nhóm topology đánh giá bằng confusion matrix riêng. Hai kết quả
  không gộp vào nhau.
- Cảnh báo botnet thể hiện mức nghi vấn, không khẳng định có mã độc.
- `dos` là DoS từ một nguồn.

## 3. Định dạng cảnh báo

Bản đầu tiên chỉ xuất ra **terminal** và **file CSV** (`output/alerts.csv`).
Mọi module dùng chung một schema:

| Cột | Ý nghĩa |
|---|---|
| `module` | `anomaly`, `attack_classification` hoặc `botnet_topology` |
| `label` | Nhãn dự đoán theo bảng ở mục 2 |
| `window_start`, `window_end` | Cửa sổ quan sát (UTC, ISO 8601) |
| `src_ip` | Host nguồn / host nghi vấn |
| `dst_ip` | Host đích / node trung tâm |
| `score` | Điểm bất thường hoặc xác suất của mô hình |
| `threshold` | Ngưỡng quyết định (nếu có) |
| `run_id` | Mã lần chạy, khớp với nhật ký kịch bản |
| `detail` | Ghi chú thêm |
| `created_at` | Thời điểm phát cảnh báo, dùng để tính độ trễ phát hiện |

Dạng một dòng trên terminal:

```
<created_at> | [module] | LABEL | src -> dst | score=... (ngưỡng ...) | run=... | detail
```

Mặc định chỉ dự đoán là cảnh báo mới được ghi. Bật `log_all` để lưu cả dự đoán
bình thường vào CSV, cần cho việc tính báo động giả và confusion matrix.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Module | Một phần độc lập của hệ thống, làm một việc riêng |
| Anomaly / attack classification / botnet-topology | Phát hiện bất thường / phân loại tấn công / phát hiện botnet và hình dạng mạng giao tiếp |
| Nhãn (label) | Kết quả mà module trả về cho một mẫu, ví dụ `port_scan` |
| Nhãn sinh cảnh báo | Nhãn mà khi module đoán ra thì ghi cảnh báo; nhãn bình thường thì không |
| Host–cửa sổ | Đơn vị đánh giá: một máy trong một đoạn thời gian. Ví dụ máy .41 trong 120 giây đầu là một mẫu |
| Centralized / p2p / none | Tập trung (có máy điều khiển trung tâm) / ngang hàng / không có cấu trúc botnet |
| Confusion matrix | Bảng đếm mỗi lớp thật bị đoán thành lớp nào |
| Schema | Danh sách cột cố định và ý nghĩa từng cột của một bảng dữ liệu |
| UTC | Giờ chuẩn quốc tế, không theo múi giờ; Việt Nam là UTC+7 |
| ISO 8601 | Cách viết ngày giờ chuẩn quốc tế, ví dụ `2026-10-11T12:46:28.876Z`; chữ Z nghĩa là giờ UTC |
| Score, threshold | Điểm của mô hình và ngưỡng; điểm vượt ngưỡng thì cảnh báo |
| run_id | Mã của một lần chạy thử nghiệm, để nối cảnh báo với nhật ký lần chạy |
| Node trung tâm | Máy mà các bot cùng liên lạc tới trong mạng tập trung |
| log_all | Tùy chọn ghi cả dự đoán bình thường, không chỉ cảnh báo |
| Báo động giả | Cảnh báo khi thực ra không có tấn công |
