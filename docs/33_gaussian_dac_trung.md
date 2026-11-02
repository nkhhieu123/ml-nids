# C06-T01 — Chọn đặc trưng và lấy mẫu bình thường trong train

Mã nguồn: `normal_train`, `select_features`, `fill_empty` trong `src/nids/gaussian.py`. Kiểm thử:
`tests/test_gaussian.py`. Quyết định: QĐ-029 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

Module anomaly học **phân bố của hành vi bình thường** bằng một Gaussian đa biến, rồi coi
mẫu nằm quá xa phân bố đó là bất thường. Task này chọn đơn vị dữ liệu, mẫu để học và các
đặc trưng.

## 1. Đơn vị: cửa sổ host

Dùng **bảng cửa sổ host** (10 giây, bước 2 giây), không dùng bảng flow:
- Cảnh báo của hệ thống theo cửa sổ (docs/02).
- Bảng flow có quá nhiều mẫu trùng, đánh giá sẽ đẹp giả (docs/30 mục 5).
- Bất thường kiểu quét hay DoS thể hiện ở hành vi của host trong một khoảng thời gian, không
  ở từng kết nối.

## 2. Mẫu bình thường trong train

Gaussian chỉ học trên mẫu **`normal` của tập train** (`label_anomaly = normal`, `split =
train`); không mẫu tấn công, mơ hồ hay của validation/test nào được dùng.

| Lựa chọn | Mẫu | Ghi chú |
|---|---|---|
| Chỉ thứ Hai (QĐ-028, mặc định) | 88 929 | Ngày không có tấn công nên chắc chắn sạch |
| Normal của train cả ba ngày | 252 221 | Thêm phần bình thường của thứ Tư, thứ Sáu |

Cả hai đều không rò rỉ: chỉ lấy train. Dùng thêm hai ngày có thể giúp mô hình hiểu dao động
bình thường giữa các ngày, nhưng nhãn `normal` của hai ngày đó phụ thuộc lịch tấn công. Lựa
chọn cuối được quyết định **trên validation** ở C06-T04, không chọn trước.

Không lấy mẫu con: 88 929 mẫu đủ nhỏ để học trọn.

## 3. Quy tắc chọn đặc trưng

Ứng viên là 20 đặc trưng có vai trò `dac_trung` của bảng cửa sổ (QĐ-024). Các quy tắc chạy
**trên mẫu train**, theo thứ tự, nên chạy lại trên dữ liệu lab vẫn cho cách chọn nhất quán:

| Quy tắc | Lý do |
|---|---|
| Bỏ cột trống quá 50% trong train | Gaussian cần giá trị ở mọi cột. Thông tin của cột tỷ lệ đã có trong các cột đếm |
| Cột trống mang nghĩa "không có gì" thì điền 0 | `dst_port_entropy` trống khi host không gửi gói TCP/UDP nào trong vai client: không có độ đa dạng cổng nào |
| Bỏ cột bằng tổng các cột khác | `incomplete_out` = `no_reply_out` + `rejected_out` + `half_open_out`; giữ cả bốn thì ma trận hiệp phương sai **suy biến chắc chắn** |
| Bỏ cột hằng số trong train | Phương sai bằng 0 |
| Trong mỗi cặp tương quan Spearman \|r\| ≥ 0,95, bỏ cột đứng sau | Hai cột gần như cùng thông tin làm hiệp phương sai gần suy biến (docs/31 mục 5) |

Giữ ba thành phần thay vì tổng `incomplete_out`, vì chúng phân biệt được kiểu không hoàn tất:
không trả lời, bị từ chối, hay bắt tay dở.

## 4. Kết quả

Trên 88 929 cửa sổ normal của train thứ Hai:

| Bỏ | Lý do |
|---|---|
| `incomplete_ratio_out` | Trống 70,4% |
| `incomplete_ratio_in` | Trống 95,1% |
| `incomplete_out` | Bằng tổng `no_reply_out` + `rejected_out` + `half_open_out` |
| `bytes_out` | Spearman 0,965 với `packets_out` |
| `bytes_in` | Spearman 0,958 với `packets_in` |
| `dst_host_ports` | Spearman 0,991 với `dst_hosts` |

**14 đặc trưng được chọn:** `packets_out`, `packets_in`, `dst_hosts`, `dst_ports`,
`new_conn_out`, `src_hosts`, `new_conn_in`, `dst_port_entropy`, `tcp_attempts_out`,
`no_reply_out`, `rejected_out`, `half_open_out`, `tcp_attempts_in`, `incomplete_in`.

Fit trên normal của train cả ba ngày (252 221 mẫu) cho **đúng cùng 14 đặc trưng**, với hệ số
tương quan gần như cũ (0,957; 0,952; 0,988), nên cách chọn ổn định.

**Đặc điểm cần chú ý cho các task sau** (đo trên train thứ Hai):

| Đặc trưng | Bằng 0 | Ghi chú |
|---|---|---|
| `incomplete_in` | gần 100% (chỉ 2 giá trị khác nhau) | Phương sai gần 0 |
| `half_open_out`, `rejected_out` | 99,6% | |
| `no_reply_out` | 98,8% | |
| `tcp_attempts_in` | 95,1% | |
| `new_conn_in` | 83% | |

Các cột về kết nối không hoàn tất gần như luôn bằng 0 khi bình thường. Đó chính là tín hiệu
bất thường mạnh (quét cổng), nhưng cũng làm phân bố rất xa dạng chuông và làm hiệp phương sai
gần suy biến. C06-T02 và C06-T03 xử lý hai vấn đề này.

## 5. Kiểm thử

Kiểm thử tự động (4 ca): các quy tắc bỏ cột trống, cột tổng, cột hằng số, cột tương quan; cột
tổng được giữ khi thiếu thành phần; điền 0 chỉ cho cột được phép; mẫu normal của train theo
phiên.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Gaussian đa biến | Mô hình mô tả dữ liệu bằng trung bình và ma trận hiệp phương sai của nhiều đặc trưng cùng lúc; mẫu càng xa trung bình (theo hình dạng phân bố) càng bất thường |
| Phát hiện bất thường | Học dữ liệu bình thường rồi báo các mẫu khác xa nó, không cần biết trước loại tấn công |
| Ma trận hiệp phương sai | Bảng đo từng cặp đặc trưng biến thiên cùng nhau ra sao |
| Suy biến | Ma trận không nghịch đảo được, khi có đặc trưng là tổ hợp của đặc trưng khác hoặc có phương sai 0 |
| Tương quan Spearman | Mức hai đặc trưng cùng tăng giảm theo thứ hạng, từ −1 đến 1 |
| Phương sai | Mức dao động của một đặc trưng quanh trung bình |
| Dạng chuông | Hình phân bố chuẩn: đối xứng, nhiều mẫu ở giữa, ít dần hai bên |
| Mẫu con | Một phần mẫu lấy ngẫu nhiên từ tập lớn |
