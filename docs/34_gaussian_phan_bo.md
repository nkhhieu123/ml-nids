# C06-T02 — Kiểm tra phân bố và chọn phép biến đổi

Mã nguồn: `GaussianTransform`, `normality_report`, `compare_transforms` trong
`src/nids/gaussian.py`. Kiểm thử: `tests/test_gaussian.py`. Quyết định: QĐ-030 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

```bash
cd src
python -m nids.gaussian phan-bo ../output/features/cic17_monday --fit-session cic17_monday --out ../docs/hinh
```

Lệnh ghi `docs/hinh/gauss_phan_bo.json` (số liệu), `gauss_phan_bo.png` (histogram trước và sau
biến đổi) và `gauss_qq_chi2.png` (QQ của khoảng cách Mahalanobis²).

## 1. Cách kiểm tra

Dữ liệu: 88 929 cửa sổ normal của train thứ Hai, 14 đặc trưng của C06-T01. Ba thước đo:

- **Độ lệch** (skew) của từng cột: 0 khi đối xứng như dạng chuông.
- **Độ nhọn dư** (kurtosis): 0 với phân bố chuẩn; lớn là đuôi dày.
- **So khoảng cách Mahalanobis² (d²) với χ²(14).** Nếu dữ liệu đúng là Gaussian 14 chiều thì d²
  theo phân bố χ² 14 bậc tự do. So phân vị của hai bên kiểm tra **cả mô hình**, không chỉ từng
  cột, và đây chính là điểm số bất thường sẽ dùng ở C06-T04.

## 2. So sánh ba cách

| Cách | \|skew\| trung vị | Trị riêng nhỏ nhất | Chỉ số điều kiện | d² phân vị 50% | 90% | 99% | 99,9% |
|---|---|---|---|---|---|---|---|
| Giữ nguyên | 10,52 | 0,0014 | 2 390 | 2,5 | 19,0 | 175,8 | 918,0 |
| log(1 + x) | 1,97 | 0,053 | 88 | 6,4 | 22,9 | 102,3 | 529,8 |
| **Yeo-Johnson + log (chọn)** | **1,04** | **0,075** | **63** | 6,9 | 22,5 | 97,9 | 533,0 |
| χ²(14) lý thuyết | | | | 13,3 | 21,1 | 29,1 | 36,1 |

Cách chọn:
- **Yeo-Johnson** cho 9 cột liên tục, λ học trên train.
- **log(1 + x)** cho 5 cột có từ 90% giá trị 0 trở lên trong train: `no_reply_out`, `rejected_out`,
  `half_open_out`, `tcp_attempts_in`, `incomplete_in`. Với các cột này, λ học từ vài chục mẫu
  khác 0 rất cực đoan (−48 tới −110), không đáng tin, và không phép lũy thừa nào biến một khối
  dồn tại 0 thành dạng chuông.
- Sau đó chuẩn hóa về trung bình 0, độ lệch chuẩn 1 **theo train**.

Mọi tham số (λ, trung bình, độ lệch chuẩn) học từ train và lưu cùng mô hình.

## 3. Kết quả theo cột

Độ lệch sau biến đổi:

| Nhóm | Cột | Skew |
|---|---|---|
| Gần chuông | `packets_out`, `packets_in`, `dst_hosts`, `dst_ports`, `dst_port_entropy` | −0,02 tới 0,12 |
| Lệch vừa (khối tại 0 còn lại) | `new_conn_out`, `src_hosts`, `tcp_attempts_out`, `new_conn_in` | 0,75 – 1,78 |
| Không gần chuông được | `tcp_attempts_in`, `no_reply_out`, `rejected_out`, `half_open_out` | 5,2 – 21 |
| | `incomplete_in` | 94 (chỉ 1 mẫu khác 0 trong 88 929) |

Hình `docs/hinh/gauss_phan_bo.png` minh họa: `packets_in` thành gần chuông; `new_conn_out` vẫn có
62,6% dồn tại một điểm; `no_reply_out` vẫn là vài cột rời rạc.

## 4. Kết luận về giả định Gaussian

- **Giả định Gaussian không đúng với dữ liệu này, kể cả sau biến đổi.** Phần giữa phân bố khớp
  χ² khá tốt (phân vị 90%: 22,5 so với 21,1), nhưng **đuôi dày hơn rất nhiều**: phân vị 99% là
  98 so với 29, phân vị 99,9% là 533 so với 36 (hình `gauss_qq_chi2.png`).
- Hệ quả: **không thể đặt ngưỡng theo lý thuyết χ²**. Ví dụ ngưỡng χ² 99% = 29,1 sẽ báo động
  khoảng 5% cửa sổ bình thường, gấp 5 lần dự tính. Ngưỡng phải chọn **theo số liệu trên
  validation** (C06-T04).
- Đuôi dày đến từ các cột đếm kết nối không hoàn tất: hầu như luôn 0, thỉnh thoảng có vài lần
  (máy in, dịch vụ không trả lời). Mỗi lần như vậy cho d² rất lớn. Đây là điểm yếu cố hữu: các
  cột này cũng là tín hiệu quét cổng mạnh nhất, nên không bỏ chúng (phân tích đầy đủ ở C06-T05).
- Biến đổi làm hiệp phương sai **ổn định hơn**: trị riêng nhỏ nhất tăng từ 0,0014 lên 0,075, chỉ
  số điều kiện giảm từ 2 390 xuống 63. Ma trận vẫn nghịch đảo được mà không cần xử lý thêm, nhưng
  C06-T03 vẫn thêm bước làm ổn định cho dữ liệu khác (lab).

## 5. Kiểm thử

Kiểm thử tự động (3 ca): chia cột Yeo-Johnson / log theo tỷ lệ 0; sau biến đổi không còn ô trống,
trung bình 0 và độ lệch giảm rõ; tham số không đổi khi biến đổi dữ liệu khác; báo cáo so sánh có
đủ các phân vị.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Phân bố chuẩn (Gaussian) | Phân bố dạng chuông, đối xứng quanh trung bình |
| Độ lệch (skew) | Mức phân bố lệch về một phía; 0 là đối xứng |
| Độ nhọn dư (kurtosis) | Mức đuôi phân bố dày hơn phân bố chuẩn; 0 là bằng |
| Yeo-Johnson | Phép biến đổi lũy thừa có tham số λ, làm phân bố gần dạng chuông; dùng được cả với số 0 và số âm |
| λ (lambda) | Tham số của Yeo-Johnson, học từ train |
| Khoảng cách Mahalanobis | Khoảng cách từ mẫu tới trung bình có tính đến độ dao động và tương quan giữa các đặc trưng |
| χ² (chi bình phương) | Phân bố của d² khi dữ liệu đúng là Gaussian; số bậc tự do bằng số đặc trưng |
| Phân vị | Giá trị mà một tỷ lệ mẫu nằm dưới, ví dụ phân vị 99% |
| QQ | Hình so phân vị thực tế với phân vị lý thuyết; trùng đường chéo là khớp |
| Đuôi dày | Có nhiều giá trị cực lớn hơn phân bố chuẩn dự đoán |
| Trị riêng, chỉ số điều kiện | Đo độ "dẹt" của ma trận hiệp phương sai; trị riêng nhỏ gần 0 hoặc chỉ số điều kiện lớn là gần suy biến |
| Ngưỡng | Mức điểm bất thường mà từ đó trở lên thì báo động |
