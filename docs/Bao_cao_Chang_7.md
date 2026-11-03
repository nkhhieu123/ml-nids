# Báo cáo Chặng 7 — Phân loại tấn công đa lớp

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 02–03/11/2026 |
| Trạng thái | Xong 6/6 task |
| Chặng trước | [Bao_cao_Chang_6.md](Bao_cao_Chang_6.md) |

## 1. Tóm tắt

Chặng 7 xây module **phân loại tấn công**: với mỗi cửa sổ host 10 giây, đoán một trong ba lớp
`benign`, `port_scan`, `dos`. So sánh Logistic Regression (mức chuẩn) với Random Forest trên cùng
dữ liệu, cùng tiền xử lý.

```
Cửa sổ host ─> chốt nhãn 3 lớp ─> bỏ trùng train ─> log, điền trống, chuẩn hóa ─> LR / RF ─> chọn trên validation ─> test
(Chặng 4–5)    (T01)              (T02)             (fit trên train)              (T02, T03)  (T04)                  (T05)
                                                                                                    phân tích, lưu (T06)
```

**Bảng so sánh hai mô hình** trên test CIC-IDS2017 (68 902 cửa sổ: benign 67 713, dos 727,
port_scan 462), tham số chọn trên validation, đo test một lần:

| | Logistic Regression | **Random Forest (chọn)** |
|---|---|---|
| Macro-F1 validation | 0,883 | 0,913 |
| **Macro-F1 test** | 0,766 (0,747–0,784) | **0,831 (0,815–0,846)** |
| port_scan: P / R / F1 | 0,923 / 0,336 / 0,492 | 0,967 / 0,448 / 0,612 |
| dos: P / R / F1 | 0,901 / 0,737 / 0,811 | 0,969 / 0,813 / 0,884 |
| benign: F1 | 0,996 | 0,997 |
| Benign bị báo tấn công | 0,047% | 0,031% |

RF hơn LR ở 100% trong 1 000 lần bootstrap ghép cặp trên test (hiệu +0,065, khoảng 95%
[+0,051; +0,079]).

**Tiêu chí nghiệm thu:** có bảng so sánh hai mô hình trên cùng bài toán. Brute-force, exploit hoặc
DDoS chỉ thêm khi có dữ liệu và kiểm thử tương ứng.

| Tiêu chí | Đáp ứng |
|---|---|
| Bảng so sánh hai mô hình trên cùng bài toán | Bảng trên và docs/43 mục 1: cùng mẫu, cùng train, cùng bộ tiền xử lý, cùng test; mỗi mô hình chọn tham số bằng cùng quy trình trên validation; kèm khoảng tin cậy và bootstrap ghép cặp |
| Chỉ thêm lớp khi có dữ liệu và kiểm thử | Giữ ba lớp. DDoS (một đợt), Heartbleed, Bot bị loại có lý do (QĐ-033); brute-force và exploit chưa có dữ liệu. Các đợt bị loại được dùng để xem mô hình phản ứng ra sao (mục 4) |

## 2. Các task

| Task | Nội dung | Tài liệu |
|---|---|---|
| C07-T01 | Chốt nhãn thực tế: Benign, PortScan, DoS | [39_phan_loai_nhan.md](39_phan_loai_nhan.md) |
| C07-T02 | Logistic Regression làm mô hình đối chiếu | [40_phan_loai_lr.md](40_phan_loai_lr.md) |
| C07-T03 | Random Forest | [41_phan_loai_rf.md](41_phan_loai_rf.md) |
| C07-T04 | Chọn tham số và mô hình bằng validation | [42_phan_loai_chon.md](42_phan_loai_chon.md) |
| C07-T05 | Đánh giá macro-F1, chỉ số từng lớp và confusion matrix | [43_phan_loai_danh_gia.md](43_phan_loai_danh_gia.md) |
| C07-T06 | Phân tích nhầm lẫn và lưu artifact | [44_phan_loai_phan_tich.md](44_phan_loai_phan_tich.md) |

Mã nguồn: `src/nids/classifier.py` (thêm `balance_indices` trong `src/nids/preprocessing.py`).
Kiểm thử: `tests/test_classifier.py`.

## 3. Kết quả từng task

### 3.1. C07-T01 — Nhãn

- Đơn vị là **cửa sổ host** của thứ Tư và thứ Sáu; chỉ nhãn chắc chắn (`khop`, `khong_khop`).
- Train 166 233 (port_scan 671, dos 2 270), validation 54 647 (**port_scan chỉ 50**), test 68 902.
- Bên tấn công và nạn nhân đều mang nhãn tấn công, mỗi bên khoảng một nửa.
- Bị loại: Bot 11 616, Heartbleed 1 170, DDoS 1 132 cửa sổ (ba tập cộng lại).

### 3.2. C07-T02 — Logistic Regression

- Với cân bằng lớp mặc định (giảm benign xuống 10 lần lớp ít nhất, `class_weight = balanced`):
  macro-F1 validation chỉ **0,418**; 13% cửa sổ benign bị báo tấn công.
- Nguyên nhân: train cân bằng có 37% tấn công, thực tế chỉ khoảng 1,3%, nên mô hình đánh giá quá cao
  khả năng gặp tấn công. Bỏ cân bằng: 0,883.
- Vì vậy cân bằng lớp trở thành tham số chọn trên validation (QĐ-034).

### 3.3. C07-T03 — Random Forest

- Cùng vấn đề với cân bằng mặc định (0,421; thuộc lòng train 1,0).
- Không cân bằng: **0,911**, hơn LR chủ yếu nhờ recall dos (0,93 so với 0,79).
- RF tách được nhiều cụm trong một lớp (bên tấn công và nạn nhân), điều LR tuyến tính làm kém.

### 3.4. C07-T04 — Chọn trên validation

- Hai bước: tỷ lệ giảm mẫu × `class_weight`, rồi tham số còn lại; chỉ số macro-F1 validation.
- Cả hai mô hình tốt nhất khi **không cân bằng, không trọng số**.
- RF: 300 cây, `max_depth` 20, `min_samples_leaf` 3, sqrt (0,913); các tham số cây gần như không
  ảnh hưởng (0,89–0,913). LR: C = 1 (0,883).
- Bootstrap ghép cặp trên validation: RF hơn LR ở 99,7% lần lấy lại. **Chọn RF** (QĐ-035).

### 3.5. C07-T05 — Test

- Bảng so sánh ở mục 1. Lỗi gần như chỉ là **bỏ sót**; báo nhầm benign rất ít (RF 21 cửa sổ,
  khoảng 0,4–0,5 đợt mỗi giờ, so với khoảng 17 đợt mỗi giờ của Gaussian ở Chặng 6).
- Theo đợt (recall RF): slowloris 0,956, Hulk 0,805, GoldenEye 0,667 (24 cửa sổ), Slowhttptest
  0,605, PortScan 0,448.
- **Port_scan:** cửa sổ có ≥ 20 lần thử TCP được bắt **97,8%**; 282/462 cửa sổ test gần như không
  có lần thử TCP nào, chỉ được bắt 11%.
- Mẫu test trùng train gần như toàn benign; bỏ đi thì macro-F1 RF 0,834, gần như không đổi.

### 3.6. C07-T06 — Phân tích nhầm lẫn, artifact

- **Port_scan bỏ sót là quét UDP và SCTP.** Phần test của đợt quét có các lượt Nmap kiểu UDP (92
  cửa sổ) và SCTP (122 cửa sổ, train không có cửa sổ nào). Đặc trưng "lần thử" và "không hoàn tất"
  chỉ đếm TCP, nên các lượt này trông như benign (recall 0,01–0,02).
- **DoS bỏ sót** là pha giữ kết nối của Slowhttptest và khoảng nghỉ của Hulk: lưu lượng thấp hơn
  khoảng 5 lần cửa sổ bắt được, khoảng một kết nối mới.
- **Tấn công chưa học:** DDoS được đoán `dos` 204/206; Heartbleed trông benign; RF báo 224/3 554
  cửa sổ Bot là `port_scan`.
- **Hoán vị:** RF dựa vào `packets_out`, `dst_hosts`, `incomplete_ratio_in`, `bytes_out`, và ít
  phụ thuộc vào một đặc trưng riêng lẻ; LR phụ thuộc mạnh vào từng hệ số.
- **Artifact:** `models/phan_loai_rf_windows.joblib` và `phan_loai_lr_windows.joblib` gồm bộ tiền
  xử lý và mô hình, kèm `.json` metadata. Nạp lại ở tiến trình khác cho **đúng cùng** kết quả test.
  Dự đoán thứ Hai (không tấn công, chưa dùng khi học): 15/152 513 cửa sổ bị báo (0,01%).

## 4. So với Gaussian (Chặng 6)

| | Gaussian (anomaly) | Random Forest (phân loại) |
|---|---|---|
| Học từ | Chỉ traffic bình thường | Cả benign lẫn tấn công có nhãn |
| Báo nhầm benign | 1,42% (khoảng 17 đợt/giờ) | 0,031% (khoảng 0,5 đợt/giờ) |
| Tấn công đã biết (PortScan TCP, DoS HTTP) | Recall 0,13–0,91 theo đợt | Recall 0,45–0,96 theo đợt (quét TCP 0,98) |
| Tấn công chưa biết | Báo được một phần (Bot 0,86, DDoS 0,50) | Gán vào lớp gần nhất (DDoS → dos) hoặc bỏ qua (Heartbleed, phần lớn Bot) |

Hai module bù cho nhau: RF chính xác với loại đã học, Gaussian bắt được một phần cái chưa học. Chặng
9 sẽ kết hợp.

## 5. Sửa ở chặng trước

- Cân bằng lớp 10 lần của QĐ-028 không dùng cho Chặng 7 (thay bởi QĐ-034, QĐ-035).
- Thêm `balance_indices` vào `preprocessing.py` để lọc cả bảng gốc khi giảm mẫu; `balance` cũ giữ
  nguyên hành vi.
- Tài liệu việc còn thiếu đổi thành `docs/Viec_con_thieu.md` (Chặng 1–7), việc đang dở ghi ở đầu.

## 6. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-033 | Ba lớp trên cửa sổ host; DDoS, Heartbleed, Bot chưa thành lớp | Đã chốt cho CIC-IDS2017 |
| QĐ-034 | LR làm mức chuẩn; tỷ lệ cân bằng và trọng số lớp chọn trên validation | Đã chốt |
| QĐ-035 | Chọn Random Forest, không cân bằng lớp | Đã chốt cho CIC-IDS2017 |

Cấu hình mới: mục `classifier` trong `config/default.yaml` (tham số khởi đầu của hai mô hình, lưới
tìm `search`).

## 7. Kiểm thử

`python -m unittest discover -s tests`: **316/316 ca đạt** (Chặng 6 kết thúc ở 295).
`tests/test_classifier.py` có 21 ca:

| Task | Số ca | Nội dung |
|---|---|---|
| T01 | 4 | Số mẫu theo tập khớp nhãn; mẫu loại và mơ hồ; cảnh báo lớp ít mẫu; vai trò host |
| T02 | 4 | Bỏ trùng và giảm mẫu chỉ ở train; chỉ số tính tay; LR học dữ liệu ba lớp; mô hình lạ bị từ chối |
| T03 | 2 | RF học dữ liệu ba lớp, cùng seed cùng kết quả |
| T04 | 3 | Hai bước tìm; chọn mô hình; bootstrap nhận chênh lệch |
| T05 | 3 | Đánh giá theo phiên, đợt, trùng train; so vector có ô trống; khoảng tin cậy |
| T06 | 5 | Bảng lỗi, hồ sơ, hoán vị; kiểu flow quét; tấn công chưa học; lưu/nạp; chuỗi dòng lệnh đầy đủ |

## 8. Cách chạy

```bash
cd src
F=../output/features
python -m nids.classifier nhan $F/cic17_wednesday $F/cic17_friday --out ../docs/hinh
python -m nids.classifier chon $F/cic17_wednesday $F/cic17_friday --out ../docs/hinh        # khoảng 20 phút
python -m nids.classifier danh-gia $F/cic17_wednesday $F/cic17_friday --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
python -m nids.classifier huan-luyen $F/cic17_wednesday $F/cic17_friday --chon ../docs/hinh/phan_loai_chon.json
python -m nids.classifier phan-tich $F/cic17_wednesday $F/cic17_friday \
    --model ../models/phan_loai_rf_windows.joblib --model ../models/phan_loai_lr_windows.joblib --hoan-vi --out ../docs/hinh
python -m nids.classifier du-doan $F/cic17_monday --khong-nhan \
    --model ../models/phan_loai_rf_windows.joblib --out ../output/du_doan_phan_loai.csv
```

## 9. Điểm cần lưu ý

1. **Recall port_scan 0,45 không có nghĩa mô hình kém với quét TCP** (bắt 97,8%). Mô hình chưa bắt
   được quét UDP/SCTP vì đặc trưng chỉ đếm TCP. Sửa cần đặc trưng mới hoặc chia lại theo lượt Nmap
   (làm lại Chặng 4–5, chọn lại trên validation); chưa sửa để không chỉnh theo kết quả test.
2. **Validation port_scan chỉ 50 cửa sổ**, toàn quét TCP, nên không báo trước được vấn đề UDP/SCTP.
   Đây là lý do macro-F1 giảm từ 0,913 (validation) xuống 0,831 (test).
3. **DoS HTTP chậm** (Slowhttptest) bị bỏ sót nhiều: cửa sổ 10 giây quá ngắn để thấy kết nối giữ lâu.
4. **DoS kiểu SYN chưa có dữ liệu** (lab); chưa biết mô hình có nhận ra SYN flood không.
5. **Một nguồn, một nạn nhân, cùng ngày.** Phải đo lại trên dữ liệu lab (Chặng 11).
6. **Bảng đặc trưng xuất khi mã chưa commit** (docs/Viec_con_thieu.md mục 0): kết quả cần kiểm tra
   lại sau khi xuất lại.

## 10. Việc tiếp theo

**Chặng 8 — Botnet/topology** (cần CTU-13):
- Tải 13 file `.binetflow` (đang dở, docs/Viec_con_thieu.md mục 0) và chốt scenario validation.
- Đặc trưng beaconing và đồ thị giao tiếp trên cửa sổ dài; host nghi vấn và cấu trúc tập trung/ngang hàng.

Song song: dựng lab; cân nhắc thêm đặc trưng quét UDP/SCTP và đặc trưng kết nối giữ lâu cho DoS chậm.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Phân loại đa lớp | Đoán một trong nhiều nhãn cho mỗi mẫu |
| Logistic Regression, Random Forest | Mô hình tuyến tính; tập nhiều cây quyết định |
| Mức chuẩn (baseline) | Mô hình đơn giản để so; mô hình phức tạp phải hơn nó |
| Macro-F1 | Trung bình F1 các lớp, mỗi lớp nặng như nhau |
| Precision, Recall, F1 | Tỷ lệ báo đúng; tỷ lệ bắt được; trung bình điều hòa của hai số |
| Confusion matrix | Bảng đếm mẫu theo nhãn thật và nhãn dự đoán |
| Cân bằng lớp, `class_weight` | Giảm mẫu lớp đông trong train; nhân trọng số lớp ít mẫu |
| Bootstrap ghép cặp | Lấy lại mẫu nhiều lần, so hai mô hình trên cùng mẫu lấy lại |
| Bỏ sót, báo nhầm | Tấn công bị đoán là benign; benign bị đoán là tấn công |
| UDP, SCTP | Giao thức khác TCP; Nmap có kiểu quét riêng cho từng giao thức |
| Hoán vị (permutation importance) | Xáo trộn một đặc trưng rồi đo chỉ số giảm bao nhiêu |
| Artifact | File kết quả cần giữ: mô hình, metadata, bảng số liệu, hình |
| DDoS, Heartbleed, Bot | Từ chối dịch vụ nhiều nguồn; khai thác lỗi OpenSSL; máy bị điều khiển từ xa |
| Brute-force, exploit | Dò mật khẩu; khai thác lỗ hổng phần mềm |
