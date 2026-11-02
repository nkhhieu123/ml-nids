# Báo cáo Chặng 5 — Gán nhãn, EDA và chia dữ liệu

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 29/10/2026 – 30/10/2026 |
| Trạng thái | Xong 7/7 task |
| Chặng trước | [Bao_cao_Chang_4.md](Bao_cao_Chang_4.md) |

## 1. Tóm tắt

Chặng 5 biến hai bảng đặc trưng của Chặng 4 thành **dữ liệu sẵn sàng huấn luyện**: có nhãn,
đã kiểm tra, đã chia train/validation/test và có bộ tiền xử lý đã fit.

```
Bảng flow, cửa sổ ─> gán nhãn theo lịch ─> báo cáo, đối chiếu CSV CIC ─> chia theo thời gian ─> kiểm tra ─> EDA ─> tiền xử lý
(Chặng 4)            (T01, T03)             (T02)                        (T04)                  (T05)     (T06)  (T07)
```

Dữ liệu: cả ba ngày CIC-IDS2017 đã chọn (thứ Hai, thứ Tư, thứ Sáu), xuất lại bảng đặc trưng
ngày 29–30/10/2026.

| | Flow | Cửa sổ host |
|---|---|---|
| Tổng | 1 442 894 | 465 393 |
| Dùng được (có tập) | 1 380 528 | 456 259 |

**Tiêu chí nghiệm thu: dữ liệu sẵn sàng huấn luyện, có giải thích cách tránh rò rỉ giữa các
tập.**

| Tiêu chí | Đáp ứng |
|---|---|
| Dữ liệu sẵn sàng huấn luyện | Bốn bộ tiền xử lý (flow/cửa sổ × phân loại/anomaly) đã fit và lưu; `prepare(...)` trả về X, y của ba tập. **Chỉ cho hai module anomaly và phân loại tấn công**, trên CIC-IDS2017 (mục 6) |
| Giải thích cách tránh rò rỉ | Bảng tổng hợp 9 nguồn rò rỉ và biện pháp ở [32_tien_xu_ly.md](32_tien_xu_ly.md) mục 3; kiểm chứng trên dữ liệu thật (mục 3.7 dưới đây) |

## 2. Các task

| Task | Nội dung | Mã nguồn | Tài liệu |
|---|---|---|---|
| C05-T01 | Ghép nhãn từ nguồn và metadata phù hợp | `src/nids/labeling.py`, `config/label_schedule.csv` | [26_gan_nhan.md](26_gan_nhan.md) |
| C05-T02 | Báo cáo mẫu khớp, không khớp và mơ hồ | `src/nids/label_report.py` | [27_bao_cao_nhan.md](27_bao_cao_nhan.md) |
| C05-T03 | Định nghĩa nhãn cho cửa sổ chứa nhiều hành vi | `src/nids/labeling.py` | [28_nhan_cua_so.md](28_nhan_cua_so.md) |
| C05-T04 | Chia train/validation/test theo phiên hoặc scenario | `src/nids/splits.py` | [29_chia_du_lieu.md](29_chia_du_lieu.md) |
| C05-T05 | Kiểm tra thiếu, vô hạn, trùng và phân bố lớp | `src/nids/data_quality.py`, `src/nids/dataset.py` | [30_kiem_tra_du_lieu.md](30_kiem_tra_du_lieu.md) |
| C05-T06 | Vẽ EDA cho các đặc trưng chính | `src/nids/eda.py`, `docs/hinh/` | [31_eda.md](31_eda.md) |
| C05-T07 | Xây dựng tiền xử lý; chỉ fit và cân bằng lớp trên train | `src/nids/preprocessing.py` | [32_tien_xu_ly.md](32_tien_xu_ly.md) |

## 3. Kết quả từng task

### 3.1. C05-T01 — Gán nhãn theo lịch tấn công

- Nguồn nhãn là **lịch tấn công** trong `config/label_schedule.csv`, 9 đợt. Mỗi đợt ghi khung giờ
  địa phương (UTC−3), IP bên tấn công và nạn nhân như thấy trong PCAP (sau NAT), cổng nạn
  nhân và nhãn. Không lấy nhãn từ CSV của CIC (QĐ-009).
- Một flow khớp đợt tấn công khi hai đầu là cặp tấn công, đúng cổng nạn nhân, và thời gian
  chạm khung giờ (nới 60 giây). Bốn trạng thái: `khop`, `loai` (DDoS, Heartbleed, bot: chỉ
  dùng cho anomaly), `mo_ho` (không gán nhãn), `khong_khop` (benign).
- Các đợt bị loại khỏi phân loại vẫn có trong lịch, để flow của chúng không bị gán nhầm là
  benign.
- **Cổng nạn nhân là cần thiết.** Lần chạy đầu có 2 616 flow mơ hồ, trong đó 2 322 là HTTPS
  bình thường của `192.168.10.51` trùng cặp IP với Heartbleed. Chỉ định cổng 444 cho Heartbleed
  thì còn 288.

### 3.2. C05-T02 — Khớp, không khớp, mơ hồ; đối chiếu CSV CIC

| Phiên | Flow | Benign | Tấn công | `loai` | Mơ hồ |
|---|---|---|---|---|---|
| Thứ Hai | 381 707 | 381 707 | 0 | 0 | 0 |
| Thứ Tư | 506 163 | 325 096 | 180 768 `dos` | 11 | 288 |
| Thứ Sáu | 555 024 | 293 215 | 161 268 `port_scan` | 100 529 | 12 |

Mẫu mơ hồ chỉ là 0,02%: đều là traffic giữa bên tấn công và nạn nhân ngay ngoài khung giờ
(đuôi của Hulk tới 11:07).

Đối chiếu với CSV có nhãn của CIC, một nguồn nhãn độc lập:

| File CSV | Đồng ý |
|---|---|
| Thứ Hai | 100% |
| Thứ Tư | 98,98% |
| Thứ Sáu sáng (bot) | 99,99% |
| Thứ Sáu PortScan | 99,44% |
| Thứ Sáu DDoS | 85,95% |

Phần lệch chủ yếu là CSV ghi `BENIGN` cho flow giữa bên tấn công và nạn nhân ngay trong khung
tấn công (31 690 flow ở file DDoS). Đây là dạng lỗi nhãn của CSV gốc đã được Engelen (2021) chỉ
ra.

### 3.3. C05-T03 — Nhãn cửa sổ chứa nhiều hành vi

- Cửa sổ nhận nhãn từ các flow của host chồng lên nó.
  - Có flow tấn công bị loại thì là `loai`.
  - Một lớp tấn công chiếm ít nhất 20% số flow thì nhận lớp đó.
  - Dưới 20%, hoặc có hai lớp tấn công, thì là `mo_ho` (vẫn tính là `anomaly`).
  - Còn lại là benign.
- **81% cửa sổ tấn công thứ Tư lẫn flow bình thường**: cửa sổ nhiều hành vi là chuyện thường.
  Ngưỡng 20% ít nhạy: từ 0 tới 0,5, số cửa sổ `dos` chỉ đổi trong khoảng 3 816–4 016.

### 3.4. C05-T04 — Chia theo thời gian

- Mỗi khối tấn công và mỗi khoảng bình thường được cắt **theo thứ tự thời gian**: 60% số flow
  đầu là train, 20% kế là validation, 20% cuối là test.
- Mẫu vắt qua ranh giới, hoặc cách ranh giới hai tập dưới 10 giây, bị bỏ (2,0% số cửa sổ, 4,3% số flow).
- Ban đầu chia theo thời lượng, nhưng traffic buổi sáng dày nên train thứ Sáu chiếm 82% số
  flow; chuyển sang chia theo số flow thì đúng tỷ lệ.
- Không gán nguyên khối vào một tập, vì `port_scan` chỉ có 2 khối và một khối gần như rỗng.
- Heartbleed và DDoS cũng là khối riêng, để module anomaly có chúng ở cả ba tập (sửa ngày
  02/11/2026; bản đầu để Heartbleed nằm trọn trong validation).

### 3.5. C05-T05 — Kiểm tra dữ liệu

- **Không có giá trị vô hạn.** CSV của CIC có 1 586 ô `Infinity` chỉ riêng thứ Tư.
- **Ô trống là có chủ ý:** khoảng cách giữa gói trống khi flow có dưới 2 gói (25–26% ở các cột
  theo chiều), tỷ lệ kết nối không hoàn tất trống khi không có lần thử (74–94%).
- **98,9% flow `port_scan` có vector đặc trưng trùng nhau**, và 98,3% mẫu test trùng một mẫu
  train. Ở bảng cửa sổ chỉ 0,2%. Vì vậy đề xuất **lấy bảng cửa sổ làm đơn vị đánh giá chính**.
- **Mất cân bằng nặng ở bảng cửa sổ:** trong train, benign gấp 111 lần `dos` và 376 lần
  `port_scan`.
- Có 3 vector ở bảng flow mang cùng đặc trưng nhưng khác nhãn: đều là flow một gói (SYN đơn
  lẻ, hoặc RST+ACK đơn lẻ). Đây là mức sai không thể tránh.

### 3.6. C05-T06 — EDA (chỉ trên train)

- Ba lớp tách nhau rõ ở `bytes`, `pkt_len_mean` (flow) và `incomplete_ratio_out/in`,
  `new_conn_in` (cửa sổ).
- **Hulk chiếm 88,6% flow `dos` của train**, nên mô hình mức flow có nguy cơ học thuộc Hulk.
- **Mỗi lớp tấn công có hai "chân dung" đối lập**, bên tấn công và nạn nhân, với số cửa sổ gần
  bằng nhau.
- 58% cửa sổ `anomaly` của train là máy bot, rất ít gói, chồng nhiều lên `normal`.
- 5 cặp đặc trưng cửa sổ tương quan |r| ≥ 0,95. Ma trận hiệp phương sai của Gaussian có thể gần
  suy biến (việc của C06-T03).

### 3.7. C05-T07 — Tiền xử lý

- Các bước: log(1 + x) cho đặc trưng đếm, byte, giây; điền trung vị **của train** kèm cột đánh
  dấu ô trống; chuẩn hóa theo train.
- Module phân loại: chỉ dùng thứ Tư và thứ Sáu, bỏ mẫu train trùng hệt, giảm mẫu mỗi lớp xuống
  tối đa 10 lần lớp ít nhất, kèm trọng số lớp.
- Module anomaly: fit trên mẫu normal của train thứ Hai, **không bỏ trùng** vì tần suất là
  thông tin của phân bố.
- Validation và test giữ nguyên phân bố thật.

| Bộ | Train sau cân bằng | Test |
|---|---|---|
| Cửa sổ, phân loại | benign 4 450, dos 2 165, port_scan 445 | benign 67 713, dos 727, port_scan 462 |
| Flow, phân loại | benign 11 610, dos 11 610, port_scan 1 161 | benign 130 760, dos 33 320, port_scan 18 553 |
| Cửa sổ, anomaly | normal 88 929 (thứ Hai) | normal 99 988, anomaly 5 373 |
| Flow, anomaly | normal 228 512 (thứ Hai) | normal 206 992, anomaly 70 551 |

**Kiểm chứng chống rò rỉ trên dữ liệu thật:**
- Trên cả ba ngày, **0 cặp mẫu** ở hai tập khác nhau chồng thời gian; khoảng cách nhỏ nhất là
  22 giây (cửa sổ) và 20 giây (flow).
- Tham số đã lưu (trung vị, trung bình, độ lệch chuẩn) **trùng khớp** với số tính tay từ 88 929
  mẫu train thứ Hai.
- Kiểm thử: sửa dữ liệu validation/test thì tham số không đổi.

## 4. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-025 | Nhãn theo lịch tấn công, cặp IP và cổng nạn nhân; bốn trạng thái nhãn | Đã chốt (nới 60 giây tạm thời) |
| QĐ-026 | Nhãn cửa sổ theo phần flow tấn công; dưới 20% là mơ hồ | Tạm thời |
| QĐ-027 | Chia theo thời gian trong từng khối, 60/20/20 số flow, vùng đệm 10 giây | Đã chốt |
| QĐ-028 | Tiền xử lý chỉ fit trên train; bỏ trùng và cân bằng chỉ trên train; Gaussian học trên thứ Hai | Đã chốt |

Tham số mới trong `config/default.yaml`: mục `labeling` (nới 60 giây, ngưỡng cửa sổ 0,2), `split`
(60/20/20, vùng đệm 10 giây), `preprocess` (bỏ trùng, tỷ lệ cân bằng 10, phiên của từng module).

## 5. Kiểm thử

`python -m unittest discover -s tests`: **274/274 ca đạt** (Chặng 4 kết thúc ở 228).

| File | Số ca | Nội dung |
|---|---|---|
| `tests/test_labeling.py` | 17 | Đọc lịch, đổi múi giờ, bốn trạng thái, cổng nạn nhân, nới khung giờ; nhãn cửa sổ (8 ca) |
| `tests/test_label_report.py` | 4 | Giờ 12 tiếng của CSV CIC, khóa 5-tuple, bảng chéo, báo cáo từ file |
| `tests/test_splits.py` | 9 | Đoạn theo khối, cắt theo phân vị, vùng đệm, mẫu vắt qua ranh giới, dòng lệnh |
| `tests/test_data_quality.py` | 4 | Đọc bảng kèm nhãn và tập, cột đặc trưng, ô trống, trùng giữa các tập |
| `tests/test_eda.py` | 1 | Tạo đủ hình (bỏ qua nếu chưa cài matplotlib) |
| `tests/test_preprocessing.py` | 11 | Fit chỉ trên train, cột đánh dấu, log, phiên, bỏ trùng, cân bằng, nạp lại joblib từ dòng lệnh |

Ngoài kiểm thử tự động, mọi số liệu ở mục 3 được chạy trên dữ liệu thật. Có ba lỗi chỉ lộ ra
khi chạy thật và đã sửa:
- thiếu cổng nạn nhân trong lịch;
- chia theo thời lượng làm lệch tỷ lệ;
- file tiền xử lý lưu từ dòng lệnh không nạp lại được ở chương trình khác.

## 6. Điểm cần lưu ý

1. **Mới sẵn sàng cho hai trên ba module.** Module botnet chưa có dữ liệu: CTU-13 mới tải 2/13
   file `.binetflow`, lab chưa dựng. Mẫu DoS kiểu SYN cũng phải lấy từ lab (docs/06 mục 6).
2. **Validation của `port_scan` ở bảng cửa sổ chỉ có 50 mẫu.** Quét diễn ra theo đợt ngắn, nên
   kết quả chọn ngưỡng của lớp này sẽ dao động nhiều.
3. **Kết quả ở mức flow có thể đẹp giả** với `port_scan` vì mẫu trùng; nên đánh giá chính trên
   bảng cửa sổ và báo kèm kết quả sau khi bỏ mẫu test trùng train.
4. **Train và test cùng đợt tấn công**, chỉ khác thời điểm. Khả năng gặp công cụ chưa từng thấy
   phải đo riêng ở Chặng 7.
5. **Bảng đặc trưng xuất khi mã Chặng 5 chưa commit** (`co_sua_chua_commit: true` trong metadata).
   Lệnh xuất không dùng các phần đó, nhưng muốn dùng cho kết quả cuối thì xuất lại từ mã đã
   commit; khi máy rảnh mỗi ngày mất khoảng 10–25 phút.
6. **Tham số tạm thời:** nới lịch 60 giây, ngưỡng cửa sổ 0,2, tỷ lệ cân bằng 10 sẽ chỉnh trên
   validation.

## 7. Cách chạy

```bash
F=output/features
python -m nids.labeling $F/cic17_monday.flows.csv $F/cic17_wednesday.flows.csv $F/cic17_friday.flows.csv
python -m nids.label_report $F/cic17_wednesday.flows.csv --cic-csv data/cic-ids2017/TrafficLabelling/Wednesday-workingHours.pcap_ISCX.csv
python -m nids.splits $F/cic17_monday.flows.csv $F/cic17_wednesday.flows.csv $F/cic17_friday.flows.csv
python -m nids.data_quality $F/cic17_monday $F/cic17_wednesday $F/cic17_friday --out output/quality.json
python -m nids.eda $F/cic17_monday $F/cic17_wednesday $F/cic17_friday --out docs/hinh
python -m nids.preprocessing --table windows --module attack_classification $F/cic17_monday $F/cic17_wednesday $F/cic17_friday
```

## 8. Việc tiếp theo

**Chặng 6 — Gaussian anomaly detection**, dùng bộ tiền xử lý `anomaly` đã có:
- Chọn đặc trưng; xử lý các cặp tương quan cao (mục 3.6) để ma trận hiệp phương sai không suy biến.
- Kiểm tra phân bố sau log, huấn luyện Gaussian trên normal của train thứ Hai.
- Chọn ngưỡng trên validation; báo cáo Precision, Recall, F1 và tỷ lệ báo động giả trên test.
- Báo cáo Recall tách theo loại tấn công (DoS, quét, DDoS, Heartbleed, bot).

Song song: tải 11 file `.binetflow` còn lại của CTU-13; dựng lab.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Gán nhãn | Ghi cho mỗi mẫu biết nó là bình thường hay loại tấn công nào |
| Lịch tấn công | Danh sách đợt tấn công (giờ, IP, cổng, nhãn) dùng làm nguồn nhãn |
| Khớp / không khớp / mơ hồ / loại | Khớp một đợt tấn công / bình thường / không đủ căn cứ / tấn công ngoài ba lớp phân loại |
| Đối chiếu | So nhãn của dự án với một nguồn nhãn khác để tìm sai sót |
| Cửa sổ chứa nhiều hành vi | Cửa sổ có cả flow tấn công và flow bình thường |
| Train / validation / test | Dữ liệu để học / để chọn tham số, ngưỡng / để đánh giá cuối |
| Rò rỉ (leakage) | Thông tin của test lọt vào lúc huấn luyện, làm kết quả đẹp giả |
| Vùng đệm (embargo) | Khoảng bỏ trống ở ranh giới giữa hai tập |
| Phân vị | Mốc chia dữ liệu đã sắp xếp theo tỷ lệ |
| Mẫu trùng | Các mẫu có vector đặc trưng giống hệt nhau |
| Mất cân bằng lớp | Một lớp có nhiều mẫu hơn hẳn lớp khác |
| EDA | Khảo sát dữ liệu bằng thống kê và biểu đồ trước khi huấn luyện |
| Tiền xử lý, fit | Các bước đưa dữ liệu về dạng mô hình dùng được / tính tham số từ dữ liệu |
| Giảm mẫu, trọng số lớp | Bỏ bớt mẫu lớp đông / phạt nặng hơn khi đoán sai lớp ít mẫu |
| Hiệp phương sai, suy biến | Bảng đo các đặc trưng biến thiên cùng nhau; suy biến khi có đặc trưng gần như trùng thông tin |
| Precision, Recall, F1 | Trong các mẫu đoán là tấn công, bao nhiêu đúng / trong các tấn công thật, bắt được bao nhiêu / trung bình điều hòa của hai số |
| NAT | Tường lửa thay địa chỉ thật bằng địa chỉ của nó |
| UTC−3 | Giờ địa phương nơi CIC thu dữ liệu |
