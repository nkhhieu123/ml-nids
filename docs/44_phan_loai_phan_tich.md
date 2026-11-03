# C07-T06 — Phân tích nhầm lẫn và lưu artifact

Mã nguồn: `error_table`, `compare_profiles`, `scan_window_traffic`, `unseen_attacks`,
`permutation_importance`, `save_model`, `load_model`, `predict_frame` trong
`src/nids/classifier.py`. Kiểm thử: `tests/test_classifier.py`. Kết quả:
`docs/hinh/phan_loai_phan_tich.json`.

```bash
cd src
F=../output/features
# Fit lại cấu hình đã chọn ở C07-T04, lưu cả hai mô hình vào models/
python -m nids.classifier huan-luyen $F/cic17_wednesday $F/cic17_friday --chon ../docs/hinh/phan_loai_chon.json
# Phân tích nhầm lẫn bằng mô hình đã lưu (--hoan-vi: thêm độ quan trọng hoán vị, khoảng 3 phút)
python -m nids.classifier phan-tich $F/cic17_wednesday $F/cic17_friday \
    --model ../models/phan_loai_rf_windows.joblib --model ../models/phan_loai_lr_windows.joblib --hoan-vi --out ../docs/hinh
# Dự đoán một bảng cửa sổ chưa gán nhãn
python -m nids.classifier du-doan $F/cic17_monday --khong-nhan --model ../models/phan_loai_rf_windows.joblib --out ../output/du_doan_phan_loai.csv
```

## 1. Lỗi gặp nhiều nhất trên test (RF)

| Nhãn thật | Đoán là | Đợt | Vai trò host | Số cửa sổ |
|---|---|---|---|---|
| port_scan | benign | PortScan | bên tấn công | 128 |
| port_scan | benign | PortScan | nạn nhân | 122 |
| dos | benign | Slowhttptest | nạn nhân | 54 |
| dos | benign | Hulk | bên tấn công | 23 |
| dos | benign | Slowhttptest | bên tấn công | 23 |
| dos | benign | Hulk | nạn nhân | 14 |

Gần như mọi lỗi là **bỏ sót** (tấn công → benign). Nhầm giữa hai lớp tấn công rất hiếm ở RF
(5 port_scan → dos); LR nhầm nhiều hơn (39 port_scan → dos, đều phía nạn nhân).

## 2. Port_scan bị bỏ sót: các kiểu quét không có trong train

C07-T05 cho thấy cửa sổ port_scan có ≥ 20 lần thử TCP được bắt 97,8%, còn cửa sổ ít hoạt động thì
chỉ 11%. Ghép với bảng flow (flow mang nhãn `port_scan` chạm cửa sổ, cùng host) để xem các cửa sổ
ít hoạt động chứa gì, theo kiểu flow chiếm nhiều nhất trong cửa sổ:

| Kiểu flow chủ đạo | Train (sau bỏ trùng) | Test | Recall RF (test) | Recall LR (test) |
|---|---|---|---|---|
| TCP có SYN (vài kết nối tới 21, 22, 80, 443, 444) | 241 | 63 | 0,43 | 0,05 |
| UDP | 48 | 92 | 0,01 | 0,00 |
| **SCTP** | **0** | 122 | 0,02 | 0,00 |
| ICMP | 10 | 5 | 0,00 | 0,00 |

Đợt quét thứ Sáu gồm nhiều lượt Nmap kiểu khác nhau nối tiếp nhau. Chia theo thời gian (QĐ-027)
làm phần train chứa chủ yếu quét TCP, còn phần test có **quét SCTP và UDP** (mỗi flow trung vị 1
gói, nhiều cổng lạ). Bảng đặc trưng cửa sổ đếm "lần thử" và "kết nối không hoàn tất" chỉ cho TCP
(docs/24), nên một lượt quét UDP hay SCTP chỉ hiện ra như vài gói lẻ, trông như benign.

Hệ quả và cách sửa (chưa làm, vì phải làm lại từ Chặng 4–5 và chọn lại trên validation):
- Thêm đặc trưng không phụ thuộc TCP: số cổng đích UDP/SCTP khác nhau, số gói ICMP "port unreachable"
  nhận về.
- Hoặc chia port_scan theo **lượt Nmap** thay vì theo thời gian, để mỗi kiểu quét có ở cả ba tập.
- Ghi rõ trong báo cáo: mô hình hiện bắt được **quét TCP**, chưa bắt được quét UDP/SCTP.

## 3. DoS bị bỏ sót

| Trung vị (test, RF) | DoS đoán đúng | DoS bỏ sót | Benign |
|---|---|---|---|
| Số cửa sổ | 591 | 136 | 67 713 |
| `packets_out` | 301 | 56 | 16 |
| `packets_in` | 278 | 55 | 15 |
| `bytes_in` | 52 733 | 10 847 | 1 582 |
| `new_conn_in` | 5 | 1 | 0 |

Cửa sổ DoS bị bỏ sót có lưu lượng gấp vài lần benign nhưng thấp hơn 5 lần cửa sổ bắt được, và chỉ
khoảng một kết nối mới. Đó là pha "giữ kết nối" của Slowhttptest và các khoảng giữa hai đợt gửi của
Hulk: một kết nối HTTP chậm trông như một client web bình thường. Phát hiện được chúng cần đặc trưng
theo thời gian dài hơn 10 giây (số kết nối đang mở lâu tới cùng server), thuộc phạm vi cửa sổ dài ở
Chặng 8–9.

## 4. Tấn công chưa từng học (bị loại ở C07-T01), cửa sổ test

| Đợt | Số cửa sổ | RF đoán | LR đoán |
|---|---|---|---|
| DDoS (LOIT) | 206 | dos 204, benign 2 | dos 204, benign 2 |
| Heartbleed | 402 | benign 392, dos 10 | benign 402 |
| Bot (ARES) | 3 554 | benign 3 330, **port_scan 224** | benign 3 542, port_scan 12 |

- **DDoS** được nhận là `dos` gần như hết: hợp lý, cùng kiểu làm nghẽn web server. Khi có dữ liệu
  DDoS thứ hai, có thể thêm lớp riêng hoặc gộp vào `dos`.
- **Heartbleed** trông như benign với mọi đặc trưng lưu lượng (như Gaussian ở Chặng 6): cần phát
  hiện theo nội dung gói, ngoài phạm vi đồ án.
- **Bot**: RF báo 224 cửa sổ là quét cổng (6%). Ở hệ thống thật, đây là cảnh báo đúng là có vấn đề
  nhưng sai loại. Module botnet (Chặng 8) mới là nơi nhận diện bot; Chặng 9 cần quy tắc kết hợp khi
  hai module cùng báo.

## 5. Mô hình dựa vào đặc trưng nào (hoán vị trên validation)

Macro-F1 giảm bao nhiêu khi xáo trộn một đặc trưng (trung bình 3 lần):

| RF | Giảm | LR | Giảm |
|---|---|---|---|
| `packets_out` | 0,089 | `packets_in` | 0,412 |
| `dst_hosts` | 0,062 | `dst_port_entropy` | 0,400 |
| `incomplete_ratio_in` | 0,056 | `tcp_attempts_in` | 0,391 |
| `bytes_out` | 0,054 | `tcp_attempts_out` | 0,342 |
| `incomplete_in` | 0,021 | `new_conn_in` | 0,305 |
| `packets_in` | 0,017 | `dst_host_ports` | 0,235 |

RF giảm ít với từng đặc trưng vì nhiều đặc trưng chứa thông tin trùng nhau (gói, byte, kết nối):
mất một cái thì cây dùng cái khác. LR phụ thuộc mạnh vào từng hệ số, nên kém bền hơn khi một đặc
trưng bị nhiễu. Đặc trưng kết nối không hoàn tất (`incomplete_*`, C04-T07) nằm trong nhóm đầu của RF.

## 6. Artifact đã lưu

| File | Nội dung |
|---|---|
| `models/phan_loai_rf_windows.joblib` (4,1 MB) | `AttackClassifier`: bộ tiền xử lý fit trên train + Random Forest đã chọn |
| `models/phan_loai_lr_windows.joblib` (3 KB) | Như trên với Logistic Regression (mức chuẩn) |
| `models/*.json` | Lớp, tham số, đặc trưng, cột sau tiền xử lý, số mẫu train, macro-F1 validation, cấu hình, commit mã nguồn, phiên bản thư viện |
| `docs/hinh/phan_loai_nhan.json` | Số mẫu từng lớp (C07-T01) |
| `docs/hinh/phan_loai_chon.json` | Mọi lần thử tham số trên validation (C07-T04) |
| `docs/hinh/phan_loai_test.json`, `phan_loai_confusion.png` | Kết quả test, confusion matrix (C07-T05) |
| `docs/hinh/phan_loai_phan_tich.json` | Phân tích nhầm lẫn (mục này) |

Mô hình không đưa lên git (`models/*` trong `.gitignore`); chạy lại `huan-luyen` để tạo. Bộ tiền xử
lý nằm **trong** file mô hình, nên không thể nạp nhầm mô hình với một phép biến đổi khác.

```python
from nids.classifier import load_model, predict_frame
model = load_model("models/phan_loai_rf_windows.joblib")
pred = predict_frame(model, windows)   # host, window_start, du_doan, p_benign, p_dos, p_port_scan
```

Kiểm chứng:
- Hai mô hình nạp lại cho **đúng cùng** confusion matrix test như C07-T05 (RF macro-F1 0,8312, LR
  0,7664); lớp được ghi là `nids.classifier.AttackClassifier`, nạp được ở tiến trình khác.
- `du-doan --khong-nhan` trên thứ Hai (không có tấn công, không dùng khi học): 152 513 cửa sổ, RF
  báo 15 (11 port_scan, 4 dos), tức 0,01%.

## 7. Kiểm thử

- Bảng lỗi chỉ gồm mẫu sai; hồ sơ đúng/sai cộng lại bằng số mẫu của lớp.
- Hoán vị: đặc trưng tách lớp trong dữ liệu giả lập là quan trọng nhất.
- Phân loại kiểu flow (UDP, SCTP, TCP có SYN) và ghép flow vào cửa sổ theo host và thời gian.
- Tấn công chưa học: đếm đúng số cửa sổ bị loại.
- Lưu, nạp lại cho cùng xác suất; từ chối file không phải mô hình và bảng thiếu cột.
- Dòng lệnh đủ chuỗi `chon` → `danh-gia` → `huan-luyen` → `phan-tich` → nạp ở tiến trình khác →
  `du-doan`.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Bỏ sót | Tấn công bị đoán là benign |
| Artifact | File kết quả cần giữ lại: mô hình, metadata, bảng số liệu, hình |
| joblib | Thư viện lưu đối tượng Python ra file và nạp lại |
| SCTP, UDP, ICMP | Các giao thức khác TCP; Nmap có kiểu quét riêng cho từng giao thức |
| Lượt Nmap | Một lần chạy Nmap với một kiểu quét |
| Hoán vị (permutation importance) | Xáo trộn một đặc trưng rồi đo chỉ số giảm bao nhiêu |
| Slowhttptest, Hulk | Công cụ DoS HTTP chậm; công cụ DoS HTTP gửi dồn dập |
| DDoS, Heartbleed, Bot | Tấn công từ chối dịch vụ nhiều nguồn; khai thác lỗi OpenSSL; máy bị điều khiển từ xa |
| Metadata | Thông tin mô tả đi kèm mô hình |
| Tiến trình khác | Chương trình Python chạy riêng, như chương trình realtime sau này |
