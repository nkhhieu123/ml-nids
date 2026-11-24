# C12-T02, C12-T04 — Bảng kết quả offline, realtime; phân tích báo động giả, bỏ sót và giới hạn

Gom mọi số liệu cuối cùng vào một chỗ, tách **offline** (chấm trên bảng đặc trưng hoặc phát lại PCAP) với
**realtime** (cảm biến chấm từng cửa sổ khi nó đóng), rồi phân tích các trường hợp báo nhầm và bỏ sót. Mỗi số có
tài liệu gốc để tra.

Nguyên tắc đọc bảng: chỉ so trực tiếp hai số khi **cùng nhãn mục tiêu và cùng đơn vị đánh giá**. Ba module dùng
đơn vị khác nhau (cửa sổ host 10 s; host–cửa sổ 120 s), nên không cộng hay so chéo giữa các module.

## 1. Kết quả offline trên dữ liệu công khai (tập test, đọc một lần)

### 1.1. Phát hiện bất thường — Gaussian, CIC-IDS2017 (đơn vị: cửa sổ host 10 s)

| Chỉ số | Giá trị | Tài liệu |
|---|---|---|
| Precision / Recall / F1 | 0,733 / 0,727 / **0,730** | `37` |
| Tỷ lệ cửa sổ bình thường bị báo | 1,42% | `37` |
| Đợt báo động giả mỗi giờ (thứ Sáu / thứ Tư / thứ Hai) | 16,6 / 12,4 / 42,1 | `37` |
| Recall theo loại: slowloris / Hulk / PortScan / Slowhttptest / GoldenEye / Heartbleed | 0,91 / 0,71 / 0,54 / 0,28 / 0,13 / 0 | `37` |
| Bản chờ bắt tay 1 giây (`config/cic_h1.yaml`) | F1 0,742; báo nhầm 0,59% | `72` mục 2.5 |

### 1.2. Phân loại tấn công — CIC-IDS2017 (đơn vị: cửa sổ host 10 s; 3 lớp)

| Mô hình | Macro-F1 test | Accuracy | Ghi chú | Tài liệu |
|---|---|---|---|---|
| **Random Forest** (dùng trong hệ thống) | **0,908** (khoảng 95%: 0,892–0,923) | 0,997 | `port_scan` P 0,947 R 0,736; `dos` P 0,964 R 0,838 | `43` |
| Logistic Regression | 0,828 | 0,995 | đối chiếu bắt buộc (B04) | `43` |
| 8 baseline (Naive Bayes … MLP) | 0,600–0,896 | | Random Forest đứng đầu | `78` |
| LightGBM | 0,915 | 0,997 | | `82` |
| **GRU** (học sâu, đọc chuỗi 5 cửa sổ trước) | **0,940 ± 0,007**; gộp 3 seed **0,950** | 0,998 | cao hơn mô hình cơ sở ở cả 3 seed; chưa nối vào cảm biến | `82` |
| Random Forest + lớp giữ nhãn `dos` | 0,924 | | recall Slowhttptest 0,66 → 0,82 | `75` |
| Accuracy nếu đoán mọi cửa sổ là `benign` | — | 0,986 | lý do không dùng accuracy làm thước đo chính | `43` |

### 1.3. Phát hiện botnet — CTU-13 (đơn vị: host–cửa sổ 120 s, test là kịch bản 1, 2, 6, 8, 9)

| Mô hình | Precision | Recall | F1 | Background bị báo | Tài liệu |
|---|---|---|---|---|---|
| **Random Forest** | 0,971 | 0,678 | **0,798** | 11,9% | `52` |
| Logistic Regression | 0,949 | 0,132 | 0,232 | 10,7% | `49`, notebook `08` |

| Topology (quy tắc) | Kết quả | Tài liệu |
|---|---|---|
| Cửa sổ bot tập trung CTU-13 test gán đúng `centralized` | 99,9% | `52` |
| P2P | test CTU-13 không có kịch bản P2P (B11); trên giả lập 82% | `51`, `52` |

### 1.4. Pipeline ghép ba module — 4 đoạn PCAP test CIC

| Chế độ | Bỏ sót cửa sổ quét | Bỏ sót cửa sổ DoS Hulk | Cửa sổ bình thường bị báo (`fri_binh_thuong`) | Tài liệu |
|---|---|---|---|---|
| `doc_lap` (ba module độc lập) | 0% | 0% | 22,9% | `57` |
| `tuan_tu` (Gaussian lọc trước) | 34,8% | 28,4% | 4,5% | `57` |
| `ket_hop` (mặc định CIC) | 34,1% | 20,1% | 4,5% | `57` |

## 2. Kết quả trên lab ảo (offline: phát lại PCAP lần chạy lab)

Lab 9 máy, nhãn chuẩn từ nhật ký lần chạy. Bộ mô hình lab lần ba (`config/lab.yaml`), 63 lần `test` mới
(12–14) + 3 lần DDoS (21–23), chưa từng dùng để học hay chỉnh. Tài liệu: `80`.

| Loại | Đợt | Phát hiện | Độ trễ tới cuối cửa sổ (trung vị) |
|---|---|---|---|
| Quét cổng Nmap (chậm, nhanh) | 6 | 6 | 1,7–1,9 s |
| DoS tải kết nối (3 mức) | 9 | 9 | 0,9–2,0 s |
| SYN flood gói thô (3 mức) | 9 | 9 | 1,0–1,1 s |
| DoS HTTP chậm | 3 | 3 | 1,1 s |
| DDoS năm nguồn | 3 | 3 | 0,9 s |
| Botnet tập trung 3 bot, ngang hàng 3 bot | 9 | 9 | 6–9 s |
| Botnet năm bot (tập trung, ngang hàng) | 6 | 6 | 10–15 s |
| Botnet đổi vai trò máy | 6 | 6 | 8–14 s |
| **Tổng** | **51** | **51** | |
| Sự kiện báo động giả (66 lần chạy, gồm 15 lần đối chứng lành tính) | | **0** | |

Theo từng bot: 15/15 bot năm-bot tập trung và 15/15 ngang hàng bị báo; topology đúng 100% và 99,2%. Theo cửa sổ:
recall `dos` phía nạn nhân SYN flood 0,97; 0 cửa sổ bình thường bị gán tấn công.

## 3. Kết quả realtime

| Đo gì | Kết quả | Cách đo | Tài liệu |
|---|---|---|---|
| Nhất quán realtime – offline | **Cùng nhãn ở mọi cửa sổ** (15 467 cửa sổ 10 s); botnet 6/1 558 nhãn khác, đều sát ngưỡng | Phát lại 4 đoạn PCAP CIC qua cảm biến, so với pipeline offline | `66` |
| Độ trễ realtime thật (cảm biến bắt trực tiếp trên lab) | Quét 4,2 s; DoS 3,9 s; botnet tập trung 30,0 s; ngang hàng 17,8 s | Giờ phát cảnh báo − giờ bắt đầu hành vi theo nhật ký, cùng đồng hồ | `74` mục 1 |
| Độ trễ realtime khi phát lại 33 lần test (mô hình cũ) | Quét và DoS 3,5–6,3 s, trung vị 4,6 s | Phát lại theo nhịp thật | `Bao_cao_Chang_11` mục 4 |
| Gói bỏ, tài nguyên (bắt trực tiếp) | 0 gói bỏ; CPU < 6% một nhân; RAM 213–257 MB | Số liệu vận hành của cảm biến | `74` mục 1 |
| Tải cao (phát lại nhanh CIC) | 0 gói bỏ tới khoảng 2 900 gói/s; vượt ×4 trên đoạn quét thì hàng đợi đầy, bỏ 3,8% | Phát lại ×1, ×4, ×16 | `63` |
| Chờ bắt tay 1 s thay 3 s | Cảnh báo quét, DoS đến sớm hơn khoảng 2 s | Đo bằng phát lại | `72` mục 2.2 |

Độ trễ realtime gồm cả thời gian chờ cửa sổ đóng (B21): khoảng 1–2 s tới cuối cửa sổ, thêm 1–3 s chờ trả lời bắt
tay TCP; botnet chờ thêm một cửa sổ đồ thị 10 s nên chậm hơn nhiều.

## 4. Phân tích báo động giả (C12-T04)

| Nguồn báo nhầm | Ở đâu | Nguyên nhân | Đã xử lý thế nào | Còn lại |
|---|---|---|---|---|
| Gaussian báo máy chủ web của lab suốt bản thu | Lab, mô hình CIC | Học "bình thường" từ máy trạm CIC; máy chủ nhận kết nối liên tục trông khác thường | Học lại Gaussian trên traffic bình thường của lab | 0 trên lab |
| Bộ phân loại gán `dos` khi các máy chia sẻ khối dữ liệu lớn (`k5-doi-chung`) | Lab, mô hình CIC | Chưa từng thấy truyền dữ liệu lớn nội bộ | Thêm 3 lần `train` của đối chứng này | 0 trên lab |
| Gaussian khoảng 17 đợt báo giả mỗi giờ | CIC | Traffic người dùng thật đa dạng; Gaussian một cụm không mô tả hết | Không dùng Gaussian một mình; chế độ `ket_hop`; ngưỡng ổn định ±20% | Hạn chế đã biết |
| Module botnet báo 11,9% cửa sổ Background | CTU-13 test | Background chưa rõ là gì, có thể có bot thật; chỉ 4 máy bình thường đã xác nhận | Ràng buộc ≤ 5% trên validation (QĐ-040) | Không vượt qua được bằng dữ liệu hiện có |
| Lớp giữ nhãn `dos` giữ nhãn 20 s sau khi tấn công dừng | Lab | Thiết kế của lớp này | Mặc định tắt; các cửa sổ này nối liền đợt nên không tạo sự kiện báo giả | 72 cửa sổ trên 12 lần chạy khi bật |
| Đối chứng lành tính (gọi định kỳ, chia sẻ ngang hàng) | Lab | — | Có trong `train` | **0** sự kiện trên 15 lần đối chứng mới |

## 5. Phân tích bỏ sót (C12-T04)

| Bỏ sót | Ở đâu | Nguyên nhân | Đã xử lý thế nào | Còn lại |
|---|---|---|---|---|
| Botnet lab 9/9 với mô hình CTU-13 | Lab | Bot CTU-13 ồn (spam, quét); bot lab gọi nhẹ, đều. Mô hình cho bot lab điểm 0,084 < ngưỡng 0,1 | Học lại trên lab; chế độ `doc_lap` cho bot chậm | 0 bỏ sót trên lab; mô hình lab cho recall 0 trên CTU-13 (`76` mục 4) |
| DoS HTTP chậm (Slowhttptest recall 0,66) | CIC | Giữa hai đợt gửi, cửa sổ 10 s trông bình thường | Lớp giữ nhãn `dos` (0,82); GRU đọc chuỗi (recall `dos` 0,92) | GRU chưa nối vào cảm biến |
| Quét cổng recall 0,73 | CIC | Lượt quét chậm chỉ vài gói mỗi cửa sổ; quét đi qua NAT lẫn traffic khác | GRU recall 0,89 | |
| Kịch bản Murlo (bot chậm) F1 0,26 | CTU-13 | 4 909/6 723 cửa sổ bot chỉ có 2–3 flow | Lớp gộp theo host (`69`) | Hạn chế đã biết |
| Phía nạn nhân SYN flood (recall 0,10) | Lab, bộ lần hai | Nạn nhân SYN flood không có kết nối hoàn tất, khác DoS đã học | Thêm `train` SYN flood | 0,97 với bộ lần ba |
| Bot `.50` ở kịch bản đổi vai (6/9) | Lab, bộ lần hai | Máy không duyệt web làm nền, hồ sơ khác bot đã học | Thêm `train` đổi vai | 9/9 |
| Chế độ tuần tự bỏ sót 28–35% cửa sổ tấn công | CIC | Gaussian không báo thì phân loại không được hỏi | Không dùng `tuan_tu` làm mặc định | |

## 6. Giới hạn chung

- Mọi số realtime và lab là trên **lab ảo** (WSL2), chưa có Kali và lab vật lý.
- Lab chỉ 9 máy, bot mô phỏng; 51/51 đợt chỉ có nghĩa trong lab (`76` mục 4).
- Dữ liệu công khai nhỏ ở vài lớp: GoldenEye 24 cửa sổ test; validation `port_scan` 164 cửa sổ; CTU-13 chỉ 4 máy
  bình thường.
- Brute-force, exploit chưa có lớp. Hệ thống chỉ cảnh báo, không chặn.
- Gaussian: test CIC đã được xem một lần khi chẩn đoán cách chọn ngưỡng (`36` mục 5).

Danh sách đầy đủ: `Viec_con_thieu.md`.

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Offline / realtime | Chấm trên dữ liệu đã lưu / chấm ngay khi gói tới, từng cửa sổ khi nó đóng |
| Phát lại PCAP | Đưa file gói tin đã bắt vào cảm biến như thể đang bắt trực tiếp |
| Báo động giả | Cảnh báo khi không có tấn công |
| Bỏ sót | Tấn công xảy ra mà không có cảnh báo đúng loại |
| Sự kiện | Nhiều cảnh báo liên tiếp của cùng một đợt, gộp lại thành một |
| Độ trễ | Thời gian từ lúc tấn công bắt đầu tới cảnh báo đúng đầu tiên, gồm cả thời gian chờ cửa sổ |
| Background (CTU-13) | Máy chưa được xác nhận là bot hay bình thường |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp tính ngang nhau |
| `doc_lap`, `tuan_tu`, `ket_hop` | Ba cách ghép module: độc lập; Gaussian lọc trước; phân loại độc lập, botnet sau Gaussian |
| B11, B21 | Yêu cầu chia tập không chồng lấn; độ trễ gồm thời gian chờ cửa sổ |
