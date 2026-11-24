# C12-T05 — Bảng yêu cầu đề tài → mã nguồn → bằng chứng

Mỗi yêu cầu B01–B25 của `docs/01_yeu_cau.md`: phần mã đáp ứng, bằng chứng (số liệu, file, kiểm thử) và trạng thái.
**Xong** là có mã và bằng chứng đo được; **Một phần** là thiếu một điều kiện, ghi rõ thiếu gì.

| Mã | Yêu cầu (rút gọn) | Mã nguồn | Bằng chứng | Trạng thái |
|---|---|---|---|---|
| B01 | Giám sát trên Kali, bắt gói, lưu PCAP | `nguon_goi.py`, `realtime.py`, `scripts/cai_dat_kali.sh`, `moi_truong.py` | Cảm biến bắt trực tiếp trên lab ảo, 0 gói bỏ (`74` mục 1); lab lưu PCAP mọi lần chạy | Một phần: **chưa chạy trên Kali thật** |
| B02 | Flow hai chiều có timeout; cửa sổ 10 s/2 s và 120 s/10 s | `flows.py`, `host_windows.py`, `graph_features.py` | `18`–`24`, `45`–`47`; độ nhạy timeout và cửa sổ (`72`, QĐ-073, 075, 081, 082) | Xong |
| B03 | Gaussian đa biến trên traffic bình thường, điểm và quyết định | `gaussian.py` | Test CIC F1 0,730 (`37`); mô hình lưu kèm ngưỡng (`38`) | Xong |
| B04 | Random Forest so với Logistic Regression, 3 lớp | `classifier.py` | RF 0,908 so với LR 0,828 (`43`); thêm 8 baseline (`78`), LightGBM, GRU (`82`) | Xong |
| B05 | Module botnet: đặc trưng giao tiếp/đồ thị, đầu ra host nghi vấn | `graph_features.py`, `botnet.py` | CTU-13 test F1 0,798 (`52`); lab 21/21 đợt (`80`) | Xong |
| B06 | Topology tập trung/ngang hàng, báo cáo riêng | `botnet.py` (`recognize_topology`, `group_p2p`), `bot_lab.py` | CTU-13 99,9% tập trung (`52`); lab 5 bot: 100% / 99,2% (`80` mục 4.2) | Xong |
| B07 | Ba module song song; Gaussian không là cổng lọc bắt buộc | `pipeline.py` (`run_independent`) | Chế độ `doc_lap`, so với tuần tự (`57`) | Xong |
| B08 | Hợp nhất và ghi cảnh báo | `alerts.py`, `pipeline.py` | Schema chung, gộp sự kiện (`55`, `58`) | Xong |
| B09 | Dữ liệu CIC-IDS2017, CTU-13, PCAP tự thu | `feature_export.py`, `ctu13.py`, `scripts/lab_ao.py` | Manifest có mã băm (`08`); 278 nhật ký lần chạy lab | Xong |
| B10 | Nhật ký mỗi lần thử nghiệm, cơ sở gán nhãn, độc lập với dự đoán | `scripts/lab_ao.py` | `data/run_logs/*.json`: giờ, IP, hành vi, tham số, mã băm PCAP; bộ chạy không đọc kết quả mô hình (`70`) | Xong |
| B11 | Chia tập theo lần thu/scenario; không chồng lấn; tiền xử lý chỉ học trên train | `splits.py`, `preprocessing.py` | Đệm 10 s ở ranh giới; CTU-13 theo kịch bản; lab theo lần chạy (`29`, `32`); kiểm thử `test_fit_only_on_train` | Xong |
| B12 | Huấn luyện và realtime cùng quy tắc | `realtime.py` dùng lại `packets`, `flows`, `host_windows`, `pipeline` | Cùng nhãn ở mọi cửa sổ trên 15 467 cửa sổ (`66`) | Xong |
| B13 | Lab 7 node cô lập, mirror về Kali, kiểm tra hai chiều | `scripts/lab_ao.py`, `cam_bien.py` | Lab **ảo** 9 namespace, mirror bằng `tc mirred`, bridge không có đường ra (`70`); kiểm tra hai chiều (`60`) | Một phần: **lab ảo**, chưa có switch và máy thật |
| B14 | Kịch bản bình thường 10 phút, tác vụ định kỳ, đo báo giả | `scripts/sinh_traffic.py` (`binh-thuong`) | `k1-binh-thuong`: 0 cảnh báo (`71` mục 1, `74`) | Xong |
| B15 | Quét Nmap chậm và nhanh, có traffic bình thường trước sau | `scripts/lab_ao.py` (`k2-*`) | 6/6 đợt trên test mới (`80`) | Xong |
| B16 | DoS một nguồn, 60 s, ba mức tải | `scripts/sinh_traffic.py` (`tai-ket-noi`), `lab_ao.py` (`k3-*`, `x3-syn-*`, `x3-dos-cham`) | 9/9 tải kết nối, 9/9 SYN, 3/3 DoS chậm; thêm DDoS năm nguồn 3/3 (`80`) | Xong |
| B17 | Botnet tập trung: chu kỳ cố định và biến thiên, ≥ 10 phút, có đối chứng | `scripts/sinh_topology.py`, `lab_ao.py` (`k4-*`, `k6-tap-trung`) | 3 bot và 5 bot; đối chứng `k4-doi-chung`, `k6-doi-chung` không bị báo (`71`, `80`) | Xong |
| B18 | Botnet P2P: đổi chu kỳ và danh sách peer, ≥ 10 phút, có đối chứng | `sinh_topology.py`, `lab_ao.py` (`k5-*`, `k6-p2p`) | Lưới, vòng, hai-kế-tiếp; đối chứng chia sẻ ngang hàng không bị báo (`71`, `80`) | Xong |
| B19 | Mỗi kịch bản ≥ 3 lần, lịch khác nhau; lần test cuối không dùng để chỉnh | `lab_ao.py` (seed theo mã lần chạy) | 3 lần mỗi biến thể mỗi vai trò; mỗi lần học lại thu lần test mới (QĐ-072, 083) | Xong |
| B20 | Báo cáo đủ chỉ số từng module, confusion matrix | `classifier.py`, `gaussian.py`, `botnet.py`, `thuc_nghiem.py` | `37`, `43`, `52`, `85`; hình confusion matrix | Xong |
| B21 | Độ trễ từ lúc hành vi bắt đầu, gồm chờ cửa sổ; không phát hiện là bỏ sót | `thuc_nghiem.py`, `do_tre_realtime.py` | Độ trễ thật 3,9–4,2 s (`74`); bỏ sót được đếm (`71`, `85`) | Xong |
| B22 | Trình diễn: bình thường → quét → DoS → tập trung → P2P | `demo/*.bat`, `scripts/demo_lab.sh` | `demo/HUONG_DAN.md`, `demo/KICH_BAN_BAO_VE.md` | Xong (botnet trình diễn bằng kết quả đã lưu vì mỗi lần chạy 12 phút) |
| B23 | Sản phẩm bàn giao | xem `84` mục 6 | Script, notebook (`notebooks/05`–`08`), realtime, script sinh traffic, nhật ký, bảng chỉ số | Xong |
| B24 | An toàn: chỉ trong mạng cô lập; botnet bằng thông điệp vô hại | `sinh_traffic.py`, `sinh_topology.py` (từ chối đích ngoài lab), `lab_ao.py` | Bridge không có IP, không đường ra; DoS ≤ 60 s; gói thô chỉ trong lab ảo, không giả mạo nguồn (QĐ-069) | Xong |
| B25 | Trung thực: kết quả từ thực nghiệm; botnet chỉ là mức nghi vấn | `alerts.py` (chi tiết "mức nghi vấn") | Mọi số trong `85` có file JSON gốc; bỏ sót và báo giả được ghi (`71`: 9/9 bot bị sót với mô hình CTU-13) | Xong |

**Tổng:** 22/25 Xong; 3 Một phần (B01, B13 cần máy Kali và lab vật lý; B22 trình diễn botnet bằng kết quả lưu sẵn).

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Bằng chứng | Số liệu, file kết quả hoặc kiểm thử cho thấy yêu cầu đã đạt |
| Kali Linux | Hệ điều hành dự kiến của máy giám sát |
| Lab ảo | Mạng thử nghiệm dựng bằng network namespace trên một máy Linux |
| `tc mirred` | Lệnh của Linux sao chép gói từ card này sang card khác, dùng làm cổng mirror ảo |
| Đối chứng | Kịch bản lành tính có hình dạng giống tấn công |
| Seed | Số khởi tạo cho phần ngẫu nhiên; khác seed thì lịch chạy khác |
| Confusion matrix | Bảng đếm nhãn thật so với nhãn dự đoán |
