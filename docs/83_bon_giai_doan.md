# Bốn giai đoạn của đề tài: làm gì, ở đâu, kết quả ra sao

Tài liệu này đi lần lượt **từng dòng yêu cầu** của bốn giai đoạn trong đề cương và trả lời bốn câu: đã làm thế nào,
mã nguồn ở đâu, tài liệu `.md` nào giải thích chi tiết, kết quả đo được là gì. Cột "Trạng thái" ghi trung thực:
**Xong**, **Một phần** (làm được nhưng còn thiếu điều kiện, ghi rõ thiếu gì) hoặc **Chưa**.

Quy ước đường dẫn: mã nguồn trong `src/nids/` và `scripts/`; tài liệu trong `docs/`; số liệu và hình trong
`docs/hinh/`. Mọi lệnh chạy từ thư mục `src/` trừ khi ghi khác. "QĐ-xxx" là quyết định trong
`docs/03_nhat_ky_quyet_dinh.md`. Quy trình xử lý dữ liệu đầy đủ từ gói tin tới kết quả: `docs/77`.

## Sơ đồ tổng quát

```
GIAI ĐOẠN 1: log và traffic -> dữ liệu có cấu trúc                            (Chặng 1-4)
  PCAP / card mạng --[pcap_reader, packets]--> bảng gói --[flows]--> bảng flow
  access log Nginx --[service_log]----------> bảng log         \--[host_windows]--> bảng cửa sổ host 10 s
                                                                \--[graph_features]-> bảng host–cửa sổ 120 s
GIAI ĐOẠN 2: phân tích, phát hiện bất thường, phân loại                        (Chặng 5-7)
  gán nhãn [labeling] -> chia tập [splits] -> EDA [eda, eda_tong_hop] -> tiền xử lý [preprocessing]
  -> Gaussian [gaussian]   -> Random Forest + so sánh [classifier, so_sanh_mo_hinh, hoc_sau]
GIAI ĐOẠN 3: tấn công và botnet                                                (Chặng 8-9)
  đồ thị + beaconing [graph_features] -> LR/RF botnet [botnet] -> topology (quy tắc) [botnet]
  -> ghép ba module, chế độ độc lập / tuần tự / kết hợp [pipeline]
GIAI ĐOẠN 4: realtime và kiểm thử                                              (Chặng 10-12)
  card mạng [nguon_goi] -> cùng bộ trích xuất -> ba module -> cảnh báo, sự kiện [realtime]
  lab ảo [scripts/lab_ao.py] -> nhật ký ground truth -> chấm [thuc_nghiem, lab_cua_so, bot_lab]
```

---

## Giai đoạn 1 — Chuyển đổi log và traffic thành dữ liệu có cấu trúc

### 1.1. Thu thập và tìm hiểu dữ liệu

| Dòng yêu cầu | Đã làm thế nào | Mã nguồn | Tài liệu | Kết quả | Trạng thái |
|---|---|---|---|---|---|
| Khảo sát nguồn PCAP công khai (NETRESEC); chọn CIC-IDS2017, CTU-13, dữ liệu lab theo từng bài toán; ghi nguồn, nhãn, phạm vi | Khảo sát danh sách của NETRESEC; chọn CIC-IDS2017 (PCAP gốc + lịch tấn công) cho bất thường và phân loại, CTU-13 (flow có nhãn) cho botnet, lab tự thu cho kiểm thử; bảng kê mọi file kèm nguồn, kích thước, mã băm | `src/nids/manifest.py`, `src/nids/pcap_survey.py` | `06_cic_ids2017.md`, `07_ctu13.md`, `08_manifest_du_lieu.md`, `09_du_lieu_lab.md`, `10_tong_quan_du_lieu_mo_hinh.md` | CIC: thứ Hai (bình thường), thứ Tư (4 công cụ DoS), thứ Sáu (Nmap). CTU-13: 13 kịch bản, chia theo kịch bản. Lab: 278 file nhật ký lần chạy | Xong |
| Tìm hiểu Global Header, Packet Header, Packet Data, timestamp của PCAP; phân biệt PCAPNG | Mô tả từng trường, thứ tự byte, độ phân giải micro/nano giây; khối SHB, IDB, EPB của PCAPNG | `src/nids/pcap_reader.py` | `04_dinh_dang_pcap.md`, `11_bo_doc_pcap.md` | Bộ đọc hỗ trợ PCAP (µs, ns, hai thứ tự byte), PCAPNG nhiều giao diện, file nén | Xong |
| Tìm hiểu Scapy, PyShark, dpkt; chọn công cụ đọc packet | So sánh bằng đo thật trên cùng 20 000 gói: cả bốn cho cùng kết quả; tự viết ≈ 110 000 gói/s, dpkt 62 000, Scapy 4 400, PyShark 320. Chọn **tự viết** bằng `struct` | `src/nids/so_sanh_bo_doc.py` | `11_bo_doc_pcap.md` mục 6; QĐ-013, QĐ-014, QĐ-088 | Một ngày CIC (10–14 triệu gói) đọc trong khoảng 2 phút | Xong |
| Chọn một loại log dịch vụ, chuyển log text thành bảng | Chọn access log Nginx với định dạng `nids` (thời điểm, IP, cổng, yêu cầu, mã trả về, byte, thời gian xử lý); bộ đọc thành bảng, đối chiếu với bản gốc, ghép với flow | `src/nids/service_log.py`, `src/nids/log_compare.py`, `src/nids/log_flow.py` | `05_log_dich_vu.md`, `15_parser_log.md`, `16_xuat_doi_chieu_log.md`, `74_thi_nghiem_bo_sung.md` | Khớp mọi ô với bản gốc; ghép 33 003 dòng log lab với flow, lệch 0 | Xong |
| Trích xuất timestamp, IP nguồn/đích, giao thức, kích thước, port, cờ TCP | Bóc header Ethernet (có VLAN), Linux cooked, IPv4, IPv6 (cả header mở rộng), TCP, UDP; gói không hỗ trợ được đếm theo lý do | `src/nids/packets.py` | `12_trich_xuat_packet.md`, `13_port_co_tcp.md`, `14_goi_bo_qua.md`, `17_doi_chieu_wireshark.md` | **Khớp Wireshark ở mọi trường của 35,5 triệu gói** CIC; khớp cả IPv6, phân mảnh, TSO, đường hầm của lab | Xong |

### 1.2. Tổ chức dữ liệu và trích xuất đặc trưng

| Dòng yêu cầu | Đã làm thế nào | Mã nguồn | Tài liệu | Kết quả | Trạng thái |
|---|---|---|---|---|---|
| Gom packet theo flow 5-tuple, ghép hai chiều; quy định timeout và thời điểm đóng flow | Flow hai chiều: chiều thuận là bên mở kết nối. Đóng khi FIN hai chiều/RST (chờ thêm 10 s), im lặng 60 s, hoặc dài quá 120 s (cắt thành flow tiếp nối). Mảnh IP sau được gắn vào flow của mảnh đầu | `src/nids/flows.py` | `18_flow_hai_chieu.md`, `19_ket_thuc_flow.md`; độ nhạy `72_do_nhay_tham_so.md` mục 2; QĐ-006, 016, 017, 073 | 1,44 triệu flow từ ba ngày CIC; bảo toàn byte (tổng byte flow = tổng byte gói) | Xong |
| Bảng flow hoặc snapshot theo cửa sổ; tổng hợp theo IP nguồn trong cửa sổ | Bảng flow; bảng **cửa sổ host** 10 s trượt 2 s: mỗi máy mỗi cửa sổ một dòng | `src/nids/flow_features.py`, `src/nids/host_windows.py`, `src/nids/feature_export.py` | `22_cua_so_host.md`, `25_xuat_bang_dac_trung.md`; độ nhạy cửa sổ `72` mục 3; QĐ-075, 081 | 465 nghìn cửa sổ host CIC; schema và metadata đi kèm mỗi bảng | Xong |
| Thống kê kích thước packet, khoảng cách thời gian, số và tỷ lệ cờ TCP | Theo flow: min/max/trung bình/độ lệch kích thước gói, thời gian giữa hai gói, đếm từng cờ SYN/FIN/RST/PSH/ACK/URG | `src/nids/flow_features.py` | `21_thong_ke_flow.md` | Đối chiếu độc lập với Wireshark | Xong |
| Thời lượng flow, byte/packet hai chiều, tỷ lệ gửi/nhận; ở host: số/tỷ lệ kết nối không hoàn tất sau thời gian quan sát | Theo flow: thời lượng, gói/byte mỗi chiều, tỷ lệ chiều thuận. Theo host: số lần thử TCP, không trả lời, bị từ chối, mở dở, tỷ lệ không hoàn tất sau **thời gian chờ bắt tay** 3 s (lab 1 s) | `src/nids/flow_features.py`, `src/nids/window_features.py` | `20_dac_trung_flow_co_ban.md`, `24_ket_noi_khong_hoan_tat.md`; QĐ-023, 072, 080 | Chờ 1 s làm cảnh báo đến sớm hơn khoảng 2 s, kết quả không kém (`72` mục 2.5) | Xong |
| Số IP đích, số cổng đích, tần suất kết nối, entropy cổng đích, dấu hiệu kết nối lặp lại định kỳ | Theo cửa sổ host: số máy đích, cổng đích, cặp máy–cổng, kết nối mới mỗi chiều, entropy cổng đích. Gọi định kỳ: nhìn lại 600 s, cặp có ≥ 5 lần liên lạc và hệ số biến thiên ≤ 0,3 | `src/nids/window_features.py`, `src/nids/graph_features.py` | `23_dac_trung_cua_so.md`, `47_beaconing.md` | 20 đặc trưng cửa sổ host; 24 đặc trưng đồ thị và gọi định kỳ | Xong |
| **Đầu ra:** dữ liệu packet, log, flow, host có cấu trúc; tài liệu schema, công thức, cách gán nhãn | Mỗi bảng xuất kèm `schema.json` (tên cột, đơn vị, công thức) và `meta.json` (tham số, phiên bản mã) | `src/nids/feature_export.py`, `src/nids/labeling.py` | `25_xuat_bang_dac_trung.md`, `26_gan_nhan.md`, `27_bao_cao_nhan.md`, `28_nhan_cua_so.md` | | Xong |

---

## Giai đoạn 2 — Phân tích và phát hiện hành vi bất thường

| Dòng yêu cầu | Đã làm thế nào | Mã nguồn | Tài liệu | Kết quả | Trạng thái |
|---|---|---|---|---|---|
| Chốt dữ liệu và nhãn; EDA thống kê phân bố, trực quan khác biệt bình thường – tấn công | Nhãn từ lịch tấn công CIC (nới 60 s mỗi đầu), cửa sổ có < 20% flow tấn công là mơ hồ và bị bỏ. EDA cho cả ba bộ dữ liệu, chỉ trên train | `src/nids/labeling.py`, `src/nids/eda.py`, `src/nids/eda_tong_hop.py`; notebook `notebooks/05_eda.ipynb` | `26`–`28`, `31_eda.md`, `81_eda_tong_hop.md`; QĐ-025, 026 | Mất cân bằng 1 : 111 (DoS) và 1 : 357 (quét); không đặc trưng nào một mình đủ (AUC ≤ 0,87) | Xong |
| So sánh host bình thường và host quét qua số cổng đích, số kết nối | Trung vị và hình hộp theo lớp; AUC một biến | `src/nids/eda.py`, `src/nids/eda_tong_hop.py` | `31_eda.md` mục 3, `81` mục 5 | Quét: `dst_port_entropy` AUC 0,79, `new_conn_in` 0,72; quét của Nmap trên lab chạm tới 1 024 cổng trong vài giây | Xong |
| Xử lý dữ liệu thiếu, giá trị vô hạn, mất cân bằng; chia train/validation/test theo phiên hoặc scenario trước khi học tiền xử lý | Ô trống điền trung vị + cột đánh dấu; vô hạn coi như ô trống (dữ liệu thật có 0 giá trị vô hạn); thử cân bằng lớp khi chọn mô hình. Chia 60/20/20 theo thời gian trong từng đợt, đệm 10 s; CTU-13 theo kịch bản; lab theo lần chạy; tham số tiền xử lý chỉ học trên train | `src/nids/preprocessing.py`, `src/nids/splits.py`, `src/nids/data_quality.py` | `29_chia_du_lieu.md`, `30_kiem_tra_du_lieu.md`, `32_tien_xu_ly.md`, `77` mục 6; QĐ-027, 028, 089 | 46% cửa sổ train trùng hệt nên bỏ trùng (166 269 → 85 989) | Xong |
| Huấn luyện Gaussian trên dữ liệu bình thường; chọn ngưỡng bằng validation; đánh giá trên test | Gaussian đa biến 14 đặc trưng, Yeo-Johnson/log, hiệp phương sai Ledoit-Wolf; điểm là khoảng cách Mahalanobis bình phương; ngưỡng tại F1 cao và ổn định trên validation | `src/nids/gaussian.py`; `notebooks/06_gaussian.ipynb` | `33`–`38` | Test CIC: F1 0,730, precision 0,733, recall 0,727, báo nhầm 1,42% cửa sổ; khoảng 17 đợt báo giả mỗi giờ (không đủ dùng một mình) | Xong |
| Mô hình supervised (Random Forest) phân loại Benign, PortScan, DoS; mở rộng brute-force, exploit, DDoS khi có nhãn | Random Forest 300 cây, chọn tham số trên validation; so với Logistic Regression, 8 baseline, LightGBM, MLP, GRU. DDoS năm nguồn đã thử trong lab (được gán `dos`) | `src/nids/classifier.py`, `src/nids/so_sanh_mo_hinh.py`, `src/nids/hoc_sau.py`; `notebooks/07_phan_loai.ipynb` | `39`–`44`, `78_so_sanh_baseline.md`, `82_lightgbm_va_hoc_sau.md`, `80` mục 4.4 | RF test macro-F1 0,908; GRU 0,940–0,950. DDoS lab 3/3 | Một phần: chưa có lớp brute-force, exploit (không có dữ liệu; lab cấm exploit, B24) |
| Đánh giá Accuracy, Precision, Recall, F1, macro-F1, confusion matrix; báo cáo từng lớp; phân tích mất cân bằng | Mọi bảng đánh giá có cả accuracy và macro-F1, precision/recall/F1 từng lớp, confusion matrix, theo từng công cụ tấn công, khoảng tin cậy bootstrap | `src/nids/classifier.py` (`multiclass_metrics`, `evaluate`) | `43_phan_loai_danh_gia.md`, `44_phan_loai_phan_tich.md`; hình `phan_loai_confusion.png` | Accuracy 0,997 nhưng đoán toàn `benign` cũng được 0,986, nên dùng macro-F1 | Xong |
| **Đầu ra:** notebook EDA, dữ liệu đã chia, mô hình Gaussian, mô hình phân loại, bảng đánh giá | Notebook chạy sẵn kết quả; mô hình `.joblib` kèm `.json` mô tả (tham số, ngưỡng, phiên bản thư viện, commit) | `notebooks/05`–`08`, `models/` (tạo lại theo README) | `38`, `44`, `53_nap_artifact.md` | | Xong |

---

## Giai đoạn 3 — Phát hiện tấn công và phân tích botnet

| Dòng yêu cầu | Đã làm thế nào | Mã nguồn | Tài liệu | Kết quả | Trạng thái |
|---|---|---|---|---|---|
| So sánh thuật toán trên cùng bài toán, đặc trưng, cách chia; ít nhất hai mô hình phát hiện botnet | Phân loại: RF với 8 baseline, LightGBM, MLP, GRU. Botnet: Logistic Regression và Random Forest trên cùng host–cửa sổ CTU-13 | `src/nids/so_sanh_mo_hinh.py`, `src/nids/hoc_sau.py`, `src/nids/botnet.py`; `notebooks/08_botnet.ipynb` | `78`, `82`, `49_botnet_mo_hinh.md`, `52_botnet_danh_gia.md` | Botnet test CTU-13: RF F1 0,798 (P 0,971, R 0,678), LR F1 0,232 | Xong |
| Beaconing theo chuỗi kết nối tới cùng đích: chu kỳ, độ biến thiên, số quan sát; đối chứng lành tính | Cặp (máy, đích, cổng, giao thức); đo chu kỳ, hệ số biến thiên, số lần quan sát. Đối chứng: máy lành tính gọi định kỳ máy chủ web (`k4-doi-chung`, `k6-doi-chung`), chia sẻ dữ liệu ngang hàng (`k5-doi-chung`) | `src/nids/graph_features.py` (`beacon_*`), `scripts/sinh_topology.py` | `47_beaconing.md`, `50_du_lieu_topology.md`, `71` mục 6 | Đối chứng không bị báo ở mọi lần chạy. Trên CTU-13 chính máy bình thường gọi đều, bot thật ồn: gọi định kỳ không tự chứng minh botnet (`81` mục 6) | Xong |
| Đồ thị giao tiếp theo cửa sổ; đặc trưng node/cạnh; nhận diện tập trung hoặc ngang hàng; đánh giá topology riêng | Đồ thị có hướng mỗi 120 s: số peer vào/ra, tính tương hỗ, mức tập trung, entropy, tỷ lệ UDP. Topology bằng **quy tắc**: quy tắc ngưỡng (CTU-13), quy tắc nhóm "bot bị nghi có flow trực tiếp với bot bị nghi khác" (lab). Đánh giá topology bằng bảng riêng | `src/nids/graph_features.py`, `src/nids/botnet.py` (`recognize_topology`), `src/nids/bot_lab.py` | `45`, `46`, `51_nhan_dien_topology.md`, `52`, `76` mục 5, `80` mục 4.2; QĐ-042, 070 | CTU-13: 99,9% cửa sổ tập trung đúng. Lab 5 bot: 100% tập trung, 99,2% ngang hàng | Xong |
| Tổng hợp Gaussian, phân loại, botnet; ưu nhược; chỉ so khi cùng nhãn và đơn vị | Ba module báo cáo riêng, đơn vị riêng (cửa sổ host 10 s; host–cửa sổ 120 s); bảng tổng hợp ghi rõ đơn vị | | `57_so_sanh_che_do.md`, `Bao_cao_Chang_9.md`, `85_bang_ket_qua.md` | | Xong |
| Tích hợp module chạy độc lập; thử tuần tự Gaussian → phân loại → botnet; đo bỏ sót và thời gian | Ba chế độ: `doc_lap`, `tuan_tu`, `ket_hop`; đo trên 4 đoạn PCAP test | `src/nids/pipeline.py` | `54`–`58`; QĐ-046, 047, 068 | Tuần tự bỏ sót tới 34,8% cửa sổ quét; độc lập 0% bỏ sót nhưng báo nhầm nhiều hơn. CIC dùng `ket_hop`, lab dùng `doc_lap` | Xong |
| **Đầu ra:** module botnet/đồ thị, kết quả centralized/P2P, bảng so sánh, pipeline offline | `python -m nids.pipeline chay <pcap>` ra file cảnh báo và sự kiện của cả ba module | `src/nids/pipeline.py`, `src/nids/alerts.py` | `54`, `55`, `58` | | Xong |

---

## Giai đoạn 4 — Triển khai hệ thống phát hiện thời gian thực

### 4.1. Triển khai và tích hợp

| Dòng yêu cầu | Đã làm thế nào | Mã nguồn | Tài liệu | Kết quả | Trạng thái |
|---|---|---|---|---|---|
| Lưu mô hình, tiền xử lý, ngưỡng, schema; cài Python và thư viện thực sự dùng trên Kali | Mỗi mô hình một `.joblib` (gồm bộ tiền xử lý, ngưỡng) và `.json` (tham số, phiên bản, commit); bộ nạp kiểm tra schema. Script cài trên Kali; `pyproject.toml` chỉ liệt kê thư viện thật sự dùng. Đã kiểm tra clone và cài trên môi trường mới (461 kiểm thử đạt) | `src/nids/pipeline.py` (`load_artifacts`), `scripts/cai_dat_kali.sh`, `src/nids/moi_truong.py`, `pyproject.toml` | `53_nap_artifact.md`, `59_cai_dat_kali.md`, `84_kien_truc_trien_khai.md` | | Một phần: **chưa chạy trên máy Kali thật** |
| Bắt packet; bố trí cảm biến thấy traffic cần giám sát; gom flow và cửa sổ theo cùng quy tắc huấn luyện | Bắt bằng socket `AF_PACKET` của Linux (không dùng Scapy vì chậm, QĐ-088), dấu thời gian của nhân; cảm biến đặt ở cổng mirror. Gói đi thẳng vào **đúng** bộ trích xuất của offline (B12). Công cụ kiểm tra cảm biến thấy hai chiều | `src/nids/nguon_goi.py`, `src/nids/cam_bien.py`, `src/nids/realtime.py` | `60_cam_bien_hai_chieu.md`, `61_realtime.md`, `66_nhat_quan_offline_realtime.md` | Realtime và offline cho **cùng nhãn ở mọi cửa sổ** trên 15 467 cửa sổ | Xong trên lab ảo |
| Chạy nền: bắt packet → đặc trưng → mô hình → hợp nhất cảnh báo; quản lý hàng đợi, bộ nhớ, log | Hai luồng (đọc gói, xử lý) qua hàng đợi có giới hạn; trần flow đang mở; dọn state; dừng êm khi nhận tín hiệu; log xoay vòng; dịch vụ systemd | `src/nids/realtime.py`, `deploy/nids-realtime.service`, `scripts/cai_dich_vu.sh` | `62_hang_doi_don_state.md`, `63_do_hieu_nang.md`, `64_dung_va_log.md`, `65_chay_nen_systemd.md` | Nhịp thật: 0 gói bỏ tới khoảng 2 900 gói/s, CPU 32%, RAM 347 MB | Một phần: systemd chưa cài trên Kali thật |
| Ghi thời điểm sự kiện, thời điểm cảnh báo, IP, loại, module, điểm; phân biệt điểm bất thường với xác suất phân loại | Schema cảnh báo chung: module, nhãn, đầu/cuối cửa sổ, IP, điểm, ngưỡng, mã lần chạy, chi tiết, thời điểm tạo. Gaussian ghi d² kèm ngưỡng; phân loại ghi xác suất từng lớp; botnet ghi mức nghi vấn | `src/nids/alerts.py`, `src/nids/pipeline.py` | `02_dau_ra_module.md`, `55`, `58` | Cảnh báo lặp gộp thành sự kiện (cách nhau ≤ 30 s) | Xong |

### 4.2. Kiểm thử và đo lường

| Dòng yêu cầu | Đã làm thế nào | Mã nguồn | Tài liệu | Kết quả | Trạng thái |
|---|---|---|---|---|---|
| Trong lab được phép: quét cổng Nmap, DoS có giới hạn (ICMP hoặc SYN); DDoS cần nhiều nguồn | Lab ảo 9 máy cô lập trên WSL2 (network namespace, cổng mirror). Nmap chậm và nhanh; DoS tải kết nối 3 mức; SYN flood gói thô 3 mức (hping3, không giả mạo nguồn); DoS HTTP chậm; **DDoS năm nguồn**. Mọi DoS ≤ 60 s | `scripts/lab_ao.py`, `scripts/sinh_traffic.py`, `scripts/chay_chang_11.sh`, `scripts/chay_bo_lab_3.sh`, `scripts/chay_ddos.sh` | `09_du_lieu_lab.md`, `68_sinh_traffic_lab.md`, `70_lab_ao.md`, `71`, `76` mục 6, `80`; QĐ-061, 069, 077, 087 | Lần test mới: quét 6/6, DoS 9/9, SYN 9/9, DoS chậm 3/3, DDoS 3/3 | Một phần: lab **ảo**, chưa có lab vật lý (B13) |
| Mô phỏng beaconing bằng thông điệp vô hại; kiểm thử tập trung, ngang hàng, đối chứng lành tính | Bot gửi tin nhắn vô hại tới máy trong lab (từ chối đích ngoài lab). 3 bot và **5 bot**; chu kỳ cố định và biến thiên; đổi vai trò máy; đối chứng | `scripts/sinh_topology.py`, `scripts/lab_ao.py` | `71` mục 4–6, `76` mục 3, `80` | Botnet 21/21 đợt; 5 bot: 15/15 mỗi kiểu; đối chứng không bị báo | Xong trên lab ảo |
| Lưu nhật ký ground truth, PCAP, cảnh báo; quan sát dự đoán thực tế | Mỗi lần chạy một nhật ký (giờ bắt đầu/kết thúc, IP, hành vi, tham số, mã băm PCAP) do bộ chạy kịch bản ghi, **độc lập với mô hình**; giữ PCAP và file cảnh báo | `scripts/lab_ao.py`, `src/nids/thuc_nghiem.py` | `70`, `71`; dữ liệu `data/run_logs/` | 278 file nhật ký lần chạy trong git | Xong (trên lab ảo, không phải Kali) |
| Đo độ trễ (gồm thời gian chờ cửa sổ), phát hiện, bỏ sót, báo động giả, tài nguyên; đối chiếu realtime với offline | Độ trễ = từ lúc hành vi bắt đầu tới cảnh báo đúng đầu tiên; lần không phát hiện ghi là bỏ sót; báo giả theo sự kiện; tài nguyên đo trong cảm biến | `src/nids/thuc_nghiem.py`, `src/nids/do_tre_realtime.py`, `src/nids/nhat_quan.py`, `src/nids/thuc_nghiem_lab.py` | `63`, `66`, `71` mục 7, `74` mục 1, `85_bang_ket_qua.md` | Realtime thật trên lab: quét/DoS 3,9–4,2 s. 48/48 đợt, 0 báo giả trên 63 lần test mới | Xong |
| Tùy chọn: dashboard; tích hợp firewall | Dashboard HTML tĩnh từ file cảnh báo: dòng thời gian, máy bị báo nhiều nhất, đồ thị liên lạc của botnet | `src/nids/dashboard.py` | `84_kien_truc_trien_khai.md` mục 5 | | Dashboard: Xong (bản tĩnh). Firewall: **Chưa**, cố ý: chưa đánh giá rủi ro chặn nhầm trên mạng thật |

---

## Những gì chưa làm được và vì sao

| Việc | Vì sao chưa | Ảnh hưởng |
|---|---|---|
| Chạy trên máy Kali và lab vật lý 7 máy có switch mirror | Nhóm chưa có thiết bị | Mọi số đo realtime là trên lab ảo (WSL2); số gói bỏ và độ trễ trên card thật chưa biết |
| Lớp brute-force, exploit | CIC thứ Ba, thứ Năm chưa tải; lab không được chạy exploit (B24) | Ba lớp hiện tại không phủ các loại này |
| Tích hợp firewall chặn IP | Tùy chọn; chặn nhầm trên mạng thật gây gián đoạn | Hệ thống chỉ cảnh báo, không chặn |

Danh sách đầy đủ các hạn chế đã biết: `Viec_con_thieu.md`.

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| PCAP, PCAPNG | Hai định dạng file lưu gói tin đã bắt; PCAPNG là bản mới, có nhiều loại khối |
| Flow, 5-tuple | Một cuộc kết nối; xác định bằng IP nguồn, IP đích, cổng nguồn, cổng đích, giao thức |
| Cửa sổ host | Hành vi của một máy trong 10 giây, tóm tắt thành 20 con số |
| Beaconing (gọi định kỳ) | Liên lạc theo chu kỳ đều; dấu hiệu thường thấy của bot nhưng máy lành tính cũng có |
| Topology tập trung / ngang hàng | Bot cùng gọi về một máy điều khiển / bot gọi trực tiếp cho nhau |
| Ground truth, nhật ký lần chạy | Đáp án đúng của mỗi lần thử nghiệm, do bộ chạy kịch bản ghi, không do mô hình đoán |
| Cổng mirror | Cổng switch sao chép traffic sang máy giám sát |
| Đối chứng lành tính | Kịch bản trông giống tấn công nhưng vô hại, để kiểm tra báo nhầm |
| Chế độ độc lập / tuần tự / kết hợp | Cách ghép ba module: chạy song song / lọc nối tiếp / phân loại song song, botnet sau Gaussian |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp tính ngang nhau |
| QĐ-xxx | Mã quyết định kỹ thuật trong nhật ký quyết định |
| B13, B24 | Yêu cầu lab có mirror; yêu cầu an toàn, không ra ngoài lab, không mã độc |
