# Giải thích từng đầu ra của hệ thống

Tài liệu đi qua **mọi file hệ thống sinh ra**, theo thứ tự của quy trình: file nằm ở đâu, lệnh nào tạo ra, mỗi cột
hay mỗi trường nghĩa là gì, và đọc thế nào. Mỗi loại có một dòng ví dụ lấy từ file thật.

Quy trình đầy đủ: `docs/77`. Từng yêu cầu ở đâu: `docs/83`.

## Bảng tóm tắt

| # | Đầu ra | Ở đâu | Tạo bởi | Giai đoạn |
|---|---|---|---|---|
| 1 | Bảng flow | `output/features/<phiên>.flows.csv` | `nids.feature_export` | 1 |
| 2 | Bảng cửa sổ host | `output/features/<phiên>.windows.csv` | `nids.feature_export` | 1 |
| 3 | Mô tả cột (schema) | `output/features/<phiên>.schema.json` | `nids.feature_export` | 1 |
| 4 | Nguồn gốc bảng (meta) | `output/features/<phiên>.meta.json` | `nids.feature_export` | 1 |
| 5 | Nhãn flow, nhãn cửa sổ | `<phiên>.flows.labels.csv`, `<phiên>.windows.labels.csv` | `nids.labeling` | 2 |
| 6 | Chia tập | `<phiên>.flows.split.csv`, `<phiên>.windows.split.csv` | `nids.splits` | 2 |
| 7 | Bảng CTU-13: flow, host–cửa sổ 120 s | `output/ctu13/ctu13_sXX.*` | `nids.ctu13`, `nids.graph_features` | 1, 3 |
| 8 | Mô hình | `models/*.joblib` + `models/*.json` | `nids.gaussian`, `nids.classifier`, `nids.botnet`, `nids.hoc_lai_lab` | 2, 3 |
| 9 | Kết quả đánh giá, hình | `docs/hinh/*.json`, `*.png` | các lệnh `danh-gia`, `so_sanh_mo_hinh`, `hoc_sau`, `eda_tong_hop` | 2, 3 |
| 10 | **Cảnh báo** | `<tên>.alerts.csv` | `nids.pipeline`, `nids.realtime` | 3, 4 |
| 11 | **Sự kiện** | `<tên>.su_kien.csv` | `nids.pipeline`, `nids.realtime` | 3, 4 |
| 12 | Điểm mọi cửa sổ | `<tên>.diem.csv` | `nids.realtime --ghi-diem` | 4 |
| 13 | Số liệu vận hành | `<tên>.so_lieu.jsonl`, `<tên>.so_lieu_tong.json` | `nids.realtime` | 4 |
| 14 | Dấu hiệu giả mạo ARP | `<tên>.arp.jsonl` | `nids.realtime`, `nids.arp_gia_mao` | 4 |
| 15 | Log cảm biến | `output/realtime/log/nids_realtime.log` | `nids.realtime` | 4 |
| 16 | Nhật ký lần chạy lab | `data/run_logs/<mã lần chạy>.json` | `scripts/lab_ao.py` | 4 |
| 17 | Kết quả chấm lab | `docs/hinh/thuc_nghiem/lab/**/*.json` | `nids.thuc_nghiem`, `nids.lab_cua_so`, `nids.bot_lab` | 4 |
| 18 | Dashboard | `*.html` | `nids.dashboard` | 4 |
| 19 | Đầu ra demo | `output/demo/<lần chạy>/`, `output/phat_lai/<lần chạy>/` | `demo/*.bat` | 4 |

`data/`, `output/`, `models/` không có trong git (lớn); tạo lại theo `docs/84` mục 4. `data/run_logs/` và
`docs/hinh/` có trong git.

---

## 1. Bảng flow — `<phiên>.flows.csv`

Mỗi dòng là **một cuộc kết nối hai chiều**. Thời điểm là giây từ 1/1/1970 UTC, 9 chữ số thập phân.

Ví dụ (CIC thứ Sáu):

```
first_index=286  first_ts=1499428835.357533  ip_version=4  protocol=6
fwd_ip=192.168.10.9  fwd_port=1031  bwd_ip=192.168.10.3  bwd_port=88  direction_basis=syn  end_reason=rst
packets=16  fwd_packets=8  bwd_packets=8  bytes=1568  duration_s=0.000708  syn_count=4  rst_count=2 ...
```

Đọc là: máy `.9` mở kết nối TCP (`protocol=6`) từ cổng 1031 tới cổng 88 (Kerberos) của máy `.3`; 16 gói, 1 568 byte
trong 0,7 mili giây; kết thúc bằng RST.

| Nhóm cột | Cột | Ý nghĩa |
|---|---|---|
| Định danh | `first_index` | Số thứ tự của gói đầu tiên trong file PCAP; dùng để nối với nhãn và tập |
| | `first_ts`, `last_ts` | Thời điểm gói đầu, gói cuối |
| | `ip_version`, `protocol` | 4 hoặc 6; giao thức (6 = TCP, 17 = UDP, 1 = ICMP) |
| | `fwd_ip`, `fwd_port`, `bwd_ip`, `bwd_port` | Hai đầu của kết nối. `fwd` là bên mở kết nối |
| Cách xác định | `direction_basis` | Vì sao biết bên nào mở: `syn` (thấy gói SYN), `syn_ack` (thấy SYN+ACK), `cong_dich_vu` (đoán theo cổng dịch vụ), `goi_dau` (lấy theo gói đầu tiên) |
| | `continuation` | 1 nếu là phần tiếp của một flow bị cắt vì dài quá 120 s |
| | `end_reason` | Vì sao flow kết thúc: `fin`, `rst`, `idle_timeout` (im lặng 60 s), `active_timeout` (quá 120 s), `het_du_lieu` (hết file) |
| | `fragments_attached` | Số mảnh IP sau được gắn vào flow này |
| Khối lượng | `packets`, `bytes` và bản `fwd_`/`bwd_` | Số gói, số byte tổng và từng chiều |
| | `payload_bytes` và bản theo chiều | Byte dữ liệu ứng dụng (không tính header) |
| | `duration_s` | Thời lượng (giây) |
| | `fwd_packet_share`, `fwd_byte_share` | Phần gói, phần byte của chiều thuận (0–1) |
| Thống kê | `pkt_len_min/max/mean/std` và bản theo chiều | Kích thước gói (byte) |
| | `iat_min/max/mean/std` và bản theo chiều | Khoảng cách thời gian giữa hai gói liên tiếp (giây) |
| Cờ TCP | `syn_count`, `fin_count`, `rst_count`, `psh_count`, `ack_count`, `urg_count`, `ece_count`, `cwr_count` | Số gói mang từng cờ |

Ô trống nghĩa là **không tính được** (ví dụ flow một gói không có khoảng cách giữa hai gói), không phải 0.

## 2. Bảng cửa sổ host — `<phiên>.windows.csv`

Mỗi dòng là **một máy trong một cửa sổ 10 giây** (cửa sổ trượt 2 giây). Đây là đầu vào của Gaussian và bộ phân
loại. Ví dụ:

```
host=192.168.10.3  window_start=1499428782  window_end=1499428792
packets_out=4  packets_in=8  bytes_out=984  bytes_in=2028  dst_hosts=0  dst_ports=0  new_conn_out=0
src_hosts=1  new_conn_in=2  dst_port_entropy=(trống)  tcp_attempts_out=0  incomplete_ratio_out=(trống) ...
```

Đọc là: trong 10 giây đó, máy `.3` không mở kết nối nào ra ngoài; có 1 máy gọi tới với 2 kết nối mới. Entropy cổng
đích và tỷ lệ không hoàn tất để trống vì máy không mở kết nối nào.

| Cột | Ý nghĩa |
|---|---|
| `host`, `window_start`, `window_end` | Máy và cửa sổ (định danh, không đưa vào mô hình) |
| `first_ts`, `last_ts` | Gói đầu, gói cuối của máy trong cửa sổ (kiểm tra) |
| `packets_out/in`, `bytes_out/in` | Số gói, số byte máy gửi đi và nhận về |
| `dst_hosts`, `dst_ports`, `dst_host_ports` | Số máy đích, cổng đích, cặp máy–cổng khác nhau máy này mở kết nối tới |
| `new_conn_out`, `new_conn_in` | Số kết nối mới máy mở ra / nhận vào |
| `src_hosts` | Số máy khác mở kết nối tới máy này |
| `dst_port_entropy` | Độ rải của cổng đích (bit): 0 là dồn một cổng, lớn là rải nhiều cổng (quét) |
| `tcp_attempts_out/in` | Số lần thử mở kết nối TCP đi / đến |
| `incomplete_out/in` | Số lần thử không hoàn tất bắt tay sau thời gian chờ (3 s; lab 1 s) |
| `no_reply_out`, `rejected_out`, `half_open_out` | Không được trả lời; bị từ chối (RST); mở dở |
| `incomplete_ratio_out/in` | Tỷ lệ không hoàn tất (0–1) |

## 3. Mô tả cột — `<phiên>.schema.json`

Từ điển của hai bảng trên. Với mỗi cột: `ten`, `kieu` (`int`, `float`, `str`, `thoi_diem`), `don_vi`, `vai_tro`, có
thể trống không, mô tả. Vai trò quan trọng nhất:

| `vai_tro` | Nghĩa |
|---|---|
| `dac_trung` | Đưa vào mô hình |
| `dinh_danh` | Chỉ để gán nhãn, chia tập, truy vết; **không** đưa vào mô hình để mô hình không học thuộc địa chỉ |
| `ngu_canh` | Thuộc tính của flow, chỉ dùng khi chứng minh không gây rò rỉ |
| `kiem_tra` | Kiểm tra chất lượng dữ liệu |

## 4. Nguồn gốc bảng — `<phiên>.meta.json`

| Trường | Ý nghĩa |
|---|---|
| `tao_luc_utc`, `thoi_gian_chay_s` | Lúc tạo, thời gian trích xuất |
| `nguon` | File PCAP gốc, kích thước, mã băm |
| `ma_nguon` | Commit git và phiên bản Python lúc tạo: biết bảng được tạo bằng mã nào |
| `tham_so` | Timeout flow, cửa sổ, thời gian chờ bắt tay, dải mạng giám sát |
| `bang` | Tên file và số dòng của từng bảng |
| `thong_ke.packet` | Số gói giữ lại, gói bỏ theo lý do (không phải IP, hỏng...), gói trùng bị bỏ (nếu bật khử trùng) |
| `thong_ke.flow`, `thong_ke.cua_so` | Số flow theo lý do kết thúc, mảnh đã gắn, số cửa sổ |

## 5. Nhãn — `<phiên>.flows.labels.csv`, `<phiên>.windows.labels.csv`

| Cột | Ý nghĩa |
|---|---|
| `first_index` / `host`, `window_start` | Khóa nối với bảng flow / cửa sổ |
| `label_attack` | Nhãn của bộ phân loại: `benign`, `port_scan`, `dos`, hoặc nhãn gốc bị loại (ví dụ `DDoS`, `Bot`) |
| `label_anomaly` | Nhãn của Gaussian: `normal` hoặc `anomaly` |
| `label_status` | `khop` (trùng lịch tấn công), `khong_khop` (bình thường), `mo_ho` (không chắc, bị bỏ), `loai` (loại tấn công ngoài phạm vi) |
| `rule_id` | Dòng nào của lịch tấn công đã khớp |
| `attack_share`, `n_flows`, `n_attack_flows` | (cửa sổ) Phần flow tấn công trong cửa sổ; dưới 20% là `mo_ho` |

## 6. Chia tập — `<phiên>.*.split.csv`

Mỗi flow hay cửa sổ một dòng, cột `split` là `train`, `validation`, `test` hoặc `bo` (bị bỏ vì nằm trong 10 giây sát
ranh giới hai tập). Các lệnh học chỉ đọc dòng `train`; validation để chọn; test chỉ để đánh giá cuối.

## 7. Bảng CTU-13 — `output/ctu13/`

| File | Nội dung |
|---|---|
| `ctu13_sXX.flows.csv.gz` | Flow của kịch bản XX đã lọc: `ts`, `end_ts`, `proto`, `src`, `sport`, `dst`, `dport`, `packets`, `bytes`, `src_bytes`, `dst_bytes`, `state`, `label` (nhãn gốc của CTU-13) |
| `ctu13_sXX.host_windows.csv.gz` | **Host–cửa sổ 120 giây** (trượt 10 s), đầu vào module botnet: 24 đặc trưng bên dưới |
| `ctu13_sXX.json` | Thông tin kịch bản: số flow, giờ, danh sách IP bot, máy bình thường đã xác nhận, flow bot đầu tiên |

Đặc trưng host–cửa sổ 120 giây (cũng là đặc trưng botnet trong cảm biến):

| Cột | Ý nghĩa |
|---|---|
| `so_peer`, `so_peer_ra`, `so_peer_vao` | Số máy liên lạc tổng / máy này gọi tới / gọi tới máy này |
| `so_flow_ra/vao`, `so_byte_ra/vao`, `so_goi_ra/vao` | Khối lượng mỗi chiều |
| `ty_le_tuong_ho` | Phần đối tác liên lạc cả hai chiều |
| `tap_trung_ra/vao`, `entropy_peer_ra/vao` | Mức dồn vào một đối tác (1 là chỉ một đối tác) và độ rải |
| `so_cong_ra`, `ty_le_udp` | Số cổng đích; phần flow UDP |
| `ty_le_khong_tra_loi_ra` | Phần kết nối ra không được trả lời (bot spam, quét thì cao) |
| `ty_le_peer_noi_bo`, `ty_le_peer_moi` | Phần đối tác trong mạng nội bộ; phần đối tác chưa gặp ở cửa sổ trước |
| `beacon_so_cap_du_quan_sat` | Số cặp (đích, cổng) có đủ ≥ 5 lần liên lạc trong 600 s để đo nhịp |
| `beacon_so_cap_deu` | Số cặp gọi **đều** (hệ số biến thiên ≤ 0,3) |
| `beacon_cv_nho_nhat`, `beacon_chu_ky` | Hệ số biến thiên nhỏ nhất và chu kỳ (giây) của cặp đều nhất |
| `beacon_so_quan_sat_lon_nhat` | Số lần liên lạc nhiều nhất của một cặp |

## 8. Mô hình — `models/`

| File | Module | Dùng bởi |
|---|---|---|
| `gaussian_windows.joblib` | Gaussian (CIC) | `config/default.yaml` |
| `phan_loai_rf_windows.joblib`, `phan_loai_lr_windows.joblib` | Random Forest, Logistic Regression (CIC) | `default.yaml` dùng RF |
| `botnet_rf.joblib`, `botnet_lr.joblib` | Botnet (CTU-13) | `default.yaml` dùng RF |
| `h1/` | Gaussian, RF học với chờ bắt tay 1 s | `config/cic_h1.yaml` |
| `lab/` | Bộ mô hình lab lần ba | `config/lab.yaml` |
| `lab_b2/`, `lab_v1/`, `lab_h3/` | Các bộ lab cũ để so | — |

Mỗi `.joblib` chứa **mô hình + bộ tiền xử lý + ngưỡng**, nên nạp một file là dùng được ngay. File `.json` cùng tên mô
tả nó, ví dụ `phan_loai_rf_windows.json`:

| Trường | Ý nghĩa |
|---|---|
| `mo_hinh`, `loai`, `lop` | Mô tả, loại thuật toán, các lớp (`benign`, `dos`, `port_scan`) |
| `tham_so`, `seed` | Tham số đã chọn trên validation (300 cây, sâu 20...), số khởi tạo ngẫu nhiên |
| `dac_trung`, `cot_sau_tien_xu_ly` | 20 đặc trưng đầu vào; 23 cột sau tiền xử lý (thêm 3 cột "vốn trống") |
| `nguong` | Ngưỡng cảnh báo (Gaussian: d² 64,65; botnet: xác suất 0,1; lab: 0,80) |
| `so_mau_train`, `lop_train` | Số mẫu học, theo lớp |
| `ma_nguon`, `phien_ban` | Commit git, phiên bản Python và thư viện; nạp bằng phiên bản khác thì bộ nạp cảnh báo |

## 9. Kết quả đánh giá — `docs/hinh/`

| File | Nội dung chính | Đọc trường nào |
|---|---|---|
| `gauss_test.json` | Gaussian trên test CIC | `tong` (precision, recall, f1, fpr), `theo_phien`, `recall_theo_dot` |
| `phan_loai_chon.json` | Mọi lần thử tham số trên validation | `mo_hinh.<thuật toán>.tot_nhat` |
| `phan_loai_test.json` | Bộ phân loại trên test CIC | `mo_hinh.random_forest`: `macro_f1`, `accuracy`, `theo_lop`, `confusion`, `khoang_95_macro_f1`, `theo_dot`, `ty_le_benign_bi_bao` |
| `phan_loai_confusion.png` | Ma trận nhầm lẫn | hàng là nhãn thật, cột là dự đoán |
| `botnet_mo_hinh.json`, `botnet_danh_gia.json` | Module botnet trên CTU-13 | precision, recall, F1 mức host–cửa sổ; `background_bi_bao` |
| `so_sanh_mo_hinh.json` | RF với 8 baseline | `mo_hinh.<tên>.validation/test.macro_f1` |
| `hoc_sau/hoc_sau.json` | RF, LightGBM, MLP, GRU | `macro_f1_validation/test.trung_binh`, `do_lech`, `test_theo_seed` |
| `eda_tong_hop/eda_tong_hop.json` | EDA ba bộ dữ liệu | `cic.mo_ta_train`, `phan_biet_train`, `ctu13`, `lab` |
| `72`, `w20/`, `cua_so_do_thi/`, `h1/`, `flow_do_nhay_cic.json` | Độ nhạy tham số | macro-F1 validation từng cấu hình |
| `so_sanh_bo_doc.json` | Bốn công cụ đọc gói | `goi_moi_giay`, `ty_le_khop` |

Quy ước chung: `macro_f1` là trung bình F1 của ba lớp; `theo_lop` có `precision`, `recall`, `f1`, `so_mau`;
`confusion.ma_tran[i][j]` là số mẫu lớp thật `i` bị đoán là lớp `j`.

## 10. Cảnh báo — `<tên>.alerts.csv` (đầu ra chính)

Mỗi dòng là **một cửa sổ của một máy bị một module báo**. Ba module dùng chung một định dạng.

| Cột | Ý nghĩa |
|---|---|
| `module` | `anomaly` (Gaussian), `attack_classification` (Random Forest), `botnet_topology` |
| `label` | `anomaly`; `port_scan` / `dos`; `suspect_host` (máy bị nghi là bot); `centralized` / `p2p` (kiểu botnet) |
| `window_start`, `window_end` | Cửa sổ bị báo (giờ UTC, chậm hơn giờ Việt Nam 7 tiếng) |
| `src_ip` | **Máy bị báo** |
| `dst_ip` | Máy liên quan nếu có (thường để trống) |
| `score` | Điểm của mô hình, **ý nghĩa khác nhau theo module**: xem bảng dưới |
| `threshold` | Ngưỡng tương ứng |
| `run_id` | Mã lần chạy |
| `detail` | Thông tin thêm |
| `created_at` | Giờ thật lúc cảnh báo được phát (để tính độ trễ) |

| Module | `score` là gì | `threshold` | `detail` |
|---|---|---|---|
| `anomaly` | Khoảng cách Mahalanobis bình phương d²: càng lớn càng khác thường; **không phải xác suất** | d² ngưỡng (CIC 64,65; lab 3 179) | — |
| `attack_classification` | **Xác suất** của nhãn được gán (tỷ lệ cây bỏ phiếu), 0–1 | trống (chọn lớp xác suất cao nhất) | `p_benign=… p_dos=… p_port_scan=…`; thêm `giu_dos=1` nếu do lớp giữ nhãn |
| `botnet_topology` (`suspect_host`) | Xác suất là bot, 0–1 | 0,1 (CTU-13) hoặc 0,80 (lab) | "mức nghi vấn, không khẳng định có mã độc" |
| `botnet_topology` (`centralized`/`p2p`) | trống (gán bằng quy tắc, không có điểm) | trống | "topology theo quy tắc" |

Ví dụ thật (demo quét cổng):

```
anomaly,anomaly,...18:20:04Z,...18:20:14Z,192.168.50.20,,8.6838e+08,3179.34,k2-quet-nhanh-test-99,,...
attack_classification,port_scan,...18:20:04Z,...18:20:14Z,192.168.50.20,,0.93,,k2-quet-nhanh-test-99,p_benign=0.020 p_dos=0.050 p_port_scan=0.930,...
```

Đọc là: cửa sổ 18:20:04–18:20:14 UTC của máy `.20`: Gaussian thấy cực kỳ khác thường (d² ≈ 870 triệu, ngưỡng
3 179); Random Forest gán `port_scan` với 93% số cây bỏ phiếu.

Ví dụ botnet (năm bot ngang hàng):

```
botnet_topology,suspect_host,...17:25:50Z,...17:27:50Z,192.168.50.42,,0.984989,0.8023,,"mức nghi vấn, ..."
botnet_topology,p2p,...17:25:50Z,...17:27:50Z,192.168.50.42,,,,,topology theo quy tắc (QĐ-042)
```

Đọc là: trong cửa sổ 120 giây đó, máy `.42` có xác suất là bot 0,985 (ngưỡng 0,80), và nhóm bot liên lạc kiểu
ngang hàng.

Lưu ý khi đọc:

- **Một đợt tấn công sinh nhiều dòng**: cửa sổ trượt 2 giây nên một lần quét nằm trong khoảng 5 cửa sổ liên tiếp; DoS
  60 giây cho khoảng 35 cửa sổ mỗi máy.
- **Cả máy tấn công lẫn máy bị tấn công đều bị báo**: hệ thống báo mọi máy có lưu lượng tấn công trong cửa sổ.
- Mặc định file chỉ có cửa sổ **bị báo**; muốn có mọi cửa sổ thì dùng `--ghi-diem` (mục 12).

## 11. Sự kiện — `<tên>.su_kien.csv`

Cảnh báo cùng module, cùng nhãn, cùng máy, cách nhau không quá 30 giây được **gộp thành một sự kiện**: một đợt tấn
công thành một dòng thay vì hàng chục dòng.

| Cột | Ý nghĩa |
|---|---|
| `module`, `label`, `src_ip` | Như cảnh báo |
| `bat_dau`, `ket_thuc`, `thoi_luong_s` | Từ đầu cửa sổ đầu tiên tới cuối cửa sổ cuối cùng |
| `so_canh_bao` | Số cảnh báo được gộp |
| `diem_lon_nhat`, `diem_trung_binh`, `nguong` | Điểm cao nhất, trung bình trong sự kiện |
| `run_id` | Mã lần chạy |
| `canh_bao_dau_tao_luc` | Giờ phát cảnh báo đầu tiên của sự kiện |

Ví dụ (DoS 60 giây): `attack_classification,dos,192.168.50.20,16:39:56Z,16:41:14Z,78.0,35,1.0,0.999451,...` nghĩa
là 35 cảnh báo `dos` liên tiếp trên máy `.20` kéo dài 78 giây (60 giây tải + 10 giây cửa sổ cuối + bước trượt),
điểm trung bình 0,999.

Đếm **báo động giả** của lab là đếm **sự kiện** nằm ngoài mọi đợt tấn công, không đếm từng cảnh báo.

## 12. Điểm mọi cửa sổ — `<tên>.diem.csv`

Chỉ có khi chạy `nids.realtime --ghi-diem`. Cùng cột với `alerts.csv`, nhưng gồm **mọi** cửa sổ, kể cả nhãn không
cảnh báo (`normal`, `benign`, `normal_host`, `none`). Dùng để vẽ phân bố điểm hoặc đối chiếu với offline. File rất lớn.

## 13. Số liệu vận hành — `<tên>.so_lieu.jsonl`, `<tên>.so_lieu_tong.json`

`so_lieu.jsonl`: mỗi 10 giây một dòng. `so_lieu_tong.json`: tổng kết khi dừng.

| Trường | Ý nghĩa | Đọc thế nào |
|---|---|---|
| `goi_nhan`, `goi_xu_ly` | Gói nhận từ card / đã xử lý | Bằng nhau là không tồn đọng |
| `goi_bo_hang_doi`, `goi_bo_kernel`, `ty_le_bo` | Gói bỏ vì hàng đợi đầy / vì nhân Linux không kịp | **Phải là 0**; khác 0 nghĩa là máy không theo kịp tải |
| `goi_khong_phai_ip`, `goi_trung_bo` | Gói không phải IP; gói trùng đã bỏ (nếu bật) | |
| `toc_do_goi_s`, `toc_do_trung_binh_goi_s` | Gói mỗi giây | |
| `hang_doi_hien_tai`, `hang_doi_sau_nhat` | Số gói đang chờ, cao nhất | Gần `realtime.queue_size` (100 000) là sắp bỏ gói |
| `cpu_phan_tram`, `ram_mb`, `ram_lon_nhat_mb` | Tài nguyên tiến trình | |
| `do_tre_xu_ly_s` (`p50`, `p95`, `lon_nhat`) | Thời gian từ lúc gói tới đến lúc được xử lý | Không phải độ trễ phát hiện; độ trễ phát hiện còn gồm thời gian chờ cửa sổ |
| `canh_bao`, `su_kien` | Số cảnh báo, sự kiện | |
| `flow_dang_mo`, `flow_gan_day`, `cua_so_dang_mo`, `host_bat_thuong`, `su_kien_dang_mo` | Kích thước bộ nhớ trạng thái | Phải không tăng mãi |
| `cua_so_10s`, `cua_so_120s`, `thoi_gian_cham_s` | (tổng kết) Số cửa sổ đã chấm, thời gian chấm của từng module | |
| `ly_do_dung`, `goi_bo_khi_dung` | (tổng kết) `het_nguon` (hết file PCAP) hoặc tên tín hiệu dừng (`SIGINT`, `SIGTERM`); gói bỏ khi dừng | |
| `arp` | (tổng kết) Số gói ARP, số dấu hiệu giả mạo | |

## 14. Dấu hiệu giả mạo ARP — `<tên>.arp.jsonl`

Mỗi dòng một dấu hiệu (thường file **rỗng**, nghĩa là không có gì đáng ngờ).

| `loai` | Trường đi kèm | Ý nghĩa |
|---|---|---|
| `doi_mac` | `ip`, `mac_cu`, `mac_moi`, `mac_cu_thay_lan_cuoi` | Một IP đổi sang MAC khác: dấu hiệu chính của giả mạo ARP |
| `mot_mac_nhieu_ip` | `mac`, `ip` (danh sách) | Một MAC nhận là chủ của ≥ 3 IP: nghi vấn |
| `khung_khong_khop` | `ip`, `mac_arp`, `mac_khung` | MAC của khung khác MAC trong gói ARP: nghi vấn |

## 15. Log cảm biến — `output/realtime/log/nids_realtime.log`

Văn bản, xoay vòng theo dung lượng (`realtime.log_max_mb`). Gồm: dòng khởi động (nguồn, mạng, chế độ, commit, file
log), số liệu mỗi 10 giây, cảnh báo ARP, cảnh báo khi hàng đợi gần đầy, lỗi, dòng dừng (`dừng (het_nguon): ... gói,
... cảnh báo, ... sự kiện`). Đọc file này đầu tiên khi cảm biến dừng bất thường.

## 16. Nhật ký lần chạy lab — `data/run_logs/<mã>.json`

**Đáp án** của mỗi lần thử nghiệm, do bộ chạy kịch bản ghi, độc lập với mô hình. Mã lần chạy dạng
`<biến thể>-<vai trò>-<lần>`, ví dụ `k6-p2p-test-12` = kịch bản năm bot ngang hàng, dùng để kiểm tra, lần 12.

| Trường | Ý nghĩa |
|---|---|
| `ma_lan_chay`, `bien_the`, `vai_tro`, `lan`, `seed` | Định danh; `vai_tro` là `train` / `val` / `test`; seed quyết định giờ tấn công |
| `moi_truong` | Lab số mấy, nhân Linux, máy, phiên bản Nmap |
| `ban_thu` | File PCAP, giờ bắt đầu/kết thúc, máy giám sát, kích thước, **mã băm SHA-256**, `goi_bat_duoc`, `goi_nhan_bo` |
| `lech_dong_ho_s` | Lệch đồng hồ giữa các máy (lab ảo luôn 0) |
| `nen` | Lưu lượng bình thường: máy nào duyệt web, từ lúc nào |
| `hanh_vi` | **Danh sách tấn công/hành vi**: `kieu`, `nhan` (`port_scan`, `dos`, `botnet`, `benign`), `bat_dau(_epoch)`, `ket_thuc(_epoch)`, `ip_nguon`, `ip_dich`, `tham_so`, `lenh` đã chạy trên từng máy, `ma_thoat` |
| `nhat_ky_may_sinh` | Nhật ký chi tiết của các script sinh lưu lượng |

## 17. Kết quả chấm lab — `docs/hinh/thuc_nghiem/lab/`

**Theo đợt** (`nids.thuc_nghiem`, ví dụ `bo3/a_lab3.json`): `tong_hop` (`so_dot`, `phat_hien`, `bo_sot`,
`bao_gia`, `ty_le_phat_hien`) và `kich_ban` mỗi lần chạy một mục:

| Trường | Ý nghĩa |
|---|---|
| `phat_hien.theo_dot[]` | Mỗi đợt: `loai`, `host`, `bat_dau`, `thoi_luong_s`, `so_canh_bao`, `host_phat_hien`, `phat_hien` (đúng/sai), **`do_tre_s`** (giây từ lúc tấn công bắt đầu tới cuối cửa sổ đúng đầu tiên), `anomaly_do_tre_s` |
| `bao_gia` | `so_su_kien_bao_gia`, `moi_gio`, `theo_module`, `chi_tiet` |
| `do_tre` | Nhỏ nhất, trung vị, p95, lớn nhất của các đợt |
| `hieu_nang` | Số flow, số cửa sổ, thời gian từng bước |

**Theo cửa sổ** (`nids.lab_cua_so`, `cua_so_*.json`): precision/recall từng lớp trên mọi cửa sổ, `recall_theo_vai_tro`
(máy tấn công `tan_cong`, máy nạn nhân `nan_nhan`), `benign_bi_bao`.

**Theo bot** (`nids.bot_lab`, `bot_*.json`): mỗi biến thể `bot_bi_bao` / `tong_bot`, `ty_le_topology`,
`cua_so_bao_nham`, `may_bi_bao_nham`; mỗi lần chạy `bot_bo_sot`, `giay_toi_canh_bao_dau` từng bot.

## 18. Dashboard — `*.html`

Một file HTML tự chứa (hình nhúng sẵn, không cần mạng): dòng đầu tổng số cảnh báo, số máy, khoảng thời gian; bảng
số cảnh báo theo module và nhãn; **dòng thời gian** (mỗi hàng một máy, mỗi chấm một cảnh báo, màu theo nhãn); bảng
máy bị báo nhiều nhất; đồ thị máy bị nghi botnet (xanh lá: tập trung, tím: ngang hàng; cạnh giữa bot ngang hàng chỉ
minh họa cùng nhóm); bảng sự kiện. Mẫu: `docs/hinh/dashboard_mau.html`.

## 19. Đầu ra demo

| Thư mục | Từ | Gồm |
|---|---|---|
| `output/demo/<lần chạy>/` | `1_`, `2_`, `3_demo_*.bat` (lab ảo chạy trực tiếp) | `<lần chạy>.alerts.csv`, `nhat_ky_lan_chay.json` |
| `output/phat_lai/<lần chạy>/` | `5_phat_lai_ban_thu.bat` (phát lại bản thu) | `alerts.csv`, `su_kien.csv`, `so_lieu*.json*`, `arp.jsonl`, `dashboard.html` |

Mỗi lần chạy lại cùng kịch bản thì file cũ bị ghi đè. Phần tổng kết in trên màn hình demo (`Bản thu: ... gói, nhân
bỏ ... gói`, `Tấn công thật: ...`, `=> PHÁT HIỆN ... sau ... giây`, `báo động giả: ...`) được giải thích ở
`demo/HUONG_DAN.md` mục 3.2.

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Đầu ra | File hệ thống sinh ra sau một bước xử lý |
| CSV, JSON, JSONL | Bảng dạng văn bản; dữ liệu có cấu trúc; mỗi dòng một đối tượng JSON |
| Epoch | Số giây tính từ 0 giờ ngày 1/1/1970 theo giờ UTC |
| UTC | Giờ quốc tế; giờ Việt Nam = UTC + 7 |
| Flow, cửa sổ host | Một cuộc kết nối; hành vi của một máy trong 10 giây |
| Host–cửa sổ 120 giây | Hành vi liên lạc của một máy trong 120 giây, cho module botnet |
| d² Mahalanobis | Điểm của Gaussian: khoảng cách tới vùng bình thường, có tính quan hệ giữa các đặc trưng |
| Xác suất, tỷ lệ phiếu | Điểm của Random Forest: phần cây bỏ phiếu cho một nhãn |
| Sự kiện | Nhiều cảnh báo liên tiếp của cùng module, nhãn, máy, gộp thành một |
| Mã băm SHA-256 | Dấu vân tay của file; hai file cùng mã băm thì giống hệt nhau |
| Seed | Số khởi tạo phần ngẫu nhiên |
| Schema | Mô tả tên, kiểu, đơn vị, vai trò của từng cột |
| p50, p95 | Trung vị; giá trị mà 95% số đo nhỏ hơn |
