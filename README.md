# ml-nids

**Machine Learning-Based Network Intrusion Detection Using Network Traffic Data**

Đồ án: **Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng**.

Hệ thống giám sát chạy trên Kali Linux trong mạng lab cô lập, gồm ba module:

| Module | Phương pháp | Đầu ra |
|---|---|---|
| Anomaly | Gaussian đa biến học từ traffic bình thường | Bình thường/bất thường và điểm bất thường |
| Attack classification | Random Forest, so sánh với Logistic Regression | Benign, Port Scan, DoS |
| Botnet/topology | Đặc trưng beaconing và đồ thị giao tiếp | Host nghi vấn, cấu trúc tập trung/ngang hàng |

Bản đầu tiên chỉ xuất cảnh báo ra terminal và file CSV; dashboard làm sau.

## Tiến độ

Kế hoạch triển khai (12 chặng, 82 task): [docs/Ke_hoach_trien_khai.md](docs/Ke_hoach_trien_khai.md)

Tổng quan bộ dữ liệu, mô hình và dữ liệu chuẩn: [docs/10_tong_quan_du_lieu_mo_hinh.md](docs/10_tong_quan_du_lieu_mo_hinh.md)

### Chặng 1 — Chốt yêu cầu và khởi tạo dự án

- [x] C01-T01: Lập bảng yêu cầu bắt buộc và tùy chọn từ đề bài — [docs/01_yeu_cau.md](docs/01_yeu_cau.md)
- [x] C01-T02: Chốt đầu ra ba module: anomaly, attack classification, botnet/topology — [docs/02_dau_ra_module.md](docs/02_dau_ra_module.md), `src/nids/scope.py`, `src/nids/alerts.py`
- [x] C01-T03: Tạo repository và cấu trúc thư mục — xem mục Cấu trúc
- [x] C01-T04: Tạo môi trường Python, dependencies và .gitignore — `pyproject.toml`, `requirements.txt`, `.gitignore`
- [x] C01-T05: Tạo README, cấu hình chung và nhật ký quyết định kỹ thuật — `config/default.yaml`, [docs/03_nhat_ky_quyet_dinh.md](docs/03_nhat_ky_quyet_dinh.md)

Báo cáo Chặng 1: [docs/Bao_cao_Chang_1.md](docs/Bao_cao_Chang_1.md)

### Chặng 2 — Khảo sát dữ liệu và định dạng

- [x] C02-T01: Mô tả Global Header, Packet Header, Packet Data của PCAP; phân biệt với PCAPNG — [docs/04_dinh_dang_pcap.md](docs/04_dinh_dang_pcap.md)
- [x] C02-T02: Chọn một loại log dịch vụ: access log của Nginx — [docs/05_log_dich_vu.md](docs/05_log_dich_vu.md)
- [x] C02-T03: Chọn tập con CIC-IDS2017 cho phân loại — [docs/06_cic_ids2017.md](docs/06_cic_ids2017.md)
- [x] C02-T04: Kiểm tra các scenario CTU-13, file khả dụng và ý nghĩa nhãn — [docs/07_ctu13.md](docs/07_ctu13.md)
- [x] C02-T05: Tạo manifest: nguồn, file, thời gian, nhãn, mục đích sử dụng — `config/data_manifest.csv`, `src/nids/manifest.py`, [docs/08_manifest_du_lieu.md](docs/08_manifest_du_lieu.md)
- [x] C02-T06: Chốt dữ liệu còn phải tự thu trong lab — [docs/09_du_lieu_lab.md](docs/09_du_lieu_lab.md)

Báo cáo Chặng 2: [docs/Bao_cao_Chang_2.md](docs/Bao_cao_Chang_2.md)

### Chặng 3 — Chuyển PCAP và log thành dữ liệu có cấu trúc

- [x] C03-T01: Viết bộ đọc PCAP theo từng packet — `src/nids/pcap_reader.py`, [docs/11_bo_doc_pcap.md](docs/11_bo_doc_pcap.md)
- [x] C03-T02: Trích xuất timestamp, IP, giao thức, độ dài — `src/nids/packets.py`, [docs/12_trich_xuat_packet.md](docs/12_trich_xuat_packet.md)
- [x] C03-T03: Trích xuất port và cờ TCP khi tồn tại — `src/nids/packets.py`, [docs/13_port_co_tcp.md](docs/13_port_co_tcp.md)
- [x] C03-T04: Xử lý packet không hỗ trợ, lỗi và thống kê bỏ qua — `src/nids/packets.py`, [docs/14_goi_bo_qua.md](docs/14_goi_bo_qua.md)
- [x] C03-T05: Viết parser cho log dịch vụ đã chọn (access log Nginx) — `src/nids/service_log.py`, [docs/15_parser_log.md](docs/15_parser_log.md)
- [x] C03-T06: Xuất dữ liệu log thành bảng; đối chiếu một số dòng với bản gốc — `src/nids/log_compare.py`, [docs/16_xuat_doi_chieu_log.md](docs/16_xuat_doi_chieu_log.md)
- [x] C03-T07: Đối chiếu kết quả đọc packet với Wireshark — `src/nids/wireshark_compare.py`, [docs/17_doi_chieu_wireshark.md](docs/17_doi_chieu_wireshark.md)

Báo cáo Chặng 3: [docs/Bao_cao_Chang_3.md](docs/Bao_cao_Chang_3.md)

### Chặng 4 — Xây dựng flow và đặc trưng

- [x] C04-T01: Định nghĩa flow hai chiều và quy tắc forward/backward — `src/nids/flows.py`, [docs/18_flow_hai_chieu.md](docs/18_flow_hai_chieu.md)
- [x] C04-T02: Xử lý timeout, FIN/RST và tái sử dụng 5-tuple — `src/nids/flows.py`, [docs/19_ket_thuc_flow.md](docs/19_ket_thuc_flow.md)
- [x] C04-T03: Tính packet, byte, thời lượng và tỷ lệ gửi/nhận — `src/nids/flow_features.py`, [docs/20_dac_trung_flow_co_ban.md](docs/20_dac_trung_flow_co_ban.md)
- [x] C04-T04: Tính thống kê kích thước, inter-arrival time và cờ TCP — `src/nids/flow_features.py`, [docs/21_thong_ke_flow.md](docs/21_thong_ke_flow.md)
- [x] C04-T05: Xây dựng cửa sổ host theo thời gian packet — `src/nids/host_windows.py`, [docs/22_cua_so_host.md](docs/22_cua_so_host.md)
- [x] C04-T06: Tính số đích, cổng đích, kết nối mới và entropy cổng — `src/nids/window_features.py`, [docs/23_dac_trung_cua_so.md](docs/23_dac_trung_cua_so.md)
- [x] C04-T07: Tính tỷ lệ kết nối không hoàn tất sau thời gian quan sát quy định — `src/nids/window_features.py`, [docs/24_ket_noi_khong_hoan_tat.md](docs/24_ket_noi_khong_hoan_tat.md)
- [x] C04-T08: Xuất bảng đặc trưng cùng schema và metadata — `src/nids/feature_export.py`, [docs/25_xuat_bang_dac_trung.md](docs/25_xuat_bang_dac_trung.md)

Báo cáo Chặng 4: [docs/Bao_cao_Chang_4.md](docs/Bao_cao_Chang_4.md)

### Chặng 5 — Gán nhãn, EDA và chia dữ liệu

- [x] C05-T01: Ghép nhãn từ nguồn và metadata phù hợp — `src/nids/labeling.py`, `config/label_schedule.csv`, [docs/26_gan_nhan.md](docs/26_gan_nhan.md)
- [x] C05-T02: Báo cáo mẫu khớp, không khớp và mơ hồ — `src/nids/label_report.py`, [docs/27_bao_cao_nhan.md](docs/27_bao_cao_nhan.md)
- [x] C05-T03: Định nghĩa nhãn cho cửa sổ chứa nhiều hành vi — `src/nids/labeling.py`, [docs/28_nhan_cua_so.md](docs/28_nhan_cua_so.md)
- [x] C05-T04: Chia train/validation/test theo phiên hoặc scenario — `src/nids/splits.py`, [docs/29_chia_du_lieu.md](docs/29_chia_du_lieu.md)
- [x] C05-T05: Kiểm tra thiếu, vô hạn, trùng và phân bố lớp — `src/nids/data_quality.py`, `src/nids/dataset.py`, [docs/30_kiem_tra_du_lieu.md](docs/30_kiem_tra_du_lieu.md)
- [x] C05-T06: Vẽ EDA cho các đặc trưng chính — `src/nids/eda.py`, [docs/31_eda.md](docs/31_eda.md)
- [x] C05-T07: Xây dựng tiền xử lý; chỉ fit và cân bằng lớp trên train — `src/nids/preprocessing.py`, [docs/32_tien_xu_ly.md](docs/32_tien_xu_ly.md)

Báo cáo Chặng 5: [docs/Bao_cao_Chang_5.md](docs/Bao_cao_Chang_5.md)

### Chặng 6 — Gaussian anomaly detection

- [x] C06-T01: Chọn đặc trưng và lấy mẫu bình thường trong train — `src/nids/gaussian.py`, [docs/33_gaussian_dac_trung.md](docs/33_gaussian_dac_trung.md)
- [x] C06-T02: Kiểm tra phân bố và xác định phép biến đổi cần thiết — `src/nids/gaussian.py`, [docs/34_gaussian_phan_bo.md](docs/34_gaussian_phan_bo.md)
- [x] C06-T03: Huấn luyện Gaussian, xử lý covariance suy biến — `src/nids/gaussian.py`, [docs/35_gaussian_huan_luyen.md](docs/35_gaussian_huan_luyen.md)
- [x] C06-T04: Tính điểm bất thường và chọn ngưỡng trên validation — `src/nids/gaussian.py`, [docs/36_gaussian_nguong.md](docs/36_gaussian_nguong.md)
- [x] C06-T05: Đánh giá Precision, Recall, F1 và false positive rate — `src/nids/gaussian.py`, [docs/37_gaussian_danh_gia.md](docs/37_gaussian_danh_gia.md)
- [x] C06-T06: Lưu mô hình, ngưỡng, tiền xử lý và notebook — `src/nids/gaussian.py`, `notebooks/06_gaussian.ipynb`, [docs/38_gaussian_luu_mo_hinh.md](docs/38_gaussian_luu_mo_hinh.md)

Báo cáo Chặng 6: [docs/Bao_cao_Chang_6.md](docs/Bao_cao_Chang_6.md)

### Chặng 7 — Phân loại tấn công đa lớp

- [x] C07-T01: Chốt nhãn thực tế: Benign, PortScan, DoS — `src/nids/classifier.py`, [docs/39_phan_loai_nhan.md](docs/39_phan_loai_nhan.md)
- [x] C07-T02: Logistic Regression làm mô hình đối chiếu — `src/nids/classifier.py`, [docs/40_phan_loai_lr.md](docs/40_phan_loai_lr.md)
- [x] C07-T03: Random Forest — `src/nids/classifier.py`, [docs/41_phan_loai_rf.md](docs/41_phan_loai_rf.md)
- [x] C07-T04: Chọn tham số và mô hình bằng validation — `src/nids/classifier.py`, [docs/42_phan_loai_chon.md](docs/42_phan_loai_chon.md)
- [x] C07-T05: Đánh giá macro-F1, chỉ số từng lớp và confusion matrix — `src/nids/classifier.py`, [docs/43_phan_loai_danh_gia.md](docs/43_phan_loai_danh_gia.md)
- [x] C07-T06: Phân tích nhầm lẫn và lưu artifact — `src/nids/classifier.py`, [docs/44_phan_loai_phan_tich.md](docs/44_phan_loai_phan_tich.md)

Báo cáo Chặng 7: [docs/Bao_cao_Chang_7.md](docs/Bao_cao_Chang_7.md)

### Chặng 8 — Botnet và nhận diện topology

- [x] C08-T01: Đồ thị theo cửa sổ: node, cạnh, trọng số — `src/nids/ctu13.py`, `src/nids/graph_features.py`, [docs/45_do_thi_cua_so.md](docs/45_do_thi_cua_so.md)
- [x] C08-T02: Số peer, bậc vào/ra, tính tương hỗ và mức tập trung — `src/nids/graph_features.py`, [docs/46_dac_trung_do_thi.md](docs/46_dac_trung_do_thi.md)
- [x] C08-T03: Đặc trưng beaconing với số quan sát tối thiểu — `src/nids/graph_features.py`, [docs/47_beaconing.md](docs/47_beaconing.md)
- [x] C08-T04: Dữ liệu host–cửa sổ có nhãn botnet; cách xử lý Background — `src/nids/ctu13.py`, `src/nids/botnet.py`, [docs/48_botnet_nhan.md](docs/48_botnet_nhan.md)
- [x] C08-T05: Huấn luyện và so sánh hai mô hình phát hiện botnet — `src/nids/botnet.py`, [docs/49_botnet_mo_hinh.md](docs/49_botnet_mo_hinh.md)
- [x] C08-T06: Dữ liệu topology tập trung, ngang hàng và đối chứng lành tính — `src/nids/topology_sim.py`, `scripts/sinh_topology.py`, [docs/50_du_lieu_topology.md](docs/50_du_lieu_topology.md)
- [x] C08-T07: Bộ nhận diện topology (quy tắc, không ML) — `src/nids/botnet.py`, [docs/51_nhan_dien_topology.md](docs/51_nhan_dien_topology.md)
- [x] C08-T08: Đánh giá phát hiện botnet và nhận diện topology bằng hai bảng riêng — `src/nids/botnet.py`, [docs/52_botnet_danh_gia.md](docs/52_botnet_danh_gia.md)

Báo cáo Chặng 8: [docs/Bao_cao_Chang_8.md](docs/Bao_cao_Chang_8.md)

### Chặng 9 — Tích hợp pipeline offline

- [x] C09-T01: Bộ nạp artifact và kiểm tra schema — `src/nids/pipeline.py`, [docs/53_nap_artifact.md](docs/53_nap_artifact.md)
- [x] C09-T02: Chạy PCAP qua toàn bộ pipeline — `src/nids/pipeline.py`, `src/nids/pcap_cut.py`, [docs/54_chay_pcap.md](docs/54_chay_pcap.md)
- [x] C09-T03: Đầu ra độc lập của các module và hợp nhất cảnh báo — `src/nids/pipeline.py`, [docs/55_hop_nhat_canh_bao.md](docs/55_hop_nhat_canh_bao.md)

Những gì còn thiếu sau Chặng 1–8 (việc đang dở, dữ liệu, lab, tham số chưa chốt): [docs/Viec_con_thieu.md](docs/Viec_con_thieu.md)

## Cấu trúc

```
config/default.yaml   Cấu hình chung: cửa sổ, timeout, địa chỉ lab, đường dẫn
config/data_manifest.csv  Manifest dữ liệu: nguồn, file, nhãn, mục đích
config/label_schedule.csv Lịch tấn công: nguồn nhãn (giờ, IP, cổng, nhãn)
docs/                 Yêu cầu, đầu ra module, nhật ký quyết định, báo cáo
src/nids/
  scope.py            Tên module và tập nhãn
  config.py           Đọc cấu hình
  manifest.py         Đọc và kiểm tra manifest dữ liệu; so mã băm file đã tải
  pcap_reader.py      Đọc file PCAP/PCAPNG theo từng packet
  packets.py          Trích xuất timestamp, IP, giao thức, độ dài, port, cờ TCP;
                      thống kê gói bỏ qua
  service_log.py      Đọc access log Nginx định dạng nids, xuất CSV
  log_compare.py      Đối chiếu bảng CSV của log với file gốc
  wireshark_compare.py  Đối chiếu kết quả đọc packet với tshark
  flows.py            Ghép packet thành flow hai chiều, xác định forward/backward,
                      kết thúc flow theo FIN/RST, timeout, 5-tuple dùng lại
  flow_features.py    Đặc trưng flow: số gói, byte, payload, thời lượng, tỷ lệ gửi/nhận;
                      thống kê kích thước, inter-arrival time, cờ TCP
  pcap_survey.py      Khảo sát bản thu lớn: mã băm, thời gian, gói bỏ qua, flow, host
  host_windows.py     Cửa sổ thời gian theo host (10 giây, bước 2 giây) theo thời điểm gói
  window_features.py  Đặc trưng cửa sổ host: số đích, cổng đích, kết nối mới, entropy cổng,
                      tỷ lệ kết nối TCP không hoàn tất
  feature_export.py   Xuất bảng đặc trưng flow và cửa sổ kèm schema, metadata; đọc lại bảng
  labeling.py         Gán nhãn flow và cửa sổ host theo lịch tấn công
  label_report.py     Báo cáo nhãn; đối chiếu với CSV có nhãn của CIC
  splits.py           Chia train/validation/test theo thời gian trong từng khối tấn công
  dataset.py          Đọc bảng đặc trưng kèm nhãn và tập vào pandas
  data_quality.py     Kiểm tra thiếu, vô hạn, trùng, phân bố lớp
  eda.py              Vẽ EDA trên tập train
  preprocessing.py    Tiền xử lý: chỉ fit và cân bằng lớp trên train
  gaussian.py         Gaussian đa biến phát hiện bất thường trên cửa sổ host
  alerts.py           Schema cảnh báo, xuất terminal + CSV
tests/                Kiểm thử
scripts/              Script đọc PCAP, sinh traffic mô phỏng (chưa có)
notebooks/            Notebook huấn luyện và đánh giá (06_gaussian.ipynb)
data/                 Dataset, PCAP, nhật ký lần chạy (không đưa lên git)
models/               Mô hình đã huấn luyện (không đưa lên git)
output/               File cảnh báo và kết quả chạy (không đưa lên git)
```

## Cài đặt

Yêu cầu Python 3.10 trở lên.

Linux / Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

Thêm thư viện cho notebook: `pip install -e ".[notebook]"`.
Nếu không dùng `pyproject.toml`, có thể cài bằng `pip install -r requirements.txt`
rồi đặt `PYTHONPATH=src`.

## Tải dữ liệu

Dữ liệu không nằm trong git (file PCAP của CIC-IDS2017 khoảng 10 GB mỗi ngày;
GitHub không nhận file trên 100 MB). Mỗi người tự tải từ nguồn chính thức rồi
đặt vào `data/`, giữ nguyên tên file:

| Nguồn | Lấy ở đâu | Đặt vào |
|---|---|---|
| CIC-IDS2017 (PCAP thứ Hai, thứ Tư, thứ Sáu) | https://www.unb.ca/cic/datasets/ids-2017.html, điền form đăng ký. Không dùng bản chép lại trên Kaggle | `data/pcap/cic-ids2017/` |
| CIC-IDS2017 (`GeneratedLabelledFlows.zip`) | Cùng nơi tải PCAP | `data/cic-ids2017/`, giải nén vào `data/cic-ids2017/TrafficLabelling/` |
| CTU-13 (file `.binetflow`) | https://www.stratosphereips.org/datasets-ctu13. Không tải file mẫu mã độc | `data/ctu13/` |

Sau khi tải, kiểm tra file có đúng bản gốc không (so mã băm SHA-256 ghi trong
`config/data_manifest.csv`):

```bash
python -m nids.manifest --verify
```

Mọi file phải báo `khop`. File báo `sai_ma_bam` là tải dở hoặc khác bản gốc,
phải tải lại; `thieu_file` là chưa tải. Chi tiết từng file ở
[docs/06_cic_ids2017.md](docs/06_cic_ids2017.md) và
[docs/08_manifest_du_lieu.md](docs/08_manifest_du_lieu.md).

## Chạy thử

```bash
# Kiểm thử
python -m unittest discover -s tests

# Xuất cảnh báo mẫu để kiểm tra định dạng (không phải kết quả thực nghiệm)
python -m nids.alerts

# Xem nhanh một file PCAP/PCAPNG: 10 packet đầu và tóm tắt
python -m nids.pcap_reader data/pcap/<file>.pcap -n 10

# Trích xuất bảng gói IP ra CSV, kèm thống kê gói bỏ qua
python -m nids.packets data/pcap/<file>.pcap --csv output/packets.csv --stats output/packets_stats.json

# Đối chiếu từng packet với Wireshark (cần cài Wireshark/tshark)
python -m nids.wireshark_compare data/pcap/<file>.pcap --report output/ws_compare.json

# Ghép packet thành flow hai chiều và tính đặc trưng cơ bản (gói, byte, thời lượng, tỷ lệ)
python -m nids.flows data/pcap/<file>.pcap --csv output/flows.csv --stats output/flows_stats.json

# Khảo sát một bản thu lớn: mã băm, thời gian, gói bỏ qua, flow; theo dõi một cặp IP theo phút
python -m nids.pcap_survey data/pcap/cic-ids2017/Friday-WorkingHours.pcap --pair 172.16.0.1:192.168.10.50 --report output/survey_friday.json

# Cửa sổ host 10 giây bước 2 giây, chỉ cho host trong mạng nội bộ
python -m nids.host_windows data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/host_windows.csv

# Đặc trưng cửa sổ host (ghép flow cùng lúc để biết vai client/server)
python -m nids.window_features data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/windows.csv

# Xuất bảng đặc trưng (flow + cửa sổ host) kèm schema và metadata, đầu vào của Chặng 5
python -m nids.feature_export data/pcap/<file>.pcap --net 192.168.10.0/24 --out output/features

# Gán nhãn theo lịch tấn công (ghi <tên>.flows.labels.csv và <tên>.windows.labels.csv)
python -m nids.labeling output/features/cic17_wednesday.flows.csv

# Báo cáo nhãn: khớp, không khớp, mơ hồ; đối chiếu với CSV có nhãn của CIC
python -m nids.label_report output/features/cic17_wednesday.flows.csv --cic-csv data/cic-ids2017/TrafficLabelling/Wednesday-workingHours.pcap_ISCX.csv

# Chia train/validation/test theo thời gian (ghi <tên>.flows.split.csv, <tên>.windows.split.csv)
python -m nids.splits output/features/cic17_wednesday.flows.csv

# Kiểm tra dữ liệu trước khi huấn luyện
python -m nids.data_quality output/features/cic17_monday output/features/cic17_wednesday output/features/cic17_friday --out output/quality.json

# Vẽ EDA trên tập train (cần pip install -e ".[notebook]")
python -m nids.eda output/features/cic17_monday output/features/cic17_wednesday output/features/cic17_friday --out docs/hinh

# Fit tiền xử lý trên train, lưu vào models/ (--table flows|windows, --module attack_classification|anomaly)
python -m nids.preprocessing --table windows --module attack_classification output/features/cic17_monday output/features/cic17_wednesday output/features/cic17_friday

# Gaussian (chạy trong src/): kiểm tra phân bố, chọn ngưỡng, huấn luyện và lưu, đánh giá, dự đoán
python -m nids.gaussian phan-bo ../output/features/cic17_monday --fit-session cic17_monday --out ../docs/hinh
python -m nids.gaussian nguong ../output/features/cic17_monday ../output/features/cic17_wednesday ../output/features/cic17_friday --out ../docs/hinh
python -m nids.gaussian huan-luyen ../output/features/cic17_monday ../output/features/cic17_wednesday ../output/features/cic17_friday
python -m nids.gaussian danh-gia ../output/features/cic17_monday ../output/features/cic17_wednesday ../output/features/cic17_friday --model ../models/gaussian_windows.joblib --out ../docs/hinh --so-sanh
python -m nids.gaussian du-doan ../output/features/cic17_monday --khong-nhan --model ../models/gaussian_windows.joblib --out ../output/du_doan.csv

# Phân loại tấn công (chạy trong src/): nhãn, chọn trên validation, đánh giá test, lưu, phân tích, dự đoán
python -m nids.classifier nhan ../output/features/cic17_wednesday ../output/features/cic17_friday --out ../docs/hinh
python -m nids.classifier chon ../output/features/cic17_wednesday ../output/features/cic17_friday --out ../docs/hinh
python -m nids.classifier danh-gia ../output/features/cic17_wednesday ../output/features/cic17_friday --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
python -m nids.classifier huan-luyen ../output/features/cic17_wednesday ../output/features/cic17_friday --chon ../docs/hinh/phan_loai_chon.json
python -m nids.classifier phan-tich ../output/features/cic17_wednesday ../output/features/cic17_friday --model ../models/phan_loai_rf_windows.joblib --model ../models/phan_loai_lr_windows.joblib --hoan-vi --out ../docs/hinh
python -m nids.classifier du-doan ../output/features/cic17_monday --khong-nhan --model ../models/phan_loai_rf_windows.joblib --out ../output/du_doan_phan_loai.csv

# Botnet và topology: chuẩn bị CTU-13 (chạy ở thư mục gốc), đặc trưng, nhãn, mô hình, giả lập, đánh giá (chạy trong src/)
python -m nids.ctu13 chuan-bi data/ctu13 --out output/ctu13
python -m nids.graph_features dac-trung ../output/ctu13 --scenario 1 --scenario 2 --scenario 3 --scenario 4 --scenario 5 --scenario 6 --scenario 7 --scenario 8 --scenario 9 --scenario 10 --scenario 11 --scenario 12 --scenario 13 --out ../output/ctu13
python -m nids.botnet nhan ../output/ctu13 --out ../docs/hinh
python -m nids.botnet huan-luyen ../output/ctu13 --out ../docs/hinh
python -m nids.topology_sim --out ../output/topology_sim
python -m nids.botnet danh-gia ../output/ctu13 --sim-dir ../output/topology_sim --model ../models/botnet_rf.joblib --model ../models/botnet_lr.joblib --chon botnet_rf --out ../docs/hinh

# Đọc access log Nginx của một lần chạy, xuất bảng CSV rồi đối chiếu với file gốc
python -m nids.service_log data/service_logs/<run_id>/access_nids.log --csv output/log.csv
python -m nids.log_compare data/service_logs/<run_id>/access_nids.log output/log.csv -k 20
```

## Quy ước

- Tham số chỉnh trong `config/default.yaml`, không viết cứng trong mã.
- Mỗi quyết định kỹ thuật thêm một mục vào `docs/03_nhat_ky_quyet_dinh.md`.
- Chỉ thử nghiệm trong mạng lab cô lập; giao tiếp botnet mô phỏng bằng thông điệp vô hại.
- Mỗi file Markdown kết thúc bằng mục **Thuật ngữ**: bảng giải thích ngắn các
  thuật ngữ dùng trong file đó. File mới phải có mục này; khi sửa file mà thêm
  thuật ngữ mới thì bổ sung vào bảng.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Học máy (machine learning) | Cách cho máy tính tự rút ra quy luật từ dữ liệu mẫu thay vì lập trình từng quy tắc bằng tay |
| Lưu lượng mạng (traffic) | Toàn bộ gói tin đi qua mạng trong một khoảng thời gian |
| Module | Một phần độc lập của hệ thống, làm một việc riêng. Dự án có ba module phát hiện |
| Anomaly (bất thường) | Hành vi khác xa trạng thái bình thường đã học. Module anomaly báo động khi thấy hành vi như vậy, dù không biết đó là tấn công gì |
| Attack classification (phân loại tấn công) | Gán mỗi mẫu traffic vào một lớp đã biết: Benign (bình thường), Port Scan (quét cổng), DoS (làm nghẽn dịch vụ) |
| Botnet | Mạng các máy bị nhiễm mã độc, cùng nhận lệnh từ kẻ điều khiển |
| Topology | Hình dạng của mạng giao tiếp: tập trung (mọi máy nói chuyện với một máy chủ điều khiển) hay ngang hàng (các máy nói chuyện trực tiếp với nhau) |
| Gaussian đa biến | Mô hình thống kê mô tả dữ liệu bình thường bằng giá trị trung bình và độ phân tán của nhiều đặc trưng cùng lúc; mẫu nằm quá xa vùng đó bị coi là bất thường |
| Random Forest | Mô hình phân loại gồm nhiều cây quyết định; mỗi cây bỏ phiếu và lớp được nhiều phiếu nhất là kết quả |
| Logistic Regression | Mô hình phân loại đơn giản, tính xác suất của mỗi lớp từ tổng có trọng số của các đặc trưng; dùng để so sánh với Random Forest |
| Beaconing | Máy bị nhiễm định kỳ gọi về máy chủ điều khiển, ví dụ cứ 60 giây một lần, như đèn hiệu nhấp nháy đều đặn |
| Đồ thị giao tiếp | Hình vẽ (theo nghĩa toán học) trong đó mỗi máy là một điểm, mỗi cặp máy có trao đổi là một đường nối |
| Host | Một máy trong mạng, xác định bằng địa chỉ IP |
| Dashboard | Trang giao diện hiển thị số liệu và cảnh báo trực quan |
| CSV | File bảng dạng chữ, mỗi dòng một bản ghi, các cột cách nhau bằng dấu phẩy; mở được bằng Excel |
| Terminal | Cửa sổ dòng lệnh, nơi gõ lệnh và xem chương trình in kết quả |
| PCAP / PCAPNG | Hai định dạng file lưu gói tin bắt được trên mạng (xem docs/04) |
| Kali Linux | Bản Linux chuyên cho kiểm thử bảo mật; là máy giám sát của lab |
| Python, venv, pip | Python là ngôn ngữ lập trình của dự án; venv là môi trường ảo tách thư viện của dự án khỏi máy; pip là công cụ cài thư viện |
| Unittest / kiểm thử | Đoạn mã tự động chạy chương trình với dữ liệu biết trước và kiểm tra kết quả đúng như mong đợi |
| Config / YAML | Cấu hình là các tham số chỉnh được mà không sửa mã; YAML là định dạng file chữ dễ đọc dùng cho cấu hình |
| Manifest | Bảng liệt kê mọi nguồn dữ liệu: lấy ở đâu, file nào, nhãn gì, dùng làm gì |
| Lab cô lập | Mạng thử nghiệm riêng không nối ra Internet, để tấn công thử không ảnh hưởng ra ngoài |
| Mã task Cxx-Txx | Mã công việc trong kế hoạch: Cxx là số chặng, Txx là số task trong chặng |
| NIDS | Network Intrusion Detection System: hệ thống phát hiện xâm nhập mạng, theo dõi lưu lượng để phát hiện tấn công. Tên dự án `ml-nids` nghĩa là NIDS dùng học máy |
| Flow hai chiều | Mọi gói qua lại giữa hai đầu của một kết nối (cùng IP, cổng, giao thức), gộp chiều đi và chiều về |
| Forward / backward | Chiều từ bên mở kết nối (client) sang server / chiều từ server về client |
| Timeout | Khoảng thời gian không có gói mới (hoặc độ dài tối đa) sau đó flow được coi là kết thúc |
| Mã băm SHA-256 | Chuỗi 64 ký tự tính từ nội dung file; hai file cùng mã băm thì giống nhau từng byte |
| Inter-arrival time | Khoảng thời gian giữa hai gói tới liên tiếp |
| Entropy | Độ đa dạng của một phân bố; ví dụ entropy cổng cao nghĩa là gói gửi tới rất nhiều cổng khác nhau |
| Schema, metadata | Mô tả các cột của bảng / thông tin bảng được tạo từ file nào, tham số nào, mã nào |
| Đặc trưng (feature) | Con số mô tả một flow hay một host, là đầu vào của mô hình học máy |
