# C12-T03 — Kiến trúc, hướng dẫn triển khai và tái lập

Tài liệu cho người nhận bàn giao: hệ thống gồm những phần nào, chạy trên máy giám sát thế nào, và làm lại toàn bộ
kết quả từ đầu thế nào. Quy trình xử lý dữ liệu chi tiết: `docs/77`. Từng yêu cầu ở đâu: `docs/83`, `docs/86`.

## 1. Kiến trúc

```
                    ┌──────────────────────────────── máy giám sát (Kali / Linux) ───────────────────────────────┐
 cổng mirror ──────>│ nguon_goi (AF_PACKET)  ─┐                                                                   │
 hoặc file PCAP ───>│ pcap_reader ────────────┼─> packets ─> flows ─┬─> host_windows (10 s) ─┬─> Gaussian ───┐   │
                    │                         │   (header)  (flow     │                         └─> Random Forest┼─> alerts
                    │      cam_bien.Duplicate │             2 chiều)  └─> graph_features (120 s) ─> botnet RF ──┤   (CSV,
                    │      duong_ham (tùy chọn)                                                    + topology ──┘    sự kiện)
                    │      arp_gia_mao (gói không phải IP) ─────────────────────────────────────────────> arp.jsonl  │
                    └─────────────────────────────────────────────────────────────────────────────────────────────────┘
                                 config/*.yaml (tham số)        models/*.joblib (mô hình + tiền xử lý + ngưỡng)
```

| Tầng | Mô-đun (`src/nids/`) | Vai trò |
|---|---|---|
| Nguồn gói | `nguon_goi.py`, `pcap_reader.py` | Card mạng (socket `AF_PACKET`, dấu thời gian của nhân) hoặc file PCAP/PCAPNG |
| Tiền xử lý gói | `cam_bien.py` (`DuplicateFilter`), `duong_ham.py`, `packets.py` | Khử gói trùng, bóc đường hầm (đều tùy chọn), đọc header |
| Flow | `flows.py`, `flow_features.py` | Ghép gói thành flow hai chiều, đặc trưng flow |
| Cửa sổ | `host_windows.py`, `window_features.py`, `graph_features.py` | Cửa sổ host 10 s; đồ thị và gọi định kỳ 120 s |
| Mô hình | `gaussian.py`, `classifier.py`, `botnet.py`, `dos_cham.py` | Ba module và lớp giữ nhãn `dos` (tùy chọn) |
| Ghép và cảnh báo | `pipeline.py`, `alerts.py` | Chế độ `doc_lap` / `tuan_tu` / `ket_hop`; schema cảnh báo chung; gộp sự kiện |
| Realtime | `realtime.py` | Hai luồng qua hàng đợi có giới hạn; dọn state; log; số liệu vận hành |
| Quy tắc ngoài học máy | `arp_gia_mao.py` | Dấu hiệu giả mạo ARP |
| Báo cáo | `dashboard.py` | Trang HTML tĩnh từ file cảnh báo |

Nguyên tắc: **offline và realtime dùng đúng một đoạn mã** từ đọc header tới chấm điểm (B12). Kiểm tra: realtime và
offline cho cùng nhãn ở mọi cửa sổ trên 15 467 cửa sổ (`docs/66`).

### Cấu hình

| File | Dùng khi |
|---|---|
| `config/default.yaml` | Dữ liệu CIC-IDS2017 / CTU-13, mô hình trong `models/` (chờ bắt tay 3 giây, chế độ `ket_hop`) |
| `config/cic_h1.yaml` | Như trên nhưng chờ bắt tay 1 giây, mô hình `models/h1/` (`docs/72` mục 2.5) |
| `config/lab.yaml` | Mạng lab 192.168.50.0/24, mô hình học lại trên lab `models/lab/`, chế độ `doc_lap` |

Các tùy chọn mặc định tắt: `capture.khu_goi_trung_ms` (khử gói trùng), `capture.giai_duong_ham` (bóc đường hầm),
`pipeline.dos_hold` (giữ nhãn `dos`).

## 2. Cài đặt

```bash
git clone https://github.com/nkhhieu123/ml-nids && cd ml-nids
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .                                        # thư viện bắt buộc
pip install -e ".[notebook,hoc_sau,so_sanh]"            # tùy chọn: notebook, LightGBM/PyTorch, Scapy/dpkt/PyShark
python -m unittest discover -s tests                    # 461+ kiểm thử
```

Đã kiểm tra (C12-T06, 25/11/2026): clone vào thư mục mới, môi trường Python mới (pandas 3.1, numpy 2.5,
scikit-learn 1.9), cài bằng `pip install -e .`, **toàn bộ kiểm thử đạt** (2 kiểm thử bỏ qua vì cần Linux hoặc
TShark). Lần kiểm tra này tìm và sửa hai lỗi: thiếu `matplotlib` trong thư viện bắt buộc; đổi thời gian CTU-13 sai
1 000 lần trên pandas 3 (pandas 3 lưu thời gian theo micro giây).

## 3. Triển khai trên máy giám sát (Kali Linux)

```bash
sudo bash scripts/cai_dat_kali.sh                       # cài gói hệ thống, Python, thư viện
python -m nids.moi_truong                               # kiểm tra Python, quyền bắt gói, card mạng, NTP
sudo tcpdump -i eth1 -c 20000 -w thu.pcap               # bắt thử ở cổng mirror
python -m nids.cam_bien thu.pcap --net 192.168.50.0/24  # cảm biến có thấy cả hai chiều không
sudo python -m nids.realtime --iface eth1 --net 192.168.50.0/24 --config config/lab.yaml --out output/realtime
sudo bash scripts/cai_dich_vu.sh                        # chạy nền bằng systemd (deploy/nids-realtime.service)
python -m nids.dashboard output/realtime/<tên>.alerts.csv --out dashboard.html
```

Tài liệu từng bước: `docs/59` (cài), `docs/60` (cảm biến hai chiều), `docs/61` (realtime), `docs/62`–`64` (hàng
đợi, hiệu năng, dừng và log), `docs/65` (systemd).

**Trạng thái trung thực:** các bước trên đã chạy trên lab ảo (WSL2 Ubuntu, namespace máy giám sát) nhưng **chưa
chạy trên máy Kali thật với card thật**. Tên card `eth0` trong cấu hình là giả định, phải sửa `capture.interface`.

## 4. Tái lập kết quả từ đầu

Thứ tự và thời gian ước tính trên máy 12 luồng. Dữ liệu (`data/`), bảng đặc trưng (`output/`) và mô hình
(`models/`) không có trong git; nhật ký lần chạy lab (`data/run_logs/`) có trong git.

| Bước | Lệnh (chạy trong `src/`, trừ khi ghi khác) | Ra | Tài liệu |
|---|---|---|---|
| 1. Tải dữ liệu, kiểm mã băm | tải theo `config/data_manifest.csv`; `python -m nids.manifest --verify` | `data/pcap/cic-ids2017/`, `data/ctu13/` | `08` |
| 2. Trích xuất CIC (3 ngày) | `python -m nids.feature_export ../data/pcap/cic-ids2017/<ngày>.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 --out ../output/features --name cic17_<ngày>` | flow, cửa sổ host (khoảng 10 phút mỗi ngày) | `25` |
| 3. Gán nhãn, chia tập | `python -m nids.labeling ../output/features/cic17_*.flows.csv`; `python -m nids.splits ../output/features/cic17_<ngày>.flows.csv` | `*.labels.csv`, `*.split.csv` | `26`–`29` |
| 4. Gaussian | `python -m nids.gaussian huan-luyen $F/cic17_monday $F/cic17_wednesday $F/cic17_friday`; `danh-gia ... --model ../models/gaussian_windows.joblib --out ../docs/hinh` | mô hình, `gauss_test.json` | `35`–`38` |
| 5. Bộ phân loại | `python -m nids.classifier chon ...`; `danh-gia ...`; `huan-luyen ...` (thứ Tư, thứ Sáu) | `phan_loai_rf_windows.joblib`, `phan_loai_test.json` | `42`–`44` |
| 6. Baseline, học sâu | `python -m nids.so_sanh_mo_hinh ...`; `python -m nids.hoc_sau ...` | `so_sanh_mo_hinh.json`, `hoc_sau/` | `78`, `82` |
| 7. CTU-13, botnet | `python -m nids.ctu13 chuan-bi ../data/ctu13 --out ../output/ctu13`; `python -m nids.graph_features dac-trung ...`; `python -m nids.botnet huan-luyen ../output/ctu13 --out ../docs/hinh`; `danh-gia ...` | `botnet_rf.joblib` | `45`–`52` |
| 8. Pipeline offline | `python -m nids.pipeline chay <pcap> --net ... --out ../output/pipeline` | cảnh báo, sự kiện | `54`–`58` |
| 9. Lab ảo (root, Linux) | `sudo bash scripts/chay_chang_11.sh`; `scripts/chay_bo_lab_3.sh`; `scripts/chay_ddos.sh` | PCAP, nhật ký lần chạy | `70`, `80` |
| 10. Học lại cho lab, chấm | `python -m nids.hoc_lai_lab ...`; `python -m nids.thuc_nghiem ... --config ../config/lab.yaml`; `python -m nids.bot_lab ...` | `models/lab/`, bảng kết quả | `73`, `76`, `80` |
| 11. EDA, notebook | `python -m nids.eda_tong_hop ...`; `python scripts/tao_notebook.py` rồi chạy notebook | hình, notebook | `31`, `81` |

Mọi tham số mô hình đã chọn nằm trong `docs/hinh/*.json`; seed cố định (42), nên chạy lại cho cùng số liệu với cùng
phiên bản thư viện (phiên bản ghi trong `models/*.json`).

## 5. Dashboard (tùy chọn)

`python -m nids.dashboard <file .alerts.csv> --out <file .html>` sinh một trang HTML tự chứa: số cảnh báo theo
module và nhãn, dòng thời gian cảnh báo theo máy, máy bị báo nhiều nhất, bảng sự kiện, đồ thị máy bị nghi botnet.
Mẫu: `docs/hinh/dashboard_mau.html` (lần chạy năm bot ngang hàng). Trang không tự cập nhật; chạy lại lệnh để làm
mới. Không có tích hợp firewall (QĐ-090).

## 6. Bàn giao gồm những gì

| Sản phẩm (B23) | Ở đâu |
|---|---|
| Script đọc PCAP tạo flow, cửa sổ host, đồ thị | `nids.feature_export`, `nids.graph_features` |
| Notebook huấn luyện, chọn ngưỡng, đánh giá | `notebooks/05_eda`, `06_gaussian`, `07_phan_loai`, `08_botnet` |
| Chương trình realtime | `nids.realtime`, `deploy/` |
| Script sinh traffic và nhật ký nhãn | `scripts/lab_ao.py`, `sinh_traffic.py`, `sinh_topology.py`; `data/run_logs/` |
| PCAP, file cảnh báo, ảnh demo, bảng chỉ số | PCAP lab trong `data/pcap/lab/` (không có trong git, lớn); cảnh báo mẫu `output/demo/`; bảng chỉ số `docs/hinh/`; `docs/85` |
| Demo | `demo/*.bat`, `demo/HUONG_DAN.md`, kịch bản bảo vệ `demo/KICH_BAN_BAO_VE.md` |

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Kiến trúc | Các phần của hệ thống và cách chúng nối với nhau |
| Cổng mirror | Cổng switch sao chép traffic sang máy giám sát |
| `AF_PACKET` | Loại socket của Linux nhận nguyên khung từ card mạng |
| Artifact (`.joblib`) | File lưu mô hình kèm bộ tiền xử lý và ngưỡng |
| systemd | Trình quản lý dịch vụ của Linux; chạy chương trình nền và tự khởi động lại |
| Tái lập | Làm lại từ đầu và ra cùng kết quả |
| Môi trường ảo (venv) | Thư mục Python riêng cho dự án, không đụng thư viện của hệ thống |
| Seed | Số khởi tạo cho phần ngẫu nhiên; cố định thì chạy lại ra cùng kết quả |
| NTP | Giao thức đồng bộ đồng hồ giữa các máy |
| B12, B23 | Yêu cầu: offline và realtime cùng quy tắc; danh sách sản phẩm bàn giao |
