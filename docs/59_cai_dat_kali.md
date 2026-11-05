# C10-T01 — Clone và cài dự án trên Kali

Mã nguồn: `scripts/cai_dat_kali.sh` (cài đặt), `src/nids/moi_truong.py` (kiểm tra môi trường).
Kiểm thử: `tests/test_realtime.py`.

> **Trạng thái: chưa chạy trên Kali thật** (lab chưa dựng). Script đã kiểm tra cú pháp; bộ kiểm tra
> môi trường đã chạy trên máy phát triển (Windows) và có kiểm thử cho các nhánh chỉ có trên Linux.
> Khi cài trên Kali, ghi kết quả `output/moi_truong.json` vào mục 5 của tài liệu này.

## 1. Cài đặt

Trên máy Kali (user thường có sudo):

```bash
curl -O https://raw.githubusercontent.com/nkhhieu123/ml-nids/main/scripts/cai_dat_kali.sh
bash cai_dat_kali.sh --thu-muc /opt/ml-nids --iface eth1 [--mo-hinh ~/models_tu_may_huan_luyen]
```

| Bước | Việc |
|---|---|
| 1 | `apt-get install` git, python3, python3-venv, pip, libcap2-bin, tcpdump |
| 2 | Clone `https://github.com/nkhhieu123/ml-nids` vào `/opt/ml-nids` (đã có thì `git pull --ff-only`) |
| 3 | Môi trường ảo `.venv` tạo bằng `--copies`; `pip install -e .`; thêm `psutil` để đo CPU, RAM |
| 4 | Chép mô hình (nếu có `--mo-hinh`); tạo `models/`, `output/`, `data/run_logs/` |
| 5 | `setcap cap_net_raw,cap_net_admin+eip` cho python **của môi trường ảo** để bắt gói không cần root |
| 6 | Chạy `python -m nids.moi_truong`, ghi `output/moi_truong.json` |

**Mô hình không có trong git** (`models/*` bị bỏ qua). Có hai cách đưa mô hình lên Kali:
- chép từ máy huấn luyện (`scp`): `gaussian_windows`, `phan_loai_rf_windows`, `botnet_rf`, mỗi mô hình
  gồm `.joblib` và `.json`;
- hoặc huấn luyện lại trên Kali (cần dữ liệu CIC và CTU-13, xem README).

Sau khi chép, chạy `python -m nids.pipeline kiem-tra` để chắc mô hình khớp mã đang cài (C09-T01).

## 2. Vì sao dùng `--copies` và setcap trên python của môi trường ảo

`venv` mặc định tạo liên kết tới `/usr/bin/python3`. Nếu `setcap` lên đó thì **mọi** chương trình Python
trên máy đều được bắt gói. `--copies` tạo một bản python riêng trong `.venv`, nên quyền chỉ gắn với bản
đó. Script kiểm tra đường dẫn thật nằm trong `.venv`; nếu không thì không `setcap` và hướng dẫn chạy
bằng `sudo` (QĐ-049).

Mỗi lần `apt` nâng cấp Python thì cần tạo lại `.venv` và chạy lại bước 5.

## 3. Kiểm tra môi trường (`nids.moi_truong`)

```bash
cd /opt/ml-nids
.venv/bin/python -m nids.moi_truong --iface eth1 --out output/moi_truong.json
```

| Mục | Đạt | Chú ý (không chặn) | Lỗi (chặn) |
|---|---|---|---|
| Python | ≥ 3.10 (`requires-python`) | | < 3.10 |
| Thư viện | numpy, pandas, scikit-learn, scipy, PyYAML, joblib, networkx | thiếu matplotlib, psutil | thiếu thư viện bắt buộc |
| Quyền bắt gói | root, hoặc có CAP_NET_RAW (`CapEff` trong `/proc/self/status`) | không phải Linux (chỉ chạy được từ PCAP) | Linux mà không có quyền |
| Card mạng | có trong `/sys/class/net`, trạng thái up | chưa chỉ định; trạng thái khác | không có card đó (liệt kê card có thật) |
| Artifact | ba mô hình hợp lệ (`pipeline kiem-tra`) | tạo khi mã chưa commit | thiếu file, sai đặc trưng, thiếu ngưỡng |
| Đồng bộ giờ | `timedatectl` báo NTPSynchronized | chưa đồng bộ hoặc không kiểm tra được | |
| Đĩa | ≥ 5 GB trống ở thư mục ra | ít hơn | |

Mã thoát 0 khi không có lỗi.

## 4. Kết quả trên máy phát triển (Windows 11, 05/11/2026)

- Python 3.13.3, đủ thư viện, ba artifact hợp lệ, đĩa còn 45,9 GB.
- Chú ý: không phải Linux nên không bắt gói trực tiếp được, không kiểm tra được card và NTP.

Kết quả: **sẵn sàng chạy từ file PCAP**.

## 5. Kết quả trên Kali

Chưa có. Cần ghi: phiên bản Kali, Python, commit đã cài, card giám sát, kết quả từng mục kiểm tra.

## 6. Kiểm thử

- Phiên bản Python đủ và thiếu; thư viện bắt buộc thiếu là lỗi, tùy chọn thiếu là chú ý.
- Đọc `CapEff`:
  - root là đạt;
  - có bit CAP_NET_RAW là đạt;
  - không có bit là lỗi;
  - Windows là chú ý.
- Card mạng có, không có (gợi ý card thật), chưa chỉ định.
- NTP đồng bộ, chưa đồng bộ, không chạy được `timedatectl`.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Kali Linux | Bản Linux dùng cho máy giám sát của lab |
| Môi trường ảo (.venv) | Thư mục chứa Python và thư viện riêng của dự án |
| `setcap`, CAP_NET_RAW | Cấp riêng quyền đọc gói thô cho một chương trình, không cần chạy cả chương trình bằng root |
| Card mạng giám sát | Card nhận bản sao traffic từ cổng mirror của switch |
| NTP | Giao thức đồng bộ đồng hồ qua mạng |
| Artifact | Mô hình, biến đổi, ngưỡng đã lưu |
| `scp` | Lệnh chép file giữa hai máy qua SSH |
