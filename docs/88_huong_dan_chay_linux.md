# Hướng dẫn chạy trên Linux

Hướng dẫn từng bước để cài và chạy hệ thống trên một máy Linux (Ubuntu 22.04 trở lên, Kali Linux, hoặc Ubuntu trong
WSL2). Đi từ dễ tới khó: kiểm thử → phân tích một file PCAP → cảm biến phát lại PCAP → lab ảo → cảm biến trên card
mạng thật → chạy nền bằng systemd.

Mọi lệnh chạy tại thư mục dự án (`~/ml-nids`) trừ khi ghi khác. Lệnh có `sudo` cần quyền root.

| Muốn làm gì | Mục | Cần root | Cần dữ liệu lớn |
|---|---|---|---|
| Cài đặt, chạy kiểm thử | 1–2 | Chỉ khi cài gói | Không |
| Có mô hình để chạy | 3 | Không | Có, nếu tự huấn luyện |
| Phân tích một file PCAP | 4 | Không | Không |
| Cảm biến realtime phát lại PCAP, dashboard | 5 | Không | Không |
| Lab ảo: dựng mạng, chạy tấn công, demo | 6 | **Có** | Không |
| Cảm biến trên card mạng thật | 7 | Có (hoặc cấp quyền) | Không |
| Chạy nền bằng systemd | 8 | Có | Không |

## 1. Cài đặt

### 1.1. Gói hệ thống

```bash
sudo apt-get update
# Bắt buộc
sudo apt-get install -y git python3 python3-venv python3-pip libcap2-bin tcpdump
# Cho lab ảo (mục 6): mạng ảo, máy chủ web, công cụ quét và SYN flood
sudo apt-get install -y iproute2 ethtool nginx nmap hping3
# Tùy chọn: đối chiếu với Wireshark, so sánh bộ đọc gói
sudo apt-get install -y tshark
```

Cần Python 3.10 trở lên (`python3 --version`).

### 1.2. Mã nguồn và môi trường Python

```bash
git clone https://github.com/nkhhieu123/ml-nids.git ~/ml-nids
cd ~/ml-nids
python3 -m venv .venv
source .venv/bin/activate              # mỗi lần mở terminal mới phải chạy lại dòng này
pip install --upgrade pip
pip install -e .                       # thư viện bắt buộc: numpy, pandas, scikit-learn, networkx, PyYAML, joblib, matplotlib
pip install -e ".[notebook]"           # tùy chọn: Jupyter để mở notebooks/
pip install -e ".[hoc_sau]"            # tùy chọn: LightGBM, PyTorch (docs/82)
```

Trên Kali có sẵn script làm hết bước 1.1–1.2 và cấp quyền bắt gói (mục 7):

```bash
bash scripts/cai_dat_kali.sh --thu-muc /opt/ml-nids --iface eth1
```

## 2. Kiểm tra cài đặt

```bash
source .venv/bin/activate
python -m unittest discover -s tests
```

Kết quả đúng: `Ran 462 tests ... OK` (có thể vài kiểm thử `skipped` nếu chưa có TShark). Không cần dữ liệu hay mô
hình cho bước này.

## 3. Mô hình

Thư mục `models/` **không có trong git**. Có hai cách:

**Cách 1 — chép từ máy đã huấn luyện** (nhanh). Cần các file sau vào đúng chỗ:

| Dùng cấu hình | Chép vào | File |
|---|---|---|
| `config/default.yaml` (dữ liệu CIC-IDS2017, CTU-13) | `models/` | `gaussian_windows`, `phan_loai_rf_windows`, `botnet_rf` (mỗi cái `.joblib` và `.json`) |
| `config/lab.yaml` (mạng lab 192.168.50.0/24) | `models/lab/` | ba file như trên |
| `config/cic_h1.yaml` | `models/h1/` | `gaussian_windows`, `phan_loai_rf_windows` |

```bash
scp may-huan-luyen:ml-nids/models/lab/*.{joblib,json} models/lab/
```

**Cách 2 — tự huấn luyện** từ dữ liệu gốc: tải CIC-IDS2017 và CTU-13 theo `config/data_manifest.csv`, rồi làm theo
bảng 11 bước ở `docs/84_kien_truc_trien_khai.md` mục 4 (vài giờ).

Kiểm tra mô hình nạp được và đúng phiên bản:

```bash
cd src
python -m nids.pipeline kiem-tra --config ../config/lab.yaml
cd ..
```

Mô hình nên được nạp bằng **cùng phiên bản scikit-learn** đã tạo ra nó (ghi trong `models/*.json`, mục
`phien_ban`); khác phiên bản thì lệnh trên cảnh báo.

## 4. Phân tích một file PCAP (offline)

Chạy cả ba module trên một file PCAP đã có, ra file cảnh báo và sự kiện:

```bash
cd src
python -m nids.pipeline chay ../data/pcap/lab/k2-quet-nhanh-test-12.pcap \
    --net 192.168.50.0/24 --config ../config/lab.yaml --out ../output/pipeline --in-su-kien
python -m nids.dashboard ../output/pipeline/k2-quet-nhanh-test-12.alerts.csv --out ../output/pipeline/dashboard.html
cd ..
xdg-open output/pipeline/dashboard.html        # hoặc mở bằng trình duyệt
```

- `--net`: dải mạng cần giám sát (lab: `192.168.50.0/24`; CIC-IDS2017: `--net 192.168.10.0/24 --net 172.16.0.0/24`
  và `--config ../config/default.yaml`).
- Đầu ra trong `output/pipeline/`: `<tên>.alerts.csv` (cảnh báo), `<tên>.su_kien.csv` (sự kiện), `<tên>.diem.csv`
  (điểm mọi cửa sổ), `<tên>.anomaly.csv`, `<tên>.attack_classification.csv`, `<tên>.botnet_topology.csv` (dự đoán
  từng module), `<tên>.pipeline.json` (số liệu, thời gian từng bước), và bảng đặc trưng (`flows.csv`,
  `windows.csv`, `schema.json`, `meta.json`). Ý nghĩa từng cột: `docs/87_giai_thich_dau_ra.md`.

Nếu file PCAP là một lần chạy lab có nhật ký, chấm luôn với đáp án (phát hiện, độ trễ, báo động giả):

```bash
cd src
python -m nids.thuc_nghiem ../data/pcap/lab/k2-quet-nhanh-test-12.pcap --net 192.168.50.0/24 \
    --nhat-ky ../data/run_logs --config ../config/lab.yaml --out ../output/cham --ten thu
cd ..
```

## 5. Cảm biến realtime phát lại PCAP

Cảm biến realtime đọc PCAP như đang bắt trực tiếp, in cảnh báo ngay khi phát ra. Không cần root.

```bash
cd src
python -m nids.realtime --pcap ../data/pcap/lab/k6-p2p-test-12.pcap --toc-do 10 \
    --net 192.168.50.0/24 --config ../config/lab.yaml --out ../output/realtime --ten thu_bot5
cd ..
```

- `--toc-do 10`: nhanh gấp 10 lần thời gian thật (bỏ đi thì đọc nhanh nhất có thể).
- `--im-lang`: không in cảnh báo ra màn hình (chỉ ghi file).
- `--ghi-diem`: ghi điểm của mọi cửa sổ vào `<tên>.diem.csv`.
- Dừng: `Ctrl+C` một lần (cảm biến xử lý nốt hàng đợi rồi dừng), hai lần để thoát ngay.

Bản đóng gói sẵn, có tổng kết so với đáp án và tự mở dashboard:

```bash
python scripts/phat_lai_demo.py --danh-sach
python scripts/phat_lai_demo.py bot5-p2p        # binh-thuong | quet | dos | ddos | bot5-tap-trung | bot5-p2p
```

## 6. Lab ảo (cần root)

Lab ảo là 9 "máy" (network namespace) nối vào một bridge không có đường ra ngoài; máy giám sát `.10` nhận bản sao
mọi gói qua cổng mirror ảo. Mô tả: `docs/70_lab_ao.md`.

| Máy | Vai trò |
|---|---|
| `192.168.50.10` | Giám sát (tcpdump, cảm biến) |
| `192.168.50.20` | Máy thử tấn công |
| `192.168.50.30` | Máy chủ web Nginx |
| `192.168.50.41`–`.45` | Máy trạm; bot trong kịch bản botnet (`.44`, `.45` chỉ ở kịch bản năm bot) |
| `192.168.50.50` | Máy điều khiển của bot tập trung |

Các script lab gọi Python của cảm biến qua biến `PY`; đặt nó trỏ vào môi trường ảo của dự án:

```bash
export PY=$HOME/ml-nids/.venv/bin/python
```

### 6.1. Kiểm tra và dựng tay

```bash
sudo PY=$PY bash scripts/demo_kiem_tra.sh            # 8 kiểm tra: Python, nmap, nginx, tcpdump, cấu hình, mô hình, lab
sudo python3 scripts/lab_ao.py dung --lab 1          # dựng lab số 1
sudo ip netns exec nl1h20 ping -c 2 192.168.50.30    # chạy lệnh "trên máy .20" của lab 1
sudo python3 scripts/lab_ao.py go --lab 1            # gỡ lab
```

Tên namespace là `nl<số lab>h<đuôi IP>`, ví dụ `nl1h30` là máy chủ web của lab 1. Nhiều lab (số khác nhau) chạy song
song được.

### 6.2. Demo có cảnh báo trực tiếp

Dựng lab, bật cảm biến trên máy giám sát, chạy kịch bản rút gọn, in cảnh báo khi phát ra, cuối cùng so với đáp án:

```bash
sudo PY=$PY bash scripts/demo_lab.sh k1-binh-thuong   # bình thường, khoảng 2 phút, không được có cảnh báo
sudo PY=$PY bash scripts/demo_lab.sh k2-quet-nhanh    # Nmap quét cổng, khoảng 3 phút
sudo PY=$PY bash scripts/demo_lab.sh k3-dos-muc2      # tải kết nối 60 giây, khoảng 3 phút
```

Đây là cùng nội dung với `demo/1_`–`3_*.bat` trên Windows. Cách đọc màn hình: `demo/HUONG_DAN.md` mục 3.2. Kết quả
ở `output/demo/<lần chạy>/`.

### 6.3. Chạy một kịch bản đầy đủ

```bash
sudo python3 scripts/lab_ao.py dung --lab 1
sudo python3 scripts/lab_ao.py chay --lab 1 --bien-the k6-p2p --vai-tro test --lan 31
sudo python3 scripts/lab_ao.py go --lab 1
```

Ra: `data/pcap/lab/k6-p2p-test-31.pcap` (bản thu), `data/run_logs/k6-p2p-test-31.json` (đáp án). Sau đó chấm bằng
lệnh ở mục 4.

| Nhóm | Biến thể (`--bien-the`) | Thời lượng mỗi lần |
|---|---|---|
| Bình thường | `k1-binh-thuong` | 10 phút |
| Quét cổng | `k2-quet-cham`, `k2-quet-nhanh` | 10 phút |
| DoS | `k3-dos-muc1/2/3`, `x3-syn-muc1/2/3`, `x3-dos-cham`, `x3-ddos` | 5 phút |
| Botnet 3 bot | `k4-co-dinh`, `k4-bien-thien`, `k4-doi-chung`, `k5-p2p`, `k5-doi-chung` | 12 phút |
| Botnet 5 bot | `k6-tap-trung`, `k6-p2p`, `k6-doi-chung` | 12 phút |
| Đổi vai trò máy | `x4-doi-vai`, `x4-doi-chung-doi-vai`, `x5-doi-vai` | 12 phút |

- `--vai-tro` là `train`, `val` hoặc `test`; `--lan` là số thứ tự (nhiều số thì chạy lần lượt).
- Script **từ chối ghi đè** lần chạy đã có nhật ký; chọn số lần khác hoặc thêm `--ghi-de`.
- `--ti-le 0.2` co thời gian chờ trước và sau tấn công để thử nhanh (tấn công giữ nguyên độ dài).

### 6.4. Cảm biến bắt trực tiếp trong lab (đo độ trễ thật)

```bash
sudo PY=$PY bash scripts/chay_cam_bien_lab.sh 21 k3-dos-muc2 32
```

Cảm biến chạy trong namespace `.10` suốt lần chạy; cảnh báo và số liệu ở `output/cam_bien_lab/`.

### 6.5. Thu nhiều lần chạy song song

```bash
sudo bash scripts/chay_chang_11.sh test 31 32 33            # 11 biến thể chính, mỗi biến thể một lab
sudo bash scripts/chay_bo_lab_3.sh                          # bộ dữ liệu của bộ mô hình lab lần ba (khoảng 90 phút)
sudo bash scripts/chay_ddos.sh                              # DDoS năm nguồn, 3 lần
```

Nhật ký từng lab ở `output/lab_log/`. Kiểm tra số gói nhân bỏ phải bằng 0:

```bash
grep -h "^Xong" output/lab_log/*.log | grep -v "nhân bỏ 0,"   # không in gì là tốt
```

### 6.6. An toàn

Mọi lưu lượng chỉ đi giữa các namespace trên chính máy này: bridge không có địa chỉ IP, không có đường ra ngoài;
script sinh lưu lượng từ chối mọi đích ngoài `192.168.50.0/24`; DoS tối đa 60 giây; bot chỉ gửi tin nhắn vô hại.
**Không chạy các kịch bản tấn công trên mạng thật.**

## 7. Cảm biến trên card mạng thật

### 7.1. Đặt cảm biến

Máy giám sát cắm vào **cổng mirror** của switch (cổng được sao chép mọi lưu lượng cần giám sát). Kiểm tra trước:

```bash
cd src
python -m nids.moi_truong --iface eth1 --config ../config/lab.yaml   # Python, quyền bắt gói, card, NTP
cd ..
sudo tcpdump -i eth1 -c 20000 -w thu.pcap                            # bắt thử 20 000 gói
cd src && python -m nids.cam_bien ../thu.pcap --net 192.168.50.0/24 && cd ..
```

`nids.cam_bien` phải kết luận `dat`: thấy cả hai chiều của kết nối TCP. Nếu `canh_bao` vì gói nhân đôi trên 5%, bật
`capture.khu_goi_trung_ms: 1` trong file cấu hình (`docs/60` mục 3.1).

### 7.2. Chạy cảm biến

Sửa `capture.interface` trong file cấu hình hoặc truyền `--iface`. Cảm biến cần quyền đọc gói thô:

```bash
# Cách 1: chạy bằng sudo với Python của môi trường ảo
sudo .venv/bin/python -m nids.realtime --iface eth1 --net 192.168.50.0/24 \
    --config config/lab.yaml --out output/realtime --ten giam_sat

# Cách 2: cấp quyền một lần cho Python của môi trường ảo, rồi chạy không cần sudo
python3 -m venv --copies .venv                       # môi trường phải có bản python riêng (cai_dat_kali.sh đã làm)
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f .venv/bin/python)"
.venv/bin/python -m nids.realtime --iface eth1 --net 192.168.50.0/24 --config config/lab.yaml --out output/realtime
```

Chạy từ thư mục dự án thì `-m nids.realtime` tìm được mã nhờ `pip install -e .`. Cảnh báo in ra màn hình và ghi vào
`output/realtime/<tên>.alerts.csv`; số liệu vận hành mỗi 10 giây trong `<tên>.so_lieu.jsonl` (số gói bỏ phải bằng 0);
log ở `output/realtime/log/nids_realtime.log`.

**Chọn cấu hình đúng mạng:** `config/lab.yaml` chỉ đúng cho mạng lab của đề tài. Trên mạng khác, mô hình phải được học
lại trên lưu lượng của chính mạng đó (`docs/73`, `docs/76`); dùng mô hình của mạng khác sẽ báo nhầm nhiều (`docs/71`).

## 8. Chạy nền bằng systemd

```bash
sudo bash scripts/cai_dich_vu.sh --thu-muc /opt/ml-nids --iface eth1 --net 192.168.50.0/24
sudo systemctl status nids-realtime
sudo journalctl -u nids-realtime -f                  # xem log trực tiếp
sudo systemctl stop nids-realtime                    # dừng êm (xử lý nốt hàng đợi tối đa 30 giây)
```

Script tạo user hệ thống `nids` (không cần root, chỉ có quyền bắt gói), chép `deploy/nids-realtime.service` và file
môi trường `/etc/ml-nids/nids-realtime.env` (card, file cấu hình, dải mạng). Trước khi chạy, dịch vụ tự kiểm tra mô
hình (`nids.pipeline kiem-tra`); lỗi thì tự khởi động lại sau 10 giây, tối đa 5 lần trong 10 phút. Chi tiết:
`docs/65_chay_nen_systemd.md`.

Xem kết quả của dịch vụ:

```bash
ls /opt/ml-nids/output/realtime/
/opt/ml-nids/.venv/bin/python -m nids.dashboard /opt/ml-nids/output/realtime/<tên>.alerts.csv --out ~/dashboard.html
```

## 9. Notebook

```bash
source .venv/bin/activate
pip install -e ".[notebook]"
cd notebooks && jupyter notebook           # mở 05_eda, 06_gaussian, 07_phan_loai, 08_botnet
```

Notebook cần bảng đặc trưng trong `output/features/`, `output/ctu13/` và mô hình trong `models/` (mục 3).

## 10. Chạy trong máy ảo VMware

Ubuntu hoặc Kali chạy trong VMware Workstation/Player dùng được cho **mọi mục ở trên**: máy ảo có nhân Linux đầy
đủ nên lab ảo (network namespace, `tc mirred`) chạy tốt, thường còn ít trục trặc hơn WSL2.

| Việc | Khuyến nghị |
|---|---|
| Ảnh hệ điều hành | Kali có bản dựng sẵn cho VMware (kali.org); hoặc Ubuntu 22.04/24.04 |
| CPU, RAM | Demo và một lab: 2 nhân, 4 GB. Thu nhiều lab song song (mục 6.5) hoặc huấn luyện lại: 4–8 nhân, 8–16 GB |
| Ổ đĩa | 40 GB nếu chỉ chạy; thêm khoảng 40 GB nếu tải PCAP CIC-IDS2017 để tự huấn luyện |
| Mã nguồn | Clone **bên trong** máy ảo (`~/ml-nids`), không chạy từ thư mục chia sẻ `/mnt/hgfs` (chậm, lỗi quyền) |
| Mô hình | Chép `models/` từ Windows sang qua thư mục chia sẻ hoặc `scp` |
| Đồng hồ | Cài `open-vm-tools` để giờ máy ảo khớp máy thật |
| Demo | File `.bat` không chạy trong Linux; dùng lệnh ở mục 5 và 6.2 |

**Giám sát lưu lượng thật từ máy ảo.** Card ảo của máy ảo mặc định chỉ thấy lưu lượng của chính nó. Hai cách:

- **Nhiều máy ảo làm lab** (gần với lab 7 máy của B13 hơn lab namespace): đặt các máy ảo cùng một mạng `host-only`
  hoặc `LAN segment`; máy ảo giám sát bật chế độ promiscuous trên card đó. Trên máy chủ Windows, VMware thường cho
  máy ảo ở chế độ promiscuous thấy lưu lượng của các máy ảo khác cùng mạng ảo.
- **Mạng thật:** thêm card ảo kiểu `bridged` gắn vào card vật lý cắm ở cổng mirror của switch.

Trước khi chạy mô hình, **luôn kiểm tra bằng `nids.cam_bien`** (mục 7.1) rằng máy ảo thấy cả hai chiều của các kết
nối giữa các máy khác; hành vi promiscuous phụ thuộc phiên bản VMware và hệ điều hành máy chủ. Cách này chưa được thử
trong đề tài.

## 11. Sự cố thường gặp

| Hiện tượng | Nguyên nhân | Cách xử lý |
|---|---|---|
| `ModuleNotFoundError: nids` | Chưa kích hoạt môi trường ảo hoặc chưa `pip install -e .` | `source .venv/bin/activate`; chạy lệnh từ thư mục `src/` hoặc cài lại |
| `PermissionError` / `Operation not permitted` khi `--iface` | Thiếu quyền đọc gói thô | Chạy bằng `sudo .venv/bin/python ...` hoặc `setcap` (mục 7.2) |
| `Cần chạy bằng root trên Linux` | Lệnh lab ảo chạy không có sudo | Thêm `sudo` |
| `Không dựng được lab` / lỗi `tc` | Thiếu mô-đun nhân `act_mirred`, `sch_ingress`, `cls_matchall` | `sudo modprobe act_mirred sch_ingress cls_matchall`; trên WSL2 dùng nhân mới (`wsl --update`) |
| Lab cũ còn sót sau khi dừng giữa chừng | Namespace chưa gỡ | `sudo python3 scripts/lab_ao.py go --lab <số>` |
| `... đã có nhật ký; chọn số lần khác hoặc thêm --ghi-de` | Trùng số lần chạy | Đổi `--lan` |
| Cảnh báo về phiên bản khi nạp mô hình | scikit-learn khác phiên bản lúc tạo mô hình | Cài đúng phiên bản trong `models/*.json` (`pip install scikit-learn==<bản>`) |
| `goi_bo_kernel` hoặc `goi_bo_hang_doi` > 0 | Máy không theo kịp tải | Tăng `realtime.queue_size`, giảm tải khác, dùng máy mạnh hơn (`docs/63`) |
| Không có cảnh báo nào khi có tấn công | Sai card, card không nhận lưu lượng mirror, hoặc sai `--net` | Kiểm tra bằng `nids.cam_bien` (mục 7.1); `--net` phải chứa IP các máy cần giám sát |
| Rất nhiều cảnh báo trên mạng bình thường | Mô hình học từ mạng khác | Học lại trên mạng này (mục 7.2) |
| Chữ tiếng Việt lỗi khi in | Terminal không dùng UTF-8 | `export PYTHONIOENCODING=utf-8 LANG=C.UTF-8` |

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Môi trường ảo (venv) | Thư mục Python riêng cho dự án, không đụng thư viện của hệ thống |
| Network namespace | Ngăn mạng riêng trong nhân Linux; mỗi ngăn đóng vai một máy của lab ảo |
| Bridge | Switch ảo nối các namespace |
| Cổng mirror | Cổng switch sao chép lưu lượng sang máy giám sát |
| `setcap`, `CAP_NET_RAW` | Cấp cho một chương trình quyền đọc gói thô mà không cần chạy bằng root |
| systemd | Trình quản lý dịch vụ của Linux; chạy chương trình nền, tự khởi động lại |
| PCAP | File lưu gói tin đã bắt |
| Phát lại PCAP | Đưa file gói tin vào cảm biến như đang bắt trực tiếp |
| Offline / realtime | Phân tích file đã lưu / giám sát lưu lượng đang chạy |
| Dashboard | Trang HTML tóm tắt cảnh báo bằng bảng và hình |
