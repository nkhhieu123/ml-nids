# Học lại ba module trên dữ liệu lab và chấm trên lần `test` mới

Mã nguồn: `src/nids/hoc_lai_lab.py` (học lại), `src/nids/thuc_nghiem.py`, `src/nids/lab_cua_so.py` (chấm). Kiểm
thử: `tests/test_hoc_lai_lab.py`, `tests/test_artifacts.py`. Cấu hình sinh ra: `config/lab.yaml`. Quyết định:
QĐ-068. Số liệu: `docs/hinh/lab_hoc_lai.json`, `docs/hinh/thuc_nghiem/lab/test2_*.json`, `cua_so_test2_*.json`,
`hoc_lai/`.

## 1. Vì sao học lại

Chặng 11 (docs/71) chấm mô hình học từ CIC-IDS2017 và CTU-13 trên lab và thấy ba lỗi:

| Module | Lỗi trên lab |
|---|---|
| Anomaly (Gaussian) | Báo máy chủ dịch vụ `.30` suốt 100% bản thu ở mọi lần chạy |
| Bộ phân loại | Báo nhầm `dos` khi các máy chia sẻ khối dữ liệu lớn (`k5-doi-chung`) |
| Botnet | Bỏ sót 9/9 đợt; điểm bot cao nhất 0,084, ngưỡng 0,1 |

Cả ba đều do mô hình chưa từng thấy mạng lab. Lab đã có đủ lần chạy `train` và `val` (QĐ-065), nên học lại.

## 2. Cách làm

```bash
cd src
python -m nids.hoc_lai_lab ../data/pcap/lab/*-train-01.pcap ../data/pcap/lab/*-val-01.pcap \
    --nhat-ky ../data/run_logs --cic ../output/features/cic17_wednesday ../output/features/cic17_friday \
    --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
```

| Module | Học trên (`train`, 11 lần chạy) | Chọn trên (`val`, 11 lần chạy) | Giữ nguyên từ trước |
|---|---|---|---|
| Gaussian | 15 067 cửa sổ bình thường | Ngưỡng d², cách chọn `f1_on_dinh` của Chặng 6 | 14 đặc trưng, co hiệp phương sai Ledoit–Wolf |
| Bộ phân loại | Train CIC + train lab: 90 651 `benign`, 2 330 `dos`, 748 `port_scan` | Không chọn gì | Random Forest và tham số của C07-T04 |
| Botnet | 3 005 host–cửa sổ bình thường, 531 của bot | Ngưỡng điểm (F1 lớn nhất) và quy tắc topology | Random Forest và tham số của Chặng 8; 24 đặc trưng |

- Nhãn lấy từ nhật ký lần chạy (docs/70). Host–cửa sổ 120 giây là của bot khi chồng lên hành vi ít nhất 60
  giây; cửa sổ chồng ít hơn và cửa sổ của máy điều khiển `.50` không dùng để học hay chấm.
- **Không đọc lần chạy `test` nào** ở bước này; chương trình từ chối nếu có PCAP `test` trong danh sách.
- Mô hình lưu ở `models/lab/` (không lên git như mọi mô hình). `config/lab.yaml` là `config/default.yaml` đổi
  ba chỗ: đường dẫn mô hình, chế độ pipeline, quy tắc topology. Mô hình cũ và `default.yaml` giữ nguyên để
  dùng cho CIC-IDS2017 và CTU-13.

Kết quả trên `val` (dùng để chọn, không phải kết quả cuối):

| Module | Mô hình cũ | Mô hình học lại |
|---|---|---|
| Gaussian: F1 anomaly / cửa sổ bình thường bị báo / máy chủ bình thường bị báo | 0,304 / 18,6% / **95,8%** | 0,928 / 0,0% / **0,0%** (ngưỡng 64,7 → 2 165) |
| Bộ phân loại: macro-F1 trên `val` lab / validation CIC / test CIC | 0,914 / 0,9352 / 0,9078 | 1,000 / 0,9356 / **0,9072** |
| Botnet: precision / recall trên `val` | 0 / 0 | 1,000 / 0,996 (ngưỡng 0,1 → 0,857) |

- **Thêm dữ liệu lab không làm hỏng kết quả trên CIC**: macro-F1 test CIC 0,9078 → 0,9072.
- **Quy tắc topology**: bot ngang hàng của lab có trung vị 2 peer gọi vào và chỉ 10% flow là UDP (bot vẫn duyệt
  web), nên quy tắc cũ (≥ 5 peer, ≥ 50% UDP) cho đúng 0%. Chọn trên `val`: `min_peer_vao` 1, `min_udp` 0,05,
  `min_entropy_vao` 0 → đúng 99,1% (p2p 97,2%, tập trung 100%).
- **Chế độ pipeline** (xét lại QĐ-047): với mô hình mới, `ket_hop` phát hiện 5/8 đợt trên `val` còn `doc_lap`
  8/8, cả hai không có báo động giả. `ket_hop` chỉ cho module botnet xét host đã bị anomaly báo, mà beaconing
  chậm không làm host bất thường. `config/lab.yaml` vì vậy dùng **`doc_lap`**.
- **Beaconing trên lab**: hai đặc trưng beaconing (`beacon_chu_ky`, `beacon_cv_nho_nhat`) đứng thứ 5 và 6 về độ
  quan trọng trong mô hình botnet mới (0,06 và 0,04); bốn đặc trưng đứng đầu là mức tập trung, entropy, số peer
  và số cổng gọi ra (0,11–0,19). Beaconing có đóng góp nhưng không phải tín hiệu chính, giống nhận xét trên
  CTU-13 (docs/47).
- Các con số gần tuyệt đối trên `val` là vì `train` và `val` chạy cùng tham số kịch bản (cùng chu kỳ, cùng
  danh sách peer); chúng chỉ dùng để chọn ngưỡng.

## 3. Kết quả trên lần `test` mới

Sau khi khóa mô hình, thu **33 lần `test` mới** (lần 4, 5, 6 của 11 biến thể, ngày 12–13/11/2026, 0 gói nhân
bỏ). Các lần này chưa từng được dùng để học, chọn ngưỡng hay xem trước; lần 5 và 6 dùng chu kỳ và danh sách
peer **không có trong `train`** (60 và 45 giây; 20 và 30 giây; peer dạng vòng).

```bash
cd src
python -m nids.thuc_nghiem ../data/pcap/lab/*-test-0[456].pcap --net 192.168.50.0/24 --nhat-ky ../data/run_logs \
    --config ../config/lab.yaml --out ../docs/hinh/thuc_nghiem/lab --ten test2_lab
```

### 3.1. Theo đợt tấn công

| | Mô hình cũ (CIC, CTU-13), `ket_hop` | **Mô hình học lại, `doc_lap`** | Mô hình học lại, `ket_hop` |
|---|---|---|---|
| Port scan phát hiện | 6/6 | **6/6** | 6/6 |
| DoS phát hiện | 9/9 | **9/9** | 9/9 |
| Botnet tập trung phát hiện | 0/6 | **6/6** | 0/6 |
| Botnet ngang hàng phát hiện | 0/3 | **3/3** | 0/3 |
| **Tổng** | 15/24 | **24/24** | 15/24 |
| Sự kiện báo động giả (5,54 giờ) | 63 (39 anomaly, 24 `dos` nhầm) | **4** (đều là `dos` nhầm) | 4 |
| Báo động giả mỗi giờ | 11,4 | **0,7** | 0,7 |

| Biến thể | Độ trễ tới cuối cửa sổ, 3 lần (mô hình học lại) |
|---|---|
| `k2-quet-cham` / `k2-quet-nhanh` | 1,9 / 2,1 / 3,0 s; 0,1 / 0,3 / 1,4 s |
| `k3-dos-muc1` / `muc2` / `muc3` | 1,5 / 2,1 / 2,6 s; 1,6 / 2,1 / 2,2 s; 1,1 / 1,1 / 2,1 s |
| `k4-co-dinh` (chu kỳ 30 / 60 / 45 s) | 13,6 / 12,9 / 16,8 s |
| `k4-bien-thien` (jitter ±20 / 40 / 30%) | 17,2 / 27,7 / 41,2 s |
| `k5-p2p` (chu kỳ 8 / 20 / 30 s) | 4,7 / 8,8 / 8,0 s |

- **Phát hiện 24/24 đợt, không bỏ sót**, kể cả sáu lần botnet có chu kỳ chưa thấy lúc học. Cả ba bot đều bị báo
  trong mọi lần chạy botnet.
- **Báo động giả giảm từ 63 xuống 4 sự kiện.** Gaussian không còn báo máy chủ dịch vụ; module botnet không
  báo nhầm lần nào, kể cả trên đối chứng tập trung `k4-doi-chung` (cùng hình dạng với bot tập trung). Còn lại 4
  sự kiện `dos` nhầm dài 10–18 giây, đều ở `k5-doi-chung` (trước là 24).
- **Botnet được báo sau 5–41 giây**, sớm hơn độ dài cửa sổ 120 giây: mô hình báo ngay ở cửa sổ đầu tiên có
  vài lần bot gọi ra. Chu kỳ dài và jitter lớn thì trễ hơn.
- **Topology**: bot tập trung được gán `centralized` ở 100% cảnh báo (1 205 cảnh báo); bot ngang hàng được gán
  `p2p` ở 90,6% (548/605), phần còn lại là `centralized`.
- Chế độ `ket_hop` với mô hình mới vẫn bỏ sót cả 9 đợt botnet: xác nhận lựa chọn `doc_lap` cho lab.
- Module anomaly báo trên host của 15/15 đợt quét và DoS, 0/9 đợt botnet, ở cả mô hình cũ lẫn mới.

### 3.2. Bộ phân loại theo cửa sổ host

| | Mô hình cũ | Mô hình học lại |
|---|---|---|
| Macro-F1 (46 928 cửa sổ) | 0,923 | **0,995** |
| `port_scan` precision / recall | 1,000 / 0,999 | 1,000 / 0,999 |
| `dos` precision / recall | 0,765 / 0,780 | **0,983 / 0,987** |
| Recall `dos` của máy nạn nhân `.30` | 0,580 | **0,990** |
| Cửa sổ `benign` bị báo | 141 (đều `k5-doi-chung`) | **10** (đều `k5-doi-chung`) |

## 4. Giới hạn — phải đọc trước khi dùng các con số này

1. **Cùng một lab, cùng bộ sinh traffic.** `train`, `val` và `test` đều do `sinh_traffic.py`, `sinh_topology.py`
   sinh trên cùng 7 máy, cùng vai trò (bot luôn là `.41`–`.43`, máy điều khiển luôn là `.50:8080`, ngang hàng
   luôn UDP 40000). Kết quả cho thấy mô hình **học được lab này**, không chứng minh nó nhận ra botnet thật hay
   bot trên mạng khác. Đặc trưng quan trọng nhất của mô hình botnet mới là mức tập trung và số peer gọi ra,
   tức "host gọi thêm một đích lạ theo nhịp".
2. **Quy tắc topology rất lỏng** (≥ 1 peer gọi vào, ≥ 5% UDP): đủ cho lab 3 bot nhưng trên mạng thật sẽ gán
   `p2p` cho nhiều host bị nghi. Nó chỉ chạy trên host đã bị module botnet báo.
3. **Mỗi biến thể chỉ có một lần `train`**: 531 host–cửa sổ bot. Đủ cho lab, ít cho mô hình tổng quát.
4. **Lab ảo** (docs/70): không có độ trễ đường truyền, mất gói hay thiết bị thật.
5. Mô hình cũ không bị thay: `config/default.yaml` vẫn trỏ tới mô hình học từ CIC và CTU-13. Dùng mô hình lab
   phải truyền `--config config/lab.yaml`.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Học lại | Huấn luyện lại mô hình với dữ liệu mới, giữ nguyên loại mô hình và đặc trưng |
| Train / val / test | Lần chạy để học / để chọn ngưỡng và tham số / để đánh giá cuối |
| Ngưỡng | Giá trị điểm mà vượt qua thì cảnh báo |
| Gaussian, d² | Mô hình của module anomaly; d² là khoảng cách từ một cửa sổ tới "bình thường" đã học |
| Host–cửa sổ 120 giây | Đơn vị chấm của module botnet: một host trong một khoảng 120 giây |
| Topology | Cấu trúc liên lạc của bot: tập trung (`centralized`) hay ngang hàng (`p2p`) |
| Peer gọi vào | Máy khác chủ động mở liên lạc tới host đang xét |
| Chế độ `ket_hop` / `doc_lap` | `ket_hop`: module botnet chỉ xét host bị anomaly báo. `doc_lap`: ba module chấm độc lập mọi host |
| Beaconing | Bot gọi về máy điều khiển theo chu kỳ |
| Jitter | Độ lệch ngẫu nhiên quanh chu kỳ |
| Đối chứng | Hành vi lành tính có hình dạng giống tấn công, để đo báo nhầm |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp tính ngang nhau |
| Precision / recall | Trong các cảnh báo, tỷ lệ đúng / trong các mẫu tấn công thật, tỷ lệ được nhận ra |
| Báo động giả | Cảnh báo không do đợt tấn công nào gây ra |
