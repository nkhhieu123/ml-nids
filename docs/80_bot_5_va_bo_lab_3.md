# Botnet năm bot và bộ mô hình lab lần ba

Tài liệu này ghi kịch bản botnet **năm bot** (trước đây lab chỉ có ba bot), cùng bộ mô hình lab lần ba được học
thêm dữ liệu cho các chỗ còn yếu: SYN flood phía nạn nhân, DoS HTTP chậm, bot đổi vai. Quyết định: QĐ-076,
QĐ-077, QĐ-083. Số liệu: `docs/hinh/lab_hoc_lai_3.json`, `docs/hinh/thuc_nghiem/lab/bo3/`.

## 1. Lab có thêm hai máy bot

| Máy | Vai trò |
|---|---|
| `.10` | Máy giám sát (chỉ nhận bản sao qua cổng mirror) |
| `.20` | Máy thử tấn công |
| `.30` | Máy chủ web Nginx |
| `.41`, `.42`, `.43` | Máy trạm; là bot ở kịch bản 4, 5 |
| **`.44`, `.45`** | **Máy trạm mới; chỉ hoạt động ở kịch bản 6.** Ở kịch bản 1–5 hai máy này im lặng, nên các lần chạy kịch bản 1–5 trước và sau khi thêm máy giống nhau về traffic |
| `.50` | Máy điều khiển của bot tập trung |

Kịch bản 6 (`scripts/lab_ao.py`, tham số chốt trong `config/default.yaml` mục `lab.nam_bot`):

| Biến thể | Năm máy `.41`–`.45` làm gì | Tham số theo lần chạy 1 / 2 / 3 |
|---|---|---|
| `k6-tap-trung` | Bot gọi máy điều khiển `.50:8080` | chu kỳ 30 / 60 / 45 giây, dao động ±20 / 40 / 30% |
| `k6-p2p` | Bot gửi UDP cho nhau, cổng 40000 | chu kỳ 8 / 20 / 30 giây; mỗi bot gọi cả bốn bot kia / một bot kế tiếp (vòng) / hai bot kế tiếp |
| `k6-doi-chung` | Lành tính: năm máy kiểm tra trạng thái máy chủ web `.30:80` định kỳ | chu kỳ 30 / 60 / 45 giây |

Mọi máy cũng duyệt web làm nền. Bot chỉ gửi tin nhắn vô hại tới máy trong lab (`scripts/sinh_topology.py`), như
kịch bản 4, 5 (B24).

## 2. Dữ liệu đã thu

96 lần chạy mới, ngày 16–17/11/2026, mỗi biến thể một lab ảo riêng chạy song song (`scripts/chay_bo_lab_3.sh`),
**0 gói nhân bỏ** ở mọi lần.

| Nhóm | Biến thể | `train` | `val` | `test` mới |
|---|---|---|---|---|
| Năm bot | `k6-tap-trung`, `k6-p2p`, `k6-doi-chung` | lần 1–3 | lần 1 | lần 12–14 |
| DoS HTTP chậm (mới, QĐ-077) | `x3-dos-cham` | lần 1–3 | lần 1 | lần 12–14 |
| SYN flood gói thô | `x3-syn-muc1/2/3` | lần 1–3 | lần 1 | lần 12–14 |
| Đổi vai bot | `x4-doi-vai`, `x4-doi-chung-doi-vai`, `x5-doi-vai` | lần 1–3 | lần 1 | lần 12–14 |
| 11 biến thể chính | `k1`–`k5` | (đã có lần 1–3) | (đã có) | lần 12–14 |

`x3-dos-cham`: máy `.20` mở 120–200 kết nối HTTP tới `.30`, gửi yêu cầu **chưa xong**, rồi cứ 8–15 giây gửi
thêm một dòng header vô hại để giữ kết nối; tối đa 60 giây và 300 kết nối như mọi DoS của lab
(`sinh_traffic.py dos-cham`).

## 3. Học lại

Cùng lệnh và cùng tham số mô hình như bộ lab lần hai (docs/76), chỉ thêm các lần chạy mới vào `train` và `val`:

```bash
sudo bash scripts/chay_bo_lab_3.sh
cd src
python -m nids.hoc_lai_lab ../data/pcap/lab/*-train-0[123].pcap ../data/pcap/lab/*-val-01.pcap \
    --nhat-ky ../data/run_logs --flow handshake_observe_s=1 --cache ../output/lab_features_h1 \
    --cic ../output/features_h1/cic17_wednesday ../output/features_h1/cic17_friday \
    --chon ../docs/hinh/phan_loai_chon.json --models ../models/lab3 --config-out ../config/lab3.yaml \
    --ten lab_hoc_lai_3 --out ../docs/hinh
```

| | Bộ lần hai | **Bộ lần ba** |
|---|---|---|
| Cửa sổ train của bộ phân loại (CIC + lab) | 106 262 (2 638 `dos`, 1 283 `port_scan`) | 124 174 (3 296 `dos`, 1 283 `port_scan`) |
| Host–cửa sổ train của module botnet | 10 531 (1 587 bot) | 21 283 (4 436 bot) |
| Ngưỡng botnet (chọn trên `val`) | 0,713 | 0,802 |
| Macro-F1 test CIC của bộ phân loại | 0,906 | 0,903 |
| Quy tắc topology chọn trên `val` | nhóm | nhóm (đúng 100% trên 1 486 cửa sổ bot) |

Bộ lần ba thay bộ lần hai ở `models/lab/` và `config/lab.yaml`; bộ lần hai giữ ở `models/lab_b2/` để so.

## 4. Kết quả trên lần `test` mới (12–14)

63 lần chạy chưa mô hình nào thấy. Chấm bằng `nids.thuc_nghiem` (theo đợt), `nids.bot_lab` (theo từng bot) và
`nids.lab_cua_so` (theo cửa sổ).

### 4.1. Theo đợt

| Nhóm | Số đợt | Bộ lần hai | **Bộ lần ba** | Độ trễ trung vị (bộ lần ba) |
|---|---|---|---|---|
| Quét cổng | 6 | 6/6 | 6/6 | 1,7–1,9 giây |
| DoS tải kết nối | 9 | 9/9 | 9/9 | 0,9–2,0 giây |
| SYN flood | 9 | 9/9 | 9/9 | 1,0–1,1 giây |
| DoS HTTP chậm | 3 | 3/3 | 3/3 | 1,1 giây |
| Botnet ba bot (`k4`, `k5`) | 9 | 9/9 | 9/9 | 6–9 giây |
| **Botnet năm bot** (`k6`) | 6 | **6/6** | **6/6** | 10–15 giây |
| Botnet đổi vai (`x4`, `x5`) | 6 | 6/6 | 6/6 | 8–14 giây |
| **Tổng** | **48** | **48/48** | **48/48** | |
| Sự kiện báo động giả (63 lần chạy) | | 0 | **0** | |

### 4.2. Theo từng bot và topology

| Biến thể | Bot bị báo, bộ lần hai | **Bot bị báo, bộ lần ba** | Topology đúng (bộ lần ba) |
|---|---|---|---|
| `k6-tap-trung` (5 bot × 3 lần) | 15/15 | **15/15** | 100% `centralized` (1 011 cửa sổ) |
| `k6-p2p` (5 bot × 3 lần) | 15/15 | **15/15** | 99,2% `p2p` (1 023/1 031) |
| `k6-doi-chung` | không báo máy nào | không báo máy nào | — |
| `k4-co-dinh`, `k4-bien-thien` | 18/18 | 18/18 | 100% |
| `k5-p2p` | 9/9 | 9/9 | 99,0% |
| `x4-doi-vai` | 9/9 | 9/9 | 100% |
| `x5-doi-vai` | **6/9** (sót `.50`) | **9/9** | 98,2% |

- **Năm bot được phát hiện đủ cả hai kiểu**, kể cả bằng bộ lần hai chưa từng thấy năm bot: mô hình học hành vi
  gọi định kỳ của từng máy, không học số lượng bot.
- **Quy tắc topology theo nhóm khái quát sang năm bot**: bot ngang hàng có flow trực tiếp với bot khác nên được gán
  `p2p`; bot tập trung chỉ nói chuyện với `.50` nên là `centralized`. Không cần chỉnh ngưỡng nào theo số bot.
- **Bot `.50` của `x5-doi-vai` hết bị sót** khi biến thể đổi vai có trong `train`.

### 4.3. Theo cửa sổ: SYN flood và DoS chậm

12 lần chạy `x3-*` (`docs/hinh/thuc_nghiem/lab/bo3/cua_so_x3_*.json`). Recall `dos` theo cửa sổ:

| | Bộ lần hai | **Bộ lần ba** | Bộ lần ba + lớp giữ nhãn `dos` |
|---|---|---|---|
| Cửa sổ máy tấn công | 0,846 | 1,000 | 1,000 |
| **Cửa sổ máy nạn nhân** | **0,104** | **0,972** | 1,000 |
| Riêng DoS HTTP chậm: máy nạn nhân | 0,143 | 0,886 | 1,000 |
| Cửa sổ bình thường bị gán `dos` (6 957 cửa sổ) | 0 | 0 | 72 |

- **SYN flood giờ nhận ra được từ phía nạn nhân** (recall 0,10 → 0,97). Nếu máy tấn công nằm ngoài mạng giám sát
  hoặc giả mạo nguồn, nạn nhân vẫn bị báo.
- **Lớp giữ nhãn `dos` (QĐ-074) trên lab:** nâng recall phía nạn nhân lên 1,000, đổi lại 72 cửa sổ bình thường bị
  gán `dos` (18 cửa sổ mỗi biến thể, đều là các cửa sổ trong 20 giây ngay sau khi tấn công dừng). Các cửa sổ này
  nối liền với đợt tấn công nên **không tạo sự kiện báo động giả nào**: chấm cả 63 lần chạy với lớp giữ nhãn bật
  vẫn 48/48 đợt, 0 sự kiện báo giả. Vì bộ lần ba đã bắt nạn nhân tới 0,97, `config/lab.yaml` **vẫn để lớp này tắt**.

### 4.4. DDoS nhiều nguồn (25/11/2026, QĐ-087)

Kế hoạch ghi: "một nguồn flood là DoS; thử nghiệm DDoS cần nhiều nguồn". Biến thể `x3-ddos`: năm máy `.20`, `.41`,
`.42`, `.44`, `.45` **cùng lúc** tải kết nối vào máy chủ web `.30` trong 60 giây (mỗi máy 50 / 50 / 200 kết nối mỗi
giây ở ba lần chạy; tổng 250 / 250 / 1 000). Chỉ trong lab ảo cô lập, giới hạn 60 giây như mọi DoS của lab. Bộ mô
hình lab lần ba **chưa từng học DDoS nhiều nguồn**; ba lần chạy là `test` 21–23 (`scripts/chay_ddos.sh`).

| | Kết quả |
|---|---|
| Đợt phát hiện | **3/3**, độ trễ tới cuối cửa sổ trung vị 0,9 giây |
| Recall `dos` theo cửa sổ, 5 máy tấn công (525 cửa sổ) | **1,000** |
| Recall `dos` theo cửa sổ, máy nạn nhân (105 cửa sổ) | **1,000** |
| Cửa sổ bình thường bị gán tấn công (463 cửa sổ) | 0 |
| Sự kiện báo động giả | 0 |
| Gói nhân bỏ | 0 (lần nặng nhất 364 483 gói) |

Hệ thống báo cả năm nguồn và máy nạn nhân, nên người vận hành thấy được đây là tấn công từ nhiều nguồn. Bộ phân
loại vẫn gán nhãn `dos`, không tách riêng lớp `ddos`: ba lớp của đề tài không có lớp DDoS riêng. 1 073 cửa sổ bị
bỏ vì mơ hồ (máy vừa duyệt web vừa tấn công trong cùng 10 giây, phần flow tấn công dưới 20%).

## 5. Giới hạn

- Năm bot vẫn là bot mô phỏng trong lab 9 máy; mạng thật có nhiều máy hơn và bot thật ồn hơn (docs/76 mục 4).
- Các lần `test` 12–14 giờ đã được xem; lần học lại sau phải thu lần `test` mới (QĐ-072).
- Kịch bản DoS HTTP chậm chỉ dài 60 giây (B16); DoS chậm thật có thể kéo dài hàng giờ với khoảng im lặng dài hơn.

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Bot | Máy bị điều khiển, liên lạc định kỳ với máy điều khiển hoặc với bot khác |
| Tập trung (`centralized`) / ngang hàng (`p2p`) | Bot cùng gọi về một máy điều khiển / bot gọi trực tiếp cho nhau |
| Đối chứng | Kịch bản có hình dạng giống tấn công nhưng lành tính, để kiểm tra báo nhầm |
| Đổi vai | Kịch bản mà máy khác làm bot hoặc làm máy điều khiển, cổng và chu kỳ cũng khác |
| SYN flood | Gửi ồ ạt gói mở kết nối TCP mà không hoàn tất bắt tay |
| DoS HTTP chậm | Giữ nhiều kết nối HTTP mở thật lâu để chiếm chỗ của máy chủ |
| Lớp giữ nhãn `dos` | Bước sau bộ phân loại: giữ nhãn `dos` cho máy vừa bị gán `dos` nhiều lần (docs/75) |
| `train` / `val` / `test` | Lần chạy để học / để chọn ngưỡng / để đánh giá cuối |
| Recall | Trong các mẫu tấn công thật, tỷ lệ được nhận ra |
| Độ trễ | Thời gian từ lúc tấn công bắt đầu tới cảnh báo đúng đầu tiên |
| Nhân bỏ gói | Gói mà nhân Linux không kịp đưa cho chương trình bắt gói |
| B16, B24 | Yêu cầu: DoS tối đa 60 giây; traffic lab vô hại, không ra ngoài lab |
