# Bộ mô hình lab lần hai: thêm dữ liệu học, kiểm tra khái quát, SYN flood, chờ bắt tay 1 giây

Tài liệu này đóng các mục ở `docs/Viec_con_thieu.md` mục 2 sau khi có bộ mô hình lab đầu tiên (docs/73). Quyết
định: QĐ-069, QĐ-070, QĐ-072. Số liệu: `docs/hinh/lab_hoc_lai.json`, `lab_hoc_lai_h3.json`,
`lab_cheo_ctu13.json`, `docs/hinh/thuc_nghiem/lab/test3_*.json`, `doi_vai_*.json`, `syn_*.json`,
`tre200ms_*.json`, `cua_so_*.json`, `hoc_lai/topology_test3.json`.

## 1. Những gì đã đổi so với bộ mô hình lab đầu tiên

| | Bộ đầu (docs/73) | Bộ hiện tại (`config/lab.yaml`) |
|---|---|---|
| Lần `train` mỗi biến thể | 1 | **3** (lần 1, 2, 3: đủ ba bộ chu kỳ và danh sách peer) |
| Host–cửa sổ bot để học | 531 | **1 587** |
| Cửa sổ bình thường để fit Gaussian | 15 067 | **44 392** |
| Quy tắc topology | ngưỡng trên từng host (≥ 1 peer gọi vào, ≥ 5% UDP) | **theo nhóm**: host bị nghi có flow trực tiếp với host bị nghi khác (QĐ-070) |
| `flow.handshake_observe_s` | 3 | **1** (QĐ-072) |
| Ngưỡng botnet / Gaussian (chọn trên `val`) | 0,857 / 2 165 | 0,713 / 2 570 |

```bash
sudo bash scripts/chay_chang_11.sh train 2 3
cd src
python -m nids.hoc_lai_lab ../data/pcap/lab/k*-train-0[123].pcap ../data/pcap/lab/k*-val-01.pcap \
    --nhat-ky ../data/run_logs --flow handshake_observe_s=1 --cache ../output/lab_features_h1 \
    --cic ../output/features_h1/cic17_wednesday ../output/features_h1/cic17_friday \
    --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
```

Bộ phân loại vẫn học trên train CIC + train lab; bảng CIC được trích xuất lại với chờ bắt tay 1 giây để huấn
luyện và chạy thật dùng cùng cách tính (B12). Macro-F1 test CIC của nó là 0,906 (mô hình CIC gốc 0,908).

## 2. Lần `test` mới (lần 9, 10, 11)

Mỗi lần học lại phải có lần `test` chưa từng xem. 33 lần này thu ngày 13/11/2026, 0 gói nhân bỏ.

| | Mô hình cũ (CIC, CTU-13) | Lab bộ đầu | **Lab hiện tại** |
|---|---|---|---|
| Đợt phát hiện | 15/24 | 24/24 | **24/24** |
| Sự kiện báo động giả | 58 | 3 (`dos` nhầm trên `k5-doi-chung`) | **0** |
| Macro-F1 theo cửa sổ | — | — | **0,9989** |
| Cửa sổ `benign` bị báo (44 505 cửa sổ) | — | — | **0** |
| Topology `p2p` đúng trên bot ngang hàng | — | 92,0% (542/589) | **98,2%** (586/597) |
| Topology `centralized` đúng trên bot tập trung | — | 100% | 100% (1 204/1 204) |

- **Báo nhầm `dos` trên chia sẻ dữ liệu lớn đã hết** (24 → 4 → 0 sự kiện) nhờ ba lần `train` của `k5-doi-chung`.
- Cả ba bot đều bị báo trong cả 9 lần chạy botnet; độ trễ tới cuối cửa sổ 3–35 giây.

## 3. Kiểm tra khái quát trong lab: đổi vai trò máy, cổng, chu kỳ

Bộ mô hình chỉ thấy bot là `.41`–`.43`, máy điều khiển `.50:8080`, ngang hàng UDP 40000. Ba biến thể sau **chỉ
dùng để chấm**, không có trong `train` hay `val` (`lab_ao.py`, tiền tố `x`), mỗi cái 3 lần:

| Biến thể | Bot | Liên lạc | Chu kỳ (3 lần) |
|---|---|---|---|
| `x4-doi-vai` | `.20`, `.42`, `.43` | gọi máy điều khiển **`.41:9090`** | 40 / 25 / 75 s, jitter ±25% |
| `x4-doi-chung-doi-vai` | (lành tính) `.20`, `.42`, `.43` | gọi máy chủ dịch vụ `.30:80` | 40 / 25 / 75 s |
| `x5-doi-vai` | `.20`, `.43`, `.50` | ngang hàng **UDP 45000** | 12 / 25 / 40 s, jitter ±35% |

| | Mô hình cũ | Lab bộ đầu | **Lab hiện tại** |
|---|---|---|---|
| Đợt botnet phát hiện | 0/6 | 6/6 | **6/6** |
| Sự kiện báo động giả (9 lần chạy) | 9 | 0 | **0** |
| Đối chứng đổi vai bị báo | — | không | **không** |
| Bot bị báo / tổng số bot | — | — | 9/9 (`x4`), **7/9** (`x5`) |
| Topology đúng | — | — | `x4`: 100% `centralized`; `x5`: 94,1% `p2p` |

- **Mô hình lab nhận ra bot ở vai trò, cổng và chu kỳ chưa từng thấy**, và không báo nhầm đối chứng cùng hình
  dạng. Nó không chỉ nhớ "`.41`–`.43` gọi `.50:8080`".
- **Bot `.50` bị sót ở 2/3 lần `x5`**: `.50` là máy duy nhất không duyệt web làm nền, nên hồ sơ liên lạc của nó
  khác các bot đã học. Đợt tấn công vẫn được phát hiện nhờ hai bot còn lại.

## 4. Giới hạn của sự khái quát: chấm chéo với CTU-13

| Mô hình botnet | Chấm trên | Recall | Bình thường bị báo | Background bị báo |
|---|---|---|---|---|
| Học từ CTU-13 | test CTU-13 (scenario 1, 2, 6, 8, 9) | 0,678 | 1,6% | 11,9% |
| Học từ CTU-13 | lab | **0** (0/9 đợt) | — | — |
| Học từ lab (bộ đầu) | test CTU-13 | **0** (0/19 188 cửa sổ bot) | 0,4% | 0,4% |

**Không mô hình nào chuyển được sang mạng kia.** Mô hình lab học kiểu bot "gọi nhẹ, đều đặn" của script lab; bot
thật của CTU-13 (spam, quét, DDoS) có hồ sơ khác hẳn. Kết quả 24/24 và 6/6 ở trên vì vậy là kết quả **trong
lab ảo với bot mô phỏng**, không phải khả năng phát hiện botnet thật.

## 5. Quy tắc topology theo nhóm (QĐ-070)

Quy tắc cũ đặt ngưỡng trên từng host (số peer gọi vào, tỷ lệ UDP), nên phải nới rất lỏng mới hợp lab 3 bot.
Quy tắc mới dùng **đặc trưng nhóm**: một host bị nghi là `p2p` khi trong cùng cửa sổ 120 giây nó có flow trực
tiếp với **ít nhất một host bị nghi khác**; còn lại là `centralized` (`botnet.group_p2p`,
`botnet.topology_rule.kieu: nhom`). Bot ngang hàng nói chuyện với nhau; bot tập trung chỉ nói chuyện với máy
điều khiển. Quy tắc không phụ thuộc số bot, giao thức hay chu kỳ.

| | Quy tắc ngưỡng (tốt nhất trên `val`) | Quy tắc nhóm |
|---|---|---|
| Đúng trên `val` (534 cửa sổ bot) | 99,1% | **100%** |
| `p2p` đúng trên `test` 9–11 | 92,0% | **98,2%** |
| `p2p` đúng trên `x5-doi-vai` (cổng và nhóm bot khác) | — | 94,1% |

Giới hạn: hai host bị nghi tình cờ có liên lạc lành tính với nhau sẽ bị gán `p2p`; quy tắc cần ít nhất hai bot
bị phát hiện trong cùng cửa sổ, nên bot ngang hàng đầu tiên bị báo vẫn là `centralized` cho tới khi bot thứ hai
bị báo. `config/default.yaml` (CTU-13) giữ quy tắc ngưỡng.

## 6. SYN flood gói thô (QĐ-069)

DoS của các kịch bản chính là tải kết nối bằng socket thường. Để biết SYN flood thật có được nhận ra không, thêm
biến thể `x3-syn-muc1/2/3`: `hping3 -S -p 80` từ `.20` tới `.30`, 50/200/600 gói SYN mỗi giây trong 60 giây,
cổng nguồn tăng dần, **không giả mạo địa chỉ nguồn**. Gói thô chỉ được phép trong lab ảo cô lập (bridge không
có đường ra ngoài). Không có lần `train` nào của biến thể này.

| | Mô hình cũ (CIC) | Lab hiện tại |
|---|---|---|
| Đợt phát hiện (9 lần chạy) | **9/9** | **9/9** |
| Độ trễ tới cuối cửa sổ | 0,1–2,0 s | 0,1–2,0 s |
| Sự kiện báo động giả | 9 (anomaly trên `.30`) | 0 |
| Recall theo cửa sổ của máy tấn công (325 cửa sổ) | 1,000 | 1,000 |
| Recall theo cửa sổ của máy nạn nhân (325 cửa sổ) | 0,369 | 0,089 |

- **SYN flood được phát hiện 9/9 dù chưa từng có trong dữ liệu học**, ở cả ba mức, nhờ cửa sổ của máy tấn công.
- **Cửa sổ của máy nạn nhân phần lớn không bị gán `dos`** (mô hình lab chỉ 9%): với nạn nhân, SYN flood không
  tạo kết nối hoàn tất nên khác DoS đã học. Nếu máy tấn công nằm ngoài mạng giám sát thì đợt này sẽ bị bỏ sót.
  Muốn sửa phải thêm lần `train` của `x3-syn`.
- Brute-force và exploit không thuộc ba lớp của bộ phân loại; không thu.

## 7. Chờ bắt tay 1 giây (QĐ-072)

`flow.handshake_observe_s` cộng thẳng vào độ trễ realtime (docs/72 mục 2.2). Ba kiểm tra trước khi đổi cho lab:

| Kiểm tra | Kết quả |
|---|---|
| Trích xuất lại CIC thứ Tư, thứ Sáu với 1 giây, huấn luyện lại Random Forest | Macro-F1 validation 0,9352 → **0,9370** (không kém đi) |
| Bộ mô hình lab học với 3 giây và với 1 giây, chấm trên `test` 9–11 | Cả hai 24/24 đợt, 0 báo động giả |
| Sáu lần chạy trên lab có **trễ khứ hồi 200 ms** (`lab_ao.py dung --tre-ms 100`) | Hai bộ cho kết quả **giống hệt**: 4/4 đợt, macro-F1 theo cửa sổ 0,971 |

Vì vậy `config/lab.yaml` dùng 1 giây: cảnh báo quét và DoS đến sớm hơn khoảng 2 giây (3,1–5,0 → 1,5–2,9 giây khi
đo bằng phát lại). `config/default.yaml` giữ 3 giây vì mô hình CIC gốc được học với giá trị đó.

Ghi chú về lab có trễ: bộ sinh tải kết nối mở kết nối tuần tự, nên với khứ hồi 200 ms nó chỉ đạt khoảng 5 kết
nối mỗi giây thay vì 50–200. Đợt tấn công yếu đi nhiều nhưng vẫn được phát hiện (độ trễ 5,8–5,9 giây, recall
theo cửa sổ 0,857), kèm 1 cửa sổ `benign` bị báo ở lần `k3-dos-muc2`.

## 8. Giới hạn

1. Mọi kết quả là trên **lab ảo** với **bot mô phỏng**; mục 4 cho thấy mô hình không chuyển sang botnet thật.
2. Lab chỉ có 7 máy; chưa biết quy tắc nhóm và mô hình cư xử thế nào khi có hàng chục máy bình thường.
3. Chưa thử trễ đường truyền trên 200 ms hay mất gói.
4. SYN flood: nạn nhân gần như không bị gán `dos`; phát hiện dựa vào việc thấy máy tấn công.
5. Bot không có traffic nền (`.50`) dễ bị sót.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Khái quát | Mô hình còn đúng trên tình huống khác với lúc học |
| Đổi vai trò | Cho máy khác đóng vai bot và máy điều khiển, dùng cổng và chu kỳ khác |
| Chấm chéo | Dùng mô hình học ở mạng này để chấm dữ liệu của mạng khác |
| Train / val / test | Lần chạy để học / để chọn ngưỡng và tham số / để đánh giá cuối |
| Host–cửa sổ | Đơn vị chấm của module botnet: một host trong một khoảng 120 giây |
| Topology, `centralized`, `p2p` | Cấu trúc liên lạc của bot: gọi về một máy điều khiển / gọi lẫn nhau |
| Đặc trưng nhóm | Đặc trưng tính trên quan hệ giữa nhiều host, không phải trên từng host riêng lẻ |
| SYN flood | Gửi ồ ạt gói mở kết nối TCP mà không hoàn tất kết nối |
| Gói thô | Gói do chương trình tự dựng, không qua ngăn xếp TCP bình thường của hệ điều hành |
| Tải kết nối | Mở rồi đóng liên tục nhiều kết nối TCP thường |
| Chờ bắt tay | Khoảng chờ trả lời của lần mở kết nối TCP trước khi coi là không hoàn tất |
| Trễ khứ hồi | Thời gian một gói đi tới đích và gói trả lời quay về |
| Background (CTU-13) | Traffic chưa được xác nhận là bot hay bình thường |
| Macro-F1, recall | Trung bình F1 của các lớp; tỷ lệ mẫu tấn công thật được nhận ra |
| Báo động giả | Cảnh báo không do đợt tấn công nào gây ra |
