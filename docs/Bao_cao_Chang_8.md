# Báo cáo Chặng 8 — Botnet và nhận diện topology

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 03/11/2026 |
| Trạng thái | Xong 8/8 task |
| Chặng trước | [Bao_cao_Chang_7.md](Bao_cao_Chang_7.md) |

## 1. Tóm tắt

Chặng 8 xây module **botnet/topology**. Module gồm hai phần, báo cáo riêng (B06, B20):
1. **Phát hiện host bot** theo host–cửa sổ 120 giây;
2. **Nhận diện topology** của bot: tập trung hay ngang hàng.

```
.binetflow CTU-13 ─> bảng flow chung ─> đồ thị theo cửa sổ ─> đặc trưng đồ thị + beaconing ─> nhãn host–cửa sổ
(13 scenario)        (T01)               (T01, 120 s / 10 s)   (T02, T03)                      (T04, chia theo scenario)
     ─> Random Forest / Logistic Regression (T05) ─> host nghi vấn ─> quy tắc topology (T07) ─> hai bảng (T08)
flow giả lập + script lab (T06) ──────────────────────────────────────────────────────────────┘
```

**Bảng 1 — Phát hiện botnet** (test CTU-13: scenario 1, 2, 6, 8, 9; họ bot Neris, DonBot, Murlo chưa
thấy ở train):

| | Random Forest (chọn) | Logistic Regression |
|---|---|---|
| Precision / Recall / F1 | **0,971 / 0,678 / 0,798** | 0,949 / 0,132 / 0,232 |
| F1 theo scenario (1, 2, 6, 8, 9) | 0,99 / 0,99 / 0,98 / **0,26** / 0,97 | 0,11 / 0,03 / 0,69 / 0,26 / 0,20 |
| Báo nhầm máy bình thường | 1,6% | 0,5% |
| Cửa sổ Background bị báo | 11,9% | 10,7% |

**Bảng 2 — Nhận diện topology** (quy tắc, chỉ bộ nhận diện, trên cửa sổ bot thật):

| Dữ liệu | Tập trung đúng | Ngang hàng đúng | Scenario / lần chạy đúng |
|---|---|---|---|
| CTU-13 test | 99,9% (19 165/19 188) | không có P2P | 5/5 |
| CTU-13 train + validation | 100% | 95,1% (663/697) | 8/8 |
| Giả lập | 100% (711/711) | 81,7% (581/711) | 11/12 |

**Tiêu chí của chặng** (task list): hai mô hình được so sánh; ghi rõ topology dùng quy tắc hay ML;
đánh giá bằng hai bảng riêng.

| Yêu cầu | Đáp ứng |
|---|---|
| Đồ thị theo cửa sổ: node, cạnh, trọng số | Cửa sổ 120 giây, bước 10 giây; cạnh có hướng, 6 loại trọng số (mục 3.1) |
| Số peer, bậc vào/ra, tương hỗ, mức tập trung | 19 đặc trưng (mục 3.2) |
| Beaconing với số quan sát tối thiểu | ≥ 5 quan sát trong 600 giây nhìn ngược, CV ≤ 0,3 (mục 3.3) |
| Quy định cách xử lý Background | Giữ trong đồ thị; không là lớp dương, không tính Precision/Recall; làm mẫu âm yếu và giới hạn báo động (mục 3.4, 3.5) |
| Ít nhất hai mô hình | Random Forest và Logistic Regression, cùng đặc trưng và quy trình chọn (mục 3.5) |
| Dữ liệu tập trung, ngang hàng, đối chứng | Flow giả lập 4 kiểu × 3 lần và script lab vô hại (mục 3.6) |
| Ghi rõ quy tắc hay ML | **Quy tắc**, có lý do (mục 3.7, QĐ-042) |
| Hai bảng riêng | Mục 1 và docs/52 |

## 2. Các task

| Task | Nội dung | Tài liệu |
|---|---|---|
| C08-T01 | Đồ thị theo cửa sổ: node, cạnh, trọng số | [45_do_thi_cua_so.md](45_do_thi_cua_so.md) |
| C08-T02 | Số peer, bậc vào/ra, tính tương hỗ và mức tập trung | [46_dac_trung_do_thi.md](46_dac_trung_do_thi.md) |
| C08-T03 | Beaconing với số quan sát tối thiểu | [47_beaconing.md](47_beaconing.md) |
| C08-T04 | Dữ liệu host–cửa sổ có nhãn botnet; cách xử lý Background | [48_botnet_nhan.md](48_botnet_nhan.md) |
| C08-T05 | Huấn luyện và so sánh hai mô hình phát hiện botnet | [49_botnet_mo_hinh.md](49_botnet_mo_hinh.md) |
| C08-T06 | Dữ liệu topology tập trung, ngang hàng, đối chứng lành tính | [50_du_lieu_topology.md](50_du_lieu_topology.md) |
| C08-T07 | Bộ nhận diện topology (quy tắc) | [51_nhan_dien_topology.md](51_nhan_dien_topology.md) |
| C08-T08 | Đánh giá bằng hai bảng riêng | [52_botnet_danh_gia.md](52_botnet_danh_gia.md) |

Mã nguồn:
- `src/nids/ctu13.py`: đọc CTU-13;
- `src/nids/graph_features.py`: đồ thị và đặc trưng;
- `src/nids/botnet.py`: nhãn, mô hình, topology, đánh giá;
- `src/nids/topology_sim.py`: giả lập;
- `scripts/sinh_topology.py`: traffic lab.

Kiểm thử: `tests/test_botnet.py`.

## 3. Kết quả từng task

### 3.1. C08-T01 — Đồ thị theo cửa sổ

- Đã tải đủ 13 file `.binetflow` (2,6 GB), mã băm trong manifest, `nids.manifest --verify` khớp.
  Không tải mẫu mã độc.
- Bảng flow chung dùng cho cả CTU-13 và flow của dự án (CIC, lab).
- Chỉ dựng đồ thị một bước quanh **host cần xét** (bot, máy bình thường, 20 host Background mẫu mỗi
  scenario) để vừa RAM: giữ 4–36% số flow (QĐ-036).
- Gộp theo ô 10 giây rồi trải ra 12 cửa sổ: 13 scenario dựng đồ thị và đặc trưng trong khoảng 10 phút.

### 3.2. C08-T02 — Đặc trưng đồ thị

- 19 đặc trưng: số peer, bậc ra/vào, flow/byte/gói mỗi hướng, tương hỗ, mức tập trung (phần flow vào
  một peer, entropy) mỗi hướng, số cổng, flow không trả lời, UDP, peer nội bộ, peer mới.
- Hướng không có flow thì để trống (QĐ-037).

### 3.3. C08-T03 — Beaconing

- Cặp (host, peer, cổng, giao thức); ≥ 5 quan sát trong 600 giây nhìn ngược; đều khi CV ≤ 0,3 và chu kỳ
  ≥ 1 giây (QĐ-038).
- **Trên CTU-13 beaconing không tách được bot khỏi máy bình thường**: 58,7% cửa sổ bot và 57,8% cửa
  sổ máy bình thường có cặp đều. Cặp kênh điều khiển có CV trung vị 0,92. Bot CTU-13 chủ yếu spam,
  quét, DDoS chứ không gọi về đều.

### 3.4. C08-T04 — Nhãn và Background

- `suspect_host`: bot có ≥ 1 flow From-Botnet trong cửa sổ.
- `normal_host`: máy bình thường đã xác nhận có flow From-Normal.
- Background: không là lớp dương, không tính chỉ số.
- Cửa sổ trước khi bị nhiễm tự bị loại.
- Chia theo scenario: train 3, 5, 7, 10, 11, 12; validation 4, 13 (**tạm chọn**); test 1, 2, 6, 8, 9
  (QĐ-039).
- Train 9 575 / 32 827, validation 6 555 / 10 453, test 19 188 / 24 880 cửa sổ bot / bình thường.
  Nhưng chỉ có khoảng 10 IP bot và **4 máy bình thường giống nhau ở mọi tập**.

### 3.5. C08-T05 — Hai mô hình

- Chọn theo F1 validation và ngưỡng 0,5 thì F1 thấp. Cho chọn cả ngưỡng thì ngưỡng về 0,05 và **84–93%
  cửa sổ Background bị báo**: mô hình học danh tính bốn máy bình thường thay vì hành vi bot.
- Sửa bằng hai cách, chỉ dùng train và validation (QĐ-040):
  - ràng buộc Background validation bị báo ≤ 5% khi chọn;
  - dùng cửa sổ Background của train làm mẫu âm yếu, tỷ lệ chọn trên validation.
- Chọn RF (300 cây, `min_samples_leaf` 5, 100% Background làm mẫu âm, ngưỡng 0,10): F1 validation
  0,536. LR tốt nhất 0,165.

### 3.6. C08-T06 — Dữ liệu topology

- `nids.topology_sim`: flow giả lập, không gửi gói; 4 kiểu × 3 lần chạy 15 phút, chu kỳ và jitter khác
  nhau; nhãn từ nhật ký lần chạy.
- `scripts/sinh_topology.py`: traffic thật cho lab; chỉ thông điệp vô hại, từ chối đích ngoài
  192.168.50.0/24, ghi nhật ký lần chạy (QĐ-041). Chưa chạy vì lab chưa dựng.
- Đối chứng tập trung lành tính có cùng đặc trưng với botnet tập trung (đúng thiết kế).

### 3.7. C08-T07 — Topology bằng quy tắc

- Chọn **quy tắc** vì CTU-13 chỉ có một scenario P2P (QĐ-042).
- Host–cửa sổ bị nghi được xếp `p2p` khi ≥ 5 peer gọi vào, ≥ 50% UDP và entropy flow vào ≥ 0,8; còn lại
  `centralized`.
- Topology của lần chạy là nhãn đa số.

### 3.8. C08-T08 — Hai bảng

- Bảng 1 và Bảng 2 ở mục 1; chi tiết, nối tiếp bộ phát hiện và mức lần chạy ở docs/52.
- **Murlo (scenario 8)** bị bỏ sót: 4 909/6 723 cửa sổ bot chỉ có 2–3 flow botnet (thử TCP chậm). RF
  bắt 100% cửa sổ có trên 50 flow botnet, 0% cửa sổ có 1–3 flow.
- **Background test bị báo 11,9%**, vượt 5% đã giữ trên validation.
- **Không chuyển được sang giả lập**: mô hình học từ CTU-13 chỉ bắt 1,7% cửa sổ bot giả lập.

## 4. So với hai module trước

| | Gaussian (Chặng 6) | Phân loại (Chặng 7) | Botnet (Chặng 8) |
|---|---|---|---|
| Đơn vị | Cửa sổ host 10 giây | Cửa sổ host 10 giây | Host–cửa sổ 120 giây |
| Dữ liệu | CIC-IDS2017 | CIC-IDS2017 | CTU-13 + giả lập |
| Chỉ số chính trên test | F1 0,730 | Macro-F1 0,831 | F1 0,798 (bot) |
| Điểm yếu chung | Cửa sổ "tấn công" có rất ít hoạt động bị bỏ sót | Quét UDP/SCTP, cửa sổ quét ít hoạt động | Bot chậm, cửa sổ ít flow botnet |

Cả ba chặng gặp cùng một vấn đề: nhãn theo cửa sổ gồm nhiều cửa sổ gần như không có hành vi. Chặng 9
nên gộp cảnh báo theo host qua nhiều cửa sổ.

## 5. Sửa ở chặng trước

- Manifest: 13 dòng CTU-13 chuyển sang `da_tai`, có SHA-256, dung lượng thật, tập theo QĐ-039 và số
  flow đếm được.
- docs/07 mục 8 cập nhật; `docs/Viec_con_thieu.md` mở rộng tới Chặng 8 (mục 4d mới, việc 2 ở mục 0
  đã xong).
- Thêm `local_nets` vào cấu hình (đã mô tả ở docs/46 nhưng trước đó thiếu trong `default.yaml`).

## 6. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-036 | Đồ thị theo cửa sổ quanh host cần xét; flow thuộc cửa sổ theo lúc bắt đầu | Đã chốt |
| QĐ-037 | 19 đặc trưng đồ thị; hướng không có flow thì để trống | Đã chốt |
| QĐ-038 | Beaconing: 600 giây nhìn ngược, ≥ 5 quan sát, CV ≤ 0,3 | Đã chốt |
| QĐ-039 | Nhãn host–cửa sổ; Background không là lớp dương; chia theo scenario | Đã chốt (validation tạm thời) |
| QĐ-040 | Chọn với giới hạn Background ≤ 5%; Background làm mẫu âm yếu | Đã chốt |
| QĐ-041 | Dữ liệu topology: giả lập ngay, lab vô hại sau; nhãn từ nhật ký | Đã chốt (giả lập tạm thời) |
| QĐ-042 | Topology bằng quy tắc, chạy sau bộ phát hiện | Đã chốt cho CTU-13, giả lập |

Cấu hình mới: mục `botnet` trong `config/default.yaml`:
- `local_nets`;
- `beaconing`;
- `splits`;
- `topology`;
- `max_background_alarm`;
- `topology_rule`.

## 7. Kiểm thử

`python -m unittest discover -s tests`: **340/340 ca đạt** (Chặng 7 kết thúc ở 316).
`tests/test_botnet.py` có 24 ca:

| Task | Số ca | Nội dung |
|---|---|---|
| T01 | 7 | Nhãn CTU-13; đọc file mẫu (cổng hex, byte về, peer ngoài); lấy mẫu Background; đổi flow dự án; 12 cửa sổ mỗi flow; trọng số, hướng; cửa sổ phải là bội của bước |
| T02 | 3 | Ví dụ tính tay đủ đặc trưng; peer mới; hướng trống; mạng nội bộ |
| T03 | 2 | Số quan sát, CV, khoảng nhìn ngược; cặp đều, cặp dồn dập, cặp ít quan sát |
| T04 | 2 | Bốn loại nhãn, topology theo scenario; mỗi scenario đúng một tập |
| T05 | 4 | Mô hình, ngưỡng; Background làm mẫu âm; lưới chọn có giới hạn Background; đánh giá, lưu/nạp |
| T06 | 3 | Giả lập (chu kỳ, P2P, đối chứng); nhãn từ nhật ký; script lab từ chối đích ngoài lab, lịch gửi đúng |
| T07 | 2 | Quy tắc ba điều kiện; nhãn đa số và confusion matrix |
| T08 | 1 | Bảng topology hai cách đo |

## 8. Cách chạy

```bash
python -m nids.ctu13 chuan-bi data/ctu13 --out output/ctu13                    # khoảng 25 phút
cd src
python -m nids.graph_features dac-trung ../output/ctu13 --scenario 1 ... --scenario 13 --out ../output/ctu13
python -m nids.botnet nhan ../output/ctu13 --out ../docs/hinh
python -m nids.botnet huan-luyen ../output/ctu13 --out ../docs/hinh             # khoảng 10 phút
python -m nids.topology_sim --out ../output/topology_sim
python -m nids.botnet danh-gia ../output/ctu13 --sim-dir ../output/topology_sim \
    --model ../models/botnet_rf.joblib --model ../models/botnet_lr.joblib --chon botnet_rf --out ../docs/hinh
```

## 9. Điểm cần lưu ý

1. **Ít host độc lập.** Bốn máy bình thường lặp lại ở mọi tập; con số báo nhầm 1,6% không đại diện cho
   mạng lạ. Tỷ lệ Background bị báo (11,9% trên test) là chỉ báo thực tế hơn.
2. **Scenario validation (4, 13) do tôi tạm chọn.** Nhóm cần xác nhận; đổi trong `botnet.splits`.
3. **Bot chậm bị bỏ sót** khi xét từng cửa sổ 120 giây; cần gộp theo host qua thời gian (Chặng 9).
4. **Mô hình CTU-13 không dùng thẳng cho lab**; phải học lại khi có dữ liệu lab.
5. **Topology P2P chỉ được kiểm tra trên một scenario thật và dữ liệu giả lập**. Kết quả giả lập chỉ
   kiểm tra logic (B25).
6. **Đã xem tập test một lần** ở C08-T08, sau khi chốt mô hình, ngưỡng và quy tắc. Không chỉnh gì sau
   đó.

## 10. Việc tiếp theo

**Chặng 9 — Pipeline offline**:
- ghép ba module (Gaussian, phân loại, botnet/topology) trên cùng luồng flow;
- quy tắc kết hợp cảnh báo, ví dụ khi bot bị phân loại thành quét cổng (Chặng 7);
- gộp cảnh báo theo host qua nhiều cửa sổ, để bù cho cửa sổ ít hoạt động.

Song song: dựng lab và chạy `scripts/sinh_topology.py`; xác nhận scenario validation CTU-13; các việc
đang dở ở `docs/Viec_con_thieu.md` mục 0.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Botnet, host bot | Mạng máy bị nhiễm cùng nghe lệnh; một máy bị nhiễm |
| Topology tập trung / ngang hàng | Các bot gọi một máy điều khiển / các bot gọi lẫn nhau |
| Host–cửa sổ | Một máy trong một cửa sổ 120 giây |
| Đồ thị giao tiếp | Các máy (node) và đường nối (cạnh) giữa hai máy có flow |
| Beaconing | Gọi tới cùng một đích theo chu kỳ đều |
| Background | Traffic và máy chưa được kiểm chứng của mạng trường (CTU-13) |
| Mẫu âm yếu | Mẫu coi như bình thường khi học dù chưa kiểm chứng chắc chắn |
| Ngưỡng xác suất | Mô hình báo bot khi xác suất ≥ ngưỡng |
| Precision, Recall, F1 | Tỷ lệ báo đúng; tỷ lệ bắt được; trung bình điều hòa |
| Confusion matrix | Bảng đếm theo nhãn thật và nhãn đoán |
| Quy tắc | Điều kiện viết tay, không học từ dữ liệu |
| Flow giả lập | Bản ghi flow do chương trình tạo, không có gói tin thật |
| Neris, Rbot, Virut, DonBot, Sogou, Murlo, NSIS.ay | Các họ bot trong CTU-13 |
