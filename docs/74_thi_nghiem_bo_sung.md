# Thí nghiệm bổ sung trên lab: cảm biến bắt trực tiếp, máy tấn công có traffic bình thường, khoảng gộp sự kiện

Ba phép đo đóng các hạn chế ghi ở `docs/Viec_con_thieu.md` mục 4e, 4f và 4g. Đều chạy ngày 12–13/11/2026 trên
lab ảo (docs/70) với mô hình học lại trên lab (`config/lab.yaml`, docs/73), trừ khi ghi khác.

## 1. Cảm biến realtime bắt gói trực tiếp trên máy giám sát

Trước đây độ trễ realtime chỉ đo bằng **phát lại PCAP** trên laptop Windows (Báo cáo Chặng 11 mục 4.1). Ở đây
cảm biến `nids.realtime --iface eth0` chạy **trong namespace máy giám sát `.10`**, bắt gói từ cổng mirror suốt
lần chạy, song song với `tcpdump`. Cảnh báo ghi giờ thật lúc phát; nhật ký lần chạy dùng cùng đồng hồ, nên độ
trễ = giờ phát cảnh báo − giờ bắt đầu hành vi, không phải quy đổi.

```bash
sudo bash scripts/chay_cam_bien_lab.sh 21 k3-dos-muc2 7          # lab số 21, biến thể, lần chạy 7
cd src
python -m nids.do_tre_realtime ../data/pcap/lab/k3-dos-muc2-test-07.pcap --nhat-ky ../data/run_logs \
    --alerts ../output/cam_bien_lab/k3-dos-muc2-test-07/k3-dos-muc2-test-07.alerts.csv
```

Cảm biến chạy bằng Python 3.14 trong WSL2 với scikit-learn 1.8.0 (đúng phiên bản đã tạo mô hình); đã kiểm tra
nó cho cùng số cảnh báo với bản chạy trên Windows khi phát lại cùng một PCAP (105 cảnh báo, 70 cửa sổ `dos`).

| Lần chạy (lần 7) | Gói nhận / xử lý | Gói nhân bỏ | Gói hàng đợi bỏ | CPU trung bình | RAM lớn nhất | Trễ xử lý p95 / lớn nhất |
|---|---|---|---|---|---|---|
| `k1-binh-thuong` | 7 898 / 7 898 | 0 | 0 | 2,6% | 213 MB | 0,083 / 0,220 s |
| `k2-quet-nhanh` | 10 104 / 10 104 | 0 | 0 | 2,8% | 215 MB | 0,060 / 0,214 s |
| `k3-dos-muc2` | 76 018 / 76 018 | 0 | 0 | 5,4% | 257 MB | 0,012 / 0,327 s |
| `k4-co-dinh` | 14 239 / 14 239 | 0 | 0 | 2,9% | 214 MB | 0,065 / 0,220 s |
| `k5-p2p` | 13 546 / 13 546 | 0 | 0 | 2,8% | 213 MB | 0,071 / 0,174 s |

| Đợt tấn công | Phát hiện | **Độ trễ thật** | Tới cuối cửa sổ | Chờ sau cuối cửa sổ |
|---|---|---|---|---|
| Quét nhanh (`k2-quet-nhanh`) | ✓ | **4,2 s** | 0,2 s | 3,9 s |
| DoS mức 2 (`k3-dos-muc2`) | ✓ | **3,9 s** | 0,9 s | 3,0 s |
| Botnet tập trung (`k4-co-dinh`, chu kỳ 30 s) | ✓ | **30,0 s** | 16,2 s | 13,8 s |
| Botnet ngang hàng (`k5-p2p`, chu kỳ 8 s) | ✓ | **17,8 s** | 3,9 s | 13,9 s |

- **Cảm biến bắt trực tiếp không bỏ gói nào** (nhân và hàng đợi đều 0) ở cả năm lần, kể cả lúc tải kết nối
  200 kết nối mỗi giây; CPU dưới 6% một nhân, RAM khoảng 215–260 MB.
- **Độ trễ thật của quét và DoS là 3,9–4,2 giây**, khớp với số đo bằng phát lại (3,5–6,3 giây, trung vị 4,6).
  Phát lại PCAP vì vậy là cách đo đáng tin.
- **Botnet được báo sau 18–30 giây.** Phần chờ sau cuối cửa sổ là 13,8–13,9 giây: 3 giây quan sát bắt tay cộng
  10 giây chờ thêm một cửa sổ để chấm đồ thị (`realtime.graph_delay_s`, QĐ-056).
- Lần chạy bình thường `k1`: **0 cảnh báo** trong 771 giây.

Giới hạn: máy giám sát là namespace trên WSL2 với card ảo, không phải Kali với card thật; tải của lab thấp (cao
nhất khoảng 2 900 gói mỗi giây trong lúc tấn công).

## 2. Máy tấn công cũng là máy làm việc bình thường

Trong 55 lần chạy chính, máy thử nghiệm `.20` chỉ sinh traffic tấn công, nên cửa sổ của nó "sạch" hơn thực tế.
Ở đây `.20` **duyệt web tới máy chủ dịch vụ suốt bản thu** như ba client, rồi mới quét hoặc tấn công
(`lab_ao.py chay --nen-may-tan-cong`, lần chạy 8 của năm biến thể kịch bản 2 và 3).

| | Mô hình cũ (CIC) | Mô hình học lại trên lab |
|---|---|---|
| Đợt phát hiện (2 quét, 3 DoS) | 5/5 | **5/5** |
| Độ trễ tới cuối cửa sổ | 0,1–1,9 s | 0,1–1,9 s |
| Sự kiện báo động giả | 5 (anomaly trên `.30`) | **0** |
| Recall `port_scan` của máy tấn công (267 cửa sổ) | 0,869 | **1,000** |
| Recall `dos` của máy tấn công (102 cửa sổ) | 0,971 | 0,971 |
| Recall `dos` của máy nạn nhân (100 cửa sổ) | 0,570 | **0,990** |
| Cửa sổ `benign` bị báo (3 341 cửa sổ) | 0 | 0 |

- **Cả năm đợt vẫn được phát hiện với cùng độ trễ** khi máy tấn công có traffic bình thường xen kẽ.
- Với mô hình cũ, recall theo cửa sổ của máy quét giảm từ 1,000 (khi `.20` chỉ quét) xuống 0,869: một phần cửa
  sổ quét chậm lẫn kết nối web hoàn tất nên trông giống bình thường. Mô hình học lại không bị ảnh hưởng.
- Các cửa sổ `.20` duyệt web **không** bị báo nhầm ở cả hai mô hình.
- 1 485 cửa sổ bị xếp mơ hồ và không chấm: `.20` duyệt web tới đúng máy và cổng mà nó tấn công, nên flow bình
  thường của cặp này ngoài khung giờ tấn công không thể gán chắc là lành tính (cùng quy tắc với CIC, QĐ-025).

## 3. Chế độ pipeline và khoảng gộp sự kiện trên PCAP lab

Trước đây so sánh chế độ và khoảng gộp sự kiện chỉ chạy trên 4 đoạn CIC ngắn (docs/57, docs/58).

**Chế độ** (33 lần `test` mới, docs/73 mục 3.1): với mô hình học lại, `doc_lap` phát hiện 24/24 đợt, `ket_hop`
15/24 (bỏ sót mọi đợt botnet), cùng 4 sự kiện báo động giả. Lab dùng `doc_lap` (QĐ-068).

**Khoảng gộp sự kiện** (`pipeline.merge_gap_s`, 11 lần `val`, `docs/hinh/thuc_nghiem/lab/gop_su_kien_val.json`):

| Khoảng gộp | Cảnh báo | Sự kiện | Theo module (anomaly / phân loại / botnet) | Báo động giả |
|---|---|---|---|---|
| 10 s | 2 592 | 41 | 7 / 10 / 24 | 0 |
| **30 s (hiện tại)** | 2 592 | 41 | 7 / 10 / 24 | 0 |
| 60 s | 2 592 | 41 | 7 / 10 / 24 | 0 |
| 120 s | 2 592 | 41 | 7 / 10 / 24 | 0 |

Số sự kiện không đổi từ 10 tới 120 giây: cảnh báo của một đợt tấn công liền nhau (cửa sổ trượt chồng lên
nhau), còn các đợt cách nhau xa hơn 120 giây. **Giữ 30 giây.** Gộp làm 2 592 cảnh báo còn 41 sự kiện (giảm 63
lần).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Bắt trực tiếp | Cảm biến đọc gói từ card mạng lúc chúng đi qua, không phải từ file đã lưu |
| Phát lại PCAP | Đưa các gói đã bắt vào chương trình theo đúng nhịp thời gian lúc bắt |
| Máy giám sát | Máy nhận bản sao mọi gói qua cổng mirror và chạy cảm biến |
| Gói nhân bỏ | Gói mà nhân hệ điều hành không kịp đưa cho chương trình bắt gói |
| Hàng đợi | Bộ đệm giữa luồng đọc gói và luồng xử lý của cảm biến; đầy thì gói mới bị bỏ |
| Trễ xử lý | Thời gian một gói chờ trong hàng đợi cộng thời gian xử lý nó |
| Độ trễ phát hiện | Thời gian từ lúc tấn công bắt đầu tới lúc cảm biến phát cảnh báo đầu tiên |
| Quan sát bắt tay | Khoảng chờ trả lời của lần mở kết nối TCP trước khi coi là không hoàn tất |
| Cửa sổ đồ thị | Khoảng 120 giây dùng để tính đặc trưng liên lạc của module botnet |
| Recall | Trong các mẫu tấn công thật, tỷ lệ được nhận ra |
| Cửa sổ mơ hồ | Cửa sổ không gán chắc được là tấn công hay bình thường; không dùng để chấm |
| Sự kiện | Nhiều cảnh báo liên tiếp cùng module, nhãn, host được gộp làm một |
| Khoảng gộp | Khoảng im lặng tối đa giữa hai cảnh báo để vẫn tính là một sự kiện |
| Chế độ `ket_hop` / `doc_lap` | `ket_hop`: module botnet chỉ xét host bị anomaly báo. `doc_lap`: ba module chấm độc lập mọi host |
