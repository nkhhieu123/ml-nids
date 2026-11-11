# C08-T04 — Dữ liệu host–cửa sổ có nhãn botnet; cách xử lý Background

Mã nguồn: `label_host_windows`, `flow_counts`, `load_labeled`, `label_report` trong
`src/nids/botnet.py`. Cấu hình: `botnet.splits`, `botnet.topology` trong `config/default.yaml`.
Kiểm thử: `tests/test_botnet.py`. Kết quả: `docs/hinh/botnet_nhan.json`.

```bash
python -m nids.ctu13 chuan-bi data/ctu13 --out output/ctu13                # 13 scenario, khoảng 25 phút
cd src
python -m nids.graph_features dac-trung ../output/ctu13 --scenario 1 ... --scenario 13 --out ../output/ctu13
python -m nids.botnet nhan ../output/ctu13 --out ../docs/hinh
```

## 1. Dữ liệu CTU-13 đã tải

Đủ 13 file `.binetflow` (2,6 GB) trong `data/ctu13/`, không tải mẫu mã độc.

| Scenario | Bot (README) | Giờ | Flow | Flow From-Botnet | Flow CC | Bot trong mạng | Flow giữ lại |
|---|---|---|---|---|---|---|---|
| 1 | Neris | 6,1 | 2 824 636 | 40 961 | 341 | 1 | 114 565 |
| 2 | Neris | 4,2 | 1 808 122 | 20 941 | 673 | 1 | 71 034 |
| 3 | Rbot | 66,8 | 4 710 638 | 26 822 | 63 | 1 | 554 620 |
| 4 | Rbot | 4,5 | 1 121 076 | 2 580 | 52 | 1 | 48 067 |
| 5 | Virut | 0,5 | 129 832 | 901 | 24 | 1 | 30 690 |
| 6 | DonBot | 2,2 | 558 919 | 4 630 | 199 | 1 | 31 513 |
| 7 | Sogou | 0,35 | 114 077 | 63 | 26 | 1 | 9 604 |
| 8 | Murlo | 19,5 | 2 954 230 | 6 127 | 1 074 | 1 | 1 053 509 |
| 9 | Neris | 5,6 | 2 087 508 | 184 987 | 2 973 | 10 | 530 054 |
| 10 | Rbot | 5,1 | 1 309 791 | 106 352 | 33 | 10 | 151 219 |
| 11 | Rbot | 0,27 | 107 251 | 8 164 | 2 | 3 | 17 058 |
| 12 | NSIS.ay | 1,7 | 325 471 | 2 168 | 25 | 3 | 25 975 |
| 13 | Virut | 16,4 | 1 925 149 | 40 003 | 536 | 1 | 100 498 |

So với README:
- Scenario 1, 2, 9, 10, 11, 13 khớp số flow botnet.
- Scenario 4, 5, 6 đếm được **đúng một nửa** con số của README (2 580/5 160; 901/1 802; 4 630/9 260).
  README có thể đã đếm cả hai chiều; ở đây chỉ đếm flow có nhãn `From-Botnet`.
- Scenario 3 và 12 có IP **ngoài** mạng trường mang nhãn `From-Botnet` (`38.229.70.20`; sáu peer P2P).
  Chúng là peer, không là host xét (QĐ-036).
- Máy bình thường: ba máy của docs/07, cộng **`147.32.1.20`** có nhãn `From-Normal` ở scenario 8, 9,
  10. Không có trong danh sách README nhưng tác giả gán `From-Normal`, nên vẫn dùng.
- `StartTime` là giờ địa phương; chỉ dùng khoảng cách thời gian trong cùng scenario nên không cần
  xác định múi giờ. Đã xác định (06/11/2026) để ghi lại: **`StartTime` là UTC+2** (giờ mùa hè Praha,
  CEST). Cách làm: khớp 5-tuple có hướng giữa PCAP chỉ-bot (dấu thời gian UTC) và binetflow của cùng
  scenario, lấy hiệu giữa thời điểm gói đầu và `StartTime`. Ba scenario (5 Virut, 6 DonBot, 7 Sogou,
  bot `147.32.84.165`) đều cho trung vị đúng −7 203 giây = −2,00 giờ; riêng DonBot có 4 426/4 468 flow
  lệch dưới 5 giây quanh trung vị. Vậy để đổi `StartTime` sang UTC thì **trừ 2 giờ**.

## 2. Nhãn host–cửa sổ

| Nhãn | Điều kiện | Dùng làm gì |
|---|---|---|
| `suspect_host` | Host là bot trong mạng và **khởi tạo ≥ 1 flow `From-Botnet`** trong cửa sổ | Học, chọn, đánh giá (lớp dương) |
| `normal_host` | Host là máy bình thường đã xác nhận và khởi tạo ≥ 1 flow `From-Normal` trong cửa sổ | Học, chọn, đánh giá |
| `background` | Host Background lấy mẫu (QĐ-036) | **Không học, không tính Precision/Recall.** Chỉ báo "tỷ lệ cửa sổ Background bị báo" như giới hạn trên của báo động trên máy chưa kiểm chứng |
| `bo` | Còn lại: bot chưa bị nhiễm hoặc đang im lặng trong cửa sổ; máy bình thường không có flow `From-Normal` | Bỏ |

**Cách xử lý Background (QĐ-039):**
- Flow Background vẫn **giữ trong đồ thị** khi chúng chạm host xét (là hàng xóm, là traffic peer gọi
  vào bot).
- Host Background **không bao giờ** được coi là `normal_host`: chưa kiểm chứng, mạng trường có thể còn
  máy nhiễm khác.
- Cửa sổ Background bị báo **không** tính là báo nhầm (FPR). Chỉ báo riêng như một ước lượng.

**Thời điểm bị nhiễm**: không cần đọc README. Cửa sổ của bot chỉ là `suspect_host` khi có flow
`From-Botnet`, nên mọi cửa sổ trước flow botnet đầu tiên tự rơi vào `bo`. Flow botnet đầu tiên đến từ
5 giây (scenario 8) tới 78 phút (scenario 1) sau đầu bản thu.

Nhãn topology đi kèm: `p2p` cho bot của scenario 12 (`botnet.topology.p2p`), `centralized` cho bot các
scenario còn lại (có kênh IRC/HTTP), `none` cho máy bình thường (docs/07 mục 5).

## 3. Chia tập theo scenario (B11)

Mặc định trong `botnet.splits` (QĐ-039):

| Tập | Scenario | Lý do |
|---|---|---|
| Train | 3, 5, 7, 10, 11, 12 | Nhóm huấn luyện của bài báo gốc trừ hai scenario validation; giữ **12 (P2P duy nhất)** và cả bốn họ bot Rbot, Virut, Sogou, NSIS.ay |
| Validation | **4 (Rbot), 13 (Virut)** | Hai họ bot đã có ở train, đủ dài (4,5 và 16,4 giờ) |
| Test | 1, 2, 6, 8, 9 | Như bài báo gốc; có Neris, DonBot, Murlo **chưa từng thấy ở train** |

Scenario validation 4 và 13 **đã khóa ngày 12/11/2026** (QĐ-065). Không scenario nào ở hai tập, nên
không có cửa sổ chồng lấn giữa các tập.

## 4. Số mẫu

| Tập | `suspect_host` | `normal_host` | Host bot khác nhau | Host bình thường khác nhau | Background |
|---|---|---|---|---|---|
| Train | 9 575 | 32 827 | 10 IP | 4 IP | 183 958 |
| Validation | 6 555 | 10 453 | 1 IP | 3 IP | 60 131 |
| Test | 19 188 | 24 880 | 10 IP | 4 IP | 148 720 |

Theo scenario (host–cửa sổ): bot 49 (scenario 7) tới 8 758 (scenario 9); bình thường 211 (11) tới
26 998 (3).

## 5. Hạn chế quan trọng

1. **Rất ít host độc lập.** `147.32.84.165` là bot ở cả 13 scenario; bốn máy bình thường **giống nhau
   ở mọi tập**. Mô hình có thể học thói quen riêng của bốn máy đó. Tỷ lệ Background bị báo là cách
   duy nhất trên CTU-13 để thấy mô hình phản ứng với máy lạ.
2. **Chỉ một scenario P2P** (12, ở train). Không đánh giá được phát hiện bot P2P trên test CTU-13.
3. Bot có thể vừa hoạt động botnet vừa sinh traffic Background trong cùng cửa sổ; nhãn theo việc có
   flow `From-Botnet`, không theo phần trăm.
4. Scenario rất khác nhau về độ dài (0,27 tới 66,8 giờ): scenario 3 chiếm 82% cửa sổ `normal_host` của
   train.

## 6. Kiểm thử

- Bot có flow From-Botnet thành `suspect_host` với topology theo scenario; bot không có flow botnet
  trong cửa sổ thành `bo`; máy bình thường có From-Normal thành `normal_host` (`none`); host Background
  thành `background`.
- Mỗi scenario thuộc đúng một tập; scenario 12 là `p2p`, còn lại `centralized`.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Host–cửa sổ | Một máy trong một cửa sổ 120 giây |
| `suspect_host`, `normal_host` | Máy nghi là bot; máy bình thường đã xác nhận |
| Background | Traffic và máy chưa được kiểm chứng của mạng trường |
| From-Botnet, From-Normal | Flow do bot khởi tạo; flow do máy bình thường khởi tạo |
| Họ bot | Loại mã độc: Neris, Rbot, Virut, DonBot, Sogou, Murlo, NSIS.ay |
| Host độc lập | Máy khác nhau (khác IP); quyết định mô hình học được hành vi chung hay thói quen riêng |
| Giới hạn trên của báo động | Số báo trên máy chưa kiểm chứng: một phần có thể là bot thật nên không tính là báo nhầm |
| Topology | Hình dạng giao tiếp của botnet: tập trung hoặc ngang hàng |
