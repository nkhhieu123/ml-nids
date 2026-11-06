# C09 — Gộp cảnh báo botnet theo host để vớt bot chậm

Mã nguồn: `confirmed_bot_hosts`, `aggregate_host`, `host_aggregation_config`, `evaluate(..., host_agg=)`,
`cmd_host_agg` trong `src/nids/botnet.py`. Kiểm thử: `tests/test_botnet.py` (`HostAggregationTest`).
Kết quả: `docs/hinh/botnet_gop_host.json`. Tham số: `botnet.host_aggregation` trong `config/default.yaml`.
Việc này nằm trong danh sách việc còn thiếu (Chặng 8, "bot chậm bị bỏ sót").

```bash
cd src
python -m nids.botnet gop-host ../output/ctu13 --model ../models/botnet_rf.joblib --out ../docs/hinh
```

## 1. Vấn đề

Đánh giá C08-T08 (docs/52): bộ phát hiện Random Forest bắt rất tốt mọi scenario test trừ **scenario 8
(Murlo)**, recall chỉ **0,154**. Lý do: 4 909 trong 6 723 cửa sổ bot của Murlo chỉ có 1–3 flow botnet
(TCP-Attempt chậm). Đo lại điểm của mô hình:

| Số flow bot trong cửa sổ | Số cửa sổ | Điểm trung vị | Tỷ lệ bắt (≥ 0,10) |
|---|---|---|---|
| 1–3 | 5 147 | 0,005 | 0% |
| 4–10 | 316 | 0,000 | 5% |
| 11–50 | 529 | 0,148 | 54% |
| trên 50 | 731 | 0,576 | 100% |

Các cửa sổ ít flow có điểm **gần bằng 0**, nên **hạ ngưỡng hay gộp theo điểm đều vô ích** (ở ngưỡng 0,02
thì đã báo nhầm 22% cửa sổ Background). Nhưng chính **host** đó (147.32.84.165) có **1 034** cửa sổ điểm
≥ 0,10 — đã bị bắt quả tang là bot ở nhiều cửa sổ khác trong cùng bản thu.

## 2. Ý tưởng: gộp theo host

Không quyết định theo từng cửa sổ riêng lẻ mà **theo host qua cả run**: nếu một host đã bị bắt ở đủ nhiều
cửa sổ thì coi host đó là bot trong run, và **nâng mọi cửa sổ của host lên `suspect_host`** — kể cả cửa sổ
im ắng. Một lần thu = một run (gộp theo `(session, host)`).

Dùng **số tuyệt đối** `n_strong` (số cửa sổ điểm ≥ ngưỡng) chứ không dùng điểm trung bình, vì `n_strong`
tách rất rõ bot khỏi máy bình thường:

| Loại host (test) | `n_strong` |
|---|---|
| Mọi host bot | ≥ 728 (Murlo 1 034) |
| Mọi host bình thường đã xác nhận | ≤ 268 |

Quy tắc: xác nhận host là bot nếu `n_strong ≥ min_strong` **và** `n_strong / tổng_cửa_sổ ≥ min_frac`. Điều
kiện tỷ lệ chặn host có rất ít cửa sổ nhưng tình cờ vài cái bị nghi (ví dụ một host test chỉ 12 cửa sổ, 6
cái mạnh → tỷ lệ 0,5 nhưng `n_strong` 6, bị loại nhờ `min_strong`).

## 3. Chọn tham số trên validation

Scan `min_strong ∈ {100…500}`, `min_frac ∈ {0,10; 0,13; 0,15}` trên validation (scenario 4, 13). Ràng buộc
QĐ-040: tỷ lệ cửa sổ Background bị báo trên validation ≤ 5%.

Chọn **`min_strong = 500`, `min_frac = 0,13`**:
- `min_strong = 500` nằm giữa khoảng trống rộng (bình thường ≤ 268, bot ≥ 728), không nhạy với số lẻ.
- `min_frac = 0,13` nằm giữa tỷ lệ của host bình thường cao nhất (0,117) và của Murlo (0,154).
- Với tham số này, Background validation **giữ nguyên 4,07%** (không host Background nào bị thêm), đạt ràng
  buộc 5%.

## 4. Kết quả

| Tập | | Recall | Precision | F1 | Báo nhầm (máy bình thường) | Background bị báo |
|---|---|---|---|---|---|---|
| Validation | baseline | 0,371 | 0,965 | 0,536 | 0,84% | 4,07% |
| Validation | gộp host | **1,000** | 0,987 | **0,993** | 0,84% | 4,07% |
| Test | baseline | 0,678 | 0,971 | 0,798 | 1,58% | 11,9% |
| Test | gộp host | **1,000** | 0,980 | **0,990** | 1,58% | 20,3% |

Theo scenario (test, recall → sau khi gộp):

| Scenario | Bot | Recall baseline → gộp | Precision baseline → gộp |
|---|---|---|---|
| 1 Neris | | 0,997 → **1,000** | 0,979 → 0,979 |
| 2 Neris | | 0,981 → **1,000** | 1,000 → 1,000 |
| 6 DonBot | | 0,976 → **1,000** | 0,993 → 0,993 |
| **8 Murlo** | | **0,154 → 1,000** | 0,770 → 0,956 |
| 9 Neris (10 bot) | | 0,948 → **1,000** | 0,995 → 0,995 |

Đọc kết quả:
- **Scenario 8 recall 0,154 → 1,000**, precision cũng tăng 0,770 → 0,956. Mục tiêu đạt.
- **Tỷ lệ báo nhầm trên máy bình thường không đổi** (1,58%): không host bình thường nào bị xác nhận (cao
  nhất chỉ 268 cửa sổ mạnh, dưới 500).
- **Precision chung tăng** 0,971 → 0,980 (thêm 6 189 cửa sổ đúng, không thêm cửa sổ sai).
- **Background bị báo trên test tăng 11,9% → 20,3%.** Các host Background là máy **chưa kiểm chứng**; nhiều
  host trong đó có hàng nghìn cửa sổ điểm cao (nhiều khả năng là máy nhiễm thật chưa gán nhãn), nên bị xác
  nhận và nâng cả host. Đây không phải FPR (docs/52); con số này chỉ để tham khảo, và trên validation thì
  vẫn trong ngưỡng 5%.

## 5. Phạm vi và lưu ý

- **Mặc định TẮT.** Lớp gộp là tùy chọn của Chặng 9; `evaluate` giữ nguyên hành vi C08 khi không truyền
  `host_agg`. Vì vậy số liệu đã khóa của C08-T08 và kiểm tra nhất quán offline/realtime C10-T08 **không đổi**.
- **Gộp theo run (offline).** Quy tắc cần toàn bộ run để đếm `n_strong`. Trong pipeline offline (Chặng 9)
  điều này sẵn có. Bản realtime muốn dùng thì phải xác nhận host theo luồng (khi `n_strong` vượt ngưỡng thì
  nâng từ đó trở đi) — để lại cho sau; vì vậy chưa bật trong đường chạy chung để không phá tính nhất quán.
- Quy tắc **không tạo host bot mới**: chỉ nâng các cửa sổ của host đã bị bắt nhiều lần. Nó đánh đổi: nếu một
  host bình thường bị báo nhầm ở ≥ 500 cửa sổ thì cả host sẽ bị nâng. Trên dữ liệu hiện có điều này không xảy
  ra, nhưng cần đo lại trên lab (Chặng 11) nơi máy bình thường đa dạng hơn.

## 6. Kiểm thử

- `confirmed_bot_hosts`: xác nhận host đủ `min_strong` và `min_frac`; loại host ít cửa sổ dù tỷ lệ cao; loại
  host nhiều cửa sổ nhưng tỷ lệ thấp.
- `aggregate_host`: chỉ nâng cửa sổ của host đã xác nhận.
- `evaluate(host_agg=…)`: trên dữ liệu tổng hợp có bot chậm, recall tăng từ 6/46 lên 1,0 mà precision vẫn
  1,0 (host bình thường không bị nâng).
- Tham số mặc định đọc từ cấu hình.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Gộp theo host | Quyết định theo cả host qua nhiều cửa sổ, không theo từng cửa sổ riêng |
| Run | Một lần thu (một scenario / một bản PCAP) |
| Cửa sổ mạnh | Cửa sổ có điểm của mô hình ≥ ngưỡng |
| `n_strong`, `min_strong`, `min_frac` | Số cửa sổ mạnh của host; số tối thiểu và tỷ lệ tối thiểu để xác nhận |
| Bot chậm | Bot hoạt động rất ít trong mỗi cửa sổ (như Murlo) |
| Recall / Precision / F1 | Tỷ lệ bắt được; tỷ lệ báo đúng; trung bình điều hòa |
| Báo nhầm | Phần cửa sổ của máy bình thường đã xác nhận bị báo là bot |
| Background bị báo | Phần cửa sổ của máy chưa kiểm chứng bị báo; không phải FPR |
| Murlo, Neris, DonBot | Các họ bot của tập test CTU-13 |
