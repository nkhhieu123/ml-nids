# C08-T03 — Đặc trưng beaconing với số quan sát tối thiểu

Mã nguồn: `pair_regularity`, `beacon_features`, `beacon_config` trong `src/nids/graph_features.py`.
Cấu hình: `botnet.beaconing` trong `config/default.yaml`. Kiểm thử: `tests/test_botnet.py`. Kết
quả: `docs/hinh/botnet_beaconing.json`.

```bash
cd src
python -m nids.graph_features dac-trung ../output/ctu13 --scenario 1 --scenario 2 ... --out ../output/ctu13
```

## 1. Định nghĩa

**Beaconing** là khi một máy gọi tới cùng một đích theo chu kỳ đều, như bot hỏi máy điều khiển xem
có lệnh mới không.

- **Cặp**: (host, peer, cổng đích, giao thức), chỉ xét flow **host khởi tạo**.
- **Quan sát**: thời điểm bắt đầu các flow của cặp trong `lookback_s` = 600 giây tính ngược từ cuối
  cửa sổ 120 giây.
- **Số quan sát tối thiểu**: `min_observations` = 5 (4 khoảng cách). Cặp ít quan sát hơn thì
  **không tính**: không thể nói về độ đều từ 2–3 lần gọi.
- **Độ đều**: CV = độ lệch chuẩn / trung bình của các khoảng cách. CV = 0 là đều tuyệt đối.
- **Cặp đều**: CV ≤ `max_cv` = 0,3 (chấp nhận lệch khoảng ±30%, cho beaconing có jitter, B17) và
  khoảng cách trung bình ≥ `min_period_s` = 1 giây (nhanh hơn là dồn dập kiểu tấn công, không phải
  gọi về định kỳ).

Năm đặc trưng mỗi host–cửa sổ:

| Đặc trưng | Ý nghĩa | Khi chưa đủ quan sát |
|---|---|---|
| `beacon_so_cap_du_quan_sat` | Số cặp có ≥ 5 quan sát | 0 |
| `beacon_so_cap_deu` | Số cặp đều | 0 |
| `beacon_cv_nho_nhat` | CV nhỏ nhất trong các cặp đủ quan sát (khoảng cách ≥ 1 giây) | **Trống** |
| `beacon_chu_ky` | Chu kỳ (khoảng cách trung bình) của cặp có CV nhỏ nhất | **Trống** |
| `beacon_so_quan_sat_lon_nhat` | Số quan sát lớn nhất của một cặp | 0 |

**Vì sao nhìn ngược 600 giây** thay vì chỉ 120 giây của cửa sổ (QĐ-038): với 5 quan sát trong 120
giây chỉ thấy được chu kỳ ≤ 30 giây. Bot thật thường gọi về mỗi vài chục giây tới vài phút. 600 giây
đủ cho chu kỳ tới 150 giây. Đổi lại, cảnh báo dựa trên beaconing chỉ có sau ít nhất 5 lần gọi (độ trễ
được tính ở Chặng 11, B21).

**Cách tính nhanh**: với mỗi cặp, sắp xếp thời điểm và tính tổng tích lũy của khoảng cách và bình
phương khoảng cách. Khi đó trung bình và CV trong bất kỳ khoảng nhìn ngược nào chỉ cần hai phép tra
(`searchsorted`). Chỉ xét các cửa sổ mà cặp có hoạt động. 11 scenario (khoảng 250 000 host–cửa sổ)
tính trong dưới 2 phút.

## 2. Kết quả trên CTU-13 (11 scenario đã có; scenario 3 và 8 thêm ở C08-T04)

Theo nhãn host–cửa sổ của C08-T04:

| | Bot (`suspect_host`) | Máy bình thường (`normal_host`) | Background mẫu |
|---|---|---|---|
| Số host–cửa sổ | 23 303 | 28 978 | 170 634 |
| Có ít nhất một cặp đủ quan sát | 85,4% | 92,9% | 56,2% |
| **Có ít nhất một cặp đều** | **58,7%** | **57,8%** | 9,1% |
| CV nhỏ nhất (trung vị) | 0,050 | 0,016 | 1,526 |
| Chu kỳ của cặp đều nhất (trung vị) | 47 giây | 31 giây | 36 giây |

Theo từng scenario, tỷ lệ cửa sổ bot có cặp đều dao động rất mạnh: 83% (scenario 9, Neris), 78% (13,
Virut), 66% (5), 55% (1) nhưng 0% ở scenario 7, 10, 11, 12. Máy bình thường thì ổn định trong khoảng
40–86%.

**Kênh điều khiển (flow `CC`)**, xét trên cả scenario: 77 cặp CC có ≥ 5 flow. CV trung vị **0,92**, chỉ
**13%** có CV ≤ 0,3, chu kỳ trung vị 38 giây.

## 3. Đọc kết quả

1. **Beaconing không tách được bot khỏi máy bình thường đã xác nhận trên CTU-13.** Máy bình thường
   cũng gọi đều (cập nhật, kiểm tra thư, đồng bộ), còn các flow CC của bot CTU-13 không đều. Đúng như
   docs/07 mục 6: hành vi nổi bật của bot CTU-13 là spam, quét, DDoS, không phải gọi về định kỳ.
2. Beaconing **tách được** bot và máy bình thường khỏi phần lớn host Background (9% có cặp đều): các
   host Background lấy mẫu thường ít hoạt động. Background không vào train (C08-T04), nên điều này
   không giúp mô hình.
3. Vì vậy beaconing **giữ làm đặc trưng nhưng không đủ một mình**. Mô hình ở C08-T05 kết hợp với đặc
   trưng đồ thị. Beaconing được kiểm tra trên dữ liệu lab và dữ liệu giả lập (C08-T06), nơi bot gọi về
   theo chu kỳ biết trước (B17).

## 4. Hạn chế

- Flow dài (một kết nối IRC giữ hàng giờ) chỉ là **một** quan sát: kênh điều khiển dạng kết nối
  thường trực không tạo beaconing ở mức flow.
- Chu kỳ dài hơn khoảng 150 giây cần nhìn ngược lâu hơn 600 giây.
- Cặp tính theo (peer, cổng). Bot đổi máy điều khiển hoặc đổi cổng mỗi lần gọi sẽ không thành cặp.

## 5. Kiểm thử

- `pair_regularity`: đếm đúng số quan sát trong khoảng nhìn ngược; CV = 0 khi đều tuyệt đối; CV bằng
  `std/mean` của numpy khi có jitter; chưa đủ quan sát thì trống.
- `beacon_features`: cặp đều được đếm; cặp dồn dập (0,1 giây) đủ quan sát nhưng không là beacon; cặp
  2 quan sát không tính; cùng peer khác cổng là cặp khác; đổi `min_observations` thì kết quả đổi theo.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Beaconing | Máy gọi tới cùng một đích theo chu kỳ đều |
| Cặp | Một host, một peer, một cổng đích, một giao thức |
| Quan sát | Một lần bắt đầu flow của cặp |
| CV (hệ số biến thiên) | Độ lệch chuẩn chia trung bình của khoảng cách giữa các lần gọi; nhỏ là đều |
| Jitter | Độ lệch ngẫu nhiên quanh chu kỳ |
| Chu kỳ | Khoảng cách trung bình giữa hai lần gọi |
| Nhìn ngược (lookback) | Khoảng thời gian tính ngược từ cuối cửa sổ để lấy quan sát |
| Kênh điều khiển (CC) | Đường bot nhận lệnh từ máy điều khiển |
| Tổng tích lũy | Dãy tổng dồn, cho phép tính tổng một đoạn bất kỳ bằng một phép trừ |
