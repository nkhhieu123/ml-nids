# C05-T03 — Nhãn cho cửa sổ chứa nhiều hành vi

Mã nguồn: `label_windows` trong `src/nids/labeling.py` (chạy cùng lệnh gán nhãn flow).
Kiểm thử: `tests/test_labeling.py` (lớp `WindowLabelTest`). Quyết định: QĐ-026 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md). Nhãn flow theo
[26_gan_nhan.md](26_gan_nhan.md).

```bash
python -m nids.labeling output/features/cic17_wednesday.flows.csv   # ghi cả <tên>.windows.labels.csv
```

Một cửa sổ 10 giây của một host thường có **nhiều hành vi cùng lúc**. Web server bị DoS
vẫn phục vụ người dùng bình thường; trong một cửa sổ, máy tấn công có thể vừa kết
thúc một đợt vừa có traffic khác. Task này quy định nhãn của cửa sổ như vậy.

## 1. Quy tắc

Với mỗi cửa sổ `[start, end)` của host H, xét mọi flow có H là một đầu và chồng lên
cửa sổ (`first_ts < end` và `last_ts >= start`). Đếm số flow theo nhãn flow: `dos`,
`port_scan`, `loai`, `mo_ho`, benign. Đặt `attack_share` = (số flow `dos` + `port_scan`) /
(tổng số flow).

Xét theo thứ tự:

| Thứ tự | Điều kiện | `label_status` | `label_attack` | `label_anomaly` |
|---|---|---|---|---|
| 1 | Có flow `loai` (DDoS, Heartbleed, bot) | `loai` | trống | `anomaly` |
| 2 | Có flow tấn công của **một** lớp và `attack_share` ≥ 0,2 | `khop` | lớp đó | `anomaly` |
| 3 | Có flow tấn công nhưng `attack_share` < 0,2 (`rule_id = it_flow_tan_cong`), hoặc có cả `dos` lẫn `port_scan` (`nhieu_lop`) | `mo_ho` | trống | `anomaly` |
| 4 | Không có flow tấn công, có flow `mo_ho` | `mo_ho` | trống | trống |
| 5 | Còn lại | `khong_khop` | `benign` | `normal` |

Ngưỡng 0,2 là `labeling.window_min_attack_share` trong `config/default.yaml`.

**Vì sao cửa sổ lẫn bình thường và tấn công vẫn mang nhãn tấn công.** Mục tiêu của
module là báo khi có tấn công. Cửa sổ của web server lúc bị DoS là cửa sổ cần cảnh báo,
dù trong đó còn traffic của người dùng thật. Phần bình thường chỉ là "nền" của cửa sổ.

**Vì sao vẫn cần ngưỡng.** Cửa sổ chỉ có một vài flow tấn công lẫn trong rất nhiều
flow bình thường (thường ở rìa đợt tấn công) có đặc trưng gần như bình thường. Gán nhãn
tấn công cho chúng thì mô hình học "cửa sổ trông bình thường cũng là tấn công"; gán
benign thì sai sự thật. Vì vậy chúng là `mo_ho`: không dùng cho phân loại, nhưng vẫn là
`anomaly` (có hành vi bất thường thật).

**Vì sao đếm flow, không đếm thời gian.** Lượt quét cổng là flow một gói, thời lượng
0. Nếu tính phần thời gian của cửa sổ có tấn công thì quét cổng gần như bằng 0.

**Tính nhanh.** Với mỗi host và mỗi loại nhãn, sắp `first_ts` và `last_ts` của các flow.
Số flow chồng lên cửa sổ = số flow có `first_ts < end` − số flow có `last_ts < start`
(hai lần tìm nhị phân). Trên 2 061 cửa sổ của đoạn port scan, kết quả trùng với cách
đếm vét cạn từng flow.

## 2. Đầu ra

`<tên>.windows.labels.csv`, khóa (`host`, `window_start`):

| Cột | Ý nghĩa |
|---|---|
| `label_attack`, `label_anomaly`, `label_status`, `rule_id` | Như bảng ở mục 1 |
| `attack_share` | Phần flow tấn công trong cửa sổ (0–1) |
| `n_flows`, `n_attack_flows` | Số flow chồng lên cửa sổ, số flow tấn công |

`attack_share` được giữ lại để Chặng 6–7 có thể thử ngưỡng khác mà không phải gán nhãn
lại.

## 3. Kết quả trên CIC thứ Tư

163 431 cửa sổ (host trong `192.168.10.0/24` và `172.16.0.0/24`):

| `label_status` | Cửa sổ |
|---|---|
| `khong_khop` (benign) | 157 995 |
| `khop` (dos) | 3 978 |
| `loai` (Heartbleed) | 1 238 |
| `mo_ho`: ít flow tấn công | 38 |
| `mo_ho`: chỉ có flow mơ hồ | 182 |

4 016 cửa sổ có flow tấn công, đều là của `192.168.10.50` (nạn nhân, 2 009) và
`172.16.0.1` (bên tấn công, 2 007). Phân bố `attack_share` trong các cửa sổ đó:

| `attack_share` | Cửa sổ |
|---|---|
| = 1 (chỉ có tấn công) | 760 |
| 0,5 – < 1 | 3 056 |
| 0,2 – < 0,5 | 162 |
| < 0,2 (thành `mo_ho`) | 38 |

**Cửa sổ chứa nhiều hành vi là chuyện thường**: 3 256 / 4 016 cửa sổ tấn công (81%) lẫn
flow bình thường. Số cửa sổ `khop` ít nhạy với ngưỡng:

| Ngưỡng | 0 (bất kỳ) | 0,1 | 0,2 | 0,5 | 0,9 |
|---|---|---|---|---|---|
| Cửa sổ `khop` | 4 016 | 4 006 | 3 978 | 3 816 | 3 419 |

1 238 cửa sổ `loai` là của `172.16.0.1` và `192.168.10.51` trong 20 phút Heartbleed:
mỗi flow Heartbleed dài nhiều phút nên chồng lên nhiều cửa sổ.

Số liệu thứ Sáu và thứ Hai ở [27_bao_cao_nhan.md](27_bao_cao_nhan.md).

## 4. Kiểm thử

Kiểm thử tự động (8 ca): cửa sổ toàn tấn công; lẫn bình thường trên ngưỡng; ít flow tấn
công thành `mo_ho` nhưng vẫn `anomaly`, và đổi khi hạ ngưỡng; hai lớp cùng lúc; tấn công
bị loại thắng; chỉ có flow mơ hồ; biên chồng lấn (flow kết thúc đúng lúc cửa sổ bắt đầu
vẫn tính, bắt đầu đúng lúc kết thúc thì không); cửa sổ bình thường và số đếm.

## 5. Giới hạn

- Đếm flow chứ không đếm gói: một flow Hulk nhiều gói và một flow DNS một gói có trọng số
  như nhau.
- Cửa sổ `khop` không ghi đợt nào (`rule_id` trống); đợt có thể suy ra từ thời gian.
- Ở CIC, `172.16.0.1` là NAT: mọi máy tấn công hiện chung một host.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Cửa sổ host | 10 giây hoạt động của một máy; một mẫu của bảng cửa sổ |
| Cửa sổ chứa nhiều hành vi | Cửa sổ có cả flow tấn công và flow bình thường |
| `attack_share` | Phần số flow tấn công trong số flow của cửa sổ |
| Chồng lên cửa sổ | Flow có thời gian giao với khoảng của cửa sổ |
| Tìm nhị phân | Cách tìm vị trí trong danh sách đã sắp xếp bằng cách chia đôi liên tục, rất nhanh |
| Rìa đợt tấn công | Lúc đợt tấn công vừa bắt đầu hoặc sắp kết thúc |
| Ngưỡng | Giá trị phân chia: trên ngưỡng gán nhãn tấn công, dưới ngưỡng coi là mơ hồ |
