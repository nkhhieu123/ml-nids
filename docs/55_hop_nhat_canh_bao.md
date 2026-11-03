# C09-T03 — Đầu ra độc lập của từng module và hợp nhất cảnh báo

Mã nguồn: `module_alerts`, `merge_alerts`, `host_overview`, `write_alerts`, `run_alerts` trong
`src/nids/pipeline.py`; schema cảnh báo trong `src/nids/alerts.py` (C01-T04). Kiểm thử:
`tests/test_pipeline.py`. Kết quả: `output/pipeline/<tên>.alerts.csv`, mục `theo_host` trong
`<tên>.pipeline.json`.

```bash
cd src
python -m nids.pipeline chay ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 \
    --out ../output/pipeline [--ma-lan-chay <mã trong nhật ký kịch bản>]
```

## 1. Đầu ra độc lập

Ba module chạy trên cùng dữ liệu, **không module nào là cổng lọc của module khác** (docs/02 mục 1).
Mỗi module đổi bảng dự đoán của mình thành cảnh báo theo **schema chung** (`nids.alerts.Alert`):

| Module | Dòng cảnh báo | `score` | `threshold` | `detail` |
|---|---|---|---|---|
| `anomaly` | `anomaly` cho cửa sổ 10 giây có d² > ngưỡng | d² | 64,65 | |
| `attack_classification` | `port_scan` hoặc `dos` | Xác suất của lớp được chọn | | Xác suất cả 3 lớp |
| `botnet_topology` (host) | `suspect_host` cho host–cửa sổ 120 giây có điểm ≥ ngưỡng | Xác suất bot | 0,10 | "mức nghi vấn, không khẳng định có mã độc" (B25) |
| `botnet_topology` (topology) | `centralized` hoặc `p2p` cho cùng host–cửa sổ bị nghi | | | "topology theo quy tắc" |

- Nhóm host và nhóm topology của module botnet là **hai dòng riêng**, không gộp (docs/02 mục 2).
- `src_ip` là host của cửa sổ.
- `run_id` lấy từ `--ma-lan-chay` để khớp với nhật ký kịch bản lab (B10); mặc định là tên đoạn PCAP.
- Nhãn sai tập của module bị `Alert` từ chối ngay.

## 2. Hợp nhất

- **Một file** `<tên>.alerts.csv`, sắp theo thời gian đầu cửa sổ, rồi host, rồi module. Ghi qua
  `AlertSink` của C01-T04 nên cùng định dạng terminal và CSV.
- Mặc định chỉ ghi cảnh báo. `log_all` ghi cả dự đoán bình thường, cần cho tính báo nhầm (C09-T06).
- **Tổng hợp theo host**: với mỗi host, module nào báo, nhãn gì, bao nhiêu cửa sổ, lần đầu và lần cuối,
  số module cùng báo. Host có **≥ 2 module cùng báo** được liệt kê riêng (QĐ-045): đây là các host đáng
  xem trước.

Hợp nhất **không bỏ** cảnh báo nào và **không** cộng điểm của các module, vì ba điểm khác thang đo
(d², xác suất 3 lớp, xác suất bot).

## 3. Kết quả trên bốn đoạn PCAP (chế độ độc lập)

| Đoạn | Cảnh báo | anomaly | port_scan | dos | suspect_host | centralized / p2p | Host có báo | Host ≥ 2 module |
|---|---|---|---|---|---|---|---|---|
| `fri_binh_thuong` | 761 | 421 | 34 | 0 | 153 | 148 / 5 | 11 | 6 |
| `fri_quet` | 1 623 | 814 | 220 | 5 | 292 | 292 / 0 | 14 | 12 |
| `wed_slowloris` | 970 | 319 | 0 | 311 | 170 | 168 / 2 | 11 | 5 |
| `wed_hulk` | 566 | 179 | 0 | 155 | 116 | 115 / 1 | 11 | 7 |

Trên `fri_quet`, tổng hợp theo host:
- **172.16.0.1** (bên quét, sau NAT): anomaly 149, `port_scan` 108, `suspect_host` 78 cửa sổ, cả ba
  module cùng báo.
- **192.168.10.50** (nạn nhân): anomaly 107, `port_scan` 105, `dos` 5, `suspect_host` 67.
- **Máy bot ARES** (.5, .8, .9, .14, .15): Gaussian báo nhiều (70–158 cửa sổ), module botnet báo
  10–25 cửa sổ, bộ phân loại gần như không báo. Đúng vai trò: bot không phải quét hay DoS.

Số cảnh báo lớn vì mỗi cửa sổ trượt 2 giây (10 giây) hoặc 10 giây (120 giây) là một dòng: một hành vi
kéo dài 1 phút sinh khoảng 30 dòng anomaly. C09-T06 gộp các dòng lặp thành sự kiện.

Module botnet báo cả trên đoạn bình thường (153 cửa sổ). Một phần là bot ARES thật (cả ngày), phần còn
lại là báo nhầm do mô hình học từ CTU-13 (docs/52). C09-T05 đo theo nhãn.

## 4. Kiểm thử

- Mỗi module thành đúng nhãn, `score`, `threshold`, `detail`; module botnet có thêm dòng topology cho
  cửa sổ bị nghi.
- Hợp nhất sắp theo thời gian; `log_all` giữ cả dự đoán bình thường.
- Tổng hợp theo host đếm đúng số module, lần đầu và lần cuối.
- Ghi CSV ghi đè file cũ, đọc lại đúng số dòng và định dạng thời gian ISO.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Đầu ra độc lập | Mỗi module tự quyết định trên toàn bộ dữ liệu, không phụ thuộc module khác |
| Hợp nhất cảnh báo | Gom cảnh báo của mọi module vào một danh sách chung, cùng định dạng |
| Schema cảnh báo | Danh sách cột cố định của một cảnh báo (docs/02 mục 3) |
| `run_id` | Mã lần chạy, khớp với nhật ký kịch bản để gán nhãn và tính độ trễ |
| Cổng lọc | Module chặn trước, chỉ cho phần dữ liệu đã qua nó đi tiếp |
| NAT | Thiết bị đổi địa chỉ IP; ở CIC mọi máy tấn công hiện ra là 172.16.0.1 |
