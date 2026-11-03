# C09-T06 — Ghi cảnh báo, điểm mô hình và gộp sự kiện lặp

Mã nguồn: `write_outputs`, `merge_events`, `write_events`, `format_event` trong `src/nids/pipeline.py`.
Cấu hình: `pipeline.merge_gap_s`. Kiểm thử: `tests/test_pipeline.py`.

```bash
cd src
python -m nids.pipeline chay ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 \
    --out ../output/pipeline [--ma-lan-chay <mã>] [--in-su-kien]
```

## 1. Các file ra (mỗi lần chạy)

| File | Nội dung | Dùng để |
|---|---|---|
| `<tên>.alerts.csv` | Cảnh báo của ba module, hợp nhất, theo schema chung (C09-T03) | Đọc, đối chiếu nhật ký kịch bản |
| `<tên>.diem.csv` | **Mọi** dự đoán, kể cả `normal`, `benign`, `normal_host`, kèm điểm và ngưỡng, cùng schema | Tính báo nhầm, vẽ đường theo ngưỡng, chỉnh ngưỡng sau này |
| `<tên>.su_kien.csv` | Cảnh báo lặp gộp thành sự kiện | Đọc nhanh; tính độ trễ phát hiện (Chặng 11) |
| `<tên>.anomaly.csv`, `.attack_classification.csv`, `.botnet_topology.csv` | Bảng dự đoán gốc của từng module (d², xác suất từng lớp, điểm bot, topology) | Phân tích chi tiết |
| `<tên>.pipeline.json` | Chế độ, thời gian từng bước, số flow, cửa sổ, host, cảnh báo, sự kiện, tổng hợp theo host | Báo cáo |

File điểm dùng cơ chế `log_all` có sẵn của `AlertSink` (C01-T04). Định dạng giống file cảnh báo, chỉ
thêm các dòng dự đoán bình thường.

## 2. Gộp sự kiện lặp (QĐ-048)

Cửa sổ trượt (10 giây bước 2 giây; 120 giây bước 10 giây) làm một hành vi dài sinh rất nhiều dòng giống
nhau. Gộp như sau:
- **Khóa**: cùng module, cùng nhãn, cùng host.
- **Nối**: cảnh báo sau bắt đầu không quá `merge_gap_s` = 30 giây sau khi cảnh báo trước kết thúc.
  Cửa sổ chồng nhau thì luôn nối.
- **Sự kiện** ghi: giờ đầu và giờ cuối, thời lượng, số cảnh báo, điểm lớn nhất, điểm trung bình,
  ngưỡng, `run_id`, thời điểm tạo của cảnh báo đầu tiên (để tính độ trễ).
- Chỉ gộp cảnh báo thật. Nhóm topology của module botnet (không có điểm) gộp riêng, đếm số dòng.
- Không gộp **giữa** các module: cảnh báo port_scan và anomaly của cùng host vẫn là hai sự kiện; tổng
  hợp chéo module theo host đã có ở C09-T03.

`--in-su-kien` in mỗi sự kiện một dòng ra terminal:

```
2017-07-07T18:08:22.000Z → 2017-07-07T18:10:30.000Z | [attack_classification] PORT_SCAN | 172.16.0.1 | 53 cảnh báo | điểm lớn nhất 0.9158
```

Trên `fri_quet`, 108 cảnh báo `port_scan` của 172.16.0.1 thành **3 sự kiện**:
- 18:08:22–18:10:30 (53 cảnh báo);
- 18:12:30 (1 cảnh báo);
- 18:21:54–18:24:02 (54 cảnh báo).

Mỗi sự kiện ứng với một lượt Nmap; giữa các lượt máy nghỉ vài phút.

## 3. Kết quả (chế độ mặc định `ket_hop`)

| Đoạn | Cảnh báo | Sự kiện | anomaly / phân loại / botnet | Dòng trong file điểm |
|---|---|---|---|---|
| `fri_binh_thuong` | 505 | **85** | 61 / 18 / 6 | mọi dự đoán của ba module |
| `fri_quet` | 1 189 | **104** | 74 / 14 / 16 | |
| `wed_slowloris` | 656 | **11** | 5 / 2 / 4 | |
| `wed_hulk` | 378 | **20** | 10 / 2 / 8 | |

Số sự kiện theo khoảng gộp:

| Đoạn | 0 s | 10 s | **30 s** | 60 s | 120 s |
|---|---|---|---|---|---|
| `fri_binh_thuong` | 115 | 89 | 85 | 62 | 29 |
| `fri_quet` | 137 | 111 | 104 | 80 | 42 |
| `wed_slowloris` | 11 | 11 | 11 | 11 | 11 |
| `wed_hulk` | 20 | 20 | 20 | 20 | 18 |

- DoS là hành vi liên tục: một đợt thành một vài sự kiện bất kể khoảng gộp (656 cảnh báo còn 11).
- Ở đoạn có bot ARES, cảnh báo đứt quãng; số sự kiện giảm dần khi tăng khoảng gộp. 30 giây (bằng 3 cửa
  sổ 10 giây) gộp được phần lớn đứt quãng ngắn mà chưa nối hai lần gọi về cách nhau vài phút thành một.
  Giá trị này chỉnh được trên dữ liệu lab.

## 4. Kiểm thử

- Cảnh báo chồng nhau và cách nhau trong khoảng gộp thành một sự kiện; điểm lớn nhất và trung bình đúng.
  Cách xa thì tách; host khác thì tách; dự đoán bình thường bị bỏ; gap 0 và gap lớn cho số sự kiện đúng.
- Sự kiện topology (không điểm) đếm đúng số dòng.
- `write_outputs` ghi đủ năm loại file. File điểm có cả dự đoán bình thường; file sự kiện đúng cột.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Sự kiện | Nhiều cảnh báo liên tiếp của cùng module, nhãn, host gộp lại |
| Khoảng gộp | Khoảng nghỉ lớn nhất giữa hai cảnh báo để vẫn tính là một sự kiện |
| File điểm | File ghi mọi dự đoán kèm điểm, kể cả bình thường |
| `log_all` | Chế độ ghi cả dự đoán bình thường của `AlertSink` |
| Độ trễ phát hiện | Thời gian từ lúc hành vi bắt đầu tới cảnh báo đầu tiên (B21) |
