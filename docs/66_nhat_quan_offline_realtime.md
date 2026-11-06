# C10-T08 — Kiểm tra tính nhất quán offline/realtime

Mã nguồn: `src/nids/nhat_quan.py`; sửa trong `src/nids/realtime.py` (`graph_delay_s`, cửa sổ 120 giây
đầu tiên, `window_sink`). Kiểm thử: `tests/test_realtime.py`. Kết quả: `docs/hinh/nhat_quan.json`.

```bash
cd src
python -m nids.nhat_quan ../output/pcap/fri_binh_thuong.pcap ../output/pcap/fri_quet.pcap \
    ../output/pcap/wed_slowloris.pcap ../output/pcap/wed_hulk.pcap \
    --net 192.168.10.0/24 --net 172.16.0.0/24 --bang ../output/nhat_quan --out ../docs/hinh/nhat_quan.json
```

## 1. Cách kiểm tra

Cùng PCAP, cùng mô hình (`n_jobs = 1` cho cả hai bên), cùng chế độ (`ket_hop`):
- **offline**: `nids.pipeline.run_pcap` (Chặng 9), đọc hết file rồi chấm;
- **realtime**: `RealtimeEngine` của C10-T03, nhận từng gói, chấm khi cửa sổ đóng. Phát lại nhanh nhất có
  thể, một luồng, để kết quả xác định (không phụ thuộc thời gian thật).

So theo khóa (host, `window_start`):

| So sánh | Đo |
|---|---|
| Cửa sổ 10 giây | Cùng tập khóa? Lệch lớn nhất của mỗi đặc trưng (ô trống ở cả hai bên coi như bằng) |
| Anomaly, phân loại | Nhãn khớp; điểm lệch (d², xác suất lớp được chọn) |
| Botnet, topology | Cùng tập host–cửa sổ 120 giây được chấm? Nhãn khớp; điểm lệch |
| Cảnh báo, sự kiện | Số theo module và nhãn; số sự kiện |

## 2. Hai chỗ lệch tìm ra và đã sửa

Lần chạy đầu trên `wed_slowloris`: cửa sổ 10 giây, anomaly, phân loại khớp tuyệt đối. Nhưng offline chấm
botnet **41** host–cửa sổ 120 giây, realtime chỉ **30**.

1. **Cửa sổ 120 giây bắt đầu trước gói đầu tiên.** Offline chấm mọi cửa sổ 120 giây có flow, kể cả cửa sổ
   bắt đầu trước gói đầu tiên (chỉ có một phần dữ liệu). Realtime bắt đầu từ cửa sổ 10 giây đầu tiên nên bỏ
   qua chúng. Kiểm tra trực tiếp: hàm chấm của realtime không bao giờ được gọi cho các cửa sổ đó. Đã sửa:
   cửa sổ 120 giây đầu tiên của realtime là cửa sổ sớm nhất chứa gói đầu tiên.
2. **Bất thường chồng lên phần cuối cửa sổ 120 giây.** Realtime chấm cửa sổ `[ws, we)` lúc `we + 3 giây`,
   nhưng cửa sổ 10 giây chồng lên phần cuối (ví dụ `[we − 8, we + 2)`) chỉ đóng lúc `kết thúc + 3 giây`.
   Lúc đó realtime chưa biết các cửa sổ này là bất thường chưa giải thích (chế độ `ket_hop` cần biết để
   quyết định kiểm tra botnet). Đã sửa: chờ thêm `realtime.graph_delay_s` = một cửa sổ 10 giây. Cảnh báo
   botnet đến muộn thêm 10 giây (QĐ-056).

Sau hai sửa: 41/41 host–cửa sổ, cảnh báo giống hệt, 11/11 sự kiện.

## 3. Kết quả trên bốn đoạn PCAP

| Đoạn | Cửa sổ 10 s (chung / tổng) | Đặc trưng lệch tối đa | Anomaly, phân loại: nhãn khác / điểm lệch | Botnet: host–cửa sổ (chung / tổng) | Nhãn botnet khác | Điểm botnet lệch tối đa | Sự kiện offline / realtime |
|---|---|---|---|---|---|---|---|
| `fri_binh_thuong` | 4 633 / 4 633 | 0 | 0 / 0 | 633 / 633 | 1 (0,16%) | 0,036 | 85 / 89 |
| `fri_quet` | 7 464 / 7 464 | 0 | 0 / 0 | 785 / 785 | 2 (0,25%) | 0,055 | 104 / 111 |
| `wed_slowloris` | 1 964 / 1 964 | 0 | 0 / 0 | 41 / 41 | 0 | 0,006 | 11 / 11 |
| `wed_hulk` | 1 406 / 1 406 | 0 | 0 / 0 | 99 / 99 | 3 (3,0%) | 0,023 | 20 / 22 |

- **Cửa sổ 10 giây, anomaly, phân loại khớp tuyệt đối** trên 15 467 cửa sổ: cùng bộ trích xuất, cùng tham
  số, đúng yêu cầu B12. Mọi cảnh báo `anomaly`, `port_scan`, `dos` giống hệt.
- **Botnet**: cùng tập host–cửa sổ được chấm; 6 trên 1 558 nhãn khác. Mọi chỗ khác là điểm sát ngưỡng 0,10.
  Nguyên nhân là chỗ khác **có chủ ý** của realtime: ở thời điểm chấm, flow dài chưa kết thúc chỉ có số đếm
  tới lúc đó (ảnh chụp), còn offline thấy flow trọn vẹn. Muốn khớp tuyệt đối thì phải chờ flow kết thúc
  (timeout tới 120 giây), làm cảnh báo botnet chậm thêm tới 2 phút. Chọn chấp nhận lệch nhỏ (QĐ-056).
- **Sự kiện** lệch 0–7 mỗi đoạn: vài cảnh báo botnet thiếu hoặc thừa làm một sự kiện bị tách đôi hoặc gộp
  khác.

## 4. Kiểm thử

- PCAP tổng hợp với mô hình giả: offline và realtime cho cùng cửa sổ (lệch đặc trưng 0), cùng dự đoán ba
  module, cùng cảnh báo, cùng số sự kiện.
- Hàm so sánh: đếm đúng khóa chung, chỉ có ở một bên, lệch đặc trưng (ô trống ở cả hai bên coi như bằng),
  nhãn khác.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Nhất quán offline/realtime | Cùng dữ liệu thì chế độ đọc file và chế độ chạy trực tiếp cho cùng kết quả |
| Khóa | Cặp (host, thời điểm đầu cửa sổ) dùng để ghép hai bảng |
| Ảnh chụp flow | Số đếm của flow chưa kết thúc tại thời điểm chấm |
| Xác định (deterministic) | Chạy lại bao nhiêu lần cũng cho đúng một kết quả |
| `graph_delay_s` | Thời gian chờ thêm trước khi chấm cửa sổ 120 giây |
