# C09-T05 — So sánh chế độ độc lập và tuần tự: bỏ sót và thời gian xử lý

Mã nguồn: `compare_modes`, `label_tables`, `coverage`, `miss_report` trong `src/nids/pipeline.py`.
Kiểm thử: `tests/test_pipeline.py`. Kết quả: `docs/hinh/pipeline_so_sanh.json`.

```bash
cd src
python -m nids.pipeline so-sanh ../output/pcap/fri_binh_thuong.pcap ../output/pcap/fri_quet.pcap \
    ../output/pcap/wed_slowloris.pcap ../output/pcap/wed_hulk.pcap \
    --net 192.168.10.0/24 --net 172.16.0.0/24 --bang ../output/pipeline_so_sanh --out ../docs/hinh/pipeline_so_sanh.json
```

## 1. Cách so sánh

- **Dữ liệu**: bốn đoạn PCAP nằm trọn trong khoảng test của Chặng 5 (docs/54 mục 2). Mỗi đoạn trích
  xuất một lần; ba chế độ chạy trên **cùng** bảng đặc trưng.
- **Nhãn**: gán bằng đúng mã của Chặng 5 (lịch tấn công, `nids.labeling`). Cửa sổ 10 giây có nhãn
  `anomaly` được xếp vào đợt tấn công (Bot, PortScan, DoS slowloris, DoS Hulk).
- **Một cửa sổ tấn công "bị bắt"** nếu có ít nhất một cảnh báo chạm tới nó:
  - anomaly hoặc phân loại báo đúng cửa sổ 10 giây đó;
  - hoặc module botnet báo `suspect_host` cho cùng host ở một cửa sổ 120 giây chồng lên.

  Ngược lại là **bỏ sót**.
- **Gọi đúng tên**: cửa sổ quét được báo `port_scan`, cửa sổ DoS được báo `dos`, cửa sổ bot được báo
  `suspect_host`.
- **Báo nhầm**: phần cửa sổ bình thường bị ít nhất một module báo.
- **Thời gian**: thời gian mô hình (không gồm trích xuất), trung vị của 3 lần chạy. Thời gian trích xuất
  ghi riêng.

Ba chế độ:

| Chế độ | Gaussian | Phân loại | Kiểm tra botnet |
|---|---|---|---|
| `doc_lap` (C09-T03) | Mọi cửa sổ | Mọi cửa sổ | Mọi host giám sát |
| `tuan_tu` (C09-T04) | Mọi cửa sổ | Chỉ cửa sổ Gaussian báo | Chỉ host có bất thường mà phân loại cho là benign |
| `ket_hop` (thêm ở bước này) | Mọi cửa sổ | **Mọi cửa sổ** | Chỉ host có bất thường chưa giải thích |

`ket_hop` được thêm sau khi xem kết quả hai chế độ đầu trên các đoạn này (mục 3). Nó chỉ đổi cách nối
các module, không chỉnh tham số mô hình nào.

## 2. Kết quả

### Bỏ sót (tỷ lệ cửa sổ tấn công không bị cảnh báo nào chạm tới)

| Đoạn | Đợt | Số cửa sổ | `doc_lap` | `tuan_tu` | `ket_hop` |
|---|---|---|---|---|---|
| `fri_binh_thuong` | Bot | 451 | 4,9% | 8,9% | 4,9% |
| `fri_quet` | Bot | 490 | 6,5% | 7,3% | 6,5% |
| `fri_quet` | PortScan | 472 | **0%** | 34,8% | 34,1% |
| `wed_slowloris` | DoS slowloris | 328 | **0%** | 8,5% | 5,2% |
| `wed_hulk` | DoS Hulk | 194 | **0%** | 28,4% | 20,1% |

### Gọi đúng tên

| Đợt | `doc_lap` | `tuan_tu` | `ket_hop` |
|---|---|---|---|
| PortScan → `port_scan` | 46,0% | 44,3% | 45,1% |
| DoS slowloris → `dos` | 94,8% | 91,5% | 94,8% |
| DoS Hulk → `dos` | 79,9% | 71,6% | 79,9% |
| Bot → `suspect_host` (`fri_quet` / `fri_binh_thuong`) | 19,4% / 4,7% | 19,4% / 4,7% | 19,4% / 4,7% |

### Báo nhầm (cửa sổ bình thường bị ít nhất một module báo)

| Đoạn | Số cửa sổ | `doc_lap` | `tuan_tu` | `ket_hop` | Riêng anomaly / phân loại / botnet (`doc_lap`) |
|---|---|---|---|---|---|
| `fri_binh_thuong` | 4 182 | 22,9% | **4,5%** | **4,5%** | 0,3% / 0% / 22,7% |
| `fri_quet` | 6 502 | 17,5% | 7,3% | 7,3% | 1,7% / 0% / 16,1% |
| `wed_slowloris` | 1 636 | 34,8% | 3,7% | 3,7% | 1,2% / 0% / 34,4% |
| `wed_hulk` | 1 212 | 39,5% | 19,1% | 19,1% | 3,3% / 0% / 38,1% |

### Thời gian (giây, máy phát triển)

| Đoạn | Trích xuất | Mô hình `doc_lap` | `tuan_tu` | `ket_hop` | Trong đó botnet (`doc_lap` → `ket_hop`) |
|---|---|---|---|---|---|
| `fri_binh_thuong` | 3,4 | 0,31 | 0,22 | 0,27 | 0,21 → 0,20 |
| `fri_quet` | 15,4 | 0,95 | 0,75 | 0,82 | 0,87 → 0,71 |
| `wed_slowloris` | 3,0 | 0,25 | 0,16 | 0,19 | 0,19 → 0,12 |
| `wed_hulk` | 24,6 | 0,30 | 0,19 | 0,19 | 0,23 → 0,13 |

## 3. Đọc kết quả

1. **Báo nhầm gần như hoàn toàn đến từ module botnet ở chế độ độc lập** (16–38% cửa sổ bình thường).
   Có hai lý do:
   - một cảnh báo 120 giây phủ lên 12 cửa sổ 10 giây;
   - mô hình học từ CTU-13 không hợp với mạng CIC (docs/52).

   Gaussian báo nhầm 0,3–3,3%, bộ phân loại 0%.
2. **Bỏ sót 0% của chế độ độc lập một phần là nhờ module botnet** phủ cảnh báo lên máy quét và máy bị
   quét, chứ không phải phát hiện đúng loại. Thước đo "gọi đúng tên" cho thấy rõ hơn: bộ phân loại chỉ
   gọi đúng 46% cửa sổ quét ở cả ba chế độ. Phần cửa sổ quét ít hoạt động (docs/43 mục 3) vẫn là điểm
   yếu.
3. **Chế độ tuần tự làm mất cảnh báo tấn công**: cửa sổ mà bộ phân loại bắt được nhưng Gaussian cho là
   bình thường bị bỏ qua. Ví dụ, Hulk gọi đúng tên giảm từ 79,9% xuống 71,6%.
4. **`ket_hop` giữ được mọi cảnh báo của bộ phân loại**: gọi đúng tên bằng `doc_lap`, bỏ sót bot bằng
   `doc_lap`. Đồng thời nó cắt báo nhầm của module botnet về mức của `tuan_tu`. Cái giá là mất phần
   "phủ ngẫu nhiên" của module botnet lên cửa sổ tấn công.
5. **Thời gian offline gần như không đổi**: trích xuất chiếm 90–99%. Cắt bớt module botnet tiết kiệm
   0,1–0,2 giây mỗi đoạn. Khác biệt thời gian chỉ đáng kể khi có nhiều host hơn (dựng đồ thị tăng theo số
   host) và ở realtime (Chặng 10).

**Quyết định (QĐ-047)**: chế độ mặc định đổi thành **`ket_hop`**.
- Bộ phân loại không bao giờ bị Gaussian chặn, vẫn đúng tinh thần docs/02 mục 1.
- Chỉ module botnet chạy sau Gaussian, vì đây là module đắt nhất và báo nhầm nhiều nhất khi chạy riêng.

`doc_lap` và `tuan_tu` vẫn chọn được bằng `--che-do`.

## 4. Hạn chế

- Bốn đoạn ngắn (3–21 phút) và một mạng (CIC). Phải đo lại trên lab.
- Nhãn cửa sổ theo lịch tấn công gồm cả cửa sổ gần như không có hoạt động tấn công (docs/43), nên tỷ lệ
  bỏ sót có phần không tránh được ở mọi chế độ.
- Module botnet học từ CTU-13 nên con số botnet trên CIC chỉ có giá trị so sánh giữa các chế độ.

## 5. Kiểm thử

- Phủ cảnh báo:
  - anomaly và phân loại tính theo đúng cửa sổ 10 giây;
  - botnet tính theo cửa sổ 120 giây chồng lên;
  - cửa sổ không bị gì chạm tới là bỏ sót.
- Báo cáo bỏ sót và gọi đúng tên theo đợt, cùng báo nhầm theo module, đúng trên ví dụ tính tay.
- Chế độ kết hợp phân loại mọi cửa sổ nhưng kiểm tra botnet đúng các host như chế độ tuần tự.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Bỏ sót | Cửa sổ tấn công không bị cảnh báo nào chạm tới |
| Gọi đúng tên | Cảnh báo đúng loại hành vi (quét là `port_scan`, DoS là `dos`, bot là `suspect_host`) |
| Báo nhầm | Cửa sổ bình thường bị báo |
| Phủ cảnh báo | Cửa sổ nào bị một cảnh báo chạm tới (cùng host, thời gian chồng lên) |
| Chế độ kết hợp | Phân loại chạy độc lập; kiểm tra botnet chỉ chạy sau Gaussian |
| Trung vị của 3 lần | Giá trị ở giữa khi chạy 3 lần, để bớt nhiễu đo thời gian |
