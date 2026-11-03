# C09-T02 — Chạy PCAP qua toàn bộ pipeline

Mã nguồn: `run_pcap`, `extract`, `load_windows`, `load_flows`, `monitored_hosts`, `score_anomaly`,
`score_attack`, `score_botnet`, `run_independent`, `Timer` trong `src/nids/pipeline.py`; công cụ
cắt PCAP `src/nids/pcap_cut.py`. Kiểm thử: `tests/test_pipeline.py`. Kết quả:
`output/pipeline/` (không lên git).

```bash
# Cắt một đoạn thời gian của PCAP CIC (giờ địa phương UTC−3)
python -m nids.pcap_cut data/pcap/cic-ids2017/Friday-WorkingHours.pcap output/pcap/fri_quet.pcap \
    --bat-dau "2017-07-07 15:08:30" --ket-thuc "2017-07-07 15:29:30" --utc-offset -3
# Chạy pipeline
cd src
python -m nids.pipeline chay ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 --out ../output/pipeline
```

## 1. Các bước

```
PCAP ─> nids.feature_export ─> flows.csv, windows.csv (cửa sổ 10 giây)
          (cùng mã lúc huấn luyện)   │
                                     ├─> Gaussian (anomaly)               ─> d², anomaly/normal
                                     ├─> Random Forest (attack_classification) ─> nhãn, xác suất 3 lớp
                                     └─> flow → bảng flow chung → đồ thị, beaconing 120 giây
                                           ─> Random Forest botnet ─> điểm, suspect_host ─> quy tắc topology
```

1. **Kiểm tra artifact** (C09-T01): có lỗi thì dừng.
2. **Trích xuất**: `nids.feature_export.export`, đúng hàm đã tạo bảng huấn luyện, nên cửa sổ, timeout
   và đặc trưng giống hệt lúc học (B12).
3. **Anomaly và phân loại** chấm từng cửa sổ host 10 giây. Trước khi chấm, kiểm tra bảng có đủ cột.
4. **Botnet**:
   - flow của dự án đổi sang bảng flow chung (`from_project_flows`);
   - **host xét** là mọi IP thuộc mạng giám sát (`--net`) có trong flow;
   - dựng đồ thị và beaconing 120 giây bằng đúng mã của Chặng 8, với `local_nets` lấy từ `--net`;
   - chấm điểm, rồi áp quy tắc topology lên cửa sổ bị nghi.
5. Ghi bảng dự đoán của từng module (`<tên>.<module>.csv`) và tóm tắt (`<tên>.pipeline.json`: thời gian
   từng bước, số flow, cửa sổ, host, số báo động).

Pipeline **không học gì**: chỉ dùng artifact đã lưu (QĐ-043, QĐ-044).

## 2. Dữ liệu chạy thử

PCAP CIC đầy đủ mỗi ngày 8–13 GB; trích xuất cả ngày mất khoảng 24 phút. Để chạy thử và đo nhanh,
`nids.pcap_cut` cắt các đoạn ngắn. Công cụ đọc bằng bộ đọc của dự án và ghi PCAP nano giây, giữ nguyên
byte gói; đọc thứ Sáu tới 15:30 mất khoảng 25 giây.

Các đoạn được chọn **nằm trọn trong khoảng test** của cách chia ở Chặng 5 (QĐ-027), để không chấm mô
hình trên dữ liệu nó đã học:

| Đoạn | Giờ địa phương | Nội dung | Gói |
|---|---|---|---|
| `fri_binh_thuong` | 07/07 12:14:30–12:34:30 | Bình thường; bot ARES gọi về cả ngày | 77 832 |
| `fri_quet` | 07/07 15:08:30–15:29:30 | Phần test của đợt quét cổng thứ hai; bot ARES | 373 396 |
| `wed_slowloris` | 05/07 10:05:20–10:10:40 | Phần test của DoS slowloris | 73 284 |
| `wed_hulk` | 05/07 10:57:30–11:00:40 | Phần test của DoS Hulk | 559 307 |

## 3. Kết quả

Thời gian (giây, máy phát triển) và số báo động mỗi module (chế độ độc lập):

| Đoạn | Flow | Cửa sổ 10 s | Host xét | Trích xuất | Anomaly | Phân loại | Botnet | Báo anomaly / phân loại / botnet |
|---|---|---|---|---|---|---|---|---|
| `fri_binh_thuong` | 4 347 | 4 633 | 15 | 3,4 | 0,008 | 0,07 | 0,29 | 421 / 34 / 153 |
| `fri_quet` | 37 223 | 7 464 | 16 | 16,9 | 0,010 | 0,07 | 0,94 | 814 / 225 / 292 |
| `wed_slowloris` | 5 189 | 1 964 | 16 | 3,3 | 0,006 | 0,05 | 0,20 | 319 / 311 / 170 |
| `wed_hulk` | 31 769 | 1 406 | 16 | 25,2 | 0,009 | 0,07 | 0,23 | 179 / 155 / 116 |

- **Trích xuất chiếm hơn 90% thời gian**: khoảng 22 000 gói/giây. Ba mô hình cộng lại dưới 1,3 giây.
- Trên `fri_quet`, các module báo đúng chỗ:
  - Gaussian báo các máy bot ARES (.5, .8, .9, .14, .15) và cặp quét 172.16.0.1 ↔ 192.168.10.50;
  - bộ phân loại báo `port_scan` cho 172.16.0.1 (108 cửa sổ) và 192.168.10.50 (105);
  - module botnet báo cặp quét, một số máy bot ARES, và cả 192.168.10.1, máy chưa rõ vai trò.

  Báo động trên đoạn **bình thường** (`fri_binh_thuong`) cho thấy mức báo nhầm. Đo bỏ sót và báo nhầm
  theo nhãn ở C09-T05.
- Module botnet học trên CTU-13 (2011), chạy trên mạng CIC (2017): kết quả chỉ để kiểm tra pipeline
  chạy đúng, không phải đánh giá module botnet (docs/52).

## 4. Hạn chế

- Đoạn cắt ngắn có hiệu ứng biên: cửa sổ ở đầu đoạn thiếu lịch sử (peer mới, beaconing nhìn ngược 600
  giây).
- Đây là xử lý **offline**, đọc cả file rồi mới chấm điểm. Bản realtime (Chặng 10) phải chấm theo từng
  cửa sổ khi đóng.

## 5. Kiểm thử

- `pcap_cut`: chỉ giữ gói trong khoảng, đọc lại được bằng bộ đọc của dự án, dừng sớm sau `ket_thuc`;
  đổi giờ địa phương sang UTC đúng.
- PCAP tổng hợp (một máy quét SYN 200 cổng, một máy có 5 kết nối thường):
  - trích ra 205 flow và đúng 3 host giám sát;
  - chế độ độc lập đo thời gian cả ba module;
  - mô hình giả báo `port_scan` và `suspect_host` cho máy quét, không báo máy thường;
  - cửa sổ botnet dài 120 giây.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Pipeline offline | Chuỗi xử lý đọc hết một file PCAP rồi chấm điểm, không chạy trực tiếp trên card mạng |
| Trích xuất | Đọc gói, ghép flow, tính cửa sổ và đặc trưng |
| Cửa sổ 10 s / 120 s | Cửa sổ của anomaly và phân loại / của module botnet |
| Host xét | Máy trong mạng giám sát được tính đặc trưng botnet |
| Mạng giám sát (`--net`) | Dải địa chỉ của mạng cần bảo vệ |
| Hiệu ứng biên | Cửa sổ ở đầu, cuối đoạn thiếu dữ liệu trước hoặc sau |
| Khoảng test | Phần thời gian của dữ liệu dành cho đánh giá cuối, mô hình chưa học |
