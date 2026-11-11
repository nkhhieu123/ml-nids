# Báo cáo Chặng 11 — Kiểm thử thực nghiệm

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 11/11/2026 |
| Trạng thái | **Đã dựng và chạy smoke test lab ảo 7 node trên WSL2.** Cần chạy đủ thời lượng/số lần theo giao thức và xác nhận lại trên lab Kali vật lý trước số liệu cuối. |
| Chặng trước | [Bao_cao_Chang_10.md](Bao_cao_Chang_10.md) |

## 1. Tóm tắt

Chặng 11 đo hiệu quả hệ thống bằng kịch bản có nhãn chuẩn (ground truth). Phần cần **mạng lab 7 node trên
Kali** (thu PCAP thật của các kịch bản) là việc dựng hạ tầng, **chưa làm được trong môi trường này**. Phần
làm được và đã làm:

- **Bộ đo Chặng 11** (`src/nids/thuc_nghiem.py`, C11-T08): từ PCAP + ground truth (lịch nhãn hoặc nhật ký
  lần chạy lab) → độ trễ phát hiện, bỏ sót, báo động giả, hiệu năng.
- **Chạy thử trên 4 đoạn CIC** (quét, DoS, bình thường + bot ARES) để kiểm chứng logic và cho số liệu minh
  họa. Khi có PCAP lab, chạy **đúng lệnh này** với `--nhat-ky` trỏ tới nhật ký lần chạy.

Tiêu chí nghiệm thu: **độ trễ bao gồm thời gian tích lũy cửa sổ**; **lần không phát hiện tính là bỏ sót**.
Cả hai được cài đúng trong bộ đo (độ trễ = cuối cửa sổ đầu tiên − bắt đầu đợt; không có cảnh báo = bỏ sót).

## 2. Phương pháp đo

```bash
cd src
# CIC: ground truth lấy từ lịch nhãn (config/label_schedule.csv)
python -m nids.thuc_nghiem ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 --out ../docs/hinh/thuc_nghiem
# Lab: ground truth lấy từ nhật ký lần chạy (độc lập với dự đoán, B10)
python -m nids.thuc_nghiem ../data/pcap/<run_id>.pcap --net 192.168.50.0/24 --nhat-ky ../data/run_logs/nhat_ky.jsonl --out ../output/thuc_nghiem
```

| Chỉ số | Cách tính |
|---|---|
| Phát hiện / bỏ sót | Mỗi đợt tấn công (loại, host, khoảng) có ≥ 1 cảnh báo **đúng loại** trên host của nó trong khoảng đó không. Không có = **bỏ sót** |
| Độ trễ | Cuối cửa sổ của cảnh báo đầu tiên − thời điểm bắt đầu đợt. Dùng **cuối cửa sổ** nên đã gồm thời gian tích lũy cửa sổ |
| Báo động giả | Sự kiện cảnh báo (đã gộp) không giải thích được bằng đợt nào (host + thời gian), quy ra số mỗi giờ, tách theo module |
| Hiệu năng | Thời gian trích xuất và chấm mỗi module (pipeline) |

Loại tấn công ↔ module: `dos`/`port_scan` → bộ phân loại; `botnet` (bot ARES, nhãn gốc `Bot`) → module
botnet. DDoS/Heartbleed chỉ tính ở anomaly (không nằm trong ba lớp phân loại).

## 3. Kết quả chạy thử trên CIC (minh họa, không phải số lab)

4 đoạn test của Chặng 9 (docs/54), chế độ `ket_hop`:

| Đoạn (vai trò) | Đợt tấn công | Phát hiện | Độ trễ | Báo giả (botnet / anomaly) | Trích xuất |
|---|---|---|---|---|---|
| `wed_slowloris` (DoS chậm) | dos | ✓ | **10 s** | 7 (4 / 3) → 75/giờ | 2,7 s |
| `wed_hulk` (DoS mạnh) | dos | ✓ | **14 s** | 16 (8 / 8) → 280/giờ | 20,0 s |
| `fri_quet` (quét cổng) | port_scan | ✓ | **10 s** | 11 (4 / 7) → 31/giờ | 16,3 s |
| `fri_quet` | botnet (ARES) | ✓ | **48 s** | — | — |
| `fri_binh_thuong` (đối chứng) | botnet (ARES) | ✓ | **78 s** | 3 (2 / 1) → **8,9/giờ** | 2,7 s |
| **Tổng** | **5 đợt** | **5/5 (0 bỏ sót)** | 10–78 s | 37 sự kiện | |

Đọc kết quả:
- **Phát hiện 5/5 đợt, 0 bỏ sót** trên dữ liệu CIC. DoS và quét cổng phát hiện sau **10–14 giây** (một tới
  hai cửa sổ 10 giây). Botnet chậm hơn (**48–78 giây**) vì cửa sổ đồ thị dài 120 giây phải tích lũy đủ —
  đúng như yêu cầu "độ trễ gồm thời gian tích lũy cửa sổ".
- **Báo động giả chủ yếu từ module botnet** (và một phần anomaly). Module botnet học từ CTU-13, trên CIC báo
  nhầm nhiều (docs/52, docs/54) — **cần học lại trên dữ liệu lab**. Đối chứng gần-bình-thường
  (`fri_binh_thuong`) có báo giả thấp nhất (8,9/giờ), phần lớn traffic của nó được giải thích bằng bot ARES.
- Trích xuất đặc trưng vẫn là phần tốn thời gian nhất (docs/54).

## 4. Đối chiếu từng task

| Task | Nội dung | Trạng thái |
|---|---|---|
| C11-T01 | Nhật ký ground truth độc lập với dự đoán | **Có công cụ**: `scripts/sinh_traffic.py`, `scripts/sinh_topology.py` ghi `nhat_ky.jsonl`; `thuc_nghiem` đọc được (docs/68, docs/50) |
| C11-T02 | Kiểm thử traffic bình thường | **Đo thử** trên `fri_binh_thuong` (đối chứng); lab: kịch bản 1 |
| C11-T03 | Kiểm thử port scan | **Đo thử** trên `fri_quet` (phát hiện, trễ 10 s); lab: kịch bản 2 |
| C11-T04 | Kiểm thử DoS giới hạn trong lab | **Đo thử** trên `wed_hulk`/`wed_slowloris`; lab: kịch bản 3 (≤ 60 s) |
| C11-T05 | Giao tiếp tập trung mô phỏng | **Đã có** trên giả lập (docs/52: topology tập trung 100%); bot ARES của CIC phát hiện được; lab: kịch bản 4 |
| C11-T06 | Giao tiếp ngang hàng mô phỏng | **Đã có** trên giả lập (docs/52: P2P 82%); lab: kịch bản 5 |
| C11-T07 | Đối chứng lành tính, lặp tình huống | Đối chứng CIC `fri_binh_thuong`; giả lập có đối chứng (docs/52); lab: mỗi kịch bản ≥ 3 lần (B19) |
| C11-T08 | Tổng hợp độ trễ, bỏ sót, báo giả, hiệu năng | **Xong**: `src/nids/thuc_nghiem.py`, `docs/hinh/thuc_nghiem/thuc_nghiem.json` |

## 5. Còn lại (cần lab thật)

1. **Thu PCAP lab** 11 biến thể (docs/09) trên mạng 7 node, bắt bằng tcpdump trên Kali; mỗi kịch bản ≥ 3
   lần với lịch khác nhau (B19); các lần `test` thu sau khi mô hình đã khóa.
2. **Chạy bộ đo với `--nhat-ky`** trên từng PCAP lab → số liệu độ trễ/bỏ sót/báo giả **thật** của lab.
3. **Học lại module botnet (và xét lại ngưỡng)** trên dữ liệu lab: mô hình CTU-13 không chuyển sang bot giả
   lập (recall 0,017, docs/52), và là nguồn báo giả chính ở mục 3.
4. **Đo số gói kernel bỏ** khi bắt trực tiếp trên Kali (phát lại luôn cho 0, docs/63).
5. Lưu ảnh (biểu đồ độ trễ, báo giả) khi có đủ số lần chạy lab.

## 6. Smoke test lab ảo (11/11/2026)

Đã bổ sung `scripts/lab_ao.py`: tạo 7 network namespace Linux nối qua bridge riêng, không gán gateway/đường ra ngoài; dùng `tc mirred` sao chép traffic từ các cổng vào máy giám sát. Lab được dựng trên WSL2 Ubuntu (kernel `6.18.33.2-microsoft-standard-WSL2`), Nmap 7.98. Đây là kiểm tra tích hợp nhanh, không thay thế các lần chạy đủ 5–12 phút và ba lần lặp độc lập trong docs/09.

| Bằng chứng | Kết quả |
|---|---|
| `kiem-tra-mirror` | 390 gói bắt được; 390 gói qua bộ lọc; 0 gói kernel bỏ |
| `k2-quet-nhanh-test-01` | PCAP 232.430 byte, 2.234 gói; 0 gói kernel bỏ; 1 lượt Nmap connect scan tới 192.168.50.30:1–1024 |
| Bộ đo Chặng 11 trên PCAP của runner | 1/1 lượt scan được phát hiện; độ trễ 0,4 giây; 2 sự kiện cảnh báo không giải thích được; lệnh chạy và JSON đo được lưu trong `output/c11-runner-results/` |
| Đối chứng nền | Ba client sinh HTTP GET và gọi `/api/status`; traffic có mặt trong bản thu. Chỉ chạy trong lần smoke test, chưa đủ mẫu để ước lượng báo động giả ổn định. |

PCAP và nhật ký/manifest lần chạy được lưu trong `data/pcap/lab/` và `data/run_logs/k2-quet-nhanh-test-01.json`; SHA-256 PCAP: `1b26e949255635d541c05183e2c73375311b4e356805ba7d25f1b6ac3368afb8`. scikit-learn trong WSL là 1.9.1, artifact được tạo bằng 1.8.0 và phát cảnh báo phiên bản; kết quả smoke chỉ kiểm tra đường đi end-to-end, cần chạy lại trong môi trường dependency đã khóa để chốt số liệu.

Các tác vụ C11-T04–T07 có sẵn trong runner nhưng chưa được chạy ở smoke này. Chưa đánh dấu Chặng 11 hoàn tất: còn chạy đủ các biến thể, đối chứng và số lần lặp đã định, rồi tổng hợp tất cả PCAP lab.

## 7. Kiểm thử

`python -m unittest discover -s tests`: **418/418 ca đạt** (Chặng 10 kết thúc ở 408). `tests/test_thuc_nghiem.py`
(7 ca): ánh xạ lịch nhãn sang đợt tấn công và lọc host ngoài mạng; đọc nhật ký lần chạy lab; độ trễ và bỏ
sót (sai host/sai nhãn không tính là phát hiện); báo động giả tách theo module; tóm tắt độ trễ.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Ground truth | Sự thật đã biết trước (đợt tấn công nào, host nào, lúc nào) để chấm điểm phát hiện |
| Độ trễ phát hiện | Thời gian từ lúc tấn công bắt đầu tới lúc có cảnh báo đầu tiên |
| Thời gian tích lũy cửa sổ | Thời gian phải chờ cho cửa sổ đủ dữ liệu trước khi chấm được |
| Bỏ sót | Tấn công có thật nhưng không có cảnh báo nào |
| Báo động giả | Cảnh báo trên lưu lượng không phải tấn công |
| Đợt tấn công | Một loại tấn công trên một hoặc vài host trong một khoảng thời gian |
| Bot ARES | Botnet trong traffic thứ Sáu của CIC-IDS2017 |
| Đối chứng | Lưu lượng lành tính dùng để kiểm tra mô hình không báo nhầm |
| Nhật ký lần chạy | File ghi mỗi lần thử trong lab, dùng làm ground truth, độc lập với dự đoán |
