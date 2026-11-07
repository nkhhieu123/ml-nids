# C10-T05 — Đo packet xử lý, packet bị bỏ và tài nguyên

Mã nguồn: `Metrics`, `rss_mb`, `ThreadedRunner` (độ trễ) trong `src/nids/realtime.py`. Cấu hình:
`realtime.metrics_interval_s`. Kiểm thử: `tests/test_realtime.py`. Kết quả:
`docs/hinh/realtime_hieu_nang.json`.

## 1. Số liệu ghi khi chạy

Mỗi `metrics_interval_s` = 10 giây (giờ thật), `nids.realtime` ghi một dòng JSON vào `<tên>.so_lieu.jsonl`
và một dòng log. Khi dừng thì ghi tổng kết `<tên>.so_lieu_tong.json`.

| Số liệu | Cách đo |
|---|---|
| Gói nhận, gói xử lý | Đếm ở nguồn và ở luồng xử lý |
| Gói bỏ ở hàng đợi | Hàng đợi đầy (C10-T04) |
| Gói bỏ ở kernel | `PACKET_STATISTICS` của socket AF_PACKET (chỉ khi bắt trực tiếp); cộng dồn |
| Tỷ lệ bỏ | (bỏ hàng đợi + bỏ kernel) / (nhận + bỏ kernel) |
| Tốc độ | Gói xử lý trong khoảng / thời gian khoảng |
| Hàng đợi | Độ sâu hiện tại và sâu nhất |
| CPU | `os.times()` user + system / thời gian thật; 100% là một lõi bận hoàn toàn |
| RAM | Bộ nhớ thường trú: `psutil` nếu có, nếu không đọc `VmRSS` trong `/proc/self/status` |
| Độ trễ xử lý | Từ lúc luồng đọc nhận gói tới lúc xử lý xong gói đó (chờ hàng đợi + xử lý); p50, p95, p99, lớn nhất |
| State | Flow mở, flow gần đây, cửa sổ mở, host bất thường, sự kiện mở (C10-T04) |
| Kết quả | Cửa sổ 10 s, host–cửa sổ 120 s, cảnh báo, sự kiện; thời gian chấm của từng module |

**Độ trễ xử lý không phải độ trễ phát hiện.** Độ trễ phát hiện (B21) còn gồm thời gian tích lũy cửa sổ
(10 hoặc 120 giây) và chờ quan sát bắt tay (3 giây), và được đo ở Chặng 11 bằng `created_at` của cảnh báo
so với nhật ký kịch bản.

## 2. Đo trên máy phát triển

Phát lại PCAP CIC **theo nhịp thật** (`--toc-do`), để luồng đọc đưa gói vào đúng nhịp như card mạng. Máy
phát triển: laptop Windows 11, Python 3.13.

Hai lần đo đầu **bị loại**, và việc này được ghi lại:
1. Lần đầu, máy vào chế độ ngủ giữa chừng: Windows ghi sự kiện Kernel-Power 42 lúc 19:51 và 20:51. CPU
   trung bình chỉ 0,3% trong 3,2 giờ.
2. Lần hai, vòng lặp của script đo cũ chưa dừng hẳn và chạy song song với script mới, làm tranh CPU.

Lần đo được dùng: script đo giữ máy thức trong lúc đo (`SetThreadExecutionState`), chạy từng phép đo một,
kiểm tra 0 lần ngủ.

| Phép đo | Gói | Tải | Bỏ gói | CPU | RAM tối đa | Hàng đợi sâu nhất | Độ trễ xử lý p50 / p95 / lớn nhất | Cảnh báo / sự kiện |
|---|---|---|---|---|---|---|---|---|
| `wed_slowloris` ×1 (nhịp thật) | 73 284 | 228 gói/s | 0 | 7,3% | 207 MB | 1 104 | 0,8 ms / 17 ms / 0,30 s | 654 / 9 |
| `wed_slowloris` ×16 | 73 284 | 3 488 gói/s | 0 | 70,5% | 210 MB | 7 642 | 49 ms / 0,36 s / 0,52 s | 654 / 9 |
| `wed_hulk` ×1 (nhịp thật, DoS) | 559 307 | 2 849 gói/s | 0 | 32,4% | 347 MB | 10 092 | 1,2 ms / 57 ms / 0,69 s | 348 / 18 |
| `fri_quet` ×4 | 373 396 | trung bình khoảng 1 200 gói/s, dồn từng đợt | **14 201 (3,8%)** | 93,3% | 400 MB | **100 000 (đầy)** | 61 s / 101 s / 107 s | 1 151 / 107 |

Thời gian chấm (giây) theo module:

| Phép đo | Anomaly | Phân loại | Botnet |
|---|---|---|---|
| `wed_slowloris` ×1 | 1,05 | 3,62 | 4,85 |
| `wed_hulk` ×1 | 0,67 | 2,26 | 10,83 |
| `fri_quet` ×4 | 12,3 | 61,1 | **258,4** |

## 3. Đọc kết quả

- **Ở nhịp thật, không bỏ gói nào, độ trễ xử lý dưới 0,7 giây**, kể cả lúc DoS Hulk (khoảng 2 850
  gói/giây, CPU 32%). Số cảnh báo giống hệt khi phát lại nhanh nhất (654, 348): pipeline cho kết quả không
  phụ thuộc tốc độ, miễn là không bỏ gói.
- **Điểm nghẽn là module botnet khi nhiều host có bất thường chưa giải thích.** Trên `fri_quet` (quét cổng
  và bot ARES, khoảng 11 host bị kiểm tra), mỗi bước 10 giây dựng lại đồ thị và beaconing từ mọi flow 600
  giây gần nhất của các host đó, chiếm 258 giây.
  - Ở ×4 thì quá tải: hàng đợi đầy, bỏ 3,8% gói (đều được đếm và ghi log).
  - Ở nhịp thật (×1), tổng thời gian chấm vẫn dưới thời lượng traffic, nên không quá tải.
  - Cách cải thiện (**đã làm 07/11/2026**, mục 3.1): chỉ tính đúng cửa sổ 120 giây đang xét và dùng cache
    chuyển đổi flow tăng dần, thay vì dựng lại toàn bộ mỗi bước.
- RAM 200–400 MB, chủ yếu là mô hình (Random Forest 300 cây) và bảng flow gần đây.
- Chưa đo trên Kali và card thật: số gói kernel bỏ luôn là 0 khi phát lại.

## 3.1. Tăng tốc module botnet (07/11/2026, QĐ-059)

Hai chỗ lãng phí ở mỗi bước chấm cửa sổ 120 giây (`_score_graph_window`), đo trên `fri_quet` (phát lại
nhanh nhất, 137 lần chấm, 785 host–cửa sổ):

1. **`build_features` dựng mọi cửa sổ 10 giây trong 600 giây flow rồi bỏ hết trừ một.** Thêm tham số
   `windows` cho `build_features`/`window_edges`/`host_ports`: chỉ tạo đúng cửa sổ đang xét (và cửa sổ liền
   trước để tính `ty_le_peer_moi`). Giá trị **y hệt** tính hết (kiểm tra trên scenario 1: lệch 0 ở mọi đặc
   trưng, gồm beacon). 32,2 → 25,9 giây (phần còn lại là `incident`/beacon trên toàn bộ 600 giây — vốn phải thế).
2. **`_flow_table` dựng lại DataFrame ~16 000 dòng mỗi lần.** Flow kết thúc có mã tăng dần liên tục (thêm ở
   cuối, prune ở đầu) nên cache bảng flow chung đã chuyển đổi, mỗi lần chỉ chuyển đổi flow mới ở cuối và bỏ
   flow bị prune ở đầu. 49,5 → 11,5 giây.

Kết quả trên `fri_quet`: thời gian chấm botnet **84,5 → 40,9 giây** (−52%), tổng chạy 130,7 → 86,4 giây.
Bằng chứng không đổi hành vi: `nids.nhat_quan` trên cả 4 đoạn cho kết quả **y hệt** `docs/hinh/nhat_quan.json`
đã khóa (realtime vẫn khớp offline như trước). Mặc định bật; không có tham số mới cho người dùng.

## 4. Kiểm thử

- Báo cáo đúng nhịp (chưa tới 10 giây thì không ghi); tốc độ theo khoảng; gói kernel bỏ cộng dồn qua
  các lần đọc; tỷ lệ bỏ gồm cả hàng đợi và kernel; độ trễ lớn nhất và trung vị; file JSONL đúng số dòng.
- RAM đọc được (hoặc None nếu không có nguồn); phân vị đúng; danh sách rỗng trả None.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Phát lại theo nhịp thật | Đưa gói của file vào đúng khoảng cách thời gian như lúc bắt |
| Gói bỏ ở kernel / hàng đợi | Gói hệ điều hành không kịp giao cho chương trình / gói chương trình không kịp xử lý |
| RAM thường trú (RSS) | Bộ nhớ tiến trình đang chiếm thật |
| p50, p95, p99 | Giá trị mà 50%, 95%, 99% số lần đo nhỏ hơn |
| Độ trễ xử lý | Thời gian từ lúc nhận gói tới lúc xử lý xong |
| Điểm nghẽn | Bước chậm nhất, quyết định tốc độ cả chương trình |
| Tính tăng dần | Cập nhật kết quả từ phần dữ liệu mới thay vì tính lại từ đầu |
