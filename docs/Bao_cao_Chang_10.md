# Báo cáo Chặng 10 — Triển khai realtime trên Kali

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 05–06/11/2026 |
| Trạng thái | Xong 8/8 task về mã; **chưa chạy trên Kali và card mạng thật** (lab chưa dựng) |
| Chặng trước | [Bao_cao_Chang_9.md](Bao_cao_Chang_9.md) |

## 1. Tóm tắt

Chặng 10 biến pipeline offline (Chặng 9) thành **cảm biến chạy liên tục**:
- đọc gói trực tiếp từ card mạng;
- chấm ba module khi cửa sổ đóng;
- ghi cảnh báo, sự kiện, số liệu vận hành;
- chạy nền bằng systemd, dừng êm.

```
card mạng (AF_PACKET) / PCAP phát lại ─> luồng đọc ─> hàng đợi giới hạn ─> luồng xử lý:
   parse_packet ─> WindowPipeline (đúng mã offline) ─> cửa sổ 10 s ─> Gaussian, phân loại
                                     └─> flow ─> mỗi bước 10 s: đồ thị 120 s ─> botnet, topology
   ─> alerts.csv, su_kien.csv (gộp ngay), so_lieu.jsonl (mỗi 10 s), log xoay vòng
systemd: user nids + CAP_NET_RAW, SIGTERM → dừng êm, tự khởi động lại khi lỗi
```

**Tiêu chí nghiệm thu**: chương trình chạy nền được, ghi cảnh báo, khởi động/dừng theo hướng dẫn.

| Tiêu chí | Đáp ứng | Bằng chứng |
|---|---|---|
| Chạy nền | Unit systemd, script cài dịch vụ, hướng dẫn start/stop/status/journal (docs/65) | Kiểm thử tự động: tham số `ExecStart` hợp lệ, script `bash -n`, file LF. **Chưa cài trên Kali** |
| Ghi cảnh báo | `alerts.csv` theo schema chung, sự kiện gộp ngay, điểm (tùy chọn), số liệu, log | Phát lại 4 đoạn PCAP CIC: cảnh báo anomaly/phân loại giống hệt offline |
| Khởi động/dừng | SIGINT/SIGTERM/SIGHUP dừng êm có hạn; mã thoát; log ghi lý do dừng | Kiểm thử dừng giữa chừng, hết hạn xử lý nốt, tín hiệu thật |

## 2. Các task

| Task | Nội dung | Tài liệu |
|---|---|---|
| C10-T01 | Cài dự án trên Kali (script, kiểm tra môi trường) | [59_cai_dat_kali.md](59_cai_dat_kali.md) |
| C10-T02 | Xác minh cảm biến thấy traffic hai chiều | [60_cam_bien_hai_chieu.md](60_cam_bien_hai_chieu.md) |
| C10-T03 | Nguồn packet live, tái sử dụng bộ trích xuất | [61_realtime.md](61_realtime.md) |
| C10-T04 | Hàng đợi giới hạn và dọn state | [62_hang_doi_don_state.md](62_hang_doi_don_state.md) |
| C10-T05 | Đo packet xử lý, packet bị bỏ, tài nguyên | [63_do_hieu_nang.md](63_do_hieu_nang.md) |
| C10-T06 | Dừng chương trình và quản lý log | [64_dung_va_log.md](64_dung_va_log.md) |
| C10-T07 | Chạy nền bằng systemd | [65_chay_nen_systemd.md](65_chay_nen_systemd.md) |
| C10-T08 | Nhất quán offline/realtime | [66_nhat_quan_offline_realtime.md](66_nhat_quan_offline_realtime.md) |

Mã nguồn:
- `src/nids/moi_truong.py`: kiểm tra môi trường;
- `src/nids/cam_bien.py`: kiểm tra hai chiều;
- `src/nids/nguon_goi.py`: nguồn gói;
- `src/nids/realtime.py`: bộ máy, hàng đợi, số liệu, dừng, log;
- `src/nids/nhat_quan.py`: so với offline;
- `scripts/cai_dat_kali.sh`, `scripts/cai_dich_vu.sh`, `deploy/`.

Kiểm thử: `tests/test_realtime.py`.

## 3. Kết quả từng task

### 3.1. C10-T01 — Cài trên Kali

- `scripts/cai_dat_kali.sh`: gói hệ thống, clone, `.venv` tạo bằng `--copies`, `pip install -e .`, chép
  mô hình, `setcap` **chỉ cho python của `.venv`** (không cấp cho python hệ thống), rồi kiểm tra.
- `python -m nids.moi_truong`: Python, thư viện, quyền bắt gói (root hoặc CAP_NET_RAW đọc từ `CapEff`), card
  mạng, artifact, NTP, đĩa.
- Trên máy phát triển (Windows): sẵn sàng chạy từ file PCAP.

### 3.2. C10-T02 — Hai chiều

- `python -m nids.cam_bien <bản bắt thử>` đo:
  - flow TCP hai chiều;
  - phản hồi bắt tay của máy trong mạng;
  - cặp chỉ thấy một chiều;
  - gói nhân đôi (so nội dung IP, bỏ TTL và checksum);
  - máy lab nào đã thấy.
- CIC: 99–99,9% flow hai chiều. Bản giả lập mirror một chiều bị phát hiện: 8% hai chiều, 382 cặp một
  chiều, kết luận `loi`.
- **PCAP CIC có 0,7–11,8% gói nhân đôi**; bộ trích xuất chưa bỏ bản sao. Cần đo trên lab.

### 3.3. C10-T03 — Nguồn gói live

- `AfPacketSource`: socket AF_PACKET, promiscuous, dấu thời gian kernel, đếm gói kernel bỏ; không cần
  scapy hay libpcap. `PcapReplaySource`: phát lại nhanh nhất hoặc theo nhịp thật.
- Chấm cửa sổ 10 giây khi đóng. Cửa sổ 120 giây chấm theo từng bước, trên flow đã kết thúc và ảnh chụp flow
  đang mở. Sự kiện gộp ngay khi chạy.
- Hai lỗi tìm ra khi chạy thử, đã sửa:
  - Random Forest `n_jobs = 4` dựng nhóm luồng cho mỗi lô nhỏ, chiếm 44/53 giây;
  - `np.isclose` với sai số tương đối làm mỗi cửa sổ 120 giây bị chấm lại ở mọi bước.

### 3.4. C10-T04 — Hàng đợi, state

- Luồng đọc → `Queue(100 000)` → luồng xử lý. Đầy thì bỏ gói mới và đếm.
- Mạng im lặng thì vẫn đẩy thời gian mỗi 1 giây, để flow hết hạn và cửa sổ đóng.
- Trần 200 000 flow mở (vượt thì kết thúc flow cũ nhất, lý do mới `gioi_han_bo_nho`) và 500 000 flow gần đây.
- Sửa lỗi đếm đôi flow đang đóng trong ảnh chụp.

### 3.5. C10-T05 — Hiệu năng (phát lại theo nhịp thật, máy phát triển)

| Phép đo | Tải | Bỏ gói | CPU | RAM | Độ trễ xử lý p95 |
|---|---|---|---|---|---|
| slowloris ×1 | 228 gói/s | 0 | 7% | 207 MB | 17 ms |
| slowloris ×16 | 3 488 gói/s | 0 | 71% | 210 MB | 0,36 s |
| Hulk ×1 (DoS thật) | 2 849 gói/s | 0 | 32% | 347 MB | 57 ms |
| Quét cổng ×4 | khoảng 1 200 gói/s, nhiều host bất thường | **3,8%** | 93% | 400 MB | 101 s |

- Điểm nghẽn: module botnet dựng lại đồ thị 600 giây ở mỗi bước khi nhiều host có bất thường.
- Hai lần đo đầu bị loại: một lần máy ngủ giữa chừng, một lần script đo cũ chạy song song. Lần đo được dùng
  giữ máy thức, chạy từng phép đo một, kiểm tra 0 lần ngủ.

### 3.6. C10-T06 — Dừng, log

- SIGINT, SIGTERM, SIGHUP: ngừng đọc, xử lý nốt hàng đợi tối đa 30 giây, chấm nốt, đóng sự kiện, ghi số liệu
  cuối, đóng file. Tín hiệu thứ hai thì thoát ngay.
- Mã thoát: 0 khi dừng bình thường, 1 khi lỗi, 130 khi buộc thoát.
- Log `RotatingFileHandler` 10 MB × 5 bản. File kết quả trùng tên được giữ thành `.cu.*`.

### 3.7. C10-T07 — systemd

- Chạy bằng user `nids` với `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`.
- Trước khi chạy thì kiểm tra mô hình (`pipeline kiem-tra`).
- `TimeoutStopSec=45`, lớn hơn 30 giây dừng êm.
- Khởi động lại khi lỗi; giới hạn RAM và CPU; chỉ ghi được thư mục kết quả.
- Script cài đặt chặn máy tự ngủ.
- `.gitattributes` buộc LF cho file chạy trên Kali.

### 3.8. C10-T08 — Nhất quán

- 4 đoạn PCAP:
  - **cửa sổ 10 giây, anomaly, phân loại khớp tuyệt đối** trên 15 467 cửa sổ;
  - botnet: cùng 1 558 host–cửa sổ; 6 nhãn khác, đều do điểm sát ngưỡng vì ảnh chụp flow đang mở.
- Hai chỗ lệch đã sửa:
  - realtime bỏ qua cửa sổ 120 giây bắt đầu trước gói đầu tiên;
  - realtime chấm trước khi biết hết bất thường chồng lên phần cuối cửa sổ. Sửa bằng `graph_delay_s` 10
    giây.

## 4. Sửa ở chặng trước

- `flows.py`: thêm lý do kết thúc `gioi_han_bo_nho` và `evict_oldest` (chỉ realtime dùng); docs/19 cập nhật.
- `.gitattributes`: bản làm việc trên Windows của `scripts/cai_dat_kali.sh` trước đây là CRLF.

## 5. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-049 | Cài bằng script; `.venv` riêng có quyền bắt gói | Đã chốt (chưa chạy trên Kali) |
| QĐ-050 | Kiểm tra hai chiều bằng bản bắt thử; nhân đôi theo nội dung IP | Đã chốt (chưa chạy trên lab) |
| QĐ-051 | AF_PACKET không thư viện ngoài; cùng bộ trích xuất; ảnh chụp flow đang mở | Đã chốt |
| QĐ-052 | Hàng đợi giới hạn bỏ gói mới; nhịp thời gian; trần state | Đã chốt |
| QĐ-053 | Số liệu vận hành định kỳ; đo theo nhịp thật, loại phép đo nhiễu | Đã chốt |
| QĐ-054 | Dừng êm có hạn; log xoay vòng; không ghi lẫn kết quả | Đã chốt |
| QĐ-055 | systemd với user riêng và hai quyền mạng; LF | Đã chốt (chưa cài trên Kali) |
| QĐ-056 | Chờ thêm một cửa sổ 10 giây trước khi chấm botnet; chấp nhận lệch do flow đang mở | Đã chốt |

Cấu hình mới: mục `realtime` gồm:
- `queue_size`, `tick_s`;
- `max_active_flows`, `max_flow_rows`;
- `metrics_interval_s`, `stop_timeout_s`, `graph_delay_s`;
- `log_dir`, `log_max_mb`, `log_backups`.

## 6. Kiểm thử

`python -m unittest discover -s tests`: **386/386 ca đạt** (Chặng 9 kết thúc ở 356). `tests/test_realtime.py`
có 30 ca:

| Task | Số ca | Nội dung |
|---|---|---|
| T01 | 4 | Python, thư viện, quyền (CapEff), card, NTP |
| T02 | 5 | Hai chiều, một chiều, nhân đôi, quá ít flow, mã băm bỏ TTL |
| T03 | 5 | AF_PACKET với socket giả, phát lại theo nhịp, cùng số cửa sổ với offline, chấm mỗi cửa sổ 120 s một lần, gộp sự kiện |
| T04 | 5 | Hàng đợi đầy bỏ gói, nhịp làm hết hạn state, trần flow, flow cũ nhất bị ép kết thúc, không đếm đôi |
| T05 | 2 | Báo cáo số liệu theo nhịp, tỷ lệ bỏ, RAM, phân vị |
| T06 | 4 | Dừng giữa chừng, hết hạn xử lý nốt, tín hiệu thật, log xoay vòng |
| T07 | 3 | Unit, `ExecStart` hợp lệ, LF và cú pháp script |
| T08 | 2 | Offline = realtime trên PCAP tổng hợp; hàm so sánh |

## 7. Cách chạy

```bash
# Máy bất kỳ: phát lại PCAP như đang bắt trực tiếp
cd src && python -m nids.realtime --pcap ../output/pcap/fri_quet.pcap --toc-do 1 --net 192.168.10.0/24 --net 172.16.0.0/24
# Kali: cài, kiểm tra, chạy nền
bash scripts/cai_dat_kali.sh --iface eth1
sudo tcpdump -i eth1 -w /tmp/thu.pcap -c 20000 && .venv/bin/python -m nids.cam_bien /tmp/thu.pcap
sudo bash scripts/cai_dich_vu.sh --iface eth1 --net 192.168.50.0/24
sudo systemctl stop|start|status nids-realtime ; journalctl -u nids-realtime -f
# So với offline
cd src && python -m nids.nhat_quan ../output/pcap/wed_slowloris.pcap --net 192.168.10.0/24 --net 172.16.0.0/24
```

## 8. Điểm cần lưu ý

1. **Chưa chạy trên Kali, card mạng thật, systemd thật.** Các phần đó đã có kiểm thử với socket giả, bộ đọc
   tham số, `bash -n`. Khi có lab, ghi kết quả vào mục "Kết quả trên Kali/lab" của docs/59, 60, 65.
2. **Module botnet là điểm nghẽn** khi nhiều host bất thường: quét cổng ×4 bỏ 3,8% gói. Nên tính đặc trưng
   120 giây tăng dần thay vì dựng lại 600 giây mỗi bước.
3. **Gói nhân đôi** của mirror chưa được khử khi trích xuất; cần đo tỷ lệ trên lab.
4. **Cảnh báo botnet** đến sau cuối cửa sổ 120 giây + 13 giây; độ trễ phát hiện đầy đủ đo ở Chặng 11.
5. Mô hình botnet học từ CTU-13 (docs/52), nên trên lab cần học lại.

## 9. Việc tiếp theo

**Chặng 11 — Kiểm thử thực nghiệm** (cần lab):
- nhật ký ground truth (đã có `scripts/sinh_topology.py` cho botnet);
- các kịch bản bình thường, quét, DoS, botnet;
- độ trễ phát hiện tính cả thời gian tích lũy cửa sổ;
- bỏ sót, báo nhầm.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Cảm biến realtime | Chương trình phân tích traffic ngay khi gói đến |
| AF_PACKET | Loại socket Linux nhận nguyên khung từ card mạng |
| Hàng đợi giới hạn | Hàng chờ có số chỗ tối đa; đầy thì bỏ và đếm |
| Dừng êm | Dừng sau khi làm xong việc dở và lưu kết quả |
| systemd | Trình quản lý dịch vụ của Linux |
| Nhất quán offline/realtime | Cùng dữ liệu thì hai chế độ cho cùng kết quả |
| Độ trễ xử lý / phát hiện | Gói chờ bao lâu mới được xử lý / hành vi bắt đầu bao lâu mới có cảnh báo |
