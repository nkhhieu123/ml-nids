# C10-T06 — Xử lý dừng chương trình và quản lý log

Mã nguồn: `install_signal_handlers`, `ThreadedRunner.stop`, `setup_logging`, `main` trong
`src/nids/realtime.py`. Cấu hình: `realtime.stop_timeout_s`, `log_dir`, `log_max_mb`, `log_backups`.
Kiểm thử: `tests/test_realtime.py`.

## 1. Dừng chương trình

| Tín hiệu | Khi nào | Xử lý |
|---|---|---|
| `SIGINT` (Ctrl+C) | Chạy tay trong terminal | Dừng êm |
| `SIGTERM` | `systemctl stop`, `kill` (C10-T07) | Dừng êm |
| `SIGHUP` (Linux) | Đóng terminal, `systemctl reload` | Dừng êm |
| Tín hiệu thứ hai trong lúc đang dừng | Người dùng muốn thoát ngay | Ghi log rồi thoát với mã 130, **không** xử lý nốt |

**Dừng êm** (QĐ-054):
1. Nguồn gói ngừng đọc. AF_PACKET chờ tối đa 0,5 giây; phát lại PCAP dừng ở gói kế tiếp.
2. Luồng xử lý làm nốt gói còn trong hàng đợi, trong tối đa `stop_timeout_s` = 30 giây. Quá hạn thì bỏ
   phần còn lại và đếm (`goi_bo_khi_dung`).
3. `engine.finish()`: đóng mọi flow và cửa sổ, chấm nốt cửa sổ 10 giây và 120 giây, đóng mọi sự kiện.
4. Ghi số liệu cuối (`so_lieu_tong.json` có `ly_do_dung` và `goi_bo_khi_dung`), đóng các file CSV.

Mã thoát:
- `0` khi hết nguồn hoặc dừng êm theo tín hiệu;
- `1` khi có lỗi (traceback ghi vào log);
- `130` khi buộc thoát bằng tín hiệu thứ hai.

## 2. Log

- `logging` với `RotatingFileHandler`: `output/realtime/log/nids_realtime.log`, mỗi file tối đa 10 MB, giữ 5
  bản cũ (`.log.1` … `.log.5`), nên log tối đa khoảng 60 MB. Thư mục tương đối trong cấu hình được tính từ
  thư mục dự án; `--log-dir` đổi được.
- Nội dung:
  - **khởi động**: tên lần chạy, nguồn, mạng, chế độ, commit, đường dẫn log;
  - **số liệu** mỗi 10 giây (C10-T05);
  - **cảnh báo** khi hàng đợi bỏ gói;
  - **lỗi** kèm traceback;
  - **dừng**: lý do, số gói, cảnh báo, sự kiện, gói bỏ khi dừng.
- `--im-lang` tắt in cảnh báo và log ra terminal (khi chạy nền, C10-T07). File log và file CSV vẫn ghi đủ.
- Khi chưa cấu hình log (ví dụ khi dùng làm thư viện, khi kiểm thử), logger không in gì.

**File kết quả trùng tên**: chạy lại với cùng `--ten` thì `alerts.csv`, `diem.csv` nối thêm vào file cũ, còn
`su_kien.csv` và `so_lieu.jsonl` bị ghi đè, nên dữ liệu bị lẫn. Lỗi này phát hiện khi đo lại hiệu năng. Nay
trước khi mở file nào, bản cũ được đổi tên thành `<tên>.cu.<đuôi>` và ghi cảnh báo vào log. Mặc định tên
lần chạy có giờ bắt đầu (`realtime_YYYYmmdd_HHMMSS`), nên chạy dịch vụ không bị trùng.

## 3. Hai lỗi phát hiện khi chạy thử, đã sửa trước khi commit

- Bước giữ bản cũ ban đầu chạy **sau** khi đã mở file sự kiện; Windows không cho đổi tên file đang mở. Đã
  dời lên trước mọi lần mở file.
- `log_dir` tương đối ban đầu bị tính từ thư mục đang đứng (chạy trong `src/` thì log nằm ở
  `src/output/...`). Đã đổi sang tính từ thư mục dự án.

## 4. Kiểm thử

- Phát lại theo nhịp thật, dừng sau 1 giây: trả về trong vài giây, lý do `SIGTERM`, `finish()` đã chạy
  (không còn cửa sổ hay sự kiện mở).
- Hàng đợi có 50 gói, bộ máy chậm, `stop_timeout_s = 0`: phần còn lại bị bỏ, xử lý + bỏ = 50, `finish()` vẫn
  chạy.
- Gửi SIGINT thật vào tiến trình kiểm thử: trình xử lý gọi dừng với lý do `SIGINT`.
- Log xoay vòng: ghi vượt dung lượng tạo đúng `.log`, `.log.1`, `.log.2`.
- Chạy thật hai lần cùng tên: lần hai giữ kết quả lần một ở `t06.cu.*`, log ghi cảnh báo, mã thoát 0.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Tín hiệu (signal) | Thông báo hệ điều hành gửi cho tiến trình, ví dụ yêu cầu dừng |
| SIGINT, SIGTERM, SIGHUP | Ctrl+C; yêu cầu dừng từ hệ thống; mất terminal |
| Dừng êm | Dừng sau khi làm xong việc dở và lưu kết quả |
| Mã thoát | Số chương trình trả về khi kết thúc; 0 là bình thường |
| Log xoay vòng | Log đầy thì đổi tên sang bản cũ và mở file mới; chỉ giữ một số bản |
| Traceback | Chuỗi lời gọi hàm dẫn tới lỗi |
