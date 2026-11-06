# C10-T07 — Cấu hình chạy nền bằng systemd

Tệp: `deploy/nids-realtime.service` (unit), `deploy/nids-realtime.env` (tham số), `scripts/cai_dich_vu.sh`
(cài đặt). Kiểm thử: `tests/test_realtime.py`.

> **Trạng thái: chưa cài trên Kali thật.** Unit, file môi trường và script đã được kiểm thử tự động: các tham
> số `ExecStart` sau khi thay biến được chương trình chấp nhận, script qua `bash -n`, mọi file dùng LF.
> Khi cài trên Kali, ghi kết quả `systemctl status` và `journalctl` vào mục 6.

## 1. Cài đặt (trên Kali, sau `scripts/cai_dat_kali.sh`)

```bash
cd /opt/ml-nids
sudo bash scripts/cai_dich_vu.sh --iface eth1 --net 192.168.50.0/24
```

Script làm:
1. tạo user hệ thống `nids` (không đăng nhập được);
2. giao `output/` và `data/run_logs/` cho user này, cho phép user này đọc mã, cấu hình, mô hình;
3. chép `deploy/nids-realtime.env` vào `/etc/ml-nids/` (chỉ lần đầu, không ghi đè bản đã sửa); điền card
   mạng và mạng giám sát nếu có tham số;
4. cài unit vào `/etc/systemd/system/`, `daemon-reload`, `systemd-analyze verify`;
5. **chặn máy tự ngủ** (`systemctl mask sleep.target suspend.target ...`). Trên máy phát triển, một lần đo
   hiệu năng đã hỏng vì máy ngủ giữa chừng (docs/63);
6. bật dịch vụ khi khởi động và chạy ngay (`--khong-bat` để chỉ cài).

## 2. Unit (QĐ-055)

| Mục | Giá trị | Vì sao |
|---|---|---|
| `User=nids` | Không chạy bằng root | Cảm biến đọc traffic không tin cậy; lỗi phân tích gói không được có quyền root |
| `AmbientCapabilities` | `CAP_NET_RAW CAP_NET_ADMIN` | Đủ để mở AF_PACKET và bật promiscuous; không cần `setcap` lên file python |
| `ExecStartPre` | `python -m nids.pipeline kiem-tra` | Mô hình thiếu hoặc sai đầu vào thì không khởi động (C09-T01) |
| `ExecStart` | `python -m nids.realtime --iface ${NIDS_IFACE} --out /opt/ml-nids/output/realtime --im-lang $NIDS_ARGS` | Tham số từ `/etc/ml-nids/nids-realtime.env`; `--im-lang`: log vào file, không in cảnh báo ra journal |
| `KillSignal=SIGTERM`, `TimeoutStopSec=45` | Lâu hơn `stop_timeout_s` = 30 giây | Đủ thời gian dừng êm (C10-T06) trước khi systemd giết |
| `Restart=on-failure`, `RestartSec=10`, tối đa 5 lần trong 10 phút | | Lỗi (mã khác 0) thì khởi động lại; dừng bình thường (mã 0) thì không |
| `MemoryMax=1500M`, `CPUQuota=150%` | Đo thật: 200–400 MB, tối đa 93% một lõi (docs/63) | Không để cảm biến làm treo máy giám sát |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths` | Chỉ ghi được `output/` và `data/run_logs/` | Giảm thiệt hại nếu chương trình bị khai thác |

Mỗi lần dịch vụ khởi động là một lần chạy mới, với tên `realtime_YYYYmmdd_HHMMSS`. File kết quả của các lần
chạy không lẫn vào nhau.

## 3. Khởi động, dừng, theo dõi

```bash
sudo systemctl start nids-realtime        # khởi động
sudo systemctl stop nids-realtime         # dừng êm (SIGTERM → xử lý nốt hàng đợi → ghi số liệu cuối)
sudo systemctl restart nids-realtime      # dừng rồi chạy lại (ví dụ sau khi đổi /etc/ml-nids/nids-realtime.env)
sudo systemctl enable nids-realtime       # tự chạy khi bật máy
systemctl status nids-realtime            # trạng thái, PID, RAM
journalctl -u nids-realtime -f            # đầu ra của dịch vụ (khởi động, lỗi, số liệu cuối)
tail -f /opt/ml-nids/output/realtime/log/nids_realtime.log      # log chi tiết, số liệu mỗi 10 giây
tail -f /opt/ml-nids/output/realtime/realtime_*.su_kien.csv      # sự kiện đã gộp
```

Kết quả nằm ở `/opt/ml-nids/output/realtime/`: `<tên>.alerts.csv`, `.su_kien.csv`, `.so_lieu.jsonl`,
`.so_lieu_tong.json` (khi dừng).

## 4. Cập nhật phiên bản

```bash
sudo systemctl stop nids-realtime
cd /opt/ml-nids && git pull --ff-only && .venv/bin/pip install -q -e .
# nếu có mô hình mới: chép vào models/, rồi kiểm tra
.venv/bin/python -m nids.pipeline kiem-tra
sudo systemctl start nids-realtime
```

## 5. Sửa ở chặng trước: ký tự xuống dòng

Thêm `.gitattributes`: `*.sh`, `deploy/*`, `*.py`, `*.yaml` luôn dùng **LF**. Trên máy Windows (git
`autocrlf`), bản làm việc của `scripts/cai_dat_kali.sh` trước đây là CRLF. Nếu chép thẳng file đó sang Kali,
bash sẽ báo lỗi `$'\r': command not found`. Repo vẫn lưu LF, nên clone trên Kali không bị ảnh hưởng. Kiểm thử
mới kiểm tra mọi script và file dịch vụ đều là LF.

## 6. Kết quả trên Kali

Chưa có. Cần ghi: kết quả `systemd-analyze verify`, `systemctl status` sau khi khởi động, một lần
`systemctl stop` (log phải có dòng "dừng (SIGTERM)"), và một lần khởi động lại máy (dịch vụ tự chạy).

## 7. Kiểm thử

- Unit:
  - chạy bằng `nids`, chỉ hai quyền mạng;
  - dừng bằng SIGTERM, `TimeoutStopSec` lớn hơn `stop_timeout_s` của cấu hình;
  - khởi động lại khi lỗi; chỉ ghi được thư mục kết quả.
- `ExecStart` sau khi thay `${NIDS_IFACE}` và `$NIDS_ARGS` từ file môi trường được bộ đọc tham số của
  `nids.realtime` chấp nhận: card, mạng, chế độ, `--im-lang`. `ExecStartPre` là `pipeline kiem-tra`.
- Mọi script và file dịch vụ là LF; `bash -n` không lỗi.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| systemd, unit | Trình quản lý dịch vụ của Linux; file mô tả một dịch vụ |
| Dịch vụ chạy nền | Chương trình chạy không cần terminal, tự khởi động cùng máy |
| `journalctl` | Lệnh xem đầu ra của các dịch vụ systemd |
| Capability | Một phần quyền của root cấp riêng cho chương trình |
| File môi trường | File chứa biến (`TEN=gia_tri`) systemd đọc trước khi chạy dịch vụ |
| LF, CRLF | Ký tự xuống dòng của Linux; của Windows (thêm `\r`) |
| `.gitattributes` | File quy định cách git xử lý từng loại file, ví dụ ký tự xuống dòng |
