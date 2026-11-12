# C03-T06 — Xuất log thành bảng và đối chiếu với bản gốc

Mã nguồn: `src/nids/service_log.py` (`csv_row()`, `write_csv()`, tùy chọn
`--csv`, `--stats`) và `src/nids/log_compare.py`. Kiểm thử:
`tests/test_log_compare.py`. Parser: [15_parser_log.md](15_parser_log.md).

## 1. Bảng CSV

```bash
python -m nids.service_log data/service_logs/<run_id>/access_nids.log \
    --csv output/<run_id>_log.csv --stats output/<run_id>_log_stats.json
```

Mỗi dòng log đọc được thành một dòng CSV (UTF-8, có dòng tiêu đề). Dòng bị bỏ
qua không có trong bảng nhưng được đếm trong file thống kê JSON.

| Cột | Ví dụ | Ghi chú |
|---|---|---|
| `line_no` | `24` | Số dòng trong file gốc, khóa để đối chiếu |
| `ts` | `1792748395.988` | Giữ đúng dạng `$msec` của dòng gốc |
| `start_ts` | `1792748395.860` | `ts − request_time`: thời điểm bắt đầu yêu cầu, dùng khi ghép với flow |
| `client_ip`, `client_port`, `server_port` | `127.0.0.1`, `49340`, `18080` | Cổng trống khi Nginx ghi `-` |
| `request` | `GET /slow/a HTTP/1.1` | Dòng yêu cầu đã giải mã `\xHH` |
| `method`, `target`, `http_version` | `GET`, `/slow/a`, `HTTP/1.1` | Trống khi yêu cầu không hợp lệ |
| `status`, `body_bytes`, `request_bytes` | `200`, `12`, `66` | |
| `request_time_ms` | `128` | Mili giây |
| `conn_id`, `conn_requests` | `8`, `2` | Yêu cầu thứ 2 trên kết nối keep-alive số 8 |
| `user_agent` | `kiểm "tra" \ UA` | Đã giải mã; trống khi Nginx ghi `-` |
| `valid_request` | `1` | `0` khi dòng yêu cầu không có dạng `METHOD target HTTP/x` |

Ô có ký tự điều khiển (dòng yêu cầu là byte TLS) được module `csv` đặt trong
ngoặc kép; đọc lại bằng `csv` hoặc `pandas.read_csv` cho đúng chuỗi ban đầu.

## 2. Cách đối chiếu

```bash
python -m nids.log_compare data/service_logs/<run_id>/access_nids.log output/<run_id>_log.csv -k 20
```

**Cách đọc độc lập.** Công cụ đối chiếu không dùng lại regex hay hàm giải mã
của parser. Nó đọc lại dòng gốc theo `line_no`, tách 12 trường bằng cách duyệt
từng ký tự, giải mã `\xHH` bằng codec `unicode_escape` có sẵn của Python, tính
`start_ts` bằng `Decimal`. Kết quả phải trùng với từng ô của CSV. Nếu parser
tách nhầm trường, lệch thứ tự cột hay làm tròn sai thì hai cách sẽ khác nhau.

**Dòng được chọn** (mặc định): dòng đầu, dòng cuối, một dòng cho mỗi mã trạng
thái, tối đa 5 dòng có yêu cầu không hợp lệ, và `k` dòng ngẫu nhiên với seed cố
định 42 để chạy lại cho cùng mẫu. `--all` đối chiếu mọi dòng.

**Kiểm tra cả bảng:** `line_no` tăng dần và không trùng, không vượt số dòng của
file gốc; mọi dòng gốc tách được 12 trường đều phải có trong CSV (không sót dòng
hợp lệ). Với dòng hợp lệ, `method`, `target`, `http_version` ghép lại phải ra
đúng `request`.

`--show N` in N dòng mẫu cạnh nhau (gốc / CSV) để xem bằng mắt. Lệnh trả mã
thoát 1 nếu có lệch.

## 3. Kết quả

Dữ liệu là log thật do Nginx 1.26.3 ghi theo `log_format nids` trên máy phát
triển (ngày 21 và 23/10/2026). Lab chưa dựng nên chưa có log của máy chủ dịch
vụ.

| Log | Dòng | Nội dung | Mẫu | Toàn bộ |
|---|---|---|---|---|
| Log thử tình huống (C03-T05) | 13 | 200, 400, 404, 408, 499, 502; byte TLS; tiếng Việt; dòng yêu cầu 3 000 byte | — | 13/13 khớp |
| Log tải song song | 457 | 8 client song song, 217 yêu cầu keep-alive, 122 yêu cầu qua upstream chậm (tới 506 ms), 108 dòng không có User-Agent, 86 dòng UA có tiếng Việt và ký tự `"` `\`, 23 dòng yêu cầu không hợp lệ | 28/28 khớp | 457/457 khớp |

Một số dòng trong mẫu đối chiếu của log 457 dòng:

| Dòng | Trong log gốc | Trong CSV |
|---|---|---|
| 1 | `"GET /50x.html HTTP/1.1" 404 153 37 0.000 4 1 "-"` | `GET` / `/50x.html` / `HTTP/1.1`, status 404, `user_agent` trống |
| 13 | `"GET /a%20b?q=%22 HTTP/1.1" ... "ki\xE1\xBB\x83m \x22tra\x22 \x5C UA"` | `target` giữ `%20`, `%22`; `user_agent` = `kiểm "tra" \ UA` |
| 24 | `1792748395.988 ... "GET /slow/a HTTP/1.1" 200 12 66 0.128 8 2` | `start_ts` = `1792748395.860`, `request_time_ms` = 128, kết nối 8 yêu cầu thứ 2 |
| 15 | `"OPTIONS / RTSP/1.0" 400` | `valid_request` = 0, `method`/`target` trống, `request` giữ nguyên |
| 28 | `"\x16\x03\x01\x00\xA5" 400` | `request` = byte điều khiển `\x16\x03\x01\x00` và chữ `\xa5` (byte không phải UTF-8) |

Dòng `OPTIONS / RTSP/1.0` chính là một mẫu dò của `nmap -sV`; đây là lý do giữ
lại dòng yêu cầu không hợp lệ (mục 3 của tài liệu 15).

**Kiểm thử tự động** (12 ca, tổng 92 ca): tách trường trên 12 dòng thật, dòng
thiếu ngoặc và thừa trường, cột và ô trống của CSV, CSV giữ được ký tự điều
khiển, đối chiếu toàn bộ khớp, và công cụ **phát hiện được** ô bị sửa (cổng,
User-Agent, thời gian phục vụ), `line_no` bị lệch, dòng bị mất, `target` bị
tách sai; mẫu luôn có dòng đầu, dòng cuối, mọi mã trạng thái và các yêu cầu
không hợp lệ; mã thoát của lệnh.

## 4. Nhận xét từ log thật

- Trên log 457 dòng, `ts` không giảm lần nào nhưng `start_ts` nhỏ hơn dòng trước
  90 lần. `$msec` là lúc ghi log nên tăng dần theo thứ tự ghi; yêu cầu chậm bắt
  đầu sớm nhưng được ghi muộn. Khi ghép với flow theo thời điểm bắt đầu phải sắp
  xếp lại theo `start_ts`.
- `start_ts` chỉ chính xác tới mili giây, và `$request_time` tính từ khi Nginx
  đọc byte đầu tiên của yêu cầu, không phải từ lúc bắt tay TCP. Cửa sổ ghép với
  flow cần dung sai vài chục mili giây; chốt khi làm phần ghép ở chặng sau.

## 5. Kiểm tra trên Nginx của máy chủ dịch vụ lab (12/11/2026)

Trước đây parser chỉ được thử trên Nginx chạy trên Windows (xuống dòng CRLF, một worker). Lab ảo (docs/70) chạy
**Nginx 1.28.3 trên Linux, 2 worker, xuống dòng LF**, với đúng `log_format nids`. Mỗi lần chạy có một file
`data/service_logs/<run_id>/access_nids.log`. Chạy `nids.service_log` rồi `nids.log_compare --all` trên cả 55
file (`docs/hinh/log_lab.json`):

| Chỉ số | Giá trị |
|---|---|
| File log | 55 (11 biến thể × 5 lần chạy) |
| Dòng log | 33 003 |
| Dòng đọc được | **33 003 (100%)**, không dòng nào bị bỏ qua |
| Dòng đối chiếu với file gốc (mọi dòng) | 33 003, **lệch 0** |
| Mã trạng thái | 200: 32 751; 400: 252 |
| Ghi chú `dong_yeu_cau_khong_hop_le` | 252 |
| Ghi chú `thoi_gian_giam` | 2 |
| File có CRLF | 0 |

- **252 dòng mã 400** là của đối chứng `k4-doi-chung`: ba máy gửi chuỗi `nids-lab thong diep vo hai` tới cổng 80
  thay vì một yêu cầu HTTP. Nginx ghi nguyên chuỗi đó vào trường yêu cầu; parser giữ dòng, đánh ghi chú yêu cầu
  không hợp lệ, không bỏ.
- **2 dòng có thời gian lùi** so với dòng trước: hai worker ghi xen kẽ nên thứ tự dòng không hoàn toàn theo
  thời gian. Parser chỉ ghi chú, không sắp lại.
- **Kết nối của tải kết nối (kịch bản 3) không xuất hiện trong log**: máy tấn công mở rồi đóng kết nối mà không
  gửi yêu cầu, Nginx không ghi dòng nào. Log vì vậy không đếm được số kết nối tấn công; chỉ thấy client hợp
  lệ vẫn được phục vụ (docs/71 mục 3).

## 6. Ghép dòng log với flow và dung sai thời gian (QĐ-067)

Mã nguồn: `src/nids/log_flow.py`. Kiểm thử: `tests/test_log_flow.py`. Số liệu: `docs/hinh/log_flow.json`.

```bash
cd src
python -m nids.log_flow ../data/pcap/lab/k*.pcap --log-dir ../data/service_logs --out ../docs/hinh
```

Một dòng log khớp một flow TCP khi một đầu của flow là (IP client, cổng client) của dòng log, đầu kia dùng cổng
máy chủ của dòng log, và thời điểm ghi log (`$msec`, lúc yêu cầu kết thúc) nằm trong khoảng sống của flow, nới
thêm mỗi đầu một **dung sai**. Cùng (IP, cổng client) có thể có nhiều flow vì hệ điều hành dùng lại cổng nguồn;
khi đó lấy flow gần thời điểm ghi log nhất.

Đo trên 55 lần chạy lab (33 003 dòng log; máy chủ và máy giám sát chung đồng hồ):

| Dung sai | Dòng ghép được | Dòng khớp hơn một flow |
|---|---|---|
| 0 | 10 461 (31,7%) | 0 |
| 0,001 s | **33 003 (100%)** | 0 |
| 0,01 s; 0,1 s | 33 003 (100%) | 0 |
| **1 s** | **33 003 (100%)** | **0** |
| 5 s | 33 003 (100%) | 4 |
| 60 s | 33 003 (100%) | 68 |

- **Mọi dòng log đều có flow cùng (IP, cổng client, cổng máy chủ)**; khoảng cách lớn nhất tới flow là 0,91 mili
  giây. 68% dòng được ghi **sau** gói cuối của flow dưới 1 mili giây, vì `$msec` làm tròn tới mili giây và
  Nginx ghi log sau khi đóng kết nối. Dung sai 0 vì vậy không đủ.
- **Dung sai quá rộng làm ghép không còn duy nhất**: từ 5 giây, một dòng có thể khớp hai flow dùng lại cùng
  cổng nguồn.
- **Chốt `service_log.match_tolerance_s` = 1 giây**: lớn hơn 1 000 lần phần lệch đo được, vẫn ghép duy nhất, và
  đủ cho đồng hồ đồng bộ NTP trong mạng LAN (lệch cỡ mili giây tới vài chục mili giây). Lab vật lý phải trừ độ
  lệch đồng hồ ghi trong nhật ký lần chạy trước khi ghép; nếu lệch còn lại vượt 1 giây thì phải đồng bộ lại
  chứ không nới dung sai.
- **Chiều ngược lại**: flow tới cổng 80 không có dòng log là kết nối không gửi yêu cầu — lần thử cổng 80 của
  Nmap (1 flow mỗi lần quét) và toàn bộ kết nối của tải kết nối (3 000 ở mức 1, 12 000 ở mức 2). Mọi flow của
  client hợp lệ đều có dòng log.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Đối chiếu | So kết quả của chương trình với dữ liệu gốc để chắc là đúng |
| Cách đọc độc lập | Đọc lại dữ liệu bằng một cách khác hẳn chương trình chính; hai cách cùng kết quả thì đáng tin hơn |
| Codec `unicode_escape` | Bộ giải mã có sẵn của Python, đổi chuỗi `\xHH` thành ký tự |
| Decimal | Kiểu số thập phân chính xác của Python, không sai số như float |
| Seed | Số khởi đầu cho bộ chọn ngẫu nhiên; cùng seed thì lần nào cũng chọn ra cùng các dòng |
| Mẫu (sample) | Một số dòng được chọn ra để kiểm tra thay vì kiểm tra hết |
| Ký tự điều khiển | Ký tự không in ra được như xuống dòng, tab hay byte 0x16 |
| pandas.read_csv | Hàm của thư viện pandas đọc file CSV thành bảng |
| Mã thoát | Số chương trình trả về khi kết thúc: 0 là khớp, 1 là có lệch |
| Dung sai | Khoảng chênh lệch cho phép khi so hai thời điểm |
| Bắt tay TCP | Ba gói mở kết nối (SYN, SYN+ACK, ACK) trước khi gửi yêu cầu |
