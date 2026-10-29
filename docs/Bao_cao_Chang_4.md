# Báo cáo Chặng 4 — Xây dựng flow và đặc trưng

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 25/10/2026 – 29/10/2026 |
| Trạng thái | Xong 8/8 task |
| Chặng trước | [Bao_cao_Chang_3.md](Bao_cao_Chang_3.md) |

## 1. Tóm tắt

Chặng 4 biến bảng packet của Chặng 3 thành **hai bảng đặc trưng** cho mô hình học
máy: bảng **flow** (mỗi kết nối một dòng) và bảng **cửa sổ host** (mỗi máy trong mỗi
10 giây một dòng).

```
Gói IP (Chặng 3) ─┬─> ghép flow hai chiều ──> kết thúc flow ──> đặc trưng flow ─────────┐
                  │   (C04-T01)               (C04-T02)         (C04-T03, T04)          │
                  │                                                                     ├─> bảng + schema
                  └─> cửa sổ host 10 giây ──> đặc trưng cửa sổ ──> kết nối không ───────┘   + metadata
                      bước 2 giây (C04-T05)   (C04-T06)            hoàn tất (C04-T07)       (C04-T08)
```

Tiêu chí nghiệm thu của chặng đã đạt:

| Tiêu chí | Cách đáp ứng |
|---|---|
| Công thức, đơn vị và trường hợp biên được ghi rõ | Mỗi task có tài liệu riêng (docs/18 đến 25) với bảng công thức, đơn vị và trường hợp biên. Schema của bảng xuất ra ghi đơn vị, kiểu, có thể trống không của từng cột |
| Đặc trưng không dùng dữ liệu tương lai | Mọi quyết định chỉ dựa vào gói đã tới. Thời gian tính theo thời điểm của gói. Kiểm thử xác nhận chạy dần từng gói và chạy một lần cho cùng kết quả |
| SYN thiếu phản hồi là dấu hiệu nghi vấn, không tự động gán nhãn scan | Tỷ lệ không hoàn tất chỉ là cột đặc trưng; nhãn gán ở Chặng 5 theo lịch tấn công. Dữ liệu thật cho thấy host bình thường cũng có cửa sổ tỷ lệ cao |

Mọi đặc trưng đã được **kiểm tra độc lập với Wireshark**: các script viết riêng tính
lại đặc trưng từ đầu ra của tshark, không dùng mã của dự án, rồi so từng ô.

Trong chặng cũng đã tải đủ **dữ liệu CIC-IDS2017** (PCAP thứ Hai, thứ Tư, thứ Sáu và
CSV có nhãn) và xác nhận lịch tấn công trên dữ liệu thật.

## 2. Các task

| Task | Nội dung | Trạng thái | Mã nguồn | Tài liệu |
|---|---|---|---|---|
| C04-T01 | Định nghĩa flow hai chiều và quy tắc forward/backward | Xong | `src/nids/flows.py` | [18_flow_hai_chieu.md](18_flow_hai_chieu.md) |
| C04-T02 | Xử lý timeout, FIN/RST và tái sử dụng 5-tuple | Xong | `src/nids/flows.py` | [19_ket_thuc_flow.md](19_ket_thuc_flow.md) |
| C04-T03 | Tính packet, byte, thời lượng và tỷ lệ gửi/nhận | Xong | `src/nids/flow_features.py` | [20_dac_trung_flow_co_ban.md](20_dac_trung_flow_co_ban.md) |
| C04-T04 | Tính thống kê kích thước, inter-arrival time và cờ TCP | Xong | `src/nids/flow_features.py` | [21_thong_ke_flow.md](21_thong_ke_flow.md) |
| C04-T05 | Xây dựng cửa sổ host theo thời gian packet | Xong | `src/nids/host_windows.py` | [22_cua_so_host.md](22_cua_so_host.md) |
| C04-T06 | Tính số đích, cổng đích, kết nối mới và entropy cổng | Xong | `src/nids/window_features.py` | [23_dac_trung_cua_so.md](23_dac_trung_cua_so.md) |
| C04-T07 | Tính tỷ lệ kết nối không hoàn tất sau thời gian quan sát quy định | Xong | `src/nids/window_features.py` | [24_ket_noi_khong_hoan_tat.md](24_ket_noi_khong_hoan_tat.md) |
| C04-T08 | Xuất bảng đặc trưng cùng schema và metadata | Xong | `src/nids/feature_export.py` | [25_xuat_bang_dac_trung.md](25_xuat_bang_dac_trung.md) |

Ngoài kế hoạch: `src/nids/pcap_survey.py` (khảo sát bản thu lớn) và
`python -m nids.manifest --verify` (kiểm tra mã băm dữ liệu đã tải), làm khi nhận dữ
liệu CIC.

## 3. Kết quả từng task

### 3.1. C04-T01 — Flow hai chiều, forward/backward

- **Flow hai chiều** gồm các gói cùng phiên bản IP, giao thức và cặp đầu mút (IP,
  cổng); gói đi và gói về chung một flow.
- **Forward** là chiều của bên mở kết nối (client). Client được chọn một lần từ gói
  đầu tiên, theo thứ tự: gói SYN, gói SYN+ACK, cổng dịch vụ (với TCP bắt giữa
  chừng), và cuối cùng là bên gửi gói đầu. Mỗi flow ghi lại quy tắc đã dùng
  (`direction_basis`).
- Mảnh IP sau mảnh đầu không có cổng, nên được gắn vào đúng flow nhờ trường
  Identification (`frag_id`, thêm vào bảng packet).
- **Kiểm tra:** chiều đúng ở toàn bộ 3,3 triệu gói có SYN trên 5 bản thu thật.

### 3.2. C04-T02 — Kết thúc flow

Flow kết thúc khi xảy ra một trong các trường hợp sau, theo thứ tự ưu tiên:
1. TCP đã đóng (FIN hai chiều hoặc RST) và gặp gói có cờ SYN, hoặc đã quá 10 giây
   sau khi đóng.
2. Nhàn rỗi quá 60 giây.
3. Có gói bắt tay mới trên cùng 5-tuple.
4. Flow dài quá 120 giây, giống CICFlowMeter.

Để phân biệt **gói bắt tay gửi lại** với **kết nối mới**, bảng packet có thêm số thứ tự
TCP (`tcp_seq`). Phần sau của một kết nối giữ chiều của phần trước (`continuation`).

- Chọn 10 giây dựa trên đo đạc: 97% gói tới sau FIN/RST nằm trong 10 giây.
- Trên bản thu toàn mạng CTU-13 (4,5 triệu gói), số flow gộp hai kết nối mà
  Wireshark tách riêng giảm từ 77 xuống 2. Hai trường hợp còn lại là SYN+ACK gửi lại:
  dự án gộp là đúng.

### 3.3. C04-T03 — Gói, byte, thời lượng, tỷ lệ gửi/nhận

- **Byte dùng `ip_len`** (QĐ-018, chốt câu hỏi còn mở từ Chặng 3). Dùng thêm
  **payload** TCP/UDP, vì CIC tính độ dài theo payload và gói rỗng (payload 0) là dấu
  hiệu của quét.
- **Tỷ lệ gửi/nhận** là phần của chiều forward trong tổng (0–1), không chia hai chiều
  cho nhau. Phép chia sẽ ra vô hạn khi một chiều không có gói: ở donbot có 4 249 trên
  4 588 flow là SYN không được trả lời.
- **Kiểm tra:** payload từng gói khớp Wireshark trên 4,48 triệu gói. Tổng byte của các
  flow bằng tổng byte của các gói trên mọi file.

### 3.4. C04-T04 — Thống kê kích thước, inter-arrival time, cờ TCP

- Bốn số min/max/trung bình/độ lệch chuẩn của kích thước gói và khoảng cách giữa hai
  gói, cho cả flow và từng chiều. Thêm số gói mang từng cờ trong 8 cờ TCP. Tổng cộng
  32 cột.
- Tính dần bằng thuật toán Welford, nên bộ nhớ không tăng theo độ dài flow. Cột không
  có dữ liệu (ví dụ khoảng cách của flow một gói) để **trống**, không ghi 0.
- **Kiểm tra:** 6 100 flow, mỗi flow 39 cột, so với Wireshark: 0 lệch. Cố ý làm sai
  một giá trị thì script so sánh bắt được ở 82/82 flow.

### 3.5. C04-T05 — Cửa sổ host

- Cửa sổ dài 10 giây, bước 2 giây, bắt đầu tại bội số của 2 giây tính từ epoch. Nhờ
  vậy đọc file hay chạy realtime đều cắt cửa sổ ở cùng chỗ.
- Thời gian trôi theo thời điểm của gói. Cửa sổ đóng khi đã thấy gói có thời điểm từ
  lúc kết thúc của cửa sổ trở đi; gói đến trễ được đếm riêng.
- Có thể giới hạn host theo dải mạng (`--net 192.168.10.0/24`).
- **Kiểm tra:** tính vét cạn từ tshark trên 27 528 cửa sổ: 0 thiếu, 0 thừa, 0 lệch.

### 3.6. C04-T06 — Số đích, cổng đích, kết nối mới, entropy cổng

- 7 cột: số IP đích, số cổng đích, số cặp (IP, cổng), số kết nối mới ra và vào, số
  IP nguồn, entropy cổng đích.
- **Chỉ đếm gói host gửi trong vai client.** Nếu đếm cả gói trả lời, server web trả
  lời nhiều client sẽ trông như máy quét cổng.
- Trên đoạn port scan của CIC: bên quét tới 1 host, 998 cổng, 6 986 kết nối mới trong
  10 giây, entropy 9,95 bit.
- **Kiểm tra:** 3 537 cửa sổ trên 3 file so với tshark: 0 lệch.

### 3.7. C04-T07 — Kết nối không hoàn tất

- Mỗi lần thử TCP được xếp loại **sau 3 giây quan sát** thành `hoan_tat`, `do_dang`,
  `bi_tu_choi` hoặc `khong_phan_hoi`. Từ đó tính tỷ lệ không hoàn tất cho chiều ra
  (dấu hiệu quét) và chiều vào (dấu hiệu SYN flood).
- Cửa sổ chờ thêm 3 giây mới trả ra, để không dùng gói tới quá thời gian quan sát.
- Trên đoạn port scan của CIC: bên quét có 99,5% lần thử không hoàn tất. Host bình
  thường có trung vị là 0, nhưng 97 trên 629 cửa sổ vẫn trên 0,5. Vì vậy cột này
  chỉ là dấu hiệu nghi vấn, đúng với nghiệm thu.
- **Kiểm tra:** xếp loại lại theo `tcp.stream` của tshark trên 3 file: 0 lệch.

### 3.8. C04-T08 — Bảng đặc trưng, schema, metadata

- Một lệnh, một lượt đọc, ra 4 file: bảng flow (58 cột), bảng cửa sổ (25 cột),
  schema và metadata.
- **Schema** ghi vai trò của từng cột. IP, cổng và thời điểm có vai trò `dinh_danh`:
  chỉ dùng để gán nhãn và chia dữ liệu, không đưa vào mô hình.
- **Metadata** ghi mã băm của nguồn, commit git, tham số và thống kê.
- `read_table` đọc lại đúng kiểu và từ chối bảng lệch schema.
- **Trên CIC thứ Tư** (13,4 GB): 24 phút, ra 506 163 flow và 163 431 cửa sổ, đọc lại
  không lỗi. Cửa sổ của web server lúc Hulk tấn công có 19 412 gói vào và 2 508 kết
  nối mới trong 10 giây; lúc bình thường là 50 gói và 1 kết nối.

## 4. Dữ liệu CIC-IDS2017

Đã tải và kiểm tra đủ (docs/06, mục 7):

| File | Kích thước | Gói | Flow |
|---|---|---|---|
| `Monday-WorkingHours.pcap` | 10,8 GB | 11 709 971 | 381 707 |
| `Wednesday-workingHours.pcap` | 13,4 GB | 13 788 878 | 506 163 |
| `Friday-WorkingHours.pcap` | 8,8 GB | 9 997 874 | 555 024 |
| `GeneratedLabelledFlows.zip` | 284 MB | 8 file CSV có nhãn | |

Các phát hiện quan trọng cho Chặng 5:
- **Lịch tấn công là giờ UTC−3** và khớp dữ liệu tới từng phút, cả DoS lẫn port scan
  và DDoS. Gán nhãn phải cộng 3 giờ để đổi sang UTC.
- **Bên tấn công hiện là `172.16.0.1`** (NAT) cho mọi loại tấn công. Port scan và
  DDoS cùng IP nguồn và cùng nạn nhân, nên phải tách theo khung giờ.
- **Cột `Timestamp` của CSV** ghi giờ kiểu 12 tiếng nhưng mất SA/CH. Có vài flow bị
  gán nhãn nằm ngoài lịch tấn công.
- Ba PCAP có đuôi `.pcap` nhưng thực chất là PCAPNG.
- Số flow từng nhãn của CSV khớp đúng số thường được trích dẫn.

## 5. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-016 | Flow hai chiều; forward là chiều của bên mở kết nối | Đã chốt |
| QĐ-017 | Kết thúc flow: FIN/RST có thời gian chờ, gói bắt tay mới, timeout nhàn rỗi và active timeout | Tạm thời |
| QĐ-018 | Đặc trưng byte dùng `ip_len` kèm payload; tỷ lệ gửi/nhận là phần trong tổng | Đã chốt |
| QĐ-019 | Dữ liệu tải về: nơi đặt, mã băm, múi giờ của CIC-IDS2017 | Đã chốt |
| QĐ-020 | Thống kê theo gói: `ip_len`, độ lệch chuẩn tổng thể, ô trống khi không có dữ liệu | Đã chốt |
| QĐ-021 | Cửa sổ host theo thời gian gói, lưới cửa sổ cố định theo epoch | Đã chốt |
| QĐ-022 | Đặc trưng cửa sổ host tính theo vai client/server của flow | Đã chốt |
| QĐ-023 | Kết nối không hoàn tất xét sau 3 giây quan sát; cửa sổ chờ thêm 3 giây | Tạm thời |
| QĐ-024 | Bảng đặc trưng: hai bảng CSV, schema có vai trò cột, metadata truy vết | Đã chốt |

Tham số thời gian (60, 120, 10, 3 giây; cửa sổ 10/2 giây) đều nằm trong
`config/default.yaml` và sẽ chỉnh trên tập validation (QĐ-006).

## 6. Kiểm thử

`python -m unittest discover -s tests`: **228/228 ca đạt** (Chặng 3 kết thúc ở 103).

| File | Số ca | Nội dung |
|---|---|---|
| `tests/test_flows.py` | 49 | Khóa flow, chọn client, mảnh IP, FIN/RST, timeout, số thứ tự TCP, chạy dần |
| `tests/test_flow_features.py` | 22 | Gói, byte, payload, thời lượng, tỷ lệ; Welford, kích thước, IAT, cờ |
| `tests/test_host_windows.py` | 17 | Danh sách cửa sổ, biên, lọc dải mạng, gói trễ, thời gian chờ |
| `tests/test_window_features.py` | 16 | Entropy, quét dọc/ngang, vai server, kết nối mới, bốn loại lần thử |
| `tests/test_feature_export.py` | 8 | Schema, bốn file, đọc lại, từ chối bảng sai |
| `tests/test_pcap_survey.py` | 4 | Khảo sát, mã băm, theo dõi cặp IP |
| Chặng 1–3 (có bổ sung `frag_id`, `tcp_seq`, `payload_len`, mã băm manifest) | 112 | |

**Kiểm tra trên dữ liệu thật** (script tạm, tính độc lập từ tshark):

| Phần | Dữ liệu | Kết quả |
|---|---|---|
| Chiều flow | 5 bản thu CTU-13, WSL | 3,3 triệu gói, 0 sai chiều (sau C04-T02) |
| Trường mới của packet (`tcp_seq`, `payload_len`) | 4,48 triệu gói CTU-13; 1 triệu gói đầu mỗi file CIC | 0 lệch |
| Đặc trưng flow (39 cột) | 6 100 flow | 0 lệch |
| Cửa sổ host, đặc trưng cửa sổ, kết nối không hoàn tất | CIC port scan, donbot, WSL | 0 lệch |

## 7. Cách chạy

```bash
python -m nids.manifest --verify                       # kiểm tra dữ liệu đã tải
python -m nids.pcap_survey data/pcap/<file>.pcap --report output/survey.json
python -m nids.flows data/pcap/<file>.pcap --csv output/flows.csv
python -m nids.host_windows data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/host_windows.csv
python -m nids.window_features data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/windows.csv
python -m nids.feature_export data/pcap/<file>.pcap --net 192.168.10.0/24 --out output/features
```

Lệnh cuối là lệnh chính cho Chặng 5; các lệnh còn lại để xem từng bước.

## 8. Điểm cần lưu ý

1. **Tốc độ.** Xuất bảng một file CIC 13 GB mất 24 phút, khoảng 9 600 gói/giây trên
   máy phát triển. Đủ cho lab 7 máy, nhưng phải đo trên Kali trước khi chạy realtime.
2. **Tham số tạm thời.** Timeout 60/120/10 giây và thời gian quan sát 3 giây chưa
   chỉnh trên validation (QĐ-017, QĐ-023).
3. **Dữ liệu thật mới có CIC-IDS2017.** 11 file `.binetflow` của CTU-13 và dữ liệu lab
   vẫn chưa có (xem [Viec_con_thieu_Chang_1_3.md](Viec_con_thieu_Chang_1_3.md)).
   Module botnet cần CTU-13.
4. **Host sau NAT.** Ở CIC, mọi traffic tấn công là `172.16.0.1`, nên đặc trưng cửa sổ
   của "máy tấn công" thực ra gộp mọi máy tấn công.
5. **DoS của CIC là tầng HTTP.** Hulk có tỷ lệ không hoàn tất thấp; mẫu SYN flood
   phải lấy từ lab (đã ghi ở docs/06).
6. **Bảng đặc trưng thứ Tư** trong `output/features/` tạo trước khi commit C04-T08
   (`co_sua_chua_commit: true`). Muốn dùng cho kết quả cuối thì xuất lại; thứ Hai và
   thứ Sáu chưa xuất.

## 9. Việc tiếp theo

**Chặng 5 — Gán nhãn, EDA và chia dữ liệu:**
- Ghép nhãn theo lịch tấn công (đổi sang UTC) và cặp IP; báo cáo flow khớp, không khớp
  và mơ hồ, đối chiếu với CSV có nhãn.
- Định nghĩa nhãn cho cửa sổ chứa nhiều hành vi.
- Chia train/validation/test theo khối thời gian.
- Kiểm tra thiếu, vô hạn, trùng và phân bố lớp; vẽ EDA.
- Tiền xử lý chỉ fit trên train, gồm cách điền các ô trống của C04-T04, T06, T07.

Song song: xuất bảng đặc trưng thứ Hai, thứ Sáu từ mã đã commit; tải 11 file
`.binetflow` của CTU-13; dựng lab.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Flow hai chiều | Mọi gói qua lại giữa hai đầu của một kết nối, gộp chiều đi và chiều về |
| Forward / backward | Chiều từ client (bên mở kết nối) sang server / chiều ngược lại |
| 5-tuple | IP nguồn, IP đích, cổng nguồn, cổng đích, giao thức: nhận diện một kết nối |
| Timeout nhàn rỗi, active timeout | Không có gói mới quá lâu thì kết thúc flow / flow dài quá giới hạn thì cắt |
| FIN, RST, SYN, SYN+ACK | Cờ TCP: đóng, hủy, mở kết nối, đồng ý mở |
| Số thứ tự TCP | Số trong header TCP; gói gửi lại giữ nguyên, kết nối mới đổi số |
| Payload | Phần dữ liệu ứng dụng trong gói, không tính header |
| Inter-arrival time (IAT) | Khoảng thời gian giữa hai gói liên tiếp |
| Welford | Cách tính trung bình và độ lệch chuẩn dần từng giá trị mà không lưu lại các giá trị |
| Cửa sổ host | Khoảng 10 giây để gom gói của một máy và tính đặc trưng |
| Entropy cổng | Độ đa dạng của cổng đích, tính bằng bit; quét cổng cho entropy cao |
| Kết nối không hoàn tất | Lần thử TCP không đi hết bắt tay ba bước trong thời gian quan sát |
| Vai client / server | Bên mở / bên nhận kết nối của một flow |
| Dữ liệu tương lai | Thông tin của gói tới sau thời điểm đang xét; dùng nó là gian lận vì realtime không có |
| Schema, metadata | Mô tả các cột của bảng / thông tin bảng được tạo từ đâu, bằng gì |
| Vai trò cột | Cột là đặc trưng, định danh, ngữ cảnh hay kiểm tra |
| Định danh | IP, cổng, thời điểm: cho biết mẫu là của ai, lúc nào; không đưa vào mô hình |
| Mã băm SHA-256 | Chuỗi tính từ nội dung file; cùng mã băm nghĩa là cùng file |
| NAT | Tường lửa thay địa chỉ thật bằng địa chỉ của nó, nên nhiều máy hiện chung một IP |
| UTC−3 | Giờ chậm hơn giờ quốc tế 3 tiếng; giờ mùa hè nơi CIC thu dữ liệu |
| Vét cạn | Cách tính đơn giản, thử hết mọi khả năng, dùng làm đáp án để kiểm tra |
| EDA | Khảo sát dữ liệu bằng thống kê và biểu đồ trước khi huấn luyện |
| Fit trên train | Tham số tiền xử lý chỉ học từ tập huấn luyện để không rò rỉ sang tập kiểm tra |
