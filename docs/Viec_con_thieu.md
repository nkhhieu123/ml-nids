# Những gì còn thiếu sau Chặng 1–10

Tài liệu gom mọi thứ **chưa có** hoặc **chưa kiểm chứng** trong phạm vi Chặng 1–10, rút từ các
tài liệu task, báo cáo chặng và nhật ký quyết định. Lập ngày 23/10/2026 (Chặng 1–3), cập nhật
27/10, 29/10, 02/11, 03/11 và 06/11/2026 (mở rộng tới Chặng 10).

## 0. VIỆC ĐANG DỞ — CẦN CHẠY LẠI (đọc trước)

Ngày 02/11/2026 hai việc chạy nền **bị hệ thống dừng vì máy thiếu RAM** (việc 2 đã làm lại xong 03/11/2026) (máy 12 GB, dừng sau
khoảng 3 phút). Chỉ còn file dở dang, **chưa dùng được**, không đưa lên git. Bảng đặc trưng đang
dùng trong `output/features/` không bị ảnh hưởng. Nên đóng bớt ứng dụng rồi chạy **lần lượt từng
việc**, không chạy song song.

**Cập nhật 07/11/2026:** việc 1 (xuất lại đặc trưng 3 ngày) **đã xong**: chạy lần lượt từng ngày ở foreground, cả ba byte giống hệt bản cũ, metadata nay sạch. Việc 2 đã xong trước đó. Mục 0 này không còn việc dở.

| # | Việc | Trạng thái | Cách làm | Thời gian |
|---|---|---|---|---|
| 1 | ~~Xuất lại bảng đặc trưng 3 ngày CIC từ mã đã commit~~ | **XONG 07/11/2026.** Cả ba ngày (Hai, Tư, Sáu) xuất lại từ cây git sạch: flows+windows byte giống hệt bản cũ (SHA-256 khớp từng file) → mã trên git tái lập đúng bảng đang dùng. Meta mới ghi `co_sua_chua_commit: false` (commit `3d26b76`/`c7c42fc`/`91ed0ca`), đã thay meta/schema sạch vào `output/features`. | | |
| 2 | ~~Tải 13 file `.binetflow` CTU-13 vào `data/ctu13/`~~ | **Xong 03/11/2026**: đủ 13 file (2,6 GB), mã băm trong manifest, `nids.manifest --verify` khớp; đếm nhãn ở docs/48 | | |
| 3 | ~~Tải lại 4 bản thu CTU-13 dùng ở Chặng 3, ghi vào manifest kèm mã băm~~ | **Xong 06/11/2026**: `data/ctu13/pcap/`, 4 dòng manifest, `--verify` khớp, số gói khớp docs/17 | | |
| 4 | ~~Tải bộ nhãn đã sửa của KU Leuven, đối chiếu với nhãn Chặng 5~~ | **Xong 06/11/2026**: đồng ý 100% / 99,98% / 99,78% (bỏ flow `attempted`); không flow tấn công nào của KU bị gán lành tính (docs/67) | | |
| 5 | ~~Đối chiếu Wireshark toàn bộ file CIC~~ | **XONG 07/11/2026**: cả 3 file (35,5 triệu gói), 0 lệch (docs/17 mục 3.1) | | |

Sau khi xong mục 1 cần chạy lại nhãn, chia tập, tiền xử lý (Chặng 5) và kiểm tra lại kết quả
Chặng 6–7 (Gaussian, phân loại) nếu bảng mới khác bảng cũ.

**Việc cần bạn** (không làm thay được): dựng lab 7 node và kiểm tra mirror hai chiều; cài dự án
trên Kali, cho biết tên card mạng thật, cài NTP; chốt tham số kịch bản lab (tốc độ Nmap, ba mức
DoS SYN, beaconing); **xác nhận scenario validation của CTU-13** (Chặng 8 tạm chọn 4 và 13,
QĐ-039; đổi trong `botnet.splits` nếu muốn); chọn nguồn mẫu DoS kiểu SYN. Chi tiết ở mục 2–4.

Ở các mục dưới, **Bạn** là việc cần bạn hoặc nhóm tự làm (dựng máy, quyết định); **Làm được
ngay** là việc làm được bằng mã hoặc tải dữ liệu công khai mà không cần thêm gì.

Dữ liệu thật hiện có: **CIC-IDS2017 đủ** (PCAP thứ Hai, thứ Tư, thứ Sáu và CSV có nhãn) và
**CTU-13 đủ 13 file `.binetflow`**. Chưa có dữ liệu lab.

## 1. Tóm tắt mức độ

| Mức | Nghĩa | Số mục |
|---|---|---|
| **Chặn** | Thiếu thì không làm được chặng sau | 8 |
| **Quan trọng** | Làm tiếp được, nhưng kết quả chưa đáng tin cho tới khi bổ sung | 15 |
| **Nên có** | Hoàn thiện, kiểm tra thêm | 10 |

Số mục ở mục 2–4b (chưa tính 4c–4f), tính đến 02/11/2026, không tính các mục đã gạch (đã xong). 8 mục **chặn**
gom lại thành các việc sau (việc tải CIC-IDS2017 đã xong):

1. ~~Tải nốt CIC-IDS2017: PCAP thứ Tư và CSV có nhãn (mục 2.1).~~ Xong 29/10/2026.
2. ~~Tải 13 file `.binetflow` của CTU-13 (mục 0 và 2.2).~~ Xong 03/11/2026.
3. Dựng mạng lab 7 node, kiểm tra mirror (mục 3).
4. Chốt tham số kịch bản lab (mục 4).
5. ~~Chốt định dạng nhật ký lần chạy và viết script sinh traffic (mục 3).~~ **Xong 06/11/2026**:
   `scripts/sinh_traffic.py` (kịch bản 1–3) + `scripts/sinh_topology.py` (kịch bản 4–5); nhật ký
   `data/run_logs/nhat_ky.jsonl`; `scripts/nhat_ky_sang_lich.py` đổi sang lịch gán nhãn (docs/68).
6. Quyết định nguồn mẫu DoS kiểu SYN cho lớp `dos` (mục 4).

## 2. Dữ liệu

### 2.1. CIC-IDS2017 — đã đủ

| Thiếu | Mức | Ảnh hưởng | Ai làm | Cách bổ sung |
|---|---|---|---|---|
| ~~Chưa có PCAP thứ Tư~~ | Đã xong 29/10/2026 | | | Lịch DoS khớp UTC−3 (docs/06 mục 7.3); mã băm trong manifest |
| ~~Chưa tải `GeneratedLabelledFlows.zip`~~ | Đã xong 29/10/2026 | | | Số flow từng nhãn khớp; cột `Timestamp` kiểu 12 giờ mất SA/CH (docs/06 mục 7.5) |
| ~~Chưa tải PCAP thứ Hai, thứ Sáu~~ | Đã xong 27/10/2026 | | | Ở `data/pcap/cic-ids2017/`; `python -m nids.manifest --verify` báo khớp |
| ~~Chưa có dung lượng và mã băm~~ | Đã xong 27/10/2026 | | | SHA-256 và MD5 trong manifest và docs/06 mục 7.1 (thứ Tư thêm khi tải xong) |
| ~~Chưa xác định độ lệch giờ của lịch tấn công~~ | Đã xong 27/10/2026 | | | Lịch là giờ UTC−3, khớp dữ liệu tới từng phút (docs/06 mục 7.3) |
| ~~Chưa kiểm tra địa chỉ bên tấn công thật~~ | Đã xong 27/10/2026 | | | Là `172.16.0.1` (NAT). Port scan và DDoS cùng IP nên phải tách theo giờ |
| ~~Chưa tải bộ nhãn đã sửa lỗi của KU Leuven~~ | Đã xong 06/11/2026 | | | docs/67, manifest `cic17-ku-leuven` |
| ~~Bộ đọc PCAP mới so 1 triệu gói đầu mỗi file CIC với Wireshark~~ | Đã xong 07/11/2026 | Đã đối chiếu TOÀN BỘ ba file CIC (35,5 triệu gói), 0 lệch (docs/17 mục 3.1; `docs/hinh/wireshark_cic_*.json`) | |

### 2.2. CTU-13 — đã đủ file flow có nhãn

| Thiếu | Mức | Ảnh hưởng | Ai làm | Cách bổ sung |
|---|---|---|---|---|
| ~~Chưa có file `.binetflow` nào trong `data/ctu13/`~~ | Đã xong 03/11/2026 | Không đủ dữ liệu cho module botnet | Làm được ngay | Tải từ `mcfp.felk.cvut.cz`, đặt vào `data/ctu13/`, cập nhật manifest |
| ~~Chưa đếm nhãn của 11 scenario~~ | Đã xong 03/11/2026 (docs/48 mục 1; scenario 4, 5, 6 bằng một nửa README) | Số flow botnet theo README chưa được xác nhận | Làm được ngay sau khi tải | Lặp lại phép đếm ở [07_ctu13.md](07_ctu13.md) mục 3 |
| ~~Chưa xác định thời điểm bị nhiễm của từng scenario~~ | Không cần: cửa sổ bot chỉ là `suspect_host` khi có flow From-Botnet (QĐ-039) | Cửa sổ trước khi bot hoạt động có thể bị gán nhầm `suspect_host` | Làm được ngay | Đọc nhật ký thao tác trong README của từng scenario |
| ~~Chưa xác định múi giờ của cột `StartTime`~~ | Đã xong 06/11/2026 | `StartTime` là UTC+2 (giờ mùa hè Praha), xác định bằng khớp 5-tuple PCAP bot ↔ binetflow ở 3 scenario (docs/48) | | |
| Scenario validation **tạm chọn 4 và 13** (QĐ-039), chờ nhóm xác nhận | Quan trọng | Chưa chia được dữ liệu ở Chặng 5 | **Bạn** quyết định | Chọn 1–2 scenario trong nhóm train làm validation |
| ~~Topology của scenario 6 và 8 chưa xác định~~ | Đã xong: có flow CC, xếp `centralized` (docs/48) | Hai scenario này không có nhãn topology | Làm được ngay | Xem nhãn kênh điều khiển (`CC`) trong file flow |
| ~~4 bản thu CTU-13 đã dùng ở Chặng 3 chỉ nằm trong thư mục tạm~~ | Đã xong 06/11/2026 (manifest `ctu13-s0x-pcap-*`) | Người khác không tái lập được phép đối chiếu Wireshark | Làm được ngay | Thêm dòng manifest, ghi link tải và mã băm |

### 2.3. Dữ liệu lab — chưa thu lần nào

| Thiếu | Mức | Ảnh hưởng | Ai làm | Cách bổ sung |
|---|---|---|---|---|
| 0/55 lần chạy (cả 12 dòng manifest đều `chua_thu`) | Chặn | Không có DoS SYN, botnet ngang hàng, đối chứng lành tính, và không có dữ liệu thật của mạng sẽ triển khai | **Bạn** | Làm theo [09_du_lieu_lab.md](09_du_lieu_lab.md) sau khi có mục 3 và 4 |
| Chưa có access log Nginx của máy chủ dịch vụ thật | Quan trọng | Parser log mới thử trên Nginx Windows (CRLF, một worker) | **Bạn** dựng; kiểm tra làm được ngay | Cài Nginx với `log_format nids`, chạy `nids.service_log` và `nids.log_compare` |
| IPv6 thật gần như không có (1 gói đầy đủ, 2 gói bị cắt); TSO và đường hầm IP chưa gặp trên dữ liệu thật | Nên có | Các nhánh này mới kiểm tra bằng dữ liệu tổng hợp | Làm được ngay khi có PCAP lab | Chạy `nids.wireshark_compare` trên PCAP lab, nhất là khi bắt trên chính máy gửi |

## 3. Môi trường lab và Kali

| Thiếu | Mức | Ảnh hưởng | Ai làm |
|---|---|---|---|
| Mạng lab 7 node chưa dựng (B13) | Chặn | Không thu được dữ liệu lab, không chạy được realtime | **Bạn** |
| Chưa kiểm tra mirror: Kali thấy **cả hai chiều** traffic (B13) | Chặn | Flow hai chiều sai nếu chỉ thấy một chiều | **Bạn** |
| Dự án chưa cài thử trên Kali Linux (chỉ thử trên Windows, Python 3.13) | Quan trọng | Có thể lỗi thư viện hoặc quyền bắt gói khi triển khai | **Bạn** chạy; sửa lỗi làm được ngay |
| Tên giao diện giám sát `eth0` trong cấu hình là giả định | Quan trọng | Bắt gói sai card mạng | **Bạn** cung cấp tên thật |
| Chưa có quy trình đồng bộ đồng hồ giữa các máy | Quan trọng | Không ghép được log, PCAP và nhật ký lần chạy theo thời gian | **Bạn** cài NTP; ghi độ lệch vào nhật ký |
| ~~Định dạng file nhật ký lần chạy chưa chốt; script sinh traffic chưa viết (B23)~~ | Đã xong 06/11/2026 | `scripts/sinh_traffic.py`, `scripts/nhat_ky_sang_lich.py` (docs/68); **Bạn** vẫn cần chạy trong lab | |

## 4. Tham số và quyết định chưa chốt

| Thiếu | Mức | Ghi ở đâu khi chốt |
|---|---|---|
| Tốc độ Nmap của biến thể chậm và nhanh, dải cổng quét | Chặn với thu lab | `config/default.yaml` + nhật ký quyết định |
| Ba mức tải DoS SYN (B16 bắt buộc xác định trước) | Chặn với thu lab | `config/default.yaml` |
| Chu kỳ và độ biến thiên beaconing; số peer của kịch bản P2P | Chặn với thu lab | `config/default.yaml` |
| Nguồn mẫu huấn luyện cho DoS kiểu SYN (CIC chỉ có DoS tầng HTTP); Chặng 7 tạm chỉ dùng DoS tầng HTTP | Quan trọng | Nhật ký quyết định |
| Các quyết định còn **tạm thời**: QĐ-004 tên nhãn (nhất là `none` của topology), QĐ-006 cửa sổ và timeout 60 giây, QĐ-009 tập con CIC, QĐ-010 cách chia CTU-13, QĐ-012 dữ liệu lab, QĐ-013 bộ đọc PCAP tự viết | Quan trọng | Thêm mục quyết định mới khi khóa |
| ~~Dùng `ip_len` hay `frame_len` cho đặc trưng byte~~ | Đã xong | Chốt `ip_len` kèm payload TCP/UDP ở C04-T03 (QĐ-018) |
| Dung sai thời gian khi ghép dòng log với flow | Nên có | Chốt khi làm phần ghép log–flow |

## 4b. Chặng 4–6: việc còn thiếu hoặc hạn chế đã biết

| Thiếu | Mức | Ảnh hưởng | Ai làm |
|---|---|---|---|
| ~~Bảng đặc trưng xuất khi mã chưa commit~~ | Đã xong 07/11/2026 | Xuất lại từ cây sạch, byte giống hệt → đã chứng minh tái lập; meta ghi `co_sua_chua_commit: false` | |
| Tham số flow tạm thời: timeout 60/120/10 giây, quan sát bắt tay 3 giây (QĐ-017, QĐ-023) chưa chỉnh trên validation | Nên có | Đặc trưng có thể chưa tối ưu | Làm được ngay |
| Tốc độ xuất bảng khoảng 9 600 gói/giây trên máy phát triển, chưa đo trên Kali | Quan trọng | Có thể không kịp realtime | **Bạn** chạy trên Kali |
| Mọi traffic tấn công CIC đi qua NAT `172.16.0.1`: đặc trưng cửa sổ của "máy tấn công" gộp nhiều máy | Nên có | Kết quả theo host phía tấn công không đại diện | Cần dữ liệu lab |
| Validation lớp `port_scan` ở bảng cửa sổ chỉ 50 mẫu; GoldenEye chỉ 24 cửa sổ test | Quan trọng | Chọn ngưỡng/tham số và recall theo đợt dao động lớn | Cần thêm dữ liệu (lab) |
| Train, validation, test cùng mạng và cùng đợt tấn công; chưa đo trên công cụ hay mạng chưa thấy | Quan trọng | Kết quả có thể lạc quan | Đo lại trên lab (Chặng 11) |
| Tham số gán nhãn tạm thời: nới lịch 60 giây, ngưỡng cửa sổ 0,2, tỷ lệ cân bằng 10 | Nên có | Chỉnh trên validation khi cần | Làm được ngay |
| Gaussian: ~17 đợt báo động giả mỗi giờ; Heartbleed recall 0, DDoS 0,50, Slowhttptest 0,28; ngưỡng χ² không dùng được | Quan trọng | Không đủ dùng một mình; cần Chặng 7 và kết hợp ở Chặng 9 | Đã ghi ở docs/37 |
| Gaussian: đã xem test một lần khi chẩn đoán cách chọn ngưỡng (docs/36 mục 5) | Nên có | Cần ghi rõ trong báo cáo cuối | Đã ghi |

## 4c. Chặng 7: việc còn thiếu hoặc hạn chế đã biết

| Thiếu | Mức | Ảnh hưởng | Ai làm |
|---|---|---|---|
| ~~Đặc trưng cửa sổ chỉ đếm lần thử TCP~~ | Đã xử lý 07/11/2026 | Đo lại: `dst_ports` đã đếm UDP/SCTP; không thiếu đặc trưng. Nguyên nhân là chia theo thời gian — sửa bằng QĐ-060 (xem dưới) |
| ~~Port_scan chia theo thời gian nên kiểu quét SCTP chỉ có ở test~~ | **Xong 07/11/2026 (QĐ-060)** | Chia port_scan theo giao thức quét: recall test 0,448→0,736, F1 0,612→0,829, SCTP 0,02→0,84, precision giữ (docs/44) | |
| DoS HTTP chậm (Slowhttptest recall 0,61) cần đặc trưng kết nối giữ lâu, dài hơn cửa sổ 10 giây | Nên có | Bỏ sót DoS chậm | Làm được ngay (cửa sổ dài, Chặng 8–9) |
| DoS kiểu SYN, brute-force, exploit chưa có dữ liệu; DDoS chỉ một đợt | Quan trọng | Ba lớp hiện tại chưa đủ cho lab; chưa biết SYN flood được nhận ra không | **Bạn** thu lab; tải CIC thứ Ba, thứ Năm nếu muốn thêm lớp |
| RF báo 224 cửa sổ Bot là `port_scan` | Nên có | Cảnh báo sai loại | Quy tắc kết hợp ở Chặng 9 |

## 4d. Chặng 8: việc còn thiếu hoặc hạn chế đã biết

| Thiếu | Mức | Ảnh hưởng | Ai làm |
|---|---|---|---|
| Chỉ 4 máy bình thường đã xác nhận, giống nhau ở mọi tập; mô hình dễ học danh tính máy (docs/49 mục 2) | Quan trọng | Báo nhầm 1,6% chưa đại diện mạng lạ; Background test bị báo 11,9% | Cần dữ liệu lab có nhiều máy bình thường |
| ~~Bot chậm (Murlo, scenario 8) bị bỏ sót~~ | Đã xong 06/11/2026 (tùy chọn, mặc định tắt) | Lớp gộp theo host: recall scenario 8 0,154→1,0, F1 chung 0,798→0,990, báo nhầm máy bình thường không đổi (docs/69) |
| Mô hình học từ CTU-13 không phát hiện bot giả lập (recall 0,017) | Quan trọng | Không dùng thẳng được cho lab | Học lại trên dữ liệu lab (Chặng 11) |
| Chỉ một scenario P2P (12), nằm ở train; test CTU-13 không có P2P | Quan trọng | Nhận diện P2P chỉ kiểm tra trên giả lập | **Bạn** thu lab kịch bản 5 (B18) |
| Quy tắc topology không phân biệt đối chứng tập trung lành tính; P2P chu kỳ dài hoặc dùng TCP dễ bị xếp tập trung | Nên có | Sai topology khi bộ phát hiện báo nhầm | Thêm đặc trưng nhóm khi có đồ thị lab |
| Beaconing không tách bot khỏi máy bình thường trên CTU-13 (docs/47) | Nên có | Đặc trưng yếu trên CTU-13 | Kiểm tra lại trên lab |
| Script `scripts/sinh_topology.py` chưa chạy trong lab | Quan trọng | Chưa có traffic topology thật | **Bạn** chạy khi lab dựng xong |

## 4e. Chặng 9: việc còn thiếu hoặc hạn chế đã biết

| Thiếu | Mức | Ảnh hưởng | Ai làm |
|---|---|---|---|
| Pipeline mới chạy trên 4 đoạn PCAP CIC ngắn (3–21 phút), chưa chạy trên PCAP lab | Quan trọng | So sánh chế độ và khoảng gộp sự kiện chưa kiểm chứng trên mạng sẽ triển khai | **Bạn** thu lab; chạy `nids.pipeline chay` |
| Module botnet trong pipeline dùng mô hình học từ CTU-13; trên CIC báo nhầm nhiều khi chạy độc lập | Quan trọng | Cảnh báo botnet chưa đáng tin trên mạng mới | Học lại trên dữ liệu lab (Chặng 11) |
| ~~`created_at` offline chưa đo được độ trễ phát hiện~~ | Đã có bộ đo 09/11/2026 | `nids.thuc_nghiem` đo độ trễ = cuối cửa sổ đầu − bắt đầu đợt (gồm tích lũy cửa sổ); số lab cần PCAP thật (Bao_cao_Chang_11) | |
| Trích xuất khoảng 22 000 gói/giây, chiếm 90–99% thời gian | Quan trọng | Có thể không kịp realtime khi lưu lượng lớn | Đo trên Kali (Chặng 10) |
| Mỗi lần sửa `src/` hoặc `config/` cần chạy `pipeline kiem-tra`; mô hình tạo khi mã chưa commit chỉ bị cảnh báo | Nên có | Dễ dùng nhầm mô hình cũ | Làm được ngay khi có thay đổi |

## 4f. Chặng 10: việc còn thiếu hoặc hạn chế đã biết

| Thiếu | Mức | Ảnh hưởng | Ai làm |
|---|---|---|---|
| Chưa cài trên Kali, chưa bắt gói từ card thật, chưa chạy systemd thật (docs/59, 60, 65) | Chặn với Chặng 11 | Chưa biết lỗi quyền, card, gói kernel bỏ trên máy thật | **Bạn** dựng lab; chạy `cai_dat_kali.sh`, `cam_bien`, `cai_dich_vu.sh` |
| PCAP CIC có 0,7–11,8% gói nhân đôi; bộ trích xuất chưa bỏ bản sao (docs/60) | Quan trọng | Đặc trưng đếm gói lệch nếu mạng lab nhân đôi khác CIC | Đo trên lab rồi quyết định; khử trùng làm được ngay nếu cần |
| ~~Module botnet dựng lại đồ thị 600 giây mỗi bước~~ | Đã xong 07/11/2026 | Chỉ tính cửa sổ đang xét + cache chuyển đổi flow: chấm botnet −52% trên fri_quet, đặc trưng y hệt (docs/63 mục 3.1, QĐ-059) | |
| Hiệu năng mới đo trên laptop Windows bằng phát lại; số gói kernel bỏ chưa đo | Quan trọng | Chưa biết năng lực trên Kali | **Bạn** chạy trên Kali (Chặng 11) |

## 5. Giới hạn của mã nguồn hiện có

Đây không phải lỗi, mà là phạm vi đã chọn; ghi lại để biết khi nào cần làm thêm.

| Giới hạn | Mức | Khi nào cần làm |
|---|---|---|
| Không ghép mảnh IP; mảnh sau không có cổng | Nên có | Nếu dữ liệu lab có nhiều phân mảnh |
| Đường hầm (IP trong IP, GRE, VXLAN) chỉ đọc header ngoài | Nên có | Nếu lab dùng đường hầm |
| Gói ARP bị bỏ qua, nên không phát hiện được ARP spoofing | Nên có | Ngoài phạm vi ba lớp hiện tại |
| ~~Bộ đọc PCAP không đọc thẳng file nén `.gz`/`.bz2`~~ | Đã xong 06/11/2026 | `PcapReader` nhận magic gzip/bz2 và giải nén trong luồng (docs/04); đọc thẳng PCAP cắt ngắn `.bz2` của CTU-13 |
| Tốc độ khoảng 300 000 packet/giây (đọc); đối chiếu Wireshark 4,48 triệu gói mất khoảng 14 phút | Quan trọng | Đo lại trên file CIC 10 GB; tối ưu nếu quá chậm |
| ~~Chưa có phần bắt gói trực tiếp (live capture)~~ | Đã xong | Chặng 10 (`nids.nguon_goi`, AF_PACKET); chưa chạy trên card thật |

Các phần chưa có vì **thuộc chặng sau**, không tính là thiếu của Chặng 1–10: kiểm thử
thực nghiệm và chỉ số (Chặng 11), dashboard (tùy chọn T06).

## 6. Thứ tự nên làm

1. ~~**Bạn:** điền form CIC-IDS2017 và tải.~~ Đã tải đủ (27 và 29/10/2026).
2. **Làm được ngay, khi máy rảnh (mục 0):** xuất lại bảng đặc trưng; đưa các bản thu CTU-13
   đã dùng ở Chặng 3 vào manifest; tải nhãn KU Leuven. (Tải 13 file `.binetflow` đã xong.)
3. **Bạn:** dựng lab, kiểm tra mirror hai chiều, cài Nginx `nids`, đồng bộ đồng
   hồ, cài dự án trên Kali; chốt tham số ở mục 4.
4. ~~**Làm được ngay:** viết script sinh traffic cho kịch bản 1–3 (bình thường, quét, DoS).~~
   Xong 06/11/2026: `scripts/sinh_traffic.py` (docs/68); kịch bản botnet đã có `scripts/sinh_topology.py`.
5. ~~Khi CIC tải xong: xác định độ lệch giờ và địa chỉ NAT, khảo sát và đối chiếu
   Wireshark file thứ Tư, đối chiếu số flow CSV.~~ Xong 29/10/2026.
6. Thu lab theo thứ tự ở [09_du_lieu_lab.md](09_du_lieu_lab.md); các lần `test`
   chỉ thu sau khi mô hình đã khóa.

Chặng 7 (phân loại) đã xong trên CIC-IDS2017; Chặng 8 (botnet, topology) đã xong trên CTU-13 và
dữ liệu giả lập. Kết quả cuối của cả ba module phải đo lại trên lab (Chặng 11).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Chặn (mức) | Thiếu thì chặng sau không làm được |
| Dữ liệu thay thế | Dữ liệu dùng tạm để kiểm tra mã khi chưa có dữ liệu thật của đồ án |
| CIC-IDS2017, CTU-13 | Bộ dữ liệu tấn công mạng của Canada (2017) / bộ dữ liệu botnet của Séc (2011) |
| Manifest, `chua_tai`, `chua_thu` | Bảng liệt kê nguồn dữ liệu; trạng thái chưa tải / chưa thu |
| binetflow, scenario | File flow có nhãn của CTU-13; một lần thu riêng với một loại bot |
| Mã băm (SHA-256) | Chuỗi ngắn tính từ nội dung file, để kiểm tra file không bị hỏng hay bị sửa |
| NAT | Tường lửa thay địa chỉ IP khi gói đi qua, làm địa chỉ nguồn nhìn thấy khác địa chỉ thật |
| Múi giờ, độ lệch giờ | Chênh lệch giờ địa phương với UTC; chênh lệch giữa giờ ghi trong tài liệu và giờ trong file |
| Validation | Phần dữ liệu dùng để chọn tham số và ngưỡng |
| Topology, kênh điều khiển (CC) | Hình dạng mạng giao tiếp của botnet; đường bot nhận lệnh |
| Mirror, hai chiều | Switch sao chép traffic sang máy giám sát; thấy cả gói đi lẫn gói về của một kết nối |
| Kali Linux, giao diện `eth0` | Máy giám sát của lab; tên card mạng dùng để bắt gói |
| NTP, đồng bộ đồng hồ | Giao thức chỉnh giờ qua mạng; làm giờ các máy khớp nhau |
| Nhật ký lần chạy | File ghi mỗi lần thử nghiệm trong lab; căn cứ gán nhãn |
| Script sinh traffic | Chương trình tự tạo traffic bình thường, quét cổng, DoS, botnet mô phỏng theo kịch bản |
| Nmap, DoS SYN, beaconing, peer | Công cụ quét cổng; tấn công gửi ồ ạt gói mở kết nối; bot gọi về theo chu kỳ; máy ngang hàng |
| Quyết định tạm thời | Lựa chọn còn có thể đổi khi có thêm dữ liệu |
| `ip_len` / `frame_len` | Độ dài gói theo header IP / độ dài cả khung trên dây |
| Phân mảnh, đường hầm, ARP spoofing | Gói IP bị chia nhỏ; gói IP bọc trong gói khác; tấn công giả trả lời ARP |
| TSO | Card mạng tự chia gói lớn khi gửi; bắt trên máy gửi thấy độ dài IP bằng 0 |
| Live capture | Bắt gói trực tiếp từ card mạng thay vì đọc file |
| Wireshark, `wireshark_compare` | Công cụ xem gói tin; công cụ của dự án so kết quả đọc với Wireshark |
| RAM, chạy nền | Bộ nhớ của máy; chạy lệnh trong lúc vẫn làm việc khác |
| KU Leuven (nhãn đã sửa) | Bộ nhãn CIC-IDS2017 do nhóm KU Leuven sửa lỗi, công khai năm 2022 |
| Recall, báo động giả | Tỷ lệ tấn công bắt được; cảnh báo nhầm trên traffic bình thường |
| χ² | Phân bố lý thuyết của điểm d² nếu dữ liệu đúng Gaussian |
| UDP, SCTP, ICMP unreachable | Giao thức khác TCP; gói báo "cổng không mở" mà máy đích trả về khi bị quét UDP |
| Lượt Nmap | Một lần chạy Nmap với một kiểu quét |
