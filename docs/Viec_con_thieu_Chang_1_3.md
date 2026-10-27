# Những gì còn thiếu sau Chặng 1–3

Tài liệu gom mọi thứ **chưa có** hoặc **chưa kiểm chứng** trong phạm vi Chặng 1,
2 và 3, rút từ các tài liệu task, báo cáo chặng và nhật ký quyết định. Tình trạng
tính đến ngày 23/10/2026, cập nhật ngày 27/10/2026 sau khi tải PCAP CIC-IDS2017
thứ Hai và thứ Sáu.

Bảy chặng đầu đã có mã hoặc tài liệu. Dữ liệu thật của đồ án mới có **một phần**:
PCAP CIC-IDS2017 thứ Hai và thứ Sáu (đã kiểm tra, docs/06 mục 7). Còn thiếu PCAP
thứ Tư (đang tải), CSV có nhãn của CIC, 11 scenario CTU-13 và toàn bộ dữ liệu lab.
Các kiểm tra khác vẫn dùng dữ liệu thay thế: vài bản thu CTU-13 lưu tạm, bản tự bắt
Windows ↔ WSL, Nginx cài tạm trên máy phát triển và dữ liệu tổng hợp.

Cột "Ai làm": **Bạn** là việc cần bạn hoặc nhóm tự làm (điền form, dựng máy,
quyết định); **Làm được ngay** là việc làm được bằng mã hoặc tải dữ liệu công
khai mà không cần thêm gì.

## 1. Tóm tắt mức độ

| Mức | Nghĩa | Số mục |
|---|---|---|
| **Chặn** | Thiếu thì không làm được chặng sau | 10 |
| **Quan trọng** | Làm tiếp được, nhưng kết quả chưa đáng tin cho tới khi bổ sung | 11 |
| **Nên có** | Hoàn thiện, kiểm tra thêm | 10 |

Số mục tính đến 27/10/2026, không tính các mục đã gạch (đã xong). 10 mục **chặn**
gom lại thành 6 việc cần làm trước Chặng 5:

1. Tải nốt CIC-IDS2017: PCAP thứ Tư và CSV có nhãn (mục 2.1).
2. Tải 11 file `.binetflow` còn lại của CTU-13 (mục 2.2).
3. Dựng mạng lab 7 node, kiểm tra mirror (mục 3).
4. Chốt tham số kịch bản lab (mục 4).
5. Chốt định dạng nhật ký lần chạy và viết script sinh traffic (mục 3).
6. Quyết định nguồn mẫu DoS kiểu SYN cho lớp `dos` (mục 4).

## 2. Dữ liệu

### 2.1. CIC-IDS2017 — đã có thứ Hai và thứ Sáu

| Thiếu | Mức | Ảnh hưởng | Ai làm | Cách bổ sung |
|---|---|---|---|---|
| Chưa có PCAP thứ Tư (đang tải) | Chặn | Không có mẫu `dos` của CIC | **Bạn** tải; kiểm tra làm được ngay sau khi tải | Đặt vào `data/pcap/cic-ids2017/`, chạy `nids.pcap_survey` với cặp `172.16.0.1:192.168.10.50`, ghi mã băm vào manifest |
| Chưa tải `GeneratedLabelledFlows.zip` | Quan trọng | Số flow từng nhãn ở [06_cic_ids2017.md](06_cic_ids2017.md) mục 3 chưa đối chiếu; chưa đối chiếu được quy tắc gán nhãn | **Bạn** | Tải cùng nơi với PCAP, lấy hai file CSV ở mục 3 của docs/06 |
| ~~Chưa tải PCAP thứ Hai, thứ Sáu~~ | Đã xong 27/10/2026 | | | Ở `data/pcap/cic-ids2017/`; `python -m nids.manifest --verify` báo khớp |
| ~~Chưa có dung lượng và mã băm~~ | Đã xong 27/10/2026 | | | SHA-256 và MD5 trong manifest và docs/06 mục 7.1 (thứ Tư thêm khi tải xong) |
| ~~Chưa xác định độ lệch giờ của lịch tấn công~~ | Đã xong 27/10/2026 | | | Lịch là giờ UTC−3, khớp dữ liệu tới từng phút (docs/06 mục 7.3) |
| ~~Chưa kiểm tra địa chỉ bên tấn công thật~~ | Đã xong 27/10/2026 | | | Là `172.16.0.1` (NAT). Port scan và DDoS cùng IP nên phải tách theo giờ |
| Chưa tải bộ nhãn đã sửa lỗi của KU Leuven | Nên có | Thiếu nguồn đối chiếu nhãn tốt hơn CSV gốc | Làm được ngay | https://intrusion-detection.distrinet-research.be/CNS2022/ |
| Bộ đọc PCAP mới so 1 triệu gói đầu mỗi file CIC với Wireshark (0 lệch), chưa so hết | Nên có | Phần sau của file chưa đối chiếu từng gói (đã đọc hết không lỗi) | Làm được ngay | `nids.wireshark_compare` không `--limit`, mất vài giờ mỗi file |

### 2.2. CTU-13 — mới có một phần

| Thiếu | Mức | Ảnh hưởng | Ai làm | Cách bổ sung |
|---|---|---|---|---|
| Mới tải 2/13 file `.binetflow` (scenario 11, 12); 11 file còn lại khoảng 2,5 GB | Chặn | Không đủ dữ liệu cho module botnet | Làm được ngay | Tải từ `mcfp.felk.cvut.cz`, đặt vào `data/ctu13/`, cập nhật manifest |
| Chưa đếm nhãn của 11 scenario còn lại | Quan trọng | Số flow botnet theo README chưa được xác nhận | Làm được ngay sau khi tải | Lặp lại phép đếm ở [07_ctu13.md](07_ctu13.md) mục 3 |
| Chưa xác định thời điểm bị nhiễm của từng scenario | Quan trọng | Cửa sổ trước khi bot hoạt động có thể bị gán nhầm `suspect_host` | Làm được ngay | Đọc nhật ký thao tác trong README của từng scenario |
| Chưa xác định múi giờ của cột `StartTime` | Quan trọng | Lệch giờ khi ghép với PCAP | Làm được ngay | So `StartTime` với timestamp của PCAP cắt ngắn cùng scenario |
| Chưa chốt scenario làm validation; cách chia train/test theo bài báo gốc vẫn là tạm thời (QĐ-010) | Quan trọng | Chưa chia được dữ liệu ở Chặng 5 | **Bạn** quyết định | Chọn 1–2 scenario trong nhóm train làm validation |
| Topology của scenario 6 và 8 chưa xác định | Nên có | Hai scenario này không có nhãn topology | Làm được ngay | Xem nhãn kênh điều khiển (`CC`) trong file flow |
| 4 bản thu CTU-13 đã dùng ở Chặng 3 (donbot, sogou, Virut, PCAP cắt ngắn scenario 5) chỉ nằm trong thư mục tạm, chưa có trong `data/` và manifest | Nên có | Người khác không tái lập được phép đối chiếu Wireshark | Làm được ngay | Thêm dòng manifest, ghi link tải và mã băm |

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
| Định dạng file nhật ký lần chạy chưa chốt; script sinh traffic và ghi nhật ký chưa viết (`scripts/` còn trống, B23) | Chặn | Không có căn cứ gán nhãn cho dữ liệu lab | Làm được ngay (viết script), **Bạn** chạy trong lab |

## 4. Tham số và quyết định chưa chốt

| Thiếu | Mức | Ghi ở đâu khi chốt |
|---|---|---|
| Tốc độ Nmap của biến thể chậm và nhanh, dải cổng quét | Chặn với thu lab | `config/default.yaml` + nhật ký quyết định |
| Ba mức tải DoS SYN (B16 bắt buộc xác định trước) | Chặn với thu lab | `config/default.yaml` |
| Chu kỳ và độ biến thiên beaconing; số peer của kịch bản P2P | Chặn với thu lab | `config/default.yaml` |
| Nguồn mẫu huấn luyện cho DoS kiểu SYN (CIC chỉ có DoS tầng HTTP) | Chặn với Chặng 7 | Nhật ký quyết định |
| Các quyết định còn **tạm thời**: QĐ-004 tên nhãn (nhất là `none` của topology), QĐ-006 cửa sổ và timeout 60 giây, QĐ-009 tập con CIC, QĐ-010 cách chia CTU-13, QĐ-012 dữ liệu lab, QĐ-013 bộ đọc PCAP tự viết | Quan trọng | Thêm mục quyết định mới khi khóa |
| ~~Dùng `ip_len` hay `frame_len` cho đặc trưng byte~~ | Đã xong | Chốt `ip_len` kèm payload TCP/UDP ở C04-T03 (QĐ-018) |
| Dung sai thời gian khi ghép dòng log với flow | Nên có | Chốt khi làm phần ghép log–flow |

## 5. Giới hạn của mã nguồn hiện có

Đây không phải lỗi, mà là phạm vi đã chọn; ghi lại để biết khi nào cần làm thêm.

| Giới hạn | Mức | Khi nào cần làm |
|---|---|---|
| Không ghép mảnh IP; mảnh sau không có cổng | Nên có | Nếu dữ liệu lab có nhiều phân mảnh |
| Đường hầm (IP trong IP, GRE, VXLAN) chỉ đọc header ngoài | Nên có | Nếu lab dùng đường hầm |
| Gói ARP bị bỏ qua, nên không phát hiện được ARP spoofing | Nên có | Ngoài phạm vi ba lớp hiện tại |
| Bộ đọc PCAP không đọc thẳng file nén `.gz`/`.bz2` | Nên có | Phải giải nén trước, như PCAP cắt ngắn của CTU-13 |
| Tốc độ khoảng 300 000 packet/giây (đọc); đối chiếu Wireshark 4,48 triệu gói mất khoảng 14 phút | Quan trọng | Đo lại trên file CIC 10 GB; tối ưu nếu quá chậm |
| Chưa có phần bắt gói trực tiếp (live capture) | — | Thuộc Chặng 10 |

Các phần chưa có vì **thuộc chặng sau**, không tính là thiếu của Chặng 1–3:
flow và đặc trưng (Chặng 4), gán nhãn và chia dữ liệu (Chặng 5), ba mô hình
(Chặng 6–8), pipeline offline và realtime (Chặng 9–10), kiểm thử thực nghiệm và
chỉ số (Chặng 11), dashboard (tùy chọn T06).

## 6. Thứ tự nên làm

1. ~~**Bạn:** điền form CIC-IDS2017 và bắt đầu tải.~~ Đã tải thứ Hai và thứ Sáu;
   còn PCAP thứ Tư (đang tải) và `GeneratedLabelledFlows.zip`.
2. **Làm được ngay:** tải 11 file `.binetflow`, đếm nhãn, xác định thời điểm bị
   nhiễm và múi giờ; đưa các bản thu CTU-13 đã dùng vào manifest.
3. **Bạn:** dựng lab, kiểm tra mirror hai chiều, cài Nginx `nids`, đồng bộ đồng
   hồ, cài dự án trên Kali; chốt tham số ở mục 4.
4. **Làm được ngay:** viết script sinh traffic và ghi nhật ký lần chạy.
5. Khi CIC tải xong: ~~xác định độ lệch giờ và địa chỉ NAT~~ (đã xong trên thứ
   Sáu); khảo sát và đối chiếu Wireshark file thứ Tư; đối chiếu số flow CSV.
6. Thu lab theo thứ tự ở [09_du_lieu_lab.md](09_du_lieu_lab.md); các lần `test`
   chỉ thu sau khi mô hình đã khóa.

Chặng 4 (flow và đặc trưng) có thể bắt đầu song song với bước 1–4 bằng các bản
thu CTU-13 đang có, nhưng phải kiểm tra lại khi có CIC-IDS2017 và dữ liệu lab.

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
