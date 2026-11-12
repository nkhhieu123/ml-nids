# Những gì còn thiếu sau Chặng 1–11

Tài liệu chỉ liệt kê những gì **chưa có** hoặc **chưa kiểm chứng**. Mục nào đã xong thì đã được xóa khỏi đây;
kết quả của chúng nằm ở báo cáo từng chặng, nhật ký quyết định (docs/03) và lịch sử git của file này.
Cập nhật lần cuối: 13/11/2026.

Dữ liệu hiện có: **CIC-IDS2017 đủ** (PCAP thứ Hai, thứ Tư, thứ Sáu và CSV có nhãn), **CTU-13 đủ** 13 file
`.binetflow`, và **lab ảo**: 98 lần chạy (11 `train`, 11 `val`, 66 `test`, 10 lần thí nghiệm bổ sung) kèm nhật
ký lần chạy (docs/70, docs/71, docs/73, docs/74).

Mức: **Quan trọng** là kết quả chưa đáng tin cho tới khi bổ sung; **Nên có** là hoàn thiện, kiểm tra thêm.
Không còn mục nào ở mức chặn.

## 1. Việc cần thiết bị thật (cần bạn)

Mọi phép đo trên lab hiện là trên **lab ảo** (network namespace trên WSL2, QĐ-061). Các việc dưới đây không làm
thay được vì cần máy thật.

| Thiếu | Mức | Ảnh hưởng | Cách bổ sung |
|---|---|---|---|
| Lab vật lý 7 node với switch có cổng mirror (B13); chưa kiểm tra mirror hai chiều trên switch thật | Quan trọng | Số gói nhân bỏ, độ trễ và hành vi mirror của thiết bị thật chưa biết | Dựng lab; chạy `nids.cam_bien` trên bản bắt thử; chạy lại kịch bản bằng `sinh_traffic.py`, `sinh_topology.py` rồi so với số của lab ảo |
| Dự án chưa cài trên Kali Linux; chưa bắt gói từ card thật; chưa chạy dịch vụ systemd thật (docs/59, 60, 65) | Quan trọng | Có thể lỗi thư viện, quyền bắt gói, tên card | Chạy `scripts/cai_dat_kali.sh`, `nids.moi_truong`, `scripts/cai_dich_vu.sh` trên Kali |
| Tên card giám sát `eth0` trong cấu hình là giả định | Quan trọng | Bắt gói sai card | Cho biết tên thật, sửa `capture.interface` |
| Chưa có quy trình đồng bộ đồng hồ giữa các máy thật | Quan trọng | Ghép log với flow cần lệch dưới 1 giây (QĐ-067); lab ảo lệch 0 nên chưa thử | Cài NTP; ghi độ lệch vào nhật ký lần chạy |
| Hiệu năng trên Kali và ở tải cao chưa đo | Quan trọng | Trên lab ảo cảm biến bắt trực tiếp không bỏ gói ở tải tới khoảng 2 900 gói mỗi giây (docs/74 mục 1); trích xuất offline khoảng 20 000 gói mỗi giây. Chưa biết giới hạn trên card thật | Chạy `nids.realtime --iface` trên Kali với tải tăng dần |
| Tải kết nối 600 kết nối mỗi giây không làm chậm dịch vụ trên lab ảo | Nên có | Chưa đo được ảnh hưởng của DoS lên dịch vụ (B16) | Thử trên máy chủ thật có tài nguyên hạn chế |
| Access log Nginx mới kiểm tra trên Nginx của lab ảo (33 003 dòng, lệch 0) | Nên có | Chưa thử trên máy chủ vật lý | Chạy `nids.service_log`, `nids.log_compare --all` trên log thật |

## 2. Việc làm được tiếp bằng mã và dữ liệu đang có

| Thiếu | Mức | Ảnh hưởng | Cách bổ sung |
|---|---|---|---|
| Mô hình học lại trên lab (QĐ-068) chỉ được chấm trên **cùng lab, cùng bộ sinh traffic**: bot luôn là `.41`–`.43`, máy điều khiển luôn `.50:8080`, ngang hàng luôn UDP 40000 | Quan trọng | 24/24 đợt trên `test` mới cho thấy mô hình học được lab này, chưa chứng minh nhận ra botnet thật hay mạng khác | Thu biến thể đổi vai trò máy, cổng và máy điều khiển; chấm mô hình lab trên CTU-13 và ngược lại |
| Mỗi biến thể chỉ có một lần `train` (531 host–cửa sổ bot) | Quan trọng | Mô hình botnet của lab học từ rất ít dữ liệu | `bash scripts/chay_chang_11.sh train 2 3` rồi học lại |
| Quy tắc topology của lab rất lỏng (≥ 1 peer gọi vào, ≥ 5% UDP); trên `test` gán `p2p` đúng 90,6% | Nên có | Trên mạng nhiều host sẽ gán `p2p` quá dễ; ngang hàng dùng TCP hoặc chu kỳ dài dễ bị xếp tập trung | Thêm đặc trưng nhóm (các bot gọi lẫn nhau) thay cho ngưỡng trên từng host |
| Bộ phân loại học lại vẫn báo nhầm `dos` 4 sự kiện (10 cửa sổ) trên chia sẻ dữ liệu lớn `k5-doi-chung` | Nên có | Còn báo động giả khi truyền file nội bộ (trước là 24 sự kiện) | Thêm lần `train` của `k5-doi-chung`; xem đặc trưng phân biệt truyền file với DoS |
| `config/default.yaml` vẫn trỏ tới mô hình học từ CIC và CTU-13; mô hình lab phải gọi bằng `--config config/lab.yaml` | Nên có | Chạy dịch vụ realtime trên lab mà quên đổi cấu hình thì dùng mô hình cũ | Đặt cấu hình lab trong `deploy/nids-realtime.env` khi triển khai trên lab |
| `flow.handshake_observe_s` = 3: giảm xuống 1 giây bớt khoảng 2 giây độ trễ realtime mà không đổi kết quả trên lab (docs/72 mục 2.2) | Nên có | Độ trễ quét và DoS hiện 3,9–4,2 giây | Trích xuất lại CIC với 1 giây, huấn luyện lại, kiểm tra trên mạng có độ trễ thật |
| Tham số flow và độ dài cửa sổ mới được thử độ nhạy bằng mô hình đã khóa trên lab (QĐ-066), chưa thử bằng cách trích xuất và huấn luyện lại trên CIC | Nên có | Chưa chứng minh bộ hiện tại là tối ưu | Trích xuất lại ba ngày CIC cho từng cấu hình (mỗi cấu hình khoảng 30 phút) |
| DoS HTTP chậm (Slowhttptest recall 0,61 trên CIC) cần đặc trưng kết nối giữ lâu, dài hơn cửa sổ 10 giây | Nên có | Bỏ sót DoS chậm | Thêm đặc trưng cửa sổ dài hoặc gộp theo host như docs/69 |
| Random Forest báo 224 cửa sổ Bot của CIC là `port_scan` | Nên có | Cảnh báo sai loại trên CIC | Quy tắc kết hợp với module botnet |
| SYN flood gói thô, brute-force, exploit chưa có dữ liệu; DDoS chỉ một đợt của CIC | Quan trọng | DoS của lab là tải kết nối bằng socket thường (QĐ-064); ba lớp hiện tại chưa phủ các loại này | Cần quyết định có nới B24 để sinh gói thô trong lab không; tải CIC thứ Ba, thứ Năm nếu muốn thêm lớp |
| Các lần `test` 1–3 của lab đã được xem kết quả trước khi học lại | Nên có | Chỉ `test` 4–6 là sạch với mô hình lab | Mỗi lần học lại phải thu lần `test` mới |

## 3. Hạn chế đã biết, không có việc phải làm ngay

Ghi lại để nêu trong báo cáo cuối và để biết khi nào cần làm thêm.

| Hạn chế | Mức | Ghi chú |
|---|---|---|
| Gaussian trên CIC: khoảng 17 đợt báo động giả mỗi giờ; Heartbleed recall 0, DDoS 0,50, Slowhttptest 0,28; ngưỡng χ² không dùng được | Quan trọng | Không đủ dùng một mình (docs/37). Trên lab, Gaussian học lại không báo nhầm nhưng cũng không thấy bot chậm (docs/73) |
| Gaussian: đã xem test CIC một lần khi chẩn đoán cách chọn ngưỡng | Nên có | Đã ghi ở docs/36 mục 5; phải nêu trong báo cáo cuối |
| GoldenEye chỉ có 24 cửa sổ test; validation `port_scan` của CIC 164 cửa sổ | Quan trọng | Chỉ có trong CIC, không bổ sung được. Lab có 531 cửa sổ `port_scan` và 196 cửa sổ `dos` ở `val` (docs/71 mục 7.1) |
| Mọi traffic tấn công CIC đi qua NAT `172.16.0.1` | Nên có | Kết quả theo host phía tấn công trên CIC không đại diện; trên lab đã đo với máy tấn công thật (docs/71 mục 7) |
| CTU-13 chỉ có 4 máy bình thường đã xác nhận, giống nhau ở mọi tập; validation chỉ có 1 IP bot | Quan trọng | Mô hình CTU-13 dễ học danh tính máy; phải giữ ràng buộc Background ≤ 5% (QĐ-040). Lab cũng chỉ có 4–5 máy bình thường |
| Chế độ `ket_hop` không cho module botnet xét host không bị anomaly báo | Quan trọng | Bot chậm lọt ở chế độ này; lab dùng `doc_lap` (QĐ-068). Trên CIC `ket_hop` vẫn là mặc định (QĐ-047) |
| Không ghép mảnh IP; mảnh sau không có cổng | Nên có | Các lần chạy lab không có gói phân mảnh; mảnh tạo riêng khớp Wireshark (docs/17 mục 3.2) |
| Đường hầm (IP trong IP, GRE, VXLAN) chỉ đọc header ngoài | Nên có | Lab không dùng đường hầm |
| Gói ARP bị bỏ qua, không phát hiện được ARP spoofing | Nên có | Ngoài phạm vi ba lớp hiện tại |
| Không khử gói trùng | Nên có | Lab ảo trùng 0,01–0,63% nên không cần; đo lại nếu switch thật mirror cả hai chiều của cùng cổng |

## 4. Thứ tự nên làm

1. **Bạn:** dựng lab vật lý, cài dự án trên Kali, đồng bộ đồng hồ (mục 1); chạy lại vài kịch bản và so với lab ảo.
2. **Làm được ngay:** thu thêm lần `train` và biến thể đổi vai trò máy, học lại mô hình botnet của lab, thu
   lần `test` mới (mục 2, ba dòng đầu).
3. Quyết định có thử `handshake_observe_s` = 1 và SYN flood gói thô hay không.
4. Chặng 12: báo cáo và bàn giao; nêu rõ các hạn chế ở mục 3.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Lab ảo / lab vật lý | Mạng thử nghiệm dựng bằng network namespace trên một máy / bằng 7 máy và switch thật |
| CIC-IDS2017, CTU-13 | Bộ dữ liệu tấn công mạng của Canada (2017) / bộ dữ liệu botnet của Séc (2011) |
| Mirror, hai chiều | Switch sao chép traffic sang máy giám sát; thấy cả gói đi lẫn gói về của một kết nối |
| Kali Linux, card `eth0` | Hệ điều hành dự kiến của máy giám sát; tên card mạng dùng để bắt gói |
| NTP, đồng bộ đồng hồ | Giao thức chỉnh giờ qua mạng; làm giờ các máy khớp nhau |
| Gói nhân bỏ | Gói mà nhân hệ điều hành không kịp đưa cho chương trình bắt gói |
| Nhật ký lần chạy | File ghi mỗi lần thử nghiệm trong lab; căn cứ gán nhãn |
| Train / val / test | Lần chạy để học / để chọn ngưỡng và tham số / để đánh giá cuối |
| Biến thể | Một cách chạy cụ thể của kịch bản, ví dụ quét chậm và quét nhanh |
| Host–cửa sổ | Đơn vị chấm: một host trong một khoảng thời gian (10 giây hoặc 120 giây) |
| Topology, `p2p`, peer | Cấu trúc liên lạc của bot; kiểu ngang hàng; máy ngang hàng |
| Chế độ `ket_hop` / `doc_lap` | `ket_hop`: module botnet chỉ xét host bị anomaly báo. `doc_lap`: ba module chấm độc lập mọi host |
| Quan sát bắt tay | Khoảng chờ trả lời của lần mở kết nối TCP trước khi coi là không hoàn tất |
| DoS, SYN flood, tải kết nối | Làm máy chủ quá tải; gửi ồ ạt gói mở kết nối; mở rồi đóng liên tục nhiều kết nối thường |
| DoS HTTP chậm | Giữ nhiều kết nối HTTP mở thật lâu để chiếm chỗ của máy chủ |
| Gaussian, χ² | Mô hình của module anomaly; phân bố lý thuyết của điểm bất thường nếu dữ liệu đúng Gaussian |
| NAT | Tường lửa thay địa chỉ IP khi gói đi qua, làm địa chỉ nguồn nhìn thấy khác địa chỉ thật |
| Background (CTU-13) | Traffic chưa được xác nhận là bot hay bình thường |
| Phân mảnh, đường hầm, ARP spoofing | Gói IP bị chia nhỏ; gói IP bọc trong gói khác; tấn công giả trả lời ARP |
| Recall, báo động giả | Tỷ lệ tấn công bắt được; cảnh báo nhầm trên traffic bình thường |
| B13, B16, B24 | Mã yêu cầu trong docs/01: mirror hai chiều; DoS có giới hạn; an toàn, không ra ngoài lab |
