# Những gì còn thiếu sau Chặng 1–11

Tài liệu chỉ liệt kê những gì **chưa có** hoặc **chưa kiểm chứng**. Mục nào đã xong thì đã được xóa khỏi đây;
kết quả của chúng nằm ở báo cáo từng chặng, nhật ký quyết định (docs/03) và lịch sử git của file này.
Cập nhật lần cuối: 13/11/2026.

Dữ liệu hiện có: **CIC-IDS2017 đủ** (PCAP thứ Hai, thứ Tư, thứ Sáu và CSV có nhãn), **CTU-13 đủ** 13 file
`.binetflow`, và **lab ảo**: 177 lần chạy (33 `train`, 11 `val`, 99 `test`, 16 lần thí nghiệm bổ sung, 18 lần
của biến thể đổi vai trò máy và SYN flood) kèm nhật ký lần chạy (docs/70, 71, 73, 74, 76).

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
| Lớp giữ nhãn `dos` theo host (QĐ-071) mới đo offline trên CIC: recall `dos` trên test 0,838 → 0,938, Slowhttptest 0,66 → 0,82; chưa nối vào pipeline và realtime | Nên có | DoS HTTP chậm vẫn bị sót giữa các đợt gửi khi chạy thật | Gọi `dos_cham.hold_dos` sau bộ phân loại trong `pipeline.py` và `realtime.py`; thử `min_count` lớn hơn để giữ precision |
| SYN flood gói thô: bắt 9/9 đợt nhờ phía máy tấn công, nhưng cửa sổ của máy nạn nhân ít khi được gán `dos` | Nên có | Nếu nguồn bị giả mạo thì chỉ còn phía nạn nhân để phát hiện | Thu 3 lần `train` của `x3-syn-muc1/2/3` rồi học lại bộ phân loại lab |
| Bot đóng vai máy điều khiển cũ (`.50`) bị sót ở 2/3 lần chạy `x5-doi-vai` | Nên có | Bot ít traffic nền dễ lọt | Thêm biến thể đổi vai vào `train`; xem ngưỡng gộp theo host |
| Độ dài và bước cửa sổ (10 giây bước 2, 120 giây bước 10) chưa thử độ nhạy | Nên có | Timeout flow đã thử bằng huấn luyện lại (QĐ-073), cửa sổ thì chưa | Trích xuất lại CIC với cửa sổ 5 và 20 giây, chọn lại tham số mô hình rồi so trên validation |
| `config/default.yaml` vẫn chờ bắt tay 3 giây; 1 giây không kém trên CIC (0,9370 so với 0,9352) nhưng mô hình mặc định chưa học lại | Nên có | Cảnh báo của cấu hình mặc định chậm hơn cấu hình lab khoảng 2 giây | Huấn luyện lại ba mô hình mặc định từ `output/features_h1` nếu muốn dùng 1 giây ngoài lab |
| Brute-force, exploit chưa có dữ liệu; DDoS chỉ một đợt của CIC | Quan trọng | Ba lớp hiện tại không phủ các loại này; lab không sinh được vì B24 cấm exploit | Tải CIC thứ Ba, thứ Năm nếu muốn thêm lớp |

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
| Mô hình lab không chuyển sang dữ liệu khác: mô hình botnet lab cho recall 0 trên CTU-13 | Quan trọng | 24/24 đợt trên `test` mới chỉ có nghĩa trong lab với bot mô phỏng; đổi vai trò máy trong lab vẫn bắt 6/6 đợt (docs/76) |
| Random Forest gán 224 cửa sổ Bot của CIC là `port_scan` | Nên có | Không thêm quy tắc: ở chế độ `ket_hop` các cửa sổ này không trùng cảnh báo botnet nào, ghép theo host chỉ đúng 19/34. Bot của CIC quét cổng thật nên nhãn `port_scan` không hẳn sai |
| Lab ảo chỉ có 7 host, 3 bot | Nên có | Quy tắc topology theo nhóm (QĐ-070) cần ít nhất hai bot bị phát hiện cùng cửa sổ; chưa thử trên mạng lớn |
| Các lần `test` 1–11 của lab đều đã được xem | Nên có | Mỗi lần học lại phải thu lần `test` mới (QĐ-072) |

## 4. Thứ tự nên làm

1. **Bạn:** dựng lab vật lý, cài dự án trên Kali, đồng bộ đồng hồ (mục 1); chạy lại vài kịch bản và so với lab ảo.
2. **Làm được ngay:** nối lớp giữ nhãn `dos` vào pipeline và realtime; thu `train` cho SYN flood và biến thể
   đổi vai rồi học lại, kèm lần `test` mới (mục 2, ba dòng đầu).
3. Chặng 12: báo cáo và bàn giao; nêu rõ các hạn chế ở mục 3.

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
