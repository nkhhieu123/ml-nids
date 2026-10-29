# Báo cáo Chặng 2 — Khảo sát dữ liệu và định dạng

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 12/10/2026 – 16/10/2026 |
| Trạng thái | Xong 6/6 task |
| Chặng trước / sau | [Bao_cao_Chang_1.md](Bao_cao_Chang_1.md) / [Bao_cao_Chang_3.md](Bao_cao_Chang_3.md) |

## 1. Tóm tắt

Chặng 2 chốt **dữ liệu**: định dạng file PCAP, loại log dịch vụ, tập con
CIC-IDS2017, kết quả kiểm tra CTU-13, manifest dữ liệu cho từng bài toán và
danh sách dữ liệu phải tự thu trong lab. Cuối chặng có thêm tài liệu tổng quan
về dữ liệu, mô hình và dữ liệu chuẩn
([10_tong_quan_du_lieu_mo_hinh.md](10_tong_quan_du_lieu_mo_hinh.md)).

Chưa có mô hình nào được huấn luyện và chưa có lần thu nào trong lab. Lúc kết
thúc chặng chưa tải được CIC-IDS2017; **ngày 27/10/2026 đã tải PCAP thứ Hai và
thứ Sáu**, ngày 29/10/2026 tải nốt PCAP thứ Tư và CSV có nhãn, và cập nhật các
mục liên quan. Báo cáo không chứa kết
quả thực nghiệm hay chỉ số đánh giá.

## 2. Các task

| Task | Nội dung | Trạng thái | Sản phẩm |
|---|---|---|---|
| C02-T01 | Mô tả Global Header, Packet Header, Packet Data của PCAP; phân biệt với PCAPNG | Xong | [04_dinh_dang_pcap.md](04_dinh_dang_pcap.md) |
| C02-T02 | Chọn một loại log dịch vụ | Xong | [05_log_dich_vu.md](05_log_dich_vu.md) |
| C02-T03 | Chọn tập con CIC-IDS2017 cho phân loại | Xong; lịch tấn công và số flow từng nhãn đã đối chiếu với file thật | [06_cic_ids2017.md](06_cic_ids2017.md) |
| C02-T04 | Kiểm tra các scenario CTU-13, file khả dụng và ý nghĩa nhãn | Xong | [07_ctu13.md](07_ctu13.md) |
| C02-T05 | Tạo manifest: nguồn, file, thời gian, nhãn, mục đích | Xong | `config/data_manifest.csv`, `src/nids/manifest.py`, [08_manifest_du_lieu.md](08_manifest_du_lieu.md) |
| C02-T06 | Chốt dữ liệu còn phải tự thu trong lab | Xong | [09_du_lieu_lab.md](09_du_lieu_lab.md) |

## 3. Kết quả từng task

### 3.1. C02-T01 — Định dạng PCAP và PCAPNG

| Phần | Kích thước | Nội dung chính |
|---|---|---|
| Global Header | 24 byte, một lần ở đầu file | `magic_number` (thứ tự byte, micro/nano giây), phiên bản 2.4, `snaplen`, kiểu tầng liên kết |
| Packet Header | 16 byte, trước mỗi gói | `ts_sec`, `ts_usec`, `incl_len` (byte đã lưu), `orig_len` (byte trên đường truyền) |
| Packet Data | `incl_len` byte | Gói tin tính từ header tầng liên kết, không đệm |

Tài liệu có ví dụ đọc từng byte của một file PCAP 82 byte chứa một gói ARP giữa
hai máy lab, và bảng so sánh PCAP với PCAPNG theo 15 tiêu chí. Khác biệt chính:
PCAPNG là dãy block có kiểu và độ dài, chứa được nhiều giao diện với kiểu liên
kết khác nhau, có chú thích và thống kê mất gói; PCAP chỉ có một header cố định
và một kiểu liên kết cho cả file.

Kết luận dùng cho các chặng sau:

- Nhận biết định dạng bằng 4 byte đầu file, không theo phần mở rộng.
- File PCAP không chứa số gói bị mất; số này lấy từ thống kê của tcpdump khi
  dừng bắt gói.
- Độ dài gói lấy từ `orig_len`, không từ `incl_len`, để không sai khi gói bị
  cắt. (Chặng 3 đề xuất dùng thêm độ dài theo header IP; xem
  [Bao_cao_Chang_3.md](Bao_cao_Chang_3.md).)

### 3.2. C02-T02 — Log dịch vụ

Chọn **access log của Nginx** trên máy chủ dịch vụ `192.168.50.30`, dùng định
dạng riêng `nids` gồm 12 trường. Định dạng này thêm vào định dạng mặc định ba
thứ cần để ghép với flow: cổng nguồn của client, thời điểm tới mili giây và
thời gian phục vụ.

Log chỉ dùng để **đối chiếu**: kiểm tra nhật ký lần chạy, đo ảnh hưởng của DoS
lên client hợp lệ, phân tích phát hiện sai. Log không là đầu vào của mô hình và
không dùng để gán nhãn. SYN scan và DoS SYN không để lại dòng nào trong access
log.

### 3.3. C02-T03 — Tập con CIC-IDS2017

| Nhãn đồ án | Nhãn CIC-IDS2017 | Phiên thu |
|---|---|---|
| `dos` | DoS slowloris, Slowhttptest, Hulk, GoldenEye | Thứ Tư 05/07/2017, 09:47–11:23 |
| `port_scan` | PortScan (27 lượt Nmap, tường lửa bật và tắt) | Thứ Sáu 07/07/2017, 13:55–15:29 |
| `benign` | BENIGN | Cùng hai phiên |

Loại bỏ Heartbleed, DDoS LOIT (ba nguồn phát, trong khi lớp `dos` là một
nguồn), Botnet ARES và dữ liệu thứ Ba, thứ Năm. Thứ Hai (chỉ có traffic bình
thường) dành cho module anomaly.

Dữ liệu huấn luyện chính là **PCAP** của hai phiên, chạy qua bộ tính đặc trưng
của đồ án và gán nhãn theo lịch tấn công công bố. CSV có nhãn của CIC chỉ dùng
để đối chiếu, vì yêu cầu B12 đòi huấn luyện và realtime dùng cùng cách tính đặc
trưng, và các nghiên cứu sau này đã chỉ ra lỗi nhãn trong CSV gốc.
Train/validation/test tách theo khối thời gian vì mỗi lớp tấn công chỉ nằm
trong một ngày.

**Cập nhật 27/10/2026:** đã tải và kiểm tra PCAP thứ Hai (10,8 GB, 11,7 triệu gói)
và thứ Sáu (8,8 GB, 10,0 triệu gói); mã băm ghi trong manifest. Kiểm tra trên file
thật cho thấy:
- Giờ trong lịch tấn công là UTC−3, và lịch khớp dữ liệu tới từng phút.
- Bên tấn công hiện là `172.16.0.1` (NAT). Port scan và DDoS cùng IP nên phải
  tách theo khung giờ.
- File có đuôi `.pcap` nhưng thực chất là PCAPNG.

Ngày 29/10/2026 thêm PCAP thứ Tư (13,4 GB, 13,8 triệu gói; lịch DoS khớp UTC−3) và
`GeneratedLabelledFlows.zip`: số flow từng nhãn khớp số trích dẫn, cột `Timestamp`
của CSV là giờ địa phương kiểu 12 giờ mất SA/CH. Chi tiết ở
[06_cic_ids2017.md](06_cic_ids2017.md), mục 7.
Nguồn tải chính thức là https://www.unb.ca/cic/datasets/ids-2017.html (qua form
đăng ký ở `cicresearch.ca`); bộ nhãn đã sửa lỗi của nhóm KU Leuven ở
https://intrusion-detection.distrinet-research.be/CNS2022/.

### 3.4. C02-T04 — CTU-13

Đã kiểm tra trực tiếp máy chủ phát hành dataset ngày 12/10/2026:

- Cả 13 thư mục scenario đều truy cập được; ghi lại file, dung lượng, thời
  lượng, số bot và địa chỉ host của từng scenario.
- PCAP đầy đủ của toàn mạng **không được công bố**. Có sẵn: flow hai chiều có
  nhãn (`.binetflow`, tổng khoảng 2,6 GB), PCAP toàn mạng đã cắt còn phần
  header (khoảng 10,4 GB), PCAP chỉ có traffic của bot.
- Đã tải hai file flow của scenario 11 và 12, xác nhận 15 cột và đếm nhãn:
  scenario 11 có 107 251 flow (8 164 flow botnet), scenario 12 có 325 471 flow
  (2 168 flow botnet).

Ý nghĩa nhãn: chỉ flow `From-Botnet` là độc hại. `To-Botnet` và `To-Normal`
không được coi là độc hại; `Background` là traffic chưa kiểm chứng. Quy về nhãn
đồ án: host bot có flow `From-Botnet` trong cửa sổ là `suspect_host`, ba máy
bình thường đã xác nhận là `normal_host`, host Background không đưa vào đánh
giá. Không tải các file mẫu mã độc có trong thư mục dataset (B24).

### 3.5. C02-T05 — Manifest dữ liệu

`config/data_manifest.csv` có 30 dòng, mỗi dòng ghi nguồn, file, thời gian,
nhãn gốc, nhãn đồ án, mục đích (`train`, `validation`, `test`, `doi_chieu`),
dung lượng và mức độ đã kiểm tra.

| Nguồn | Số dòng | Trạng thái |
|---|---|---|
| CIC-IDS2017 | 5 | Cả 5 đã tải, có mã băm (cập nhật 29/10/2026) |
| CTU-13 | 13 | 11 đã kiểm tra trên máy chủ, 2 đã tải thử |
| Lab | 12 | Chưa thu |

| Bài toán | Dữ liệu |
|---|---|
| `anomaly` | CIC-IDS2017 thứ Hai (huấn luyện), thứ Tư và thứ Sáu (ngưỡng, kiểm thử); lab kịch bản 1–5 |
| `attack_classification` | CIC-IDS2017 thứ Tư và thứ Sáu; lab kịch bản 1, 2, 3 |
| `botnet_topology` | CTU-13 cả 13 scenario; lab kịch bản 4, 5 và hai đối chứng |
| Đối chiếu | CSV có nhãn của CIC-IDS2017; access log Nginx |

`src/nids/manifest.py` đọc manifest và từ chối file khi trùng mã, thiếu cột
bắt buộc, hoặc nhãn không thuộc tập nhãn của đồ án.

NETRESEC là trang danh mục liên kết tới nhiều kho PCAP khác nhau, không phải
một dataset có nhãn thống nhất, nên manifest không có dòng nào ghi nguồn là
NETRESEC. Đây là tiêu chí nghiệm thu của Chặng 2.

### 3.6. C02-T06 — Dữ liệu tự thu trong lab

| Thiếu hụt của dữ liệu công khai | Dữ liệu lab bù vào |
|---|---|
| Traffic bình thường của CIC-IDS2017 thuộc mạng khác | Kịch bản 1 |
| CIC-IDS2017 không có DoS kiểu SYN hoặc ICMP | Kịch bản 3, gồm cả lần chạy để huấn luyện |
| CTU-13 chỉ có một scenario ngang hàng với 3 bot | Kịch bản 5 |
| Flow kênh điều khiển trong CTU-13 rất ít, chu kỳ không kiểm soát được | Kịch bản 4 |
| Không có đối chứng lành tính | Hai kịch bản đối chứng |
| Độ trễ, mất gói, CPU, RAM chỉ đo được khi chạy thật | Mọi lần chạy kiểm thử |

Đã chốt 11 biến thể của năm kịch bản. DoS dùng kiểu **SYN**. Mỗi biến thể tối
thiểu 1 lần chạy huấn luyện, 1 lần validation và 3 lần kiểm thử, vai trò ghi
trước khi chạy: tổng tối thiểu **55 lần chạy, khoảng 8 giờ thu**. Mỗi lần chạy
sinh PCAP, nhật ký lần chạy (căn cứ gán nhãn) và access log.

## 4. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-008 | Log dịch vụ là access log của Nginx | Đã chốt |
| QĐ-009 | Tập con CIC-IDS2017 cho phân loại | Tạm thời |
| QĐ-010 | Dùng flow hai chiều có nhãn của CTU-13 | Tạm thời |
| QĐ-011 | Manifest dữ liệu là một file CSV trong `config/` | Đã chốt |
| QĐ-012 | Dữ liệu tự thu trong lab | Tạm thời |

## 5. Kiểm thử

| File | Số ca | Nội dung |
|---|---|---|
| `tests/test_manifest.py` | 5 | Mỗi module có dữ liệu, đủ 13 scenario CTU-13, từ chối nhãn lạ và mã trùng |

Cuối chặng: 15/15 ca của dự án đạt (gồm 10 ca của Chặng 1).

## 6. Điểm cần lưu ý

1. **Loại DoS không khớp giữa CIC-IDS2017 và lab.** CIC-IDS2017 chỉ có DoS tầng
   HTTP, lab dùng SYN. Lớp `dos` kiểu SYN phải lấy mẫu huấn luyện từ lab.
2. **Topology ngang hàng thiếu dữ liệu công khai.** CTU-13 chỉ có scenario 12,
   nên đánh giá `p2p` chủ yếu dựa vào lab.
3. **Số liệu CIC-IDS2017 đã đối chiếu** (27 và 29/10/2026): lịch tấn công, múi giờ,
   địa chỉ NAT và số flow từng nhãn khớp. CSV có một số nhãn nằm ngoài lịch.
4. **Cách chia train/test của CTU-13** đang theo bài báo gốc, trạng thái tạm thời.
5. **Tham số chưa chốt:** tốc độ Nmap, ba mức tải DoS, chu kỳ beaconing, số
   peer. Phải ghi vào cấu hình trước lần thu đầu tiên.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| PCAP, PCAPNG | Hai định dạng file lưu gói tin bắt được; PCAPNG mới hơn, là mặc định của Wireshark |
| Global Header, Packet Header, Packet Data | Header 24 byte đầu file; header 16 byte trước mỗi gói; byte của gói tin |
| magic_number, thứ tự byte | 4 byte đầu file cho biết định dạng; cách xếp byte của một số (little-endian hay big-endian) |
| snaplen, incl_len, orig_len | Số byte tối đa lưu mỗi gói; số byte đã lưu; độ dài thật của gói trên đường truyền |
| Tầng liên kết | Tầng thấp nhất trong file như Ethernet; quyết định gói bắt đầu bằng header nào |
| Block, giao diện | Khối dữ liệu có kiểu và độ dài trong PCAPNG; một card mạng |
| ARP | Giao thức hỏi địa chỉ MAC của một IP trong mạng nội bộ |
| tcpdump, Wireshark | Công cụ bắt gói dòng lệnh / có giao diện đồ họa |
| Nginx, access log | Phần mềm máy chủ web; file ghi mỗi yêu cầu web nhận được |
| Client, cổng nguồn | Bên gửi yêu cầu; số cổng phía client của kết nối |
| Flow | Tất cả gói tin của một kết nối giữa hai đầu (cùng IP, cổng, giao thức) |
| CIC-IDS2017, CTU-13 | Bộ dữ liệu tấn công mạng của Canada (2017) / bộ dữ liệu botnet của Séc (2011) |
| Tập con | Phần được chọn ra từ bộ dữ liệu lớn |
| slowloris, Slowhttptest, Hulk, GoldenEye | Bốn công cụ DoS ở tầng HTTP |
| Heartbleed, DDoS LOIT, Botnet ARES | Lỗ hổng OpenSSL; DDoS từ nhiều máy bằng LOIC; một loại botnet; đều bị loại khỏi tập con |
| Nmap, tường lửa | Công cụ quét cổng; thiết bị chặn hoặc cho qua gói tin theo luật |
| Lịch tấn công công bố | Bảng giờ và địa chỉ các đợt tấn công do tác giả bộ dữ liệu đăng; dùng để gán nhãn |
| Khối thời gian | Một khung giờ liền của một đợt tấn công; đơn vị để chia dữ liệu |
| Train / validation / test | Dữ liệu để học / để chọn tham số và ngưỡng / để đánh giá cuối |
| Scenario, bot | Một lần thu riêng trong CTU-13; máy bị nhiễm nhận lệnh từ xa |
| binetflow | File CSV flow hai chiều có nhãn của CTU-13 |
| From-Botnet, To-Botnet, Background | Flow do bot khởi tạo; flow gửi tới bot; traffic chưa kiểm chứng |
| suspect_host, normal_host | Máy nghi là bot / máy bình thường (nhãn của đồ án) |
| Manifest | Bảng liệt kê mọi nguồn dữ liệu và cách dùng |
| NETRESEC | Trang liệt kê liên kết tới các kho PCAP; không phải một bộ dữ liệu |
| Biến thể, đối chứng | Một cách chạy cụ thể của kịch bản; hành vi lành tính trông giống tấn công |
| Beaconing, peer | Bot gọi về máy điều khiển theo chu kỳ; máy ngang hàng trong mạng P2P |
| Kênh điều khiển | Đường bot nhận lệnh từ kẻ điều khiển |
| Nhật ký lần chạy | File ghi mỗi lần thử nghiệm trong lab; căn cứ gán nhãn |
| Mã độc | Phần mềm độc hại; đồ án không dùng mã độc thật |
