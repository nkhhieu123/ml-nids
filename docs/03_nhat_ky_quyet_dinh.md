# Nhật ký quyết định kỹ thuật

Mỗi quyết định ghi một mục, không sửa mục cũ. Khi đổi ý, thêm mục mới và ghi
mục cũ là "Thay bởi QĐ-xxx".

Mẫu:

```
## QĐ-xxx — Tiêu đề
- Ngày: dd/mm/yyyy
- Trạng thái: Đã chốt | Tạm thời | Thay bởi QĐ-xxx
- Bối cảnh:
- Quyết định:
- Hệ quả:
```

## QĐ-001 — Chia hệ thống thành ba module chạy song song
- Ngày: 10/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Kịch bản yêu cầu phát hiện bất thường, phân loại tấn công và phát hiện botnet/topology; Gaussian không được làm cổng lọc.
- Quyết định: Ba module `anomaly`, `attack_classification`, `botnet_topology` nhận cùng luồng đặc trưng và phát cảnh báo độc lập.
- Hệ quả: Một cửa sổ có thể sinh nhiều cảnh báo từ các module khác nhau; việc hợp nhất làm ở bước ghi cảnh báo.

## QĐ-002 — Bản đầu tiên chỉ xuất terminal và CSV
- Ngày: 10/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần kiểm chứng các module trước khi đầu tư giao diện.
- Quyết định: Cảnh báo ghi ra terminal và nối vào `output/alerts.csv`. Dashboard là yêu cầu tùy chọn T06.
- Hệ quả: CSV là nguồn dữ liệu để tính chỉ số; dashboard sau này đọc cùng file.

## QĐ-003 — Một schema cảnh báo chung cho cả ba module
- Ngày: 10/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần đối chiếu cảnh báo với nhật ký kịch bản và tính độ trễ phát hiện.
- Quyết định: Dùng các cột trong `docs/02_dau_ra_module.md`; có `run_id` để khớp nhật ký và `created_at` để tính độ trễ. Thời gian ghi theo UTC, ISO 8601.
- Hệ quả: Với cảnh báo topology, node trung tâm ghi ở `dst_ip`, `src_ip` để trống.

## QĐ-004 — Tên nhãn
- Ngày: 10/10/2026
- Trạng thái: Tạm thời → đã khóa bởi QĐ-065 (12/11/2026)
- Bối cảnh: Kịch bản nêu các lớp nhưng không quy định tên trong dữ liệu.
- Quyết định: Tên tiếng Anh viết thường: `normal`/`anomaly`; `benign`/`port_scan`/`dos`; `normal_host`/`suspect_host`; `centralized`/`p2p`/`none`.
- Hệ quả: Nhãn của CIC-IDS2017 và CTU-13 phải ánh xạ về các tên này khi chuẩn bị dữ liệu. Nhãn topology `none` cần xem lại khi thu dữ liệu đối chứng.

## QĐ-005 — Tách cấu hình khỏi mã nguồn
- Ngày: 11/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cửa sổ, địa chỉ lab và đường dẫn thay đổi theo môi trường và được chỉnh trên validation.
- Quyết định: Tham số nằm trong `config/default.yaml`, đọc qua `nids.config.load_config()`. Tên module và tập nhãn là hợp đồng giữa các phần mã nên nằm trong `src/nids/scope.py`.
- Hệ quả: Huấn luyện và realtime phải đọc cùng một file cấu hình (yêu cầu B12).

## QĐ-006 — Tham số cửa sổ và timeout ban đầu
- Ngày: 11/10/2026
- Trạng thái: Tạm thời → đã khóa bởi QĐ-066 (12/11/2026)
- Bối cảnh: Kịch bản cho giá trị cửa sổ ban đầu nhưng không cho giá trị timeout của flow.
- Quyết định: Cửa sổ flow/host 10 giây bước 2 giây; cửa sổ beaconing/đồ thị 120 giây bước 10 giây (theo kịch bản). Timeout nhàn rỗi của flow đặt 60 giây (nhóm tự chọn).
- Hệ quả: Các giá trị này được chỉnh trên tập validation rồi khóa lại trước khi kiểm thử; khi khóa phải thêm mục quyết định mới.

## QĐ-007 — Môi trường Python và thư viện
- Ngày: 11/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần một môi trường chạy được trên cả máy phát triển và Kali Linux.
- Quyết định: Python 3.10 trở lên, môi trường ảo `.venv`, cài bằng `pip install -e .`. Thư viện: numpy, pandas, scikit-learn (mô hình), scapy (bắt và đọc gói tin), networkx (đồ thị), PyYAML (cấu hình), joblib (lưu mô hình); nhóm `notebook` gồm jupyter và matplotlib.
- Hệ quả: Dữ liệu, PCAP, mô hình và kết quả chạy không đưa lên git (xem `.gitignore`).

## QĐ-008 — Log dịch vụ là access log của Nginx
- Ngày: 12/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần một loại log dịch vụ để đối chiếu với lưu lượng mạng bắt được trên Kali.
- Quyết định: Dùng access log của Nginx trên máy chủ dịch vụ `192.168.50.30`, định dạng riêng `nids` có cổng nguồn, thời điểm tới mili giây và thời gian phục vụ (xem `docs/05_log_dich_vu.md`). Log chỉ dùng để đối chiếu, không là đầu vào của mô hình và không dùng để gán nhãn.
- Hệ quả: Đồng hồ của máy chủ dịch vụ và Kali phải đồng bộ trước mỗi lần chạy. Log mỗi lần chạy lưu ở `data/service_logs/<run_id>/`.

## QĐ-009 — Tập con CIC-IDS2017 cho phân loại
- Ngày: 12/10/2026
- Trạng thái: Tạm thời → đã khóa bởi QĐ-065 (12/11/2026)
- Bối cảnh: Module phân loại có ba lớp `benign`, `port_scan`, `dos` (một nguồn); CIC-IDS2017 có nhiều loại tấn công khác.
- Quyết định: Dùng phiên thứ Tư 05/07/2017 (bốn công cụ DoS, bỏ Heartbleed) và phần port scan của chiều thứ Sáu 07/07/2017 (bỏ DDoS LOIT). Dữ liệu chính là PCAP chạy qua bộ ghép flow của đồ án, nhãn gán theo lịch tấn công; CSV có nhãn dùng để đối chiếu (xem `docs/06_cic_ids2017.md`).
- Hệ quả: Tách train/validation/test theo khối thời gian vì mỗi lớp tấn công chỉ nằm trong một ngày. DoS của CIC-IDS2017 là tầng HTTP, không khớp với SYN/ICMP của lab; nguồn mẫu `dos` cho loại này chưa được quyết định. Chưa tải file nên số liệu phải đối chiếu lại.

## QĐ-010 — Dùng flow hai chiều có nhãn của CTU-13
- Ngày: 12/10/2026
- Trạng thái: Tạm thời → đã khóa bởi QĐ-065 (12/11/2026)
- Bối cảnh: Mỗi scenario CTU-13 phát hành nhiều dạng file với hai kiểu nhãn khác nhau; PCAP đầy đủ của toàn mạng không được công bố.
- Quyết định: Dùng file `.binetflow` trong `detailed-bidirectional-flow-labels/` của cả 13 scenario. Chỉ flow `From-Botnet` là độc hại. Host bot có flow `From-Botnet` trong cửa sổ là `suspect_host`; ba máy bình thường đã xác nhận là `normal_host`; host Background không đưa vào đánh giá (xem `docs/07_ctu13.md`). Không tải các file mẫu mã độc.
- Hệ quả: Đặc trưng của module botnet phải tính được từ bản ghi flow. Chỉ scenario 12 là P2P nên topology ngang hàng phải đánh giá bằng dữ liệu lab. Điểm xuất phát cho việc tách là cách chia của bài báo gốc; scenario làm validation chưa chốt.

## QĐ-011 — Manifest dữ liệu là một file CSV trong config
- Ngày: 14/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Dữ liệu đến từ ba nguồn với định dạng và cách gán nhãn khác nhau; cần một nơi ghi dữ liệu nào phục vụ bài toán nào.
- Quyết định: Ghi vào `config/data_manifest.csv`, đọc và kiểm tra bằng `nids.manifest.load_manifest()` (xem `docs/08_manifest_du_lieu.md`). Mỗi dòng ghi nguồn gốc thật của dữ liệu; NETRESEC là trang danh mục nên không được ghi là nguồn. Dữ liệu lab ghi theo biến thể kịch bản, từng lần chạy ghi trong nhật ký lần chạy.
- Hệ quả: Khi tải hoặc thu xong dữ liệu phải cập nhật cột `trang_thai`. Nhãn trong manifest phải thuộc tập nhãn của `src/nids/scope.py`.

## QĐ-012 — Dữ liệu tự thu trong lab
- Ngày: 14/10/2026
- Trạng thái: Tạm thời → đã khóa bởi QĐ-065 (12/11/2026)
- Bối cảnh: CIC-IDS2017 không có DoS kiểu SYN/ICMP và thuộc mạng khác; CTU-13 chỉ có một scenario ngang hàng; không dataset nào có đối chứng lành tính.
- Quyết định: Thu 11 biến thể của năm kịch bản (xem `docs/09_du_lieu_lab.md`). DoS dùng SYN; ICMP và DDoS nhiều nguồn là tùy chọn. Mỗi biến thể tối thiểu 1 lần chạy `train`, 1 lần `val`, 3 lần `test`; vai trò ghi trước khi chạy. Mã lần chạy dạng `<mã biến thể>-<vai trò>-<số thứ tự>`.
- Hệ quả: Tối thiểu 55 lần chạy, khoảng 8 giờ thu. Tham số tốc độ quét, ba mức tải DoS và chu kỳ beaconing chưa chốt, phải ghi vào cấu hình trước lần chạy đầu tiên. Các lần chạy `test` thu sau khi mô hình và ngưỡng đã khóa.

## QĐ-013 — Tự viết bộ đọc file PCAP/PCAPNG bằng thư viện chuẩn
- Ngày: 17/10/2026
- Trạng thái: Tạm thời → đã khóa bởi QĐ-065 (12/11/2026)
- Bối cảnh: Kế hoạch gợi ý chọn giữa Scapy, PyShark và dpkt để đọc packet. File PCAP của CIC-IDS2017 cỡ 10 GB mỗi ngày; Scapy dựng đối tượng cho mọi tầng của từng gói nên chậm với file cỡ này; PyShark cần cài TShark trên mọi máy.
- Quyết định: Bộ đọc file (`src/nids/pcap_reader.py`) tự viết bằng `struct`, đọc theo luồng, trả về bản ghi thô kèm `orig_len` và timestamp nano giây; hỗ trợ cả PCAPNG (xem `docs/11_bo_doc_pcap.md`). Scapy vẫn là thư viện bắt gói trực tiếp ở chặng 10.
- Hệ quả: Chương trình offline và realtime phải đưa packet vào cùng một bước phân tích header (C03-T02, C03-T03) để giữ đúng yêu cầu B12. Có thể đổi sang dpkt cho bước phân tích header nếu tự viết tốn quá nhiều công; quyết định khi làm C03-T02.

## QĐ-014 — Tự viết phần đọc header Ethernet/IP
- Ngày: 19/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: QĐ-013 để ngỏ việc dùng dpkt cho bước đọc header khi làm C03-T02.
- Quyết định: Tự viết bằng `struct` trong `src/nids/packets.py`: Ethernet (có VLAN), Linux cooked, loopback, IP thô; IPv4 và IPv6 có header mở rộng (xem `docs/12_trich_xuat_packet.md`). Không thêm dpkt.
- Hệ quả: Kết quả đã khớp `tshark` trên mọi gói của hai bản thu CTU-13. Chương trình realtime phải đưa byte thô của gói bắt được qua cùng hàm `parse_packet()`.

## QĐ-015 — Gói không đọc được bị bỏ qua có thống kê; file hỏng giữ phần đã đọc
- Ngày: 21/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Bản thu có gói không phải IP (ARP chiếm 1,4% bản thu donbot của CTU-13), gói bị cắt, và có thể có file bị dừng ghi giữa chừng. Bỏ đi lặng lẽ sẽ làm sai lệch đặc trưng mà không ai biết.
- Quyết định: Mỗi gói bị bỏ có một trong năm lý do (`khong_phai_ip`, `linktype_khong_ho_tro`, `header_lien_ket_bi_cat`, `header_ip_bi_cat`, `header_ip_sai`); gói giữ lại có ghi chú bất thường; `ParseStats` đếm cả hai (xem `docs/14_goi_bo_qua.md`). File hỏng giữa chừng thì dừng đọc, giữ các gói trước đó và ghi lỗi. IPv4 có Total Length 0 (TSO) được giữ, độ dài lấy theo số byte đã bắt như Wireshark.
- Hệ quả: Nhật ký mỗi lần chạy lab phải lưu kết quả `ParseStats.as_dict()`. Lần chạy có `loi_file` hoặc tỉ lệ bỏ qua bất thường phải xem lại trước khi đưa vào train/test.

## QĐ-016 — Flow hai chiều; forward là chiều của bên mở kết nối
- Ngày: 25/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Đặc trưng fwd/bwd và tỷ lệ gửi/nhận cần biết gói nào đi từ client. CICFlowMeter lấy bên gửi gói đầu tiên làm forward, nên đảo chiều khi bắt giữa chừng kết nối hoặc khi lỡ mất gói SYN. Mảnh IP sau mảnh đầu không có cổng nên dễ rơi khỏi flow.
- Quyết định: Flow hai chiều gồm các gói cùng phiên bản IP, giao thức và cặp đầu mút (IP, cổng; giao thức không có cổng thì chỉ IP), hai đầu xếp theo IP dạng số rồi cổng. Client được chọn một lần từ gói đầu tiên của flow, theo thứ tự: SYN (bên gửi), SYN+ACK (bên nhận), TCP giữa chừng có đúng một bên dùng cổng < 1024 (bên còn lại), còn lại là bên gửi gói đầu. Không đoán theo cổng với UDP. Mảnh sau được gắn vào flow và chiều của mảnh đầu cùng (IP nguồn, IP đích, giao thức, Identification) nếu mảnh đầu tới trước tối đa `flow.fragment_timeout_s` = 30 giây (xem `docs/18_flow_hai_chieu.md`).
- Hệ quả: Bộ trích xuất packet thêm trường `frag_id`. Mỗi flow ghi `direction_basis` để biết chiều chắc chắn tới đâu. Chiều không bao giờ được sửa theo gói tới sau, nên huấn luyện và realtime giống nhau. Tách flow theo timeout, FIN/RST và 5-tuple dùng lại để cho C04-T02 (QĐ-017).

## QĐ-017 — Kết thúc flow: FIN/RST có thời gian chờ, SYN mới, timeout nhàn rỗi và active timeout
- Ngày: 26/10/2026
- Trạng thái: Đã chốt (giá trị thời gian khóa bởi QĐ-066, 12/11/2026)
- Bối cảnh: Một 5-tuple có thể chứa nhiều kết nối liên tiếp (bot Virut mở lại cùng cổng nguồn tới cùng máy chủ) hoặc một kết nối rất dài. CICFlowMeter đóng flow ngay ở FIN đầu tiên, làm gói ACK cuối thành flow một gói. Đo trên CTU-13: khoảng 97% gói tới sau khi TCP đóng nằm trong 10 giây.
- Quyết định: Flow kết thúc, theo thứ tự ưu tiên, khi: (1) TCP đã đóng bằng FIN hai chiều hoặc RST và gói mới có cờ SYN hoặc tới sau `close_grace_s` = 10 giây; (2) nhàn rỗi quá `idle_timeout_s` = 60 giây; (3) có gói bắt tay mới (SYN, SYN+ACK) trên flow chưa đóng, phân biệt với gói gửi lại bằng số thứ tự TCP (trường `tcp_seq` thêm vào bảng packet); (4) dài quá `active_timeout_s` = 120 giây, như CICFlowMeter. Flow mở lại bằng gói không phải SYN/SYN+ACK trong vòng `direction_memory_s` = 3600 giây sau flow trước cùng khóa thì giữ chiều của flow trước (`continuation`). Mọi thời gian tính theo thời điểm trong gói (xem `docs/19_ket_thuc_flow.md`).
- Hệ quả: Bảng flow có thêm `end_reason` và `continuation`. Đặc trưng theo flow là của từng đoạn tối đa 120 giây. Realtime dùng `pop_finished()`/`expire()` và cho cùng kết quả với đọc file. Thống kê flow ghi kèm bộ tham số đã dùng.

## QĐ-018 — Đặc trưng byte dùng ip_len kèm payload; tỷ lệ gửi/nhận là phần trong tổng
- Ngày: 26/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: CIC-IDS2017, CTU-13 và lab được bắt bằng cách khác nhau nên `frame_len` của cùng một gói khác nhau. CICFlowMeter tính độ dài theo payload. Tỷ lệ dạng bwd/fwd vô hạn khi một chiều không có gói (4 249 trong 4 588 flow donbot là SYN không trả lời).
- Quyết định: `*_bytes` là tổng `ip_len`; `*_payload_bytes` là tổng dữ liệu TCP/UDP (`payload_len`, tính từ ip_len trừ các header, thêm vào bản ghi packet). Thời lượng là thời điểm lớn nhất trừ nhỏ nhất của các gói. Tỷ lệ gửi/nhận là `fwd_packet_share` và `fwd_byte_share` trong [0, 1]. Không tính tốc độ byte/giây ở bước này (xem `docs/20_dac_trung_flow_co_ban.md`).
- Hệ quả: Không đặc trưng nào ở bước này có giá trị vô hạn. `payload_len` được đối chiếu với `tcp.len`/`udp.length` của Wireshark. Cột payload để trống với flow không phải TCP/UDP; C05 cần xử lý giá trị trống này.

## QĐ-019 — Dữ liệu tải về: nơi đặt, mã băm, múi giờ của CIC-IDS2017
- Ngày: 27/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Đã tải PCAP CIC-IDS2017 thứ Hai và thứ Sáu (10,8 GB và 8,8 GB). GitHub không nhận file trên 100 MB và quy ước của dự án là không đưa dữ liệu lên git, nên người khác phải tự tải lại và cần cách kiểm tra có đúng bản. Lịch tấn công của CIC không ghi múi giờ.
- Quyết định: File đặt ở `data/pcap/cic-ids2017/`, giữ nguyên tên gốc. Manifest có thêm cột `sha256` và trạng thái `da_tai` (bắt buộc có mã băm); `python -m nids.manifest --verify` so mã băm. Lịch tấn công của CIC được hiểu là giờ **UTC−3**, đã đo trên PCAP thứ Sáu và khớp tới từng phút. Bên tấn công trong PCAP là `172.16.0.1` (NAT), dùng cho cả port scan và DDoS, nên gán nhãn phải theo khung giờ (xem `docs/06_cic_ids2017.md`, mục 7).
- Hệ quả: Khi tải thêm file (PCAP thứ Tư, CSV có nhãn, CTU-13) phải ghi mã băm vào manifest. Bước gán nhãn ở Chặng 5 đổi lịch sang UTC bằng cách cộng 3 giờ.

## QĐ-020 — Thống kê theo gói: ip_len, độ lệch chuẩn tổng thể, ô trống khi không có dữ liệu
- Ngày: 29/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: C04-T04 cần thống kê kích thước, khoảng cách giữa các gói và cờ TCP. Flow một gói (SYN quét không trả lời) rất nhiều nên phải quyết định giá trị khi không có khoảng cách nào; realtime cần tính mà không giữ danh sách gói.
- Quyết định: Min/max/trung bình/độ lệch chuẩn tổng thể (chia n) của `ip_len` và của khoảng cách giữa hai gói liên tiếp (cả flow và theo từng chiều), tính dần bằng Welford; khoảng âm do sai thứ tự thời gian tính là 0. Đếm số gói có từng cờ trong 8 cờ TCP. Cột không có dữ liệu (dưới 2 gói, một chiều trống) để **trống**, không ghi 0 (xem `docs/21_thong_ke_flow.md`).
- Hệ quả: Bảng flow thêm 32 cột. Chặng 5 phải xử lý ô trống khi tiền xử lý. Không so trực tiếp được với cột CIC tương ứng vì CIC dùng payload, micro giây, độ lệch chuẩn mẫu và ghi 0.

## QĐ-021 — Cửa sổ host theo thời gian gói, lưới cửa sổ cố định theo epoch
- Ngày: 29/10/2026
- Trạng thái: Đã chốt (kích thước và bước vẫn theo QĐ-006, tạm thời)
- Bối cảnh: Đặc trưng theo host (B02) cần cửa sổ 10 giây bước 2 giây. Cửa sổ phải giống nhau khi đọc file và khi chạy realtime, và không được dùng gói tới sau khi cửa sổ đã kết thúc.
- Quyết định: Host là một địa chỉ IP; mỗi gói tính cho máy gửi (ra) và máy nhận (vào). Cửa sổ `[start, start + size)` với `start` là bội số của `step` tính từ epoch. Thời gian trôi theo thời điểm của gói: cửa sổ đóng khi đã thấy gói có thời điểm ≥ `end`. Gói sai thứ tự thuộc cửa sổ đã đóng không được cộng lại vào cửa sổ đó mà được đếm là gói trễ. Có thể giới hạn host theo dải mạng (xem `docs/22_cua_so_host.md`).
- Hệ quả: Host im lặng không có dòng. Đặc trưng cửa sổ ở C04-T06, T07 dùng lại `HostWindower` qua `window_factory`. Với CIC phải chạy kèm `--net 192.168.10.0/24`.

## QĐ-022 — Đặc trưng cửa sổ host tính theo vai client/server của flow
- Ngày: 29/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Số đích, số cổng đích và entropy cổng phân biệt quét cổng với hành vi bình thường. Nếu đếm mọi gói host gửi đi thì server trả lời nhiều client (tới cổng tạm khác nhau) trông giống máy quét.
- Quyết định: Chỉ gói host gửi theo chiều forward (host là client của flow) được tính vào `dst_hosts`, `dst_ports`, `dst_host_ports` và entropy cổng đích; gói forward host nhận tính vào `src_hosts`. Entropy Shannon (log2) theo số gói tới từng cổng. Kết nối mới là gói đầu của flow không phải phần tiếp nối, tính cho client (`new_conn_out`) và server (`new_conn_in`). Entropy để trống khi không có gói TCP/UDP trong vai client (xem `docs/23_dac_trung_cua_so.md`).
- Hệ quả: Đặc trưng cửa sổ phụ thuộc chiều của C04-T01, nên phải chạy cùng bộ ghép flow (`WindowPipeline`).

## QĐ-023 — Kết nối không hoàn tất xét sau 3 giây quan sát; cửa sổ chờ thêm 3 giây
- Ngày: 29/10/2026
- Trạng thái: Đã chốt (giá trị 3 giây khóa bởi QĐ-066, 12/11/2026)
- Bối cảnh: Quét cổng và SYN flood để lại nhiều lần thử TCP không hoàn tất. Muốn biết một lần thử có hoàn tất không phải chờ trả lời, nhưng không được dùng gói tới quá xa (dữ liệu tương lai). Nghiệm thu Chặng 4 yêu cầu SYN thiếu phản hồi chỉ là dấu hiệu nghi vấn.
- Quyết định: Lần thử là flow TCP mở bằng SYN của client, không phải phần tiếp nối. Chỉ xét các gói trong `flow.handshake_observe_s` = 3 giây sau SYN để xếp loại: `hoan_tat` (SYN+ACK rồi ACK của client), `do_dang`, `bi_tu_choi`, `khong_phan_hoi`. Tỷ lệ không hoàn tất tính cho host ra (client) và vào (server); trống khi không có lần thử. Cửa sổ host chờ thêm 3 giây sau `end` mới trả ra (xem `docs/24_ket_noi_khong_hoan_tat.md`).
- Hệ quả: Flow ghi thêm thời điểm SYN+ACK, ACK của client, RST của server. Các cột này là đặc trưng, không dùng để gán nhãn. Cảnh báo realtime theo cửa sổ chậm thêm 3 giây.

## QĐ-024 — Bảng đặc trưng: hai bảng CSV, schema có vai trò cột, metadata truy vết
- Ngày: 29/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Chặng 5 cần bảng đặc trưng đọc được đúng kiểu, biết cột nào là đặc trưng, cột nào là định danh (IP, cổng, thời điểm: đưa vào mô hình sẽ học thuộc địa chỉ), và truy được bảng tạo từ file nào, tham số nào, phiên bản mã nào.
- Quyết định: `python -m nids.feature_export` đọc PCAP một lượt, ghi `<tên>.flows.csv`, `<tên>.windows.csv`, `<tên>.schema.json` (kiểu, đơn vị, vai trò `dac_trung`/`dinh_danh`/`ngu_canh`/`kiem_tra`, có thể trống, mô tả; phiên bản 1.0) và `<tên>.meta.json` (mã băm nguồn, commit git, tham số, thống kê). `read_table` đọc lại và từ chối bảng lệch schema (xem `docs/25_xuat_bang_dac_trung.md`).
- Hệ quả: Chặng 5 chỉ dùng cột `dac_trung` cho mô hình; cột `dinh_danh` để gán nhãn và chia dữ liệu. Đổi cột thì phải tăng phiên bản schema. Bảng tạo từ mã chưa commit không dùng cho kết quả cuối.

## QĐ-025 — Nhãn gán theo lịch tấn công, cặp IP và cổng nạn nhân; bốn trạng thái nhãn
- Ngày: 29/10/2026
- Trạng thái: Đã chốt (giá trị nới 60 giây khóa bởi QĐ-063, 12/11/2026)
- Bối cảnh: QĐ-009 chọn gán nhãn CIC theo lịch tấn công thay vì cột nhãn của CSV (có lỗi). Cần một nguồn nhãn có thể kiểm tra, dùng được cho cả dữ liệu lab sau này, và không ép nhãn cho mẫu thiếu căn cứ.
- Quyết định: Lịch ở `config/label_schedule.csv` (khung giờ địa phương, múi giờ, IP bên tấn công và nạn nhân như thấy trong PCAP, cổng nạn nhân, nhãn, khối). Mẫu khớp khi hai đầu là cặp tấn công (đúng cổng nếu có) và thời gian chạm khung giờ nới `labeling.tolerance_s` = 60 giây. Bốn trạng thái: `khop`, `loai` (tấn công ngoài ba lớp: chỉ dùng cho anomaly), `mo_ho` (cặp tấn công ngoài khung giờ cùng ngày, hoặc chạm hai đợt khác nhãn: không gán nhãn), `khong_khop` (benign/normal) (xem `docs/26_gan_nhan.md`).
- Hệ quả: Nhãn ghi ra file riêng, nối với bảng đặc trưng bằng khóa. Đợt bị loại vẫn phải có trong lịch để không thành benign. Mẫu `mo_ho` bị bỏ khỏi huấn luyện và đánh giá, có báo số lượng.

## QĐ-026 — Nhãn cửa sổ theo phần flow tấn công; dưới 20% là mơ hồ
- Ngày: 29/10/2026
- Trạng thái: Đã chốt (ngưỡng 0,2 khóa bởi QĐ-063, 12/11/2026)
- Bối cảnh: Cửa sổ 10 giây của nạn nhân hay bên tấn công thường lẫn flow tấn công và bình thường (81% cửa sổ tấn công của CIC thứ Tư). Quét cổng là flow một gói nên không thể đo theo thời gian.
- Quyết định: Đếm flow của host chồng lên cửa sổ theo nhãn flow. Có flow bị loại thì cửa sổ là `loai`; một lớp tấn công với phần flow tấn công ≥ `labeling.window_min_attack_share` = 0,2 thì nhận lớp đó; dưới ngưỡng hoặc hai lớp thì `mo_ho` (vẫn `anomaly`); chỉ có flow mơ hồ thì `mo_ho`; còn lại benign (xem `docs/28_nhan_cua_so.md`).
- Hệ quả: Cột `attack_share`, `n_flows`, `n_attack_flows` được giữ để thử ngưỡng khác mà không gán nhãn lại.

## QĐ-027 — Chia dữ liệu theo thời gian trong từng khối tấn công, 60/20/20, vùng đệm 10 giây
- Ngày: 29/10/2026
- Trạng thái: Đã chốt (thay cách gán nguyên khối dự kiến ở docs/06 mục 5)
- Bối cảnh: Cửa sổ chồng nhau và mẫu của cùng một đợt rất giống nhau, nên chia ngẫu nhiên gây rò rỉ (B11). `port_scan` chỉ có 2 khối (một khối gần như rỗng), nên gán nguyên khối vào một tập làm thiếu lớp.
- Quyết định: Trong mỗi phiên, mỗi khối tấn công (cột `khoi` của lịch) và mỗi khoảng giữa các khối được cắt theo thứ tự thời gian thành train, validation, test với 60%, 20%, 20% số flow (ranh giới ở phân vị thời điểm bắt đầu flow; khoảng dưới 20 flow chia theo thời gian). Mẫu phải nằm trọn trong một đoạn và cách ranh giới hai tập khác nhau ít nhất `split.embargo_s` = 10 giây; còn lại là `bo` (xem `docs/29_chia_du_lieu.md`).
- Hệ quả: Test luôn sau train trong cùng khối; hai tập không chung gói. Khả năng gặp công cụ chưa thấy được đánh giá riêng ở Chặng 7. Validation của `port_scan` ở bảng cửa sổ mỏng (50 mẫu) vì quét diễn ra theo từng đợt ngắn.
- Sửa 02/11/2026: Heartbleed và DDoS có khối riêng (`wed-heartbleed`, `fri-ddos`) để module anomaly có mẫu của chúng ở cả ba tập; trước đó Heartbleed nằm trọn trong validation.

## QĐ-028 — Tiền xử lý chỉ fit trên train; bỏ trùng và cân bằng chỉ trên train; Gaussian học trên thứ Hai
- Ngày: 30/10/2026
- Trạng thái: Đã chốt (tỷ lệ cân bằng 10 thay bởi QĐ-035 cho Chặng 7); phần "Gaussian học trên thứ Hai" thay bởi QĐ-032
- Bối cảnh: Đặc trưng lệch phải mạnh, nhiều ô trống có ý nghĩa, lớp mất cân bằng nặng (benign gấp 376 lần port_scan ở bảng cửa sổ), 98,9% flow port_scan trùng nhau. Tham số tiền xử lý và việc cân bằng không được dùng dữ liệu đánh giá.
- Quyết định: `log(1 + x)` cho đặc trưng đếm, byte, giây; điền trung vị của train kèm cột đánh dấu ô trống; chuẩn hóa theo train. Module phân loại dùng thứ Tư và thứ Sáu, bỏ mẫu train trùng hệt, giảm mẫu mỗi lớp xuống tối đa 10 lần lớp ít nhất, kèm trọng số lớp. Module anomaly fit trên mẫu normal của train thứ Hai, không bỏ trùng vì tần suất là thông tin của phân bố. Validation và test giữ phân bố thật (xem `docs/32_tien_xu_ly.md`).
- Hệ quả: Bộ tiền xử lý lưu ở `models/`, chương trình realtime nạp lại đúng phép biến đổi này (B12). Không dùng SMOTE.

## QĐ-029 — Gaussian dùng cửa sổ host, chọn đặc trưng theo quy tắc trên train
- Ngày: 02/11/2026
- Trạng thái: Đã chốt (tập phiên để fit chọn trên validation ở C06-T04)
- Bối cảnh: Gaussian cần mọi cột có giá trị và ma trận hiệp phương sai nghịch đảo được. Bảng cửa sổ có cột trống nhiều (tỷ lệ không hoàn tất), cột là tổng của cột khác và các cặp gần trùng thông tin.
- Quyết định: Dùng bảng cửa sổ host. Học trên mẫu `normal` của train. Chọn đặc trưng bằng quy tắc chạy trên train: bỏ cột trống quá 50% (trừ `dst_port_entropy`, trống nghĩa là 0), bỏ `incomplete_out` (tổng ba cột thành phần), bỏ cột hằng số, bỏ cột sau trong mỗi cặp Spearman |r| ≥ 0,95. Trên CIC được 14 đặc trưng (xem `docs/33_gaussian_dac_trung.md`).
- Hệ quả: Danh sách đặc trưng được lưu cùng mô hình. Các cột về kết nối không hoàn tất gần như luôn 0 khi bình thường, nên phân bố lệch mạnh và hiệp phương sai gần suy biến; xử lý ở C06-T02, T03.

## QĐ-030 — Biến đổi trước Gaussian: Yeo-Johnson và log(1 + x); ngưỡng không theo χ²
- Ngày: 02/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Các đặc trưng cửa sổ lệch phải rất mạnh (|skew| trung vị 10,5). Năm cột gần như luôn bằng 0.
- Quyết định: Yeo-Johnson (λ học trên train) cho cột có dưới 90% giá trị 0; log(1 + x) cho cột còn lại; chuẩn hóa theo train. Ngưỡng điểm bất thường chọn trên validation, không lấy từ phân bố χ² lý thuyết.
- Hệ quả: |skew| trung vị còn 1,04, chỉ số điều kiện từ 2 390 xuống 63. Đuôi d² vẫn dày hơn χ²(14) rất nhiều (phân vị 99%: 98 so với 29), nên giả định Gaussian chỉ đúng gần đúng ở phần giữa phân bố (docs/34).

## QĐ-031 — Điểm bất thường là d² Mahalanobis; hiệp phương sai Ledoit-Wolf kèm sàn trị riêng
- Ngày: 02/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Σ⁻¹ phải tồn tại cả khi dữ liệu mới (lab) có cột trùng thông tin mà quy tắc chọn đặc trưng chưa lường trước.
- Quyết định: Gaussian đa biến đầy đủ (không giả định các cột độc lập). Điểm là d² = (z − μ)ᵀΣ⁻¹(z − μ). Σ ước lượng bằng Ledoit-Wolf (`gaussian.covariance`), sau đó trị riêng < 10⁻⁶ × lớn nhất được nâng lên mức đó.
- Hệ quả: Trên CIC, hệ số co chỉ 0,006 nên kết quả gần như hiệp phương sai mẫu. Trường hợp suy biến thật (đủ 20 cột) cho chỉ số điều kiện 748 thay vì 10⁶ (docs/35).

## QĐ-032 — Gaussian fit trên normal của train cả ba ngày; ngưỡng F1 ổn định chọn trên validation
- Ngày: 02/11/2026
- Trạng thái: Đã chốt (thay phần "Gaussian học trên thứ Hai" của QĐ-028)
- Bối cảnh: Trên validation, ngưỡng F1 lớn nhất (d² = 145,6) nằm sát một vách: cụm cửa sổ bot có d² quanh 125–150, ngưỡng tăng nhẹ là F1 rơi từ 0,71 xuống 0,27.
- Quyết định: Fit trên mẫu normal của train mọi phiên (F1 validation 0,700 so với 0,681 khi chỉ thứ Hai). Ngưỡng chọn bằng `f1_on_dinh`: lấy ngưỡng có F1 xấu nhất trong khoảng lệch ±20% lớn nhất. Ngưỡng đạt được: d² = 64,65.
- Hệ quả: Ngưỡng nằm trong vùng F1 phẳng (51,5–139,5), đổi lấy FPR 1,49% thay vì 0,65%. Heartbleed không bắt được (recall 0), DDoS và Slowhttptest thấp; phân tích ở docs/36 và C06-T05.

## QĐ-033 — Phân loại ba lớp trên cửa sổ host; DDoS, Heartbleed, Bot chưa thành lớp
- Ngày: 02/11/2026
- Trạng thái: Đã chốt cho CIC-IDS2017 (xem lại khi có dữ liệu lab)
- Bối cảnh: C07-T01 cần chốt nhãn thực tế. Bảng flow có phần lớn mẫu `port_scan` test trùng hệt train; CIC có thêm DDoS (một đợt), Heartbleed (một kết nối) và Bot.
- Quyết định: Ba lớp `benign`, `port_scan`, `dos` trên **cửa sổ host** của thứ Tư và thứ Sáu, chỉ nhãn chắc chắn (`khop`, `khong_khop`). DDoS, Heartbleed, Bot không thành lớp; brute-force và exploit chỉ thêm khi có dữ liệu và kiểm thử tương ứng.
- Hệ quả: Train 166 233 cửa sổ (port_scan 671, dos 2 270), validation 54 647 (port_scan chỉ 50), test 68 902 (port_scan 462, dos 727). Chi tiết ở docs/39.

## QĐ-034 — Logistic Regression làm mức chuẩn; tỷ lệ cân bằng và trọng số lớp chọn trên validation
- Ngày: 02/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Với cân bằng của QĐ-028 (tối đa 10 lần) và `class_weight = balanced`, LR đạt macro-F1 validation 0,418: 13% cửa sổ benign bị báo tấn công vì train có 37% tấn công còn thực tế khoảng 1,3%. Không cân bằng thì macro-F1 0,883.
- Quyết định: LR (C = 1, balanced) là mức chuẩn của C07-T02, dùng chung tiền xử lý với Random Forest. Tỷ lệ giảm mẫu train (10, 100, không giảm) và `class_weight` thành tham số chọn theo macro-F1 validation ở C07-T04, thay cho mức 10 cố định.
- Hệ quả: Phần "tỷ lệ cân bằng 10" của QĐ-028 không còn cố định cho Chặng 7. Chi tiết ở docs/40.

## QĐ-035 — Chọn Random Forest cho phân loại tấn công; không cân bằng lớp
- Ngày: 02/11/2026
- Trạng thái: Đã chốt cho CIC-IDS2017
- Bối cảnh: C07-T04 chọn theo macro-F1 validation, hai bước (tỷ lệ giảm mẫu × class_weight, rồi tham số còn lại). Không giảm mẫu, không trọng số tốt nhất cho cả hai mô hình.
- Quyết định: Random Forest 300 cây, max_depth 20, min_samples_leaf 3, max_features sqrt, train giữ nguyên phân bố lớp (macro-F1 validation 0,913). LR (C = 1, không cân bằng, 0,883) giữ làm mức chuẩn.
- Hệ quả: RF hơn LR ở 99,7% lần bootstrap ghép cặp trên validation (hiệu +0,029), chủ yếu nhờ recall dos. Tham số cây gần như không ảnh hưởng (0,89–0,913). Thay phần cân bằng 10 lần của QĐ-028 cho Chặng 7. Chi tiết ở docs/42.

## QĐ-036 — Đồ thị theo cửa sổ quanh host cần xét; flow thuộc cửa sổ theo thời điểm bắt đầu
- Ngày: 03/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C08-T01 cần đồ thị giao tiếp theo cửa sổ. File CTU-13 tới 4,7 triệu flow mỗi scenario, phần lớn là Background giữa các máy không có nhãn; dựng đồ thị toàn mạng trường cho mọi cửa sổ vượt RAM 12 GB.
- Quyết định: Cửa sổ 120 giây, bước 10 giây (B02, `windows.graph`). Node là IP, cạnh có hướng từ bên khởi tạo, trọng số: số flow, gói, byte, số cổng, flow UDP, flow không được trả lời. Chỉ dựng đồ thị một bước quanh **host cần xét**: bot trong mạng trường (147.32.x), ba máy bình thường đã xác nhận, và 20 host Background lấy mẫu ngẫu nhiên mỗi scenario (seed cố định) để ước lượng báo động. Mọi flow có một đầu là host cần xét đều giữ, kể cả flow Background. Flow thuộc mọi cửa sổ chứa thời điểm bắt đầu của nó.
- Hệ quả: Đặc trưng chỉ nhìn được hàng xóm trực tiếp của host, không thấy bậc của hàng xóm. Peer ngoài mạng mang nhãn From-Botnet (scenario 12) không là host xét, chỉ là peer. Flow dài được tính ở cửa sổ bắt đầu. Chi tiết ở docs/45.

## QĐ-037 — Đặc trưng đồ thị của host–cửa sổ; hướng không có flow thì để trống
- Ngày: 03/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C08-T02 cần số peer, bậc vào/ra, tính tương hỗ và mức tập trung, tính được từ bảng cạnh một bước quanh host (QĐ-036), dùng chung cho CTU-13 và lab.
- Quyết định: 19 đặc trưng: số peer, bậc ra/vào, flow/byte/gói mỗi hướng, tỷ lệ peer tương hỗ, mức tập trung (phần flow lớn nhất vào một peer, entropy chuẩn hóa) mỗi hướng, số cổng đích, tỷ lệ flow ra không được trả lời, tỷ lệ UDP, tỷ lệ peer nội bộ (`botnet.local_nets`), tỷ lệ peer mới so với cửa sổ không chồng lấn trước. Hướng không có flow thì mức tập trung, entropy, tỷ lệ không trả lời để trống.
- Hệ quả: Mô hình phải điền ô trống (trung vị train và cột đánh dấu). Không có đặc trưng độ trung tâm toàn mạng; phần nhiều bot chung một máy điều khiển để cho bộ nhận diện topology. Chi tiết ở docs/46.

## QĐ-038 — Beaconing nhìn ngược 600 giây, tối thiểu 5 quan sát, đều khi CV ≤ 0,3
- Ngày: 03/11/2026
- Trạng thái: Đã chốt (tham số chỉnh được trong `botnet.beaconing`)
- Bối cảnh: C08-T03 cần đặc trưng beaconing có số quan sát tối thiểu. Trong cửa sổ 120 giây, 5 lần gọi chỉ thấy được chu kỳ ≤ 30 giây.
- Quyết định: Cặp (host, peer, cổng, giao thức) theo flow host khởi tạo; quan sát là thời điểm bắt đầu flow trong 600 giây nhìn ngược từ cuối cửa sổ; cần ≥ 5 quan sát, nếu không thì CV và chu kỳ để trống. Cặp đều khi CV khoảng cách ≤ 0,3 và khoảng cách trung bình ≥ 1 giây.
- Hệ quả: Trên CTU-13, 58,7% cửa sổ bot và 57,8% cửa sổ máy bình thường có cặp đều; cặp CC có CV trung vị 0,92. Beaconing không tách được bot khỏi máy bình thường trên CTU-13, giữ làm đặc trưng và kiểm tra trên dữ liệu giả lập, lab. Chi tiết ở docs/47.

## QĐ-039 — Nhãn host–cửa sổ botnet; Background chỉ để ước lượng báo động; chia theo scenario
- Ngày: 03/11/2026
- Trạng thái: Đã chốt (scenario validation 4 và 13 khóa bởi QĐ-065); phần "Background không học" sửa bởi QĐ-040
- Bối cảnh: C08-T04 cần dữ liệu host–cửa sổ có nhãn và quy định cách xử lý Background, phần lớn traffic CTU-13 chưa được kiểm chứng.
- Quyết định: `suspect_host` khi bot trong mạng khởi tạo ≥ 1 flow From-Botnet trong cửa sổ; `normal_host` khi máy bình thường đã xác nhận khởi tạo flow From-Normal; host Background lấy mẫu không học, không tính Precision/Recall, chỉ báo tỷ lệ bị báo; còn lại bỏ (gồm cửa sổ trước khi bị nhiễm). Flow Background vẫn giữ trong đồ thị. Chia theo scenario: train 3, 5, 7, 10, 11, 12; validation 4, 13; test 1, 2, 6, 8, 9.
- Hệ quả: Train 9 575 bot / 32 827 bình thường, validation 6 555 / 10 453, test 19 188 / 24 880 host–cửa sổ, nhưng chỉ khoảng 10 IP bot và 4 IP bình thường. Scenario P2P duy nhất ở train. Chi tiết ở docs/48.

## QĐ-040 — Chọn mô hình botnet với giới hạn báo động trên Background; Background làm mẫu âm yếu
- Ngày: 03/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Chọn theo F1 validation đẩy ngưỡng xuống 0,05 và làm 84–93% cửa sổ Background bị báo: với 4 máy bình thường giống nhau ở mọi tập, mô hình học danh tính máy thay vì hành vi bot.
- Quyết định: Chọn tham số, ngưỡng xác suất và tỷ lệ Background làm mẫu âm theo F1 `suspect_host` trên validation, chỉ trong các cấu hình có tỷ lệ cửa sổ Background validation bị báo ≤ 5% (`botnet.max_background_alarm`). Cho phép thêm cửa sổ Background của train làm mẫu âm (`normal_host`) khi học; Background không bao giờ là lớp dương và không tính vào Precision/Recall. Sửa phần "Background không học" của QĐ-039.
- Hệ quả: Chọn Random Forest (300 cây, min_samples_leaf 5, 100% Background train làm mẫu âm, ngưỡng 0,10): F1 validation 0,536 (P 0,965, R 0,371), Background bị báo 4,1%. LR tốt nhất 0,165. Chi tiết ở docs/49.

## QĐ-041 — Dữ liệu topology: flow giả lập ngay, traffic lab vô hại sau; nhãn từ nhật ký lần chạy
- Ngày: 03/11/2026
- Trạng thái: Đã chốt (giả lập là tạm thời cho đến khi có lab)
- Bối cảnh: C08-T06 cần dữ liệu tập trung, ngang hàng và đối chứng lành tính. CTU-13 chỉ có một scenario P2P và không có đối chứng; lab chưa dựng.
- Quyết định: `nids.topology_sim` sinh bản ghi flow (không gửi gói) cho 4 kiểu × 3 lần chạy 15 phút với chu kỳ, jitter khác nhau, có nhật ký lần chạy; nhãn host–cửa sổ lấy từ nhật ký. `scripts/sinh_topology.py` sinh traffic thật trong lab: chỉ thông điệp vô hại, từ chối đích ngoài 192.168.50.0/24, ghi nhật ký vào `data/run_logs/nhat_ky.jsonl` (cũng là định dạng nhật ký lần chạy đề xuất).
- Hệ quả: Kết quả trên giả lập chỉ kiểm tra logic của bộ nhận diện, báo cáo riêng, không coi là kết quả trên botnet thật. Đối chứng tập trung có cùng đặc trưng với botnet tập trung. Chi tiết ở docs/50.

## QĐ-042 — Nhận diện topology bằng quy tắc, chạy sau bộ phát hiện botnet
- Ngày: 03/11/2026
- Trạng thái: Đã chốt cho CTU-13 và giả lập (xem lại khi có lab)
- Bối cảnh: C08-T07 phải ghi rõ dùng quy tắc hay ML. CTU-13 chỉ có một scenario P2P: học trên nó thì không còn P2P để kiểm thử (B11).
- Quyết định: Dùng quy tắc trên host–cửa sổ bị nghi là bot: `p2p` khi ≥ 5 peer gọi vào, ≥ 50% flow UDP và entropy flow vào ≥ 0,8; còn lại `centralized`; không bị nghi là `none`. Topology của lần chạy hoặc scenario là nhãn đa số. Ngưỡng đặt bằng CTU-13 train và lần chạy giả lập thứ nhất, ghi trong `botnet.topology_rule`.
- Hệ quả: Trên dữ liệu đặt ngưỡng, đúng 100% cửa sổ tập trung, 95,1% cửa sổ P2P, 8/8 scenario. Không phân biệt được đối chứng tập trung lành tính; P2P chu kỳ dài hoặc dùng TCP dễ bị xếp thành tập trung. Chi tiết ở docs/51.

## QĐ-043 — Pipeline nạp mô hình đã lưu, kiểm tra trước khi chạy
- Ngày: 03/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C09-T01 cần nạp artifact của ba module và kiểm tra schema, để pipeline không chạy với mô hình sai đầu vào hoặc thiếu ngưỡng.
- Quyết định: Đường dẫn mô hình trong `pipeline.models`. Trước khi chạy: nạp bằng `load_model` của từng module (từ chối lớp lạ), kiểm tra đặc trưng ⊆ schema đầu vào, `.json` khớp mô hình, có ngưỡng, lớp phân loại thuộc tập nhãn đã chốt (lỗi thì dừng); mã chưa commit chỉ là cảnh báo. Khi chạy, kiểm tra bảng đầu vào đủ cột.
- Hệ quả: Pipeline không học gì, chỉ dùng artifact của Chặng 6–8. Chi tiết ở docs/53.

## QĐ-044 — Pipeline offline dùng đúng mã trích xuất lúc huấn luyện; host botnet là mọi IP trong mạng giám sát
- Ngày: 03/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C09-T02 chạy PCAP qua toàn bộ pipeline. PCAP CIC mỗi ngày 8–13 GB; đánh giá phải tránh dữ liệu mô hình đã học.
- Quyết định: Trích xuất bằng `nids.feature_export.export` (cùng tham số cấu hình), anomaly và phân loại chấm cửa sổ 10 giây, module botnet dựng đồ thị 120 giây cho mọi IP thuộc mạng giám sát `--net` (cũng dùng làm `local_nets`). Chạy thử trên các đoạn PCAP cắt bằng `nids.pcap_cut`, nằm trọn trong khoảng test của Chặng 5.
- Hệ quả: Trích xuất chiếm hơn 90% thời gian (khoảng 22 000 gói/giây). Module botnet học trên CTU-13 chạy trên CIC chỉ để kiểm tra tích hợp. Chi tiết ở docs/54.

## QĐ-045 — Hợp nhất cảnh báo: giữ mọi dòng theo schema chung, không cộng điểm; đánh dấu host có nhiều module báo
- Ngày: 03/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C09-T03 cần đầu ra độc lập của từng module và một luồng cảnh báo hợp nhất. Ba module có điểm khác thang đo (d², xác suất 3 lớp, xác suất bot).
- Quyết định: Mỗi module đổi dự đoán thành `Alert` (schema docs/02); module botnet ghi nhóm host và nhóm topology thành hai dòng riêng. Hợp nhất là một file sắp theo thời gian, không bỏ dòng nào, không cộng điểm. Kèm tổng hợp theo host; host có ≥ 2 module cùng báo được liệt kê riêng.
- Hệ quả: Số dòng cảnh báo lớn (mỗi cửa sổ trượt một dòng); gộp thành sự kiện ở C09-T06. Chi tiết ở docs/55.

## QĐ-046 — Thêm chế độ tuần tự Gaussian → phân loại → kiểm tra botnet; độc lập vẫn là mặc định
- Ngày: 03/11/2026
- Trạng thái: Đã chốt (mặc định có thể đổi sau C09-T05)
- Bối cảnh: C09-T04 cần chế độ tuần tự; docs/02 mục 1 chốt rằng anomaly không là cổng lọc bắt buộc.
- Quyết định: `pipeline.mode = tuan_tu` chạy Gaussian trên mọi cửa sổ, phân loại chỉ cửa sổ bất thường, kiểm tra botnet chỉ host có bất thường mà bộ phân loại cho là benign, và chỉ giữ cửa sổ 120 giây chồng lên cửa sổ đó. Mặc định vẫn `doc_lap`.
- Hệ quả: Bộ phân loại chạy trên 5–23% cửa sổ, botnet kiểm tra 3–11 thay vì 15–16 host. Cửa sổ Gaussian không báo thì bị bỏ qua hoàn toàn. Chi tiết ở docs/56; so sánh ở C09-T05.

## QĐ-047 — Chế độ pipeline mặc định là `ket_hop`
- Ngày: 03/11/2026
- Trạng thái: Đã chốt cho CIC-IDS2017 (xem lại trên lab)
- Bối cảnh: C09-T05 so sánh độc lập và tuần tự trên bốn đoạn PCAP thuộc khoảng test. Độc lập: gần như không bỏ sót nhưng 17–40% cửa sổ bình thường bị báo, gần hết do module botnet. Tuần tự: báo nhầm 4–19% nhưng bỏ sót quét cổng 35%, Hulk 28%, vì Gaussian chặn cả cửa sổ mà bộ phân loại bắt được.
- Quyết định: Thêm chế độ `ket_hop`: phân loại mọi cửa sổ như độc lập; kiểm tra botnet chỉ host có bất thường mà phân loại cho là benign, như tuần tự. Đặt làm mặc định (`pipeline.mode`). Sửa phần thứ tự chạy của docs/02 mục 1 cho module botnet.
- Hệ quả: Gọi đúng tên và bỏ sót bot bằng chế độ độc lập; báo nhầm bằng tuần tự. Mất phần phủ ngẫu nhiên của module botnet lên cửa sổ tấn công (bỏ sót quét cổng theo nghĩa "bất kỳ cảnh báo" 34%). Thời gian offline gần như không đổi vì trích xuất chiếm 90–99%. Chi tiết ở docs/57.

## QĐ-048 — Ghi mọi dự đoán kèm điểm; gộp cảnh báo lặp thành sự kiện theo module, nhãn, host, khoảng gộp 30 giây
- Ngày: 03/11/2026
- Trạng thái: Đã chốt (khoảng gộp chỉnh được trên lab)
- Bối cảnh: C09-T06. Cửa sổ trượt làm một hành vi dài sinh hàng trăm dòng cảnh báo; tính báo nhầm cần cả dự đoán bình thường.
- Quyết định: Mỗi lần chạy ghi cảnh báo (`alerts.csv`), mọi dự đoán kèm điểm và ngưỡng (`diem.csv`, cơ chế `log_all`), sự kiện (`su_kien.csv`). Sự kiện gộp cảnh báo cùng module, nhãn, host khi cảnh báo sau bắt đầu không quá `pipeline.merge_gap_s` = 30 giây sau khi cảnh báo trước kết thúc; ghi giờ đầu, giờ cuối, số cảnh báo, điểm lớn nhất, trung bình, thời điểm tạo của cảnh báo đầu. Không gộp giữa các module.
- Hệ quả: 378–1 189 cảnh báo mỗi đoạn còn 11–104 sự kiện; DoS liên tục thành vài sự kiện, quét theo lượt Nmap tách theo từng lượt. Chi tiết ở docs/58.

## QĐ-049 — Cài trên Kali bằng script; môi trường ảo riêng có quyền bắt gói, không chạy bằng root
- Ngày: 05/11/2026
- Trạng thái: Đã chốt (chưa chạy trên Kali thật)
- Bối cảnh: C10-T01 cần cài dự án trên Kali. Bắt gói thô cần root hoặc CAP_NET_RAW; mô hình không có trong git.
- Quyết định: `scripts/cai_dat_kali.sh` cài gói hệ thống, clone repo vào `/opt/ml-nids`, tạo `.venv` bằng `--copies`, `pip install -e .`, chép mô hình từ máy huấn luyện, `setcap cap_net_raw,cap_net_admin` chỉ cho python trong `.venv` (không cho python hệ thống), rồi chạy `python -m nids.moi_truong` kiểm tra Python, thư viện, quyền, card, artifact, NTP, đĩa.
- Hệ quả: Cảm biến chạy bằng user thường. Nâng cấp Python của hệ thống thì phải tạo lại `.venv`. Chi tiết ở docs/59.

## QĐ-050 — Kiểm tra cảm biến hai chiều bằng bản bắt thử; nhân đôi nhận theo nội dung gói IP
- Ngày: 05/11/2026
- Trạng thái: Đã chốt (chưa chạy trên lab thật)
- Bối cảnh: C10-T02, B13: Kali phải thấy cả hai chiều trước khi chạy mô hình. Mirror cấu hình sai có thể chỉ sao chép một hướng, hoặc sao chép hai lần mỗi gói.
- Quyết định: `nids.cam_bien` đo phần flow TCP hai chiều, phần kết nối tới máy trong mạng có phản hồi (SYN+ACK hoặc RST), cặp một chiều, gói nhân đôi (cùng nội dung IP bỏ TTL và checksum, cách ≤ 1 ms), máy lab xuất hiện. `loi` khi một trong hai tỷ lệ chính < 50%; `canh_bao` khi < 90%, nhân đôi > 5% hoặc < 20 flow TCP.
- Hệ quả: Trên CIC thấy đủ hai chiều (99–99,9%) nhưng PCAP có 0,7–11,8% gói nhân đôi mà bộ trích xuất chưa bỏ; cần đo trên lab và quyết định có khử trùng gói khi trích xuất. Chi tiết ở docs/60.

## QĐ-051 — Realtime: AF_PACKET không thư viện ngoài; cùng bộ trích xuất; chấm khi cửa sổ đóng; botnet dùng ảnh chụp flow đang mở
- Ngày: 05/11/2026
- Trạng thái: Đã chốt (chưa chạy trên card thật)
- Bối cảnh: C10-T03 cần nguồn gói live và dùng lại bộ trích xuất (B12). Cửa sổ 120 giây của module botnet cần flow, nhưng flow chỉ kết thúc sau timeout 60–120 giây.
- Quyết định: Bắt gói bằng socket AF_PACKET (promiscuous, dấu thời gian kernel, đếm gói kernel bỏ), không dùng scapy hay libpcap; có nguồn phát lại PCAP cho máy không có card. Gói đi qua đúng `parse_packet` và `WindowPipeline` của offline. Cửa sổ 10 giây chấm khi đóng; cửa sổ 120 giây chấm mỗi bước 10 giây khi thời gian gói vượt cuối cửa sổ + 3 giây, trên flow đã kết thúc và ảnh chụp flow đang mở. Mô hình chạy với `n_jobs = 1`. Sự kiện gộp ngay khi chạy.
- Hệ quả: Phát lại CIC cho cùng số cửa sổ với offline, cảnh báo lệch 0,3–3%; nhanh hơn nhịp thật 10–18 lần trên máy phát triển. Chi tiết ở docs/61.

## QĐ-052 — Hàng đợi giới hạn bỏ gói mới khi đầy; nhịp thời gian khi im lặng; trần flow mở và bảng flow
- Ngày: 05/11/2026
- Trạng thái: Đã chốt (giá trị trần chỉnh trên Kali)
- Bối cảnh: C10-T04. Xử lý không kịp thì gói dồn lại; mạng im lặng thì flow và cửa sổ không bao giờ đóng; state không có trần thì RAM tăng theo traffic.
- Quyết định: Luồng đọc đẩy vào `Queue(realtime.queue_size)` bằng `put_nowait`, đầy thì bỏ gói mới và đếm. Không có gói trong `tick_s` thì đẩy thời gian (thời điểm gói cuối + thời gian thật × hệ số đồng hồ). Trần `max_active_flows` (kết thúc flow lâu nhất chưa có gói, lý do mới `gioi_han_bo_nho`) và `max_flow_rows`; offline không dùng trần.
- Hệ quả: Mọi gói đều xử lý hoặc được đếm là bỏ; state về 0 sau khi im lặng. Hai luồng chậm hơn một luồng khi phát lại hết tốc độ (tranh GIL). Sửa lỗi đếm đôi flow đang đóng của C10-T03. Chi tiết ở docs/62.

## QĐ-053 — Số liệu vận hành ghi định kỳ; đo theo nhịp thật, loại phép đo bị nhiễu
- Ngày: 06/11/2026
- Trạng thái: Đã chốt (chưa đo trên Kali)
- Bối cảnh: C10-T05 cần đo gói xử lý, gói bỏ và tài nguyên. Hai lần đo đầu bị nhiễu: máy vào chế độ ngủ, và một script đo cũ chạy song song.
- Quyết định: `Metrics` ghi mỗi 10 giây (giờ thật) gói nhận/xử lý/bỏ (hàng đợi, kernel), tốc độ, hàng đợi, CPU, RAM, độ trễ xử lý (p50/p95/lớn nhất), state, kết quả; tổng kết khi dừng. Đo bằng phát lại theo nhịp thật, giữ máy thức trong lúc đo, chạy từng phép đo một, kiểm tra không có sự kiện ngủ.
- Hệ quả: Ở nhịp thật không bỏ gói, độ trễ xử lý < 0,7 giây (kể cả DoS khoảng 2 850 gói/s). Quét cổng ×4 quá tải vì module botnet dựng lại đồ thị 600 giây mỗi bước: bỏ 3,8% gói. Chi tiết ở docs/63.

## QĐ-054 — Dừng êm theo tín hiệu, có hạn xử lý nốt; log xoay vòng; không ghi lẫn file kết quả
- Ngày: 06/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C10-T06. Dừng đột ngột làm mất cửa sổ đang mở, sự kiện chưa đóng và số liệu cuối; log không giới hạn sẽ đầy đĩa; chạy lại cùng tên làm lẫn kết quả.
- Quyết định: SIGINT, SIGTERM, SIGHUP: nguồn ngừng đọc, xử lý nốt hàng đợi trong tối đa `stop_timeout_s` = 30 giây (quá hạn thì bỏ và đếm), chấm nốt, đóng sự kiện, ghi số liệu, đóng file; tín hiệu thứ hai thì thoát ngay (mã 130). Log `RotatingFileHandler` 10 MB × 5 bản; `--im-lang` cho chạy nền. File kết quả trùng tên được đổi thành `.cu.` trước khi mở file mới.
- Hệ quả: Mã thoát 0 khi dừng êm, 1 khi lỗi. Chi tiết ở docs/64.

## QĐ-055 — Chạy nền bằng systemd với user riêng, chỉ hai quyền mạng; file chạy trên Kali luôn LF
- Ngày: 06/11/2026
- Trạng thái: Đã chốt (chưa cài trên Kali thật)
- Bối cảnh: C10-T07 cần cảm biến chạy nền, khởi động/dừng theo hướng dẫn. Cảm biến đọc traffic không tin cậy.
- Quyết định: Unit `nids-realtime.service` chạy bằng user hệ thống `nids` với `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, kiểm tra mô hình trước khi chạy, dừng bằng SIGTERM với `TimeoutStopSec=45` (> 30 giây dừng êm), khởi động lại khi lỗi, giới hạn RAM/CPU, chỉ ghi được thư mục kết quả. Tham số trong `/etc/ml-nids/nids-realtime.env`. `scripts/cai_dich_vu.sh` cài đặt và chặn máy tự ngủ. `.gitattributes` buộc LF cho script, unit, Python, YAML.
- Hệ quả: Không cần `setcap` lên python khi chạy bằng dịch vụ. Chi tiết ở docs/65.

## QĐ-056 — Realtime chờ thêm một cửa sổ 10 giây trước khi chấm botnet; chấp nhận lệch nhỏ do flow đang mở
- Ngày: 06/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C10-T08 so realtime với offline trên cùng PCAP. Cửa sổ 10 giây và hai module đầu khớp tuyệt đối. Module botnet chấm ít host–cửa sổ hơn: realtime bỏ qua cửa sổ 120 giây bắt đầu trước gói đầu tiên, và chấm trước khi biết hết bất thường chồng lên phần cuối cửa sổ.
- Quyết định: Cửa sổ 120 giây đầu tiên là cửa sổ sớm nhất chứa gói đầu tiên. Chấm cửa sổ 120 giây lúc cuối cửa sổ + 3 giây + `realtime.graph_delay_s` (mặc định 10 giây). Giữ ảnh chụp flow đang mở thay vì chờ flow kết thúc.
- Hệ quả: Bốn đoạn CIC: cùng tập host–cửa sổ botnet; 6/1 558 nhãn khác (điểm sát ngưỡng, lệch ≤ 0,055); cảnh báo botnet muộn thêm 10 giây. Chi tiết ở docs/66.

## QĐ-057 — Giữ nhãn theo lịch cho flow "Attempted" của bộ nhãn KU Leuven
- Ngày: 06/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Bộ nhãn đã sửa của KU Leuven gán nhãn riêng `<tấn công> - Attempted` cho flow của bên tấn công không chở nội dung tấn công, và coi chúng là lành tính. Dự án gán các flow này là `dos` theo lịch và cặp IP (QĐ-009): 5 599 flow ở thứ Tư.
- Quyết định: Giữ nhãn hiện tại. Dự án phát hiện theo cửa sổ host 10 giây; cửa sổ của bên tấn công trong khung DoS luôn có cả flow tấn công, nên đổi nhãn flow không đổi nhãn cửa sổ. Dùng KU Leuven để đối chiếu, không thay nhãn.
- Hệ quả: Đồng ý với KU 100% / 99,98% / 99,78% (thứ Hai, Tư, Sáu) khi bỏ flow `attempted`; không flow tấn công nào của KU bị gán lành tính. Nếu sau này huấn luyện theo flow thì cần xét lại. Chi tiết ở docs/67.

## QĐ-058 — Lớp gộp cảnh báo botnet theo host (tùy chọn, Chặng 9) để vớt bot chậm
- Ngày: 06/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: C08-T08 cho recall scenario 8 (Murlo) chỉ 0,154 vì phần lớn cửa sổ bot chỉ có 1–3 flow, điểm gần 0; hạ ngưỡng vô ích. Nhưng host đó có 1 034 cửa sổ điểm cao trong cùng run.
- Quyết định: Thêm lớp gộp theo host (mặc định TẮT): xác nhận host là bot trong một run nếu số cửa sổ điểm ≥ ngưỡng đạt ≥ `min_strong` và chiếm ≥ `min_frac`, rồi nâng mọi cửa sổ của host lên suspect. Chọn `min_strong=500`, `min_frac=0,13` trên validation (Background validation giữ ≤ 5%, QĐ-040). Dùng số tuyệt đối vì nó tách bot (≥728) khỏi máy bình thường (≤268).
- Hệ quả: Test recall 0,678→1,0, F1 0,798→0,990, scenario 8 recall 0,154→1,0; báo nhầm máy bình thường không đổi (1,58%); Background test 11,9%→20,3% (không phải FPR). Mặc định tắt nên C08-T08 và C10-T08 không đổi. Bản realtime cần xác nhận theo luồng (để sau). Chi tiết docs/69.

## QĐ-059 — Tăng tốc module botnet realtime: chỉ tính cửa sổ đang xét và cache chuyển đổi flow
- Ngày: 07/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Module botnet là điểm nghẽn realtime (docs/63): mỗi bước 10 giây dựng lại đồ thị + beaconing từ 600 giây flow, quét cổng ×4 bỏ 3,8% gói. Đo trên fri_quet: _flow_table 49,5s và build_features 32,2s trong 84,5s chấm botnet.
- Quyết định: (1) Thêm tham số `windows` cho `build_features`/`window_edges`/`host_ports` để chỉ tính đúng cửa sổ đang xét (và cửa sổ liền trước cho `ty_le_peer_moi`). (2) Cache bảng flow chung đã chuyển đổi của flow kết thúc, cập nhật tăng dần theo mã `_id` liên tục. Mặc định bật, không đổi API người dùng.
- Hệ quả: Chấm botnet 84,5 → 40,9 giây (−52%) trên fri_quet; _flow_table 49,5→11,5s, build_features 32,2→25,9s. Chứng minh y hệt: kiểm tra đặc trưng lệch 0 trên scenario 1; `nids.nhat_quan` 4 đoạn y hệt baseline đã khóa. Chi tiết docs/63 mục 3.1.

## QĐ-060 — Chia port_scan theo lượt Nmap (giao thức quét) để mỗi kiểu quét có ở cả ba tập
- Ngày: 07/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Recall port_scan test chỉ 0,448 (SCTP 0,02, UDP 0,01) dù quét TCP bắt 0,83 (docs/44). Đo lại: không thiếu đặc trưng (dst_ports đã đếm UDP/SCTP); nguyên nhân là chia theo thời gian (QĐ-027) dồn quét SCTP/UDP vào test nên mô hình chưa học. Host-aggregation phá precision (host nạn nhân 93% cửa sổ benign). Thêm đặc trưng UDP/SCTP không giúp (tín hiệu mỗi cửa sổ vốn yếu).
- Quyết định: Chia cửa sổ port_scan theo giao thức quét chủ đạo (TCP/UDP/SCTP, lấy từ flow bên tấn công khởi tạo), cắt 60/20/20 theo thời gian trong từng giao thức. Bật bằng `split.stratify_scan_proto` (mặc định true), chỉ đổi cửa sổ port_scan. Chọn lại mô hình trên validation mới rồi đọc test một lần.
- Hệ quả: RF test recall port_scan 0,448 → 0,736, F1 0,612 → 0,829, precision giữ 0,947, macro-F1 0,831 → 0,908; SCTP 0,02 → 0,84, UDP 0,01 → 0,14 (quét UDP vốn yếu). DoS không đổi. Chi tiết docs/44, docs/43.

## QĐ-061 — Chặng 11 chạy trên lab ảo bằng network namespace
- Ngày: 11/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Kế hoạch (docs/09) cần mạng lab 7 node với cổng mirror; nhóm chưa có 7 máy thật nên Chặng 11 mới chỉ đo thử trên đoạn CIC. Cần PCAP của đúng các kịch bản lab, có nhật ký ground truth.
- Quyết định: Dựng lab ảo trên một máy Linux (WSL2): mỗi máy là một network namespace, switch là bridge, cổng mirror là `tc mirred` sao khung đi vào từng cổng sang máy giám sát (không cắm vào switch). Traffic là gói thật của nhân Linux, Nginx, Nmap và script sinh traffic. Mỗi lần chạy do `scripts/lab_ao.py` điều khiển và ghi nhật ký `data/run_logs/<run_id>.json`; bộ chạy không đọc kết quả mô hình (B10). PCAP không đưa lên git, nhật ký thì có.
- Hệ quả: Có số liệu Chặng 11 trên đúng kịch bản lab. Giới hạn phải ghi kèm: đường truyền không trễ, không mất gói; các máy chung đồng hồ; máy giám sát không phải Kali vật lý. Chi tiết docs/70.

## QĐ-062 — Chốt tham số kịch bản lab: tốc độ Nmap, ba mức tải, beaconing, số peer
- Ngày: 12/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: QĐ-012 và docs/09 yêu cầu ghi tham số kịch bản vào cấu hình trước lần chạy đầu tiên (B15–B18). Các giá trị đã được dùng cho 33 lần `test` ngày 11/11/2026 nhưng mới nằm trong `scripts/lab_ao.py`.
- Quyết định: Ghi vào `config/default.yaml` mục `lab`. Quét cổng: Nmap connect scan `-sT -Pn -n --max-retries 0`, cổng 1–1024; chậm `--scan-delay 500ms` (2 cổng mỗi giây), nhanh `-T4`. Tải kết nối: 50/200/600 kết nối mỗi giây, tối đa 60 giây. Tập trung: ba bot gọi `.50:8080` trong 600 giây, chu kỳ 30/60/45 giây theo lần chạy; jitter 0 (cố định), ±20/40/30% (biến thiên), 0/10/30% (đối chứng gọi `.30:80`). Ngang hàng: 3 bot, UDP cổng 40000, chu kỳ 8/20/30 giây, jitter ±30/50/40%, peer lưới/vòng/lưới; đối chứng chia sẻ dữ liệu TCP cổng 6881.
- Hệ quả: `tests/test_lab_ao.py` kiểm tra kế hoạch của `lab_ao.py` khớp cấu hình. Đổi tham số thì các lần chạy cũ không còn so được với lần mới; phải đổi mã biến thể hoặc thu lại. Chi tiết docs/70.

## QĐ-063 — Khóa tham số gán nhãn: nới lịch 60 giây, ngưỡng cửa sổ 0,2
- Ngày: 12/11/2026
- Trạng thái: Đã chốt (khóa phần tạm thời của QĐ-025, QĐ-026; tỷ lệ cân bằng đã chọn ở QĐ-035)
- Bối cảnh: `labeling.tolerance_s` = 60 và `labeling.window_min_attack_share` = 0,2 được đặt tạm, hẹn chỉnh trên validation.
- Quyết định: Giữ nguyên hai giá trị. Thử nới lịch 0/30/60/120/300 giây và ngưỡng 0,05/0,1/0,2/0,3/0,5, mỗi lần đổi một tham số, fit lại Random Forest đã chọn và đo trên validation gán nhãn cố định: macro-F1 nằm trong 0,9341–0,9365 (hiện tại 0,9352). Nới lịch 0–60 giây cho cùng một bộ nhãn. Không đọc test.
- Hệ quả: Không gán nhãn hay huấn luyện lại. Macro-F1 cao hơn ở ngưỡng 0,5 khi đo trên validation gán nhãn riêng (0,9473) là do bỏ cửa sổ khó khỏi validation, không dùng làm căn cứ. Chi tiết docs/72 mục 1.

## QĐ-064 — Nguồn mẫu DoS kiểu SYN: lần chạy `train` kịch bản 3 của lab; chưa cần học lại
- Ngày: 12/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: CIC-IDS2017 chỉ có DoS tầng HTTP (QĐ-009), Chặng 7 tạm chỉ học loại này và để ngỏ nguồn mẫu cho DoS kiểu SYN của lab.
- Quyết định: Không tìm dataset ngoài. Nguồn mẫu DoS kiểu SYN là các lần chạy `train` của kịch bản 3 trong lab (`k3-dos-muc1/2/3-train-01`, thu 12/11/2026, nhãn từ nhật ký lần chạy). Hiện **chưa học lại** bộ phân loại: mô hình chỉ học DoS tầng HTTP đã phát hiện 9/9 đợt tải kết nối của lab ở cả ba mức (Chặng 11, docs/71 mục 3). Chỉ đưa mẫu lab vào train khi học lại bộ phân loại vì lý do khác (ví dụ sửa báo nhầm `dos` trên chia sẻ dữ liệu).
- Hệ quả: DoS trong lab là tải kết nối bằng socket thường (phần lớn bắt tay xong), không phải SYN flood gói thô giả mạo nguồn, vì B24 không cho tạo gói thô. SYN flood gói thô vẫn **chưa được thử**. Nếu học lại bằng mẫu lab thì phải thu lần `test` mới để báo cáo.

## QĐ-065 — Khóa các quyết định còn tạm thời: QĐ-004, QĐ-009, QĐ-010, QĐ-012, QĐ-013
- Ngày: 12/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Năm quyết định đầu dự án ghi "Tạm thời" vì lúc đó chưa có dữ liệu hay mã để kiểm chứng. Tới Chặng 11 mọi phần đã chạy và đo được. (QĐ-006, QĐ-017, QĐ-023 về cửa sổ và tham số flow khóa riêng ở QĐ-066.)
- Quyết định:
  - **QĐ-004 (tên nhãn)**: giữ nguyên. Nhãn topology `none` dùng cho mọi host không phải bot, gồm cả đối chứng lành tính (`k4-doi-chung`, `k5-doi-chung` ghi `topology: none` trong nhật ký lần chạy). Ba module, bộ đo và file cảnh báo đều dùng các tên này qua `src/nids/scope.py`; không phát sinh xung đột khi thu dữ liệu đối chứng.
  - **QĐ-009 (tập con CIC-IDS2017)**: giữ thứ Tư (DoS tầng HTTP) và phần port scan của thứ Sáu cho bộ phân loại; thứ Hai cho Gaussian. Mô hình học từ tập con này đạt macro-F1 0,908 trên test CIC và 0,923 theo cửa sổ trên lab (docs/71 mục 7). Nguồn mẫu DoS kiểu SYN theo QĐ-064.
  - **QĐ-010 (CTU-13)**: giữ flow hai chiều `.binetflow` của 13 scenario, chỉ `From-Botnet` là độc hại. Cách chia: train 3, 5, 7, 10, 11, 12; **validation 4 và 13**; test 1, 2, 6, 8, 9. Trong nhóm huấn luyện của bài báo gốc, 12 phải ở train (P2P duy nhất), 10 và 11 là nguồn duy nhất của IP bot khác ở train, 5, 7, 11 quá ngắn, 3 là phần lớn mẫu Rbot; còn lại 4 và 13. Không đổi vì test CTU-13 đã được đọc (docs/52).
  - **QĐ-012 (dữ liệu lab)**: giữ 11 biến thể của năm kịch bản, mỗi biến thể 1 lần `train`, 1 lần `val`, 3 lần `test`. Đã thu đủ **55/55 lần** trên lab ảo (QĐ-061): 33 lần `test` ngày 11/11, 11 lần `train` và 11 lần `val` ngày 12/11/2026. DoS là tải kết nối bằng socket thường thay cho SYN gói thô (B24). ICMP và DDoS nhiều nguồn không thu.
  - **QĐ-013 (bộ đọc PCAP tự viết)**: giữ, kể cả phần phân tích header tự viết (không đổi sang dpkt). Đối chiếu Wireshark trên 35,5 triệu gói của ba file CIC: lệch 0 (docs/17); đọc được PCAP lab do tcpdump ghi và file nén gzip/bz2.
- Hệ quả: Không còn quyết định nào ở trạng thái "Tạm thời" ngoài nhóm tham số flow (QĐ-066). Hạn chế vẫn còn: validation CTU-13 chỉ có 1 IP bot nên phải giữ ràng buộc Background ≤ 5% (QĐ-040); các lần `test` của lab thu trước `train`/`val`, nên nếu học lại mô hình bằng dữ liệu lab thì phải thu lần `test` mới; lab là lab ảo.

## QĐ-066 — Khóa cửa sổ và tham số flow: 10/2 và 120/10 giây; timeout 60/120/10 giây; chờ bắt tay 3 giây
- Ngày: 12/11/2026
- Trạng thái: Đã chốt (khóa QĐ-006 và phần tạm thời của QĐ-017, QĐ-023)
- Bối cảnh: Cửa sổ, ba timeout của flow và thời gian quan sát bắt tay được đặt tạm, hẹn chỉnh trên validation rồi khóa trước khi kiểm thử.
- Quyết định: Giữ nguyên: cửa sổ flow/host 10 giây bước 2 giây, cửa sổ đồ thị 120 giây bước 10 giây; `idle_timeout_s` 60, `active_timeout_s` 120, `close_grace_s` 10, `handshake_observe_s` 3. Thử trên 11 lần chạy `val` của lab, mỗi lần đổi một tham số (idle 30/120, active 60/300, grace 5/20, bắt tay 1/5), trích xuất lại và chấm bằng mô hình đã khóa: cả 9 cấu hình cho cùng số đợt phát hiện, cùng số cửa sổ cảnh báo và cùng số báo động giả.
- Hệ quả: Không trích xuất hay huấn luyện lại. `handshake_observe_s` cộng thẳng vào độ trễ realtime (1 giây: 1,5–2,9 giây; 3 giây: 3,1–5,0 giây; 5 giây: 6,2–6,9 giây); giảm xuống 1 giây sẽ bớt khoảng 2 giây nhưng đòi trích xuất và huấn luyện lại toàn bộ (B12) và chưa kiểm chứng trên mạng có độ trễ thật, nên để lại như một lựa chọn cho lần học lại sau. Phép đo dùng mô hình đã khóa trên dữ liệu lab, cho biết kết quả không nhạy với tham số, không chứng minh tối ưu. Độ dài cửa sổ không được thử lại. Chi tiết docs/72 mục 2.

## QĐ-067 — Dung sai thời gian khi ghép dòng log với flow: 1 giây
- Ngày: 12/11/2026
- Trạng thái: Đã chốt
- Bối cảnh: Access log dùng để đối chiếu với flow (docs/05) nhưng chưa có phần ghép và chưa chốt dung sai thời gian.
- Quyết định: Ghép theo (IP client, cổng client, cổng máy chủ) với flow TCP; thời điểm ghi log phải nằm trong khoảng sống của flow nới `service_log.match_tolerance_s` = 1 giây mỗi đầu; nhiều flow cùng cổng thì lấy flow gần nhất (`src/nids/log_flow.py`). Trên 33 003 dòng log của 55 lần chạy lab: dung sai 0 chỉ ghép 31,7% (log ghi sau gói cuối dưới 1 mili giây), từ 0,001 giây ghép 100%; tới 1 giây vẫn ghép duy nhất, từ 5 giây bắt đầu khớp nhầm flow dùng lại cổng nguồn.
- Hệ quả: Lab vật lý phải trừ độ lệch đồng hồ ghi trong nhật ký lần chạy trước khi ghép. Kết nối không gửi yêu cầu (quét cổng, tải kết nối) không có dòng log nên không ghép được; đó là hành vi đúng. Chi tiết docs/16 mục 6.

## QĐ-068 — Bộ mô hình riêng cho lab: học lại trên `train`, chọn trên `val`, chế độ `doc_lap`
- Ngày: 13/11/2026
- Trạng thái: Đã chốt (xét lại QĐ-047 và QĐ-042 cho mạng lab; mô hình và cấu hình cũ giữ nguyên cho CIC-IDS2017, CTU-13)
- Bối cảnh: Chặng 11 cho thấy mô hình học từ CIC và CTU-13 có ba lỗi trên lab: Gaussian báo máy chủ dịch vụ suốt bản thu, bộ phân loại báo nhầm `dos` trên chia sẻ dữ liệu, module botnet bỏ sót 9/9 đợt. Lab đã có đủ lần chạy `train`, `val`.
- Quyết định: Học lại bằng `nids.hoc_lai_lab`, giữ nguyên loại mô hình, đặc trưng và tham số đã chọn: Gaussian fit trên cửa sổ bình thường của `train` lab, ngưỡng chọn trên `val`; bộ phân loại học trên train CIC + train lab; botnet học trên host–cửa sổ của `train` lab, ngưỡng chọn trên `val`. Trên `val`: quy tắc topology đổi thành `min_peer_vao` 1, `min_udp` 0,05, `min_entropy_vao` 0 (quy tắc cũ đúng 0% bot ngang hàng của lab); chế độ pipeline là `doc_lap` vì `ket_hop` không cho module botnet xét bot chậm (5/8 so với 8/8 đợt). Mô hình ở `models/lab/`, cấu hình ở `config/lab.yaml` (sinh từ `default.yaml`).
- Hệ quả: Trên 33 lần `test` mới (lần 4–6, chưa dùng để học hay chọn): phát hiện 24/24 đợt (mô hình cũ 15/24), báo động giả 63 → 4 sự kiện, macro-F1 theo cửa sổ 0,923 → 0,995; test CIC của bộ phân loại không đổi (0,9078 → 0,9072). Giới hạn: train, val, test cùng một lab và cùng bộ sinh traffic nên kết quả không chứng minh khả năng nhận ra botnet thật; quy tắc topology mới rất lỏng. Chi tiết docs/73.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Nhật ký quyết định | Nơi ghi lại mỗi lựa chọn kỹ thuật quan trọng cùng lý do, để sau này biết vì sao làm vậy |
| Đã chốt / Tạm thời | Đã chốt: không đổi nữa trừ khi có quyết định mới. Tạm thời: còn có thể đổi khi có thêm dữ liệu |
| Schema cảnh báo | Danh sách cột cố định của file cảnh báo |
| Cấu hình (config) | Tham số chỉnh được mà không sửa mã, nằm trong `config/default.yaml` |
| Hợp đồng giữa các phần mã | Quy ước mà mọi phần mã cùng tuân theo, ví dụ tên nhãn; đổi một chỗ phải đổi mọi chỗ |
| Validation | Phần dữ liệu dùng để chọn tham số và ngưỡng, tách riêng khỏi dữ liệu học và dữ liệu đánh giá cuối |
| Timeout nhàn rỗi | Không thấy gói mới của một flow trong khoảng này thì coi flow đã kết thúc |
| Môi trường ảo (.venv) | Thư mục chứa Python và thư viện riêng của dự án, không lẫn với máy |
| numpy, pandas, scikit-learn, scapy, networkx, PyYAML, joblib | Thư viện Python: tính toán mảng số; xử lý bảng; mô hình học máy; bắt và đọc gói tin; đồ thị; đọc file YAML; lưu mô hình ra file |
| Access log | File Nginx ghi mỗi yêu cầu web nhận được, một dòng một yêu cầu |
| Binetflow | File flow hai chiều có nhãn của CTU-13 |
| Forward / backward, client | Chiều từ bên mở kết nối (client) sang bên kia / chiều ngược lại |
| SYN, SYN+ACK | Gói mở kết nối TCP của client / gói trả lời đồng ý của server |
| Identification, mảnh IP | Số chung của các mảnh thuộc cùng một gói IP lớn bị chia nhỏ |
| CICFlowMeter | Công cụ tạo file flow CSV của CIC-IDS2017 |
| FIN, RST | Cờ TCP báo đóng kết nối bình thường / hủy kết nối ngay |
| Active timeout | Độ dài tối đa của một flow; kết nối dài hơn bị cắt thành nhiều flow nối tiếp |
| Tái sử dụng 5-tuple | Mở kết nối mới với đúng IP và cổng của kết nối cũ |
| Payload | Phần dữ liệu ứng dụng trong gói TCP/UDP, không tính các header |
| Mã băm SHA-256 | Chuỗi 64 ký tự tính từ nội dung file; cùng mã băm nghĩa là cùng nội dung |
| Cửa sổ host | Khoảng thời gian cố định để gom gói của một máy và tính đặc trưng |
| Entropy cổng | Độ đa dạng của các cổng đích, tính bằng bit; cao khi gói chia đều cho nhiều cổng |
| Kết nối không hoàn tất | Lần thử TCP không đi hết bắt tay ba bước trong thời gian quan sát |
| Schema, metadata | Mô tả cấu trúc bảng / thông tin bảng được tạo từ đâu, bằng tham số và mã nào |
| Lịch tấn công | Danh sách đợt tấn công (giờ, IP, cổng, nhãn) dùng làm nguồn nhãn |
| `attack_share` | Phần số flow tấn công trong số flow của một cửa sổ host |
| Vùng đệm (embargo) | Khoảng bỏ trống ở ranh giới giữa hai tập dữ liệu |
| Fit | Tính tham số từ dữ liệu, ví dụ trung bình để chuẩn hóa |
| Giảm mẫu, trọng số lớp | Bỏ bớt mẫu của lớp đông / phạt nặng hơn khi đoán sai lớp ít mẫu |
| Gaussian đa biến | Mô hình mô tả dữ liệu bình thường bằng trung bình và ma trận hiệp phương sai |
| Yeo-Johnson | Phép biến đổi lũy thừa làm phân bố gần dạng chuông, có tham số học từ dữ liệu |
| Ledoit-Wolf | Cách co hiệp phương sai về ma trận đường chéo để luôn nghịch đảo được |
| Ngưỡng F1 ổn định | Ngưỡng có F1 tốt nhất khi ngưỡng lệch ±20%, tránh đặt sát chỗ F1 đổi đột ngột |
| UTC−3 | Giờ chậm hơn giờ quốc tế 3 tiếng; giờ mùa hè nơi CIC thu dữ liệu |
| Phần trong tổng (share) | Tỷ lệ của một chiều so với cả hai chiều, luôn từ 0 tới 1 |
| Manifest | Bảng liệt kê mọi nguồn dữ liệu và cách dùng |
| struct | Thư viện có sẵn của Python để đọc các con số nằm trong chuỗi byte |
| Scapy, PyShark, dpkt | Ba thư viện Python đọc gói tin; dự án tự viết phần đọc thay vì dùng chúng (QĐ-013, QĐ-014) |
| TShark | Bản dòng lệnh của Wireshark |
| Header | Phần đầu của gói tin hoặc file, chứa thông tin điều khiển như địa chỉ, độ dài |
| Ethernet, VLAN | Ethernet là chuẩn mạng có dây phổ biến; VLAN là thẻ chia một mạng vật lý thành nhiều mạng logic |
| Linux cooked, loopback | Kiểu ghi gói khi bắt trên mọi card mạng cùng lúc (`tcpdump -i any`); loopback là card ảo cho máy nói chuyện với chính nó |
| TSO | Card mạng tự chia một gói lớn thành nhiều gói nhỏ khi gửi; bắt gói trên chính máy gửi sẽ thấy gói lớn chưa chia, có độ dài ghi bằng 0 |
| Train/test | Dữ liệu để mô hình học / dữ liệu để đánh giá cuối |
| B12 | Yêu cầu huấn luyện và realtime dùng cùng cách tính đặc trưng (docs/01) |
