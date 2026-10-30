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
- Trạng thái: Tạm thời
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
- Trạng thái: Tạm thời
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
- Trạng thái: Tạm thời
- Bối cảnh: Module phân loại có ba lớp `benign`, `port_scan`, `dos` (một nguồn); CIC-IDS2017 có nhiều loại tấn công khác.
- Quyết định: Dùng phiên thứ Tư 05/07/2017 (bốn công cụ DoS, bỏ Heartbleed) và phần port scan của chiều thứ Sáu 07/07/2017 (bỏ DDoS LOIT). Dữ liệu chính là PCAP chạy qua bộ ghép flow của đồ án, nhãn gán theo lịch tấn công; CSV có nhãn dùng để đối chiếu (xem `docs/06_cic_ids2017.md`).
- Hệ quả: Tách train/validation/test theo khối thời gian vì mỗi lớp tấn công chỉ nằm trong một ngày. DoS của CIC-IDS2017 là tầng HTTP, không khớp với SYN/ICMP của lab; nguồn mẫu `dos` cho loại này chưa được quyết định. Chưa tải file nên số liệu phải đối chiếu lại.

## QĐ-010 — Dùng flow hai chiều có nhãn của CTU-13
- Ngày: 12/10/2026
- Trạng thái: Tạm thời
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
- Trạng thái: Tạm thời
- Bối cảnh: CIC-IDS2017 không có DoS kiểu SYN/ICMP và thuộc mạng khác; CTU-13 chỉ có một scenario ngang hàng; không dataset nào có đối chứng lành tính.
- Quyết định: Thu 11 biến thể của năm kịch bản (xem `docs/09_du_lieu_lab.md`). DoS dùng SYN; ICMP và DDoS nhiều nguồn là tùy chọn. Mỗi biến thể tối thiểu 1 lần chạy `train`, 1 lần `val`, 3 lần `test`; vai trò ghi trước khi chạy. Mã lần chạy dạng `<mã biến thể>-<vai trò>-<số thứ tự>`.
- Hệ quả: Tối thiểu 55 lần chạy, khoảng 8 giờ thu. Tham số tốc độ quét, ba mức tải DoS và chu kỳ beaconing chưa chốt, phải ghi vào cấu hình trước lần chạy đầu tiên. Các lần chạy `test` thu sau khi mô hình và ngưỡng đã khóa.

## QĐ-013 — Tự viết bộ đọc file PCAP/PCAPNG bằng thư viện chuẩn
- Ngày: 17/10/2026
- Trạng thái: Tạm thời
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
- Trạng thái: Tạm thời (giá trị thời gian chỉnh trên validation như QĐ-006)
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
- Trạng thái: Tạm thời (giá trị 3 giây chỉnh trên validation như QĐ-006)
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
- Trạng thái: Đã chốt (giá trị nới 60 giây tạm thời)
- Bối cảnh: QĐ-009 chọn gán nhãn CIC theo lịch tấn công thay vì cột nhãn của CSV (có lỗi). Cần một nguồn nhãn có thể kiểm tra, dùng được cho cả dữ liệu lab sau này, và không ép nhãn cho mẫu thiếu căn cứ.
- Quyết định: Lịch ở `config/label_schedule.csv` (khung giờ địa phương, múi giờ, IP bên tấn công và nạn nhân như thấy trong PCAP, cổng nạn nhân, nhãn, khối). Mẫu khớp khi hai đầu là cặp tấn công (đúng cổng nếu có) và thời gian chạm khung giờ nới `labeling.tolerance_s` = 60 giây. Bốn trạng thái: `khop`, `loai` (tấn công ngoài ba lớp: chỉ dùng cho anomaly), `mo_ho` (cặp tấn công ngoài khung giờ cùng ngày, hoặc chạm hai đợt khác nhãn: không gán nhãn), `khong_khop` (benign/normal) (xem `docs/26_gan_nhan.md`).
- Hệ quả: Nhãn ghi ra file riêng, nối với bảng đặc trưng bằng khóa. Đợt bị loại vẫn phải có trong lịch để không thành benign. Mẫu `mo_ho` bị bỏ khỏi huấn luyện và đánh giá, có báo số lượng.

## QĐ-026 — Nhãn cửa sổ theo phần flow tấn công; dưới 20% là mơ hồ
- Ngày: 29/10/2026
- Trạng thái: Tạm thời (ngưỡng 0,2 chỉnh trên validation)
- Bối cảnh: Cửa sổ 10 giây của nạn nhân hay bên tấn công thường lẫn flow tấn công và bình thường (81% cửa sổ tấn công của CIC thứ Tư). Quét cổng là flow một gói nên không thể đo theo thời gian.
- Quyết định: Đếm flow của host chồng lên cửa sổ theo nhãn flow. Có flow bị loại thì cửa sổ là `loai`; một lớp tấn công với phần flow tấn công ≥ `labeling.window_min_attack_share` = 0,2 thì nhận lớp đó; dưới ngưỡng hoặc hai lớp thì `mo_ho` (vẫn `anomaly`); chỉ có flow mơ hồ thì `mo_ho`; còn lại benign (xem `docs/28_nhan_cua_so.md`).
- Hệ quả: Cột `attack_share`, `n_flows`, `n_attack_flows` được giữ để thử ngưỡng khác mà không gán nhãn lại.

## QĐ-027 — Chia dữ liệu theo thời gian trong từng khối tấn công, 60/20/20, vùng đệm 10 giây
- Ngày: 29/10/2026
- Trạng thái: Đã chốt (thay cách gán nguyên khối dự kiến ở docs/06 mục 5)
- Bối cảnh: Cửa sổ chồng nhau và mẫu của cùng một đợt rất giống nhau, nên chia ngẫu nhiên gây rò rỉ (B11). `port_scan` chỉ có 2 khối (một khối gần như rỗng), nên gán nguyên khối vào một tập làm thiếu lớp.
- Quyết định: Trong mỗi phiên, mỗi khối tấn công (cột `khoi` của lịch) và mỗi khoảng giữa các khối được cắt theo thứ tự thời gian thành train, validation, test với 60%, 20%, 20% số flow (ranh giới ở phân vị thời điểm bắt đầu flow; khoảng dưới 20 flow chia theo thời gian). Mẫu phải nằm trọn trong một đoạn và cách ranh giới hai tập khác nhau ít nhất `split.embargo_s` = 10 giây; còn lại là `bo` (xem `docs/29_chia_du_lieu.md`).
- Hệ quả: Test luôn sau train trong cùng khối; hai tập không chung gói. Khả năng gặp công cụ chưa thấy được đánh giá riêng ở Chặng 7. Validation của `port_scan` ở bảng cửa sổ mỏng (50 mẫu) vì quét diễn ra theo từng đợt ngắn.

## QĐ-028 — Tiền xử lý chỉ fit trên train; bỏ trùng và cân bằng chỉ trên train; Gaussian học trên thứ Hai
- Ngày: 30/10/2026
- Trạng thái: Đã chốt (tỷ lệ cân bằng 10 chỉnh được ở Chặng 7)
- Bối cảnh: Đặc trưng lệch phải mạnh, nhiều ô trống có ý nghĩa, lớp mất cân bằng nặng (benign gấp 374 lần port_scan ở bảng cửa sổ), 98,9% flow port_scan trùng nhau. Tham số tiền xử lý và việc cân bằng không được dùng dữ liệu đánh giá.
- Quyết định: `log(1 + x)` cho đặc trưng đếm, byte, giây; điền trung vị của train kèm cột đánh dấu ô trống; chuẩn hóa theo train. Module phân loại dùng thứ Tư và thứ Sáu, bỏ mẫu train trùng hệt, giảm mẫu mỗi lớp xuống tối đa 10 lần lớp ít nhất, kèm trọng số lớp. Module anomaly fit trên mẫu normal của train thứ Hai, không bỏ trùng vì tần suất là thông tin của phân bố. Validation và test giữ phân bố thật (xem `docs/32_tien_xu_ly.md`).
- Hệ quả: Bộ tiền xử lý lưu ở `models/`, chương trình realtime nạp lại đúng phép biến đổi này (B12). Không dùng SMOTE.

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
