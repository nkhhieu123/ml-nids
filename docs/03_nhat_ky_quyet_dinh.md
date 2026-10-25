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
- Hệ quả: Bộ trích xuất packet thêm trường `frag_id`. Mỗi flow ghi `direction_basis` để biết chiều chắc chắn tới đâu. Chiều không bao giờ được sửa theo gói tới sau, nên huấn luyện và realtime giống nhau. Tách flow theo timeout, FIN/RST và 5-tuple dùng lại để cho C04-T02.

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
