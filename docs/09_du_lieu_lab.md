# C02-T06 — Dữ liệu phải tự thu trong lab

Tài liệu này chốt phần dữ liệu mà hai dataset công khai không cung cấp và nhóm
phải tự thu trong mạng lab 7 node (quyết định QĐ-012). Các dòng tương ứng trong
manifest có `nguon` là `Lab` và `trang_thai` là `chua_thu`.

## 1. Vì sao phải tự thu

| Thiếu hụt của dữ liệu công khai | Dữ liệu lab bù vào |
|---|---|
| Traffic bình thường của CIC-IDS2017 thuộc mạng khác. Gaussian học trên đó không mô tả được trạng thái bình thường của lab | Kịch bản 1 |
| CIC-IDS2017 không có DoS kiểu SYN hoặc ICMP; bốn công cụ DoS của nó đều ở tầng HTTP | Kịch bản 3, gồm cả lần chạy để huấn luyện |
| Quét cổng của CIC-IDS2017 chỉ từ một máy tới một máy, trên mạng khác | Kịch bản 2 |
| CTU-13 chỉ có một scenario ngang hàng với 3 bot | Kịch bản 5 |
| Flow kênh điều khiển trong CTU-13 rất ít và chu kỳ không kiểm soát được | Kịch bản 4, với chu kỳ đã biết |
| Không dataset nào có đối chứng lành tính: dịch vụ hợp lệ gọi định kỳ, giao tiếp ngang hàng lành tính | Hai kịch bản đối chứng |
| Độ trễ phát hiện, mất gói, CPU, RAM chỉ đo được khi chạy thật | Mọi lần chạy kiểm thử |

## 2. Vai trò các máy

| Địa chỉ | Máy | Vai trò khi thu |
|---|---|---|
| `192.168.50.10` | Máy giám sát Kali | Bắt gói từ cổng mirror; không sinh traffic |
| `192.168.50.20` | Máy thử nghiệm | Nguồn quét cổng và DoS |
| `192.168.50.30` | Máy chủ dịch vụ | Đích của traffic bình thường, quét cổng và DoS; ghi access log |
| `192.168.50.41`–`.43` | Client / bot mô phỏng | Sinh traffic bình thường; đóng vai bot ở kịch bản 4, 5 |
| `192.168.50.50` | Server điều phối mô phỏng | Điểm tập trung ở kịch bản 4 |

## 3. Các biến thể cần thu

| Mã | Kịch bản | Nội dung | Thời lượng mỗi lần | Yêu cầu |
|---|---|---|---|---|
| `k1-binh-thuong` | 1 | Traffic bình thường, có tác vụ kiểm tra trạng thái định kỳ | 10 phút | B14 |
| `k2-quet-cham` | 2 | Nmap tốc độ chậm; traffic bình thường trước và sau | Khoảng 10 phút | B15 |
| `k2-quet-nhanh` | 2 | Nmap tốc độ nhanh; traffic bình thường trước và sau | Khoảng 10 phút | B15 |
| `k3-dos-muc1` | 3 | DoS một nguồn, mức tải thấp, 60 giây | Khoảng 5 phút | B16 |
| `k3-dos-muc2` | 3 | DoS một nguồn, mức tải trung bình, 60 giây | Khoảng 5 phút | B16 |
| `k3-dos-muc3` | 3 | DoS một nguồn, mức tải cao, 60 giây | Khoảng 5 phút | B16 |
| `k4-co-dinh` | 4 | Bot gọi server điều phối theo chu kỳ cố định | Ít nhất 10 phút | B17 |
| `k4-bien-thien` | 4 | Bot gọi server điều phối theo chu kỳ biến thiên | Ít nhất 10 phút | B17 |
| `k4-doi-chung` | 4 | Dịch vụ hợp lệ gọi định kỳ tới một máy chủ | Ít nhất 10 phút | B17 |
| `k5-p2p` | 5 | Các bot trao đổi ngang hàng; đổi chu kỳ và danh sách peer giữa các lần | Ít nhất 10 phút | B18 |
| `k5-doi-chung` | 5 | Giao tiếp ngang hàng lành tính | Ít nhất 10 phút | B18 |

Lựa chọn đã chốt:

- **Loại DoS: SYN.** Kịch bản cho phép chọn một trong hai (T02). Chọn SYN vì
  các đặc trưng đã lên kế hoạch ở chặng 4 (cờ TCP, tỷ lệ kết nối không hoàn
  tất) mô tả trực tiếp hành vi này. DoS bằng ICMP là phần tùy chọn, chỉ làm
  khi còn thời gian và phải có mẫu huấn luyện riêng.
- **Giao tiếp botnet mô phỏng bằng thông điệp vô hại** do script của nhóm gửi.
  Không dùng mã độc, không dùng các file mẫu của CTU-13 (B24).
- **Không thu DDoS nhiều nguồn** (T01) trong đợt này.

Đã chốt ngày 12/11/2026 (QĐ-062), ghi ở `config/default.yaml` mục `lab` (bảng giá trị ở docs/70 mục 3):

- Tham số tốc độ Nmap của hai biến thể chậm và nhanh, và dải cổng quét.
- Giá trị ba mức tải DoS. B16 yêu cầu xác định trước khi chạy.
- Chu kỳ và độ biến thiên của beaconing; số peer của kịch bản 5.

## 4. Số lần chạy

B19 yêu cầu mỗi kịch bản lặp ít nhất ba lần với lịch khác nhau, và các lần
kiểm thử cuối không được dùng để chỉnh mô hình hay ngưỡng. B11 yêu cầu tách
train/validation/test theo lần thu. Do đó mỗi biến thể cần các lần chạy riêng
cho từng vai trò, và vai trò phải được ghi **trước khi chạy**.

| Vai trò | Số lần mỗi biến thể | Dùng để |
|---|---|---|
| `train` | 1 | Huấn luyện |
| `val` | 1 | Chọn ngưỡng, tham số, cửa sổ |
| `test` | 3 | Kiểm thử cuối; chỉ dùng để báo cáo |

| Kịch bản | Số biến thể | Số lần chạy | Thời gian thu ước tính |
|---|---|---|---|
| 1 | 1 | 5 | 50 phút |
| 2 | 2 | 10 | 100 phút |
| 3 | 3 | 15 | 75 phút |
| 4 | 3 | 15 | 150 phút |
| 5 | 2 | 10 | 100 phút |
| **Tổng** | **11** | **55** | **khoảng 8 giờ** |

Đây là mức tối thiểu suy ra từ B11 và B19. Một lần chạy `train` cho mỗi biến
thể là ít; nếu mô hình thiếu mẫu thì thêm lần chạy `train`, không lấy từ nhóm
`test`.

"Lịch khác nhau" giữa các lần lặp nghĩa là thay đổi ít nhất một trong các yếu
tố: thời điểm bắt đầu hành vi so với đầu bản thu, thứ tự và độ dài các đoạn
bình thường, chu kỳ hoặc danh sách peer.

## 5. Sản phẩm của mỗi lần chạy

Mã lần chạy có dạng `<mã biến thể>-<vai trò>-<số thứ tự>`, ví dụ
`k3-dos-muc2-test-02`.

| Sản phẩm | Vị trí | Ghi chú |
|---|---|---|
| PCAP | `data/pcap/<run_id>.pcap` | Bắt trên Kali, định dạng PCAP, không cắt gói |
| Nhật ký lần chạy | `data/run_logs/<run_id>.*` | Căn cứ gán nhãn (B10); ghi độc lập với dự đoán |
| Access log | `data/service_logs/<run_id>/access_nids.log` | Chỉ để đối chiếu |
| File cảnh báo | `output/` | Chỉ với lần chạy có chương trình realtime |

Nhật ký lần chạy phải có:

- Mã lần chạy, mã biến thể, vai trò (`train`, `val`, `test`).
- Thời điểm bắt đầu và kết thúc bản thu.
- Từng hành vi: loại, thời điểm bắt đầu và kết thúc, IP nguồn, IP đích, tham
  số (tốc độ quét, mức tải, chu kỳ, danh sách peer).
- Độ lệch đồng hồ giữa Kali và các máy sinh traffic.
- Số gói bắt được và số gói bị bỏ do tcpdump báo khi dừng.

Định dạng file nhật ký được chốt khi viết script sinh traffic (B23).

## 6. Điều kiện trước khi thu

1. Mạng lab cô lập, không có đường ra ngoài (B24).
2. Mirror hoạt động: bắt thử một kết nối giữa hai máy bất kỳ và xác nhận Kali
   thấy **cả hai chiều** (B13). Lưu bản thu kiểm tra này cùng đợt thu.
3. Đồng hồ các máy đã đồng bộ.
4. Access log của máy chủ dịch vụ đã xoay vòng.
5. Tham số của biến thể đã ghi trong cấu hình; vai trò của lần chạy đã ghi
   trong nhật ký.

## 7. Thứ tự thu

1. Kịch bản 1, để có mẫu bình thường và kiểm tra toàn bộ quy trình thu.
2. Kịch bản 2 và 3, phục vụ module phân loại.
3. Kịch bản 4 và 5 cùng đối chứng, phục vụ module botnet/topology.
4. Các lần chạy `test` của mọi kịch bản thu **sau khi** mô hình và ngưỡng đã
   khóa, theo thứ tự trình diễn ở B22.

## 8. Ngoài phạm vi thu

- Mã độc thật và mọi traffic ra ngoài mạng lab.
- DDoS nhiều nguồn (T01) và DoS bằng ICMP (T02), trừ khi quyết định bổ sung.
- Tấn công dò mật khẩu, khai thác lỗ hổng: không thuộc ba lớp của module phân
  loại.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Lab 7 node | Mạng thử nghiệm riêng gồm 7 máy, không nối ra Internet |
| Kịch bản / biến thể | Kịch bản là loại hành vi cần thu (bình thường, quét cổng, ...); biến thể là một cách chạy cụ thể của kịch bản đó |
| Cổng mirror | Cổng của switch nhận bản sao mọi gói đi qua, để Kali thấy traffic của các máy khác |
| Server điều phối | Máy đóng vai trung tâm điều khiển bot trong botnet mô phỏng |
| Nmap | Công cụ quét cổng |
| DoS, SYN, ICMP | DoS là làm máy chủ quá tải. SYN là gói mở kết nối TCP; DoS SYN gửi ồ ạt gói này. ICMP là giao thức của ping |
| Cờ TCP, kết nối không hoàn tất | Cờ TCP là các bit đánh dấu vai trò của gói (mở, xác nhận, đóng kết nối); kết nối không hoàn tất là có SYN nhưng không có trao đổi tiếp theo |
| Beaconing, chu kỳ cố định / biến thiên | Bot gọi về máy điều khiển đều đặn; chu kỳ cố định là luôn cùng khoảng cách, biến thiên là khoảng cách dao động |
| Peer, ngang hàng | Các máy nói chuyện trực tiếp với nhau, không qua máy trung tâm |
| Đối chứng | Hành vi lành tính trông giống tấn công, để kiểm tra mô hình không cảnh báo nhầm |
| Train / val / test | Lần chạy để học / để chọn tham số và ngưỡng / để đánh giá cuối |
| Mã lần chạy (run_id) | Tên của một lần chạy, dạng `<biến thể>-<vai trò>-<số>` |
| Độ lệch đồng hồ | Chênh lệch giờ giữa hai máy |
| tcpdump | Công cụ bắt gói dòng lệnh; khi dừng nó in số gói bắt được và số gói bị bỏ |
| Xoay vòng log | Đóng file log hiện tại và bắt đầu file mới, để mỗi lần chạy có một file riêng |
| Ngưỡng | Giá trị điểm mà vượt qua thì cảnh báo |
| DDoS | DoS từ nhiều nguồn cùng lúc |
