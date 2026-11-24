# Kịch bản bảo vệ đề tài (C12-T07)

Kịch bản 20 phút: 12 phút trình bày, 6 phút demo, 2 phút dự phòng. Thứ tự demo đúng yêu cầu B22: bình thường →
quét cổng → DoS → botnet tập trung → botnet ngang hàng. Chi tiết từng file `.bat` và cách đọc màn hình:
`demo/HUONG_DAN.md`. Bảng số liệu dùng khi trả lời: `docs/85_bang_ket_qua.md`.

## 1. Chuẩn bị (trước buổi bảo vệ 15 phút)

| Việc | Cách làm | Nếu hỏng |
|---|---|---|
| Kiểm tra lab ảo | Bấm `demo/0_kiem_tra.bat`, chờ mọi dòng `[OK]` | Dùng bản phát lại (mục 3, đường B) |
| Kiểm tra bản thu để phát lại | `python scripts/phat_lai_demo.py --danh-sach`: không dòng nào ghi "thiếu PCAP" | Dùng `demo/4_ket_qua_da_luu.bat` (chỉ cần Python) |
| Mở sẵn tài liệu | `docs/83_bon_giai_doan.md`, `docs/85_bang_ket_qua.md`, `docs/hinh/dashboard_mau.html` | — |
| Đóng ứng dụng nặng | Lab ảo và cảm biến cần CPU | — |

## 2. Trình bày (12 phút)

| Phút | Nội dung | Tài liệu dẫn |
|---|---|---|
| 0–1 | Bài toán: phát hiện quét cổng, DoS, botnet từ lưu lượng mạng; ba module học máy chạy song song | `01`, `02` |
| 1–3 | **Giai đoạn 1**: PCAP → gói → flow hai chiều → cửa sổ host 10 s và đồ thị 120 s. Bộ đọc tự viết khớp Wireshark ở 35,5 triệu gói, nhanh gấp 25 lần Scapy | `83` mục GĐ1, `77`, `11` mục 6 |
| 3–5 | **Giai đoạn 2**: EDA (mất cân bằng 1 : 111 và 1 : 357, đặc trưng lệch mạnh); chia 60/20/20 theo thời gian; Gaussian F1 0,730; Random Forest macro-F1 0,908 | `81`, `77`, `85` mục 1 |
| 5–6 | So sánh mô hình: 8 baseline, LightGBM 0,915, **GRU học sâu 0,940–0,950** nhờ đọc chuỗi cửa sổ | `78`, `82` |
| 6–8 | **Giai đoạn 3**: botnet CTU-13 (RF F1 0,798 so với LR 0,232), gọi định kỳ cần đối chứng, topology bằng quy tắc; ba chế độ ghép module | `83` mục GĐ3, `52`, `57` |
| 8–10 | **Giai đoạn 4**: cảm biến realtime dùng đúng mã offline (khớp mọi cửa sổ); lab ảo 9 máy; **51/51 đợt, 0 báo động giả** trên 66 lần chạy test mới; độ trễ thật 3,9–4,2 s | `85` mục 2–3, `80` |
| 10–11 | Báo động giả và bỏ sót đã gặp, nguyên nhân, cách sửa: mô hình phải học trên chính mạng cần bảo vệ | `85` mục 4–5 |
| 11–12 | Hạn chế: lab ảo chứ chưa có Kali thật; bot mô phỏng; chưa có brute-force, exploit | `85` mục 6, `86` |

## 3. Demo (6 phút)

### Đường A — lab ảo chạy trực tiếp (khi `0_kiem_tra.bat` đạt)

| Bước | Bấm | Nói gì | Thời gian |
|---|---|---|---|
| 1. Bình thường | `3_demo_binh_thuong.bat` (có thể bỏ qua nếu thiếu giờ, dùng phần đầu của bước 2) | "Mạng hoạt động bình thường, hệ thống không báo gì" | 2 phút |
| 2. Quét cổng | `1_demo_quet_cong.bat` | "Máy .20 quét 1 024 cổng của máy chủ; cảnh báo `PORT_SCAN` sau khoảng 2 giây" | 3 phút |
| 3. DoS | `2_demo_dos.bat` | "Tải 60 giây; cảnh báo bắt đầu và dừng theo đúng tấn công" | 3 phút |
| 4–5. Botnet | `5_phat_lai_ban_thu.bat`, chọn 5 rồi 6 | "Mỗi lần chạy botnet thật mất 12 phút, nên phát lại bản thu đã lưu nhanh gấp 10 lần qua đúng cảm biến realtime: năm bot đều bị báo, topology tập trung rồi ngang hàng" | 2 × 1,5 phút |

Nếu thiếu giờ: chỉ chạy bước 2 trực tiếp, các bước còn lại dùng `5_phat_lai_ban_thu.bat`.

### Đường B — không chạy được lab ảo

`5_phat_lai_ban_thu.bat` lần lượt chọn 1 → 2 → 3 → 5 → 6 (mỗi bản thu 30–70 giây). Màn hình in cảnh báo khi cảm
biến phát ra, cuối mỗi lần có tổng kết so với nhật ký lần chạy và trình duyệt mở dashboard.

### Đường C — không chạy được Python trên máy trình chiếu

Mở `docs/hinh/dashboard_mau.html`, `docs/hinh/thuc_nghiem/lab/lab_do_tre.png`, `lab_bao_gia.png`, và
`output/demo/*/*.alerts.csv` của lần chạy thử.

## 4. Câu hỏi hay gặp và câu trả lời ngắn

| Câu hỏi | Trả lời | Bằng chứng |
|---|---|---|
| Kết quả 51/51 có phải học thuộc không? | Lần test thu sau khi học, chưa từng xem; đổi vai trò máy, năm bot, DDoS chưa từng có trong train cũ vẫn bắt. Nhưng mô hình lab cho recall 0 trên CTU-13: chỉ khẳng định trong lab | `76`, `80` |
| Vì sao không dùng accuracy? | Đoán toàn `benign` đã đạt 0,986; dùng macro-F1 | `43`, `81` |
| LightGBM có phải học sâu không? | Không, là cây tăng cường. Học sâu là MLP và GRU; GRU 0,940–0,950 cao hơn Random Forest | `82` |
| Phát lại PCAP có giống realtime thật không? | Có: cùng mã; đo thật trên lab cho độ trễ 3,9–4,2 s, khớp phát lại 3,5–6,3 s | `66`, `74` |
| Có thật sự an toàn không? | Mọi traffic trong lab ảo không có đường ra ngoài; DoS ≤ 60 s; bot chỉ gửi tin vô hại; không mã độc | `70`, B24 |
| Còn thiếu gì? | Chạy trên Kali và lab vật lý; lớp brute-force, exploit; chặn tự động | `86`, `Viec_con_thieu.md` |

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Phát lại bản thu | Đưa file gói tin đã lưu vào cảm biến như đang bắt trực tiếp, có thể nhanh hơn thời gian thật |
| Dashboard | Trang HTML tóm tắt cảnh báo bằng bảng và hình |
| Đợt tấn công | Một lần tấn công trong một lần chạy lab |
| Báo động giả | Cảnh báo khi không có tấn công |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp tính ngang nhau |
| B22, B24 | Yêu cầu thứ tự trình diễn; yêu cầu an toàn |
