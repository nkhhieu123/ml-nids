# Kịch bản thuyết trình — slide `Thuyet_trinh.pptx`

Đồ án môn An toàn thông tin · Nhóm HP 22.Nh89 · Nguyễn Khắc Hiếu (123220099), Nguyễn Văn Vũ (123220135)
CBHD: PGS.TS. Nguyễn Tấn Khôi

Tổng thời gian nói: **khoảng 10–13 phút** cho 9 slide, chừa 3–5 phút hỏi đáp. Mỗi slide nói đúng ý chính, đừng đọc hết chữ trên slide.
Mẹo: slide đã có sẵn **ghi chú người nói** (mở PowerPoint → chế độ Presenter sẽ thấy). File này viết kỹ hơn để học thuộc ý và trả lời khi thầy hỏi.

---

## Slide 1 — Bìa (≈30 giây)

**Nói:** "Em chào thầy và các bạn. Nhóm em gồm hai thành viên, nhóm học phần 22.Nh89, trình bày đồ án *Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng*. Hệ thống phát hiện ba loại tấn công — quét cổng, DoS và botnet — bằng ba module học máy, chạy được cả offline lẫn realtime."

**Điểm nhấn:** nói ngay 3 loại tấn công để thầy nắm phạm vi.

---

## Slide 2 — Bài toán và mục tiêu (≈1 phút)

**Nói:** "Bài toán là giám sát lưu lượng và tự phát hiện tấn công ngay từ gói tin, không cần chữ ký có sẵn như các hệ thống dựa trên luật. Ba loại tấn công em xét: quét cổng, DoS, botnet. Mục tiêu là chạy được cả hai chế độ: offline phân tích file PCAP, và realtime bắt gói trực tiếp; cảnh báo phải đúng và ít báo động giả."

**Điểm nhấn:** "không cần chữ ký" = ưu điểm của học máy so với IDS truyền thống (Snort/Suricata).

---

## Slide 3 — Kiến trúc và luồng xử lý (≈1,5 phút)

**Nói:** "Luồng dữ liệu đi từ trái sang phải: gói tin (từ file PCAP hoặc card mạng) → gộp thành flow hai chiều theo 5-tuple → tính đặc trưng theo từng host trong cửa sổ 10 giây và đồ thị 120 giây → ba module học máy chấm điểm → xuất cảnh báo ra CSV và dashboard. Điểm đáng chú ý: **bộ đọc gói và phần tính đặc trưng nhóm em tự viết** bằng thư viện chuẩn Python, nên khi chạy realtime dùng đúng đoạn mã lúc huấn luyện, kết quả nhất quán."

**Ba module** (chỉ vào): Gaussian tìm bất thường; Random Forest phân loại benign/scan/dos; module botnet dùng Random Forest cộng quy tắc topology để biết tập trung hay ngang hàng.

**Điểm nhấn:** tự viết bộ đọc → khớp Wireshark ở mọi trường, nhanh hơn Scapy ~25 lần.

---

## Slide 4 — Dữ liệu sử dụng (≈1 phút)

**Nói:** "Em dùng ba nguồn. **CIC-IDS2017** có PCAP gốc kèm lịch tấn công, dùng để học quét cổng và DoS — em dùng PCAP chứ không dùng file đặc trưng có sẵn, để tự trích đặc trưng y như lúc realtime. **CTU-13** là botnet mã độc thật có nhãn, vì lab không được phép chạy mã độc. **Lab ảo 9 máy** với 177 lần chạy là mạng tự dựng, có nhãn chuẩn tự ghi và đo được độ trễ realtime."

**Điểm nhấn:** chia train/val/test **theo thời gian** (60/20/20), không trộn ngẫu nhiên, để tránh rò rỉ dữ liệu.

---

## Slide 5 — Kết quả trên dữ liệu công khai (≈1,5 phút)

**Nói:** "Trên tập test: Random Forest phân loại quét cổng và DoS đạt **macro-F1 0,908**. Mô hình học sâu GRU cao hơn, **0,94–0,95**, nhờ đọc được chuỗi các cửa sổ theo thời gian. Module botnet trên CTU-13 đạt F1 **0,798**, vượt xa baseline hồi quy logistic chỉ 0,232."

**Vì sao dùng macro-F1 chứ không dùng accuracy?** "Dữ liệu rất mất cân bằng — chỉ 1 cửa sổ tấn công trên hàng trăm cửa sổ bình thường. Nếu đoán tất cả là *bình thường* thì accuracy đã 0,986 nhưng vô dụng. Macro-F1 chấm công bằng mọi lớp nên phản ánh đúng."

---

## Slide 6 — Kết quả realtime trên lab (≈2 phút) — **slide quan trọng nhất**

**Nói:** "Trên lab, cảm biến realtime dùng đúng mã offline. Kết quả: phát hiện đủ **51/51 đợt tấn công**, **0 báo động giả** trên 66 lần chạy test, độ trễ cảnh báo thật **3,9–4,2 giây**."

**Thông điệp chính (nhấn mạnh, nói chậm):** "Nhưng có một kết quả quan trọng em muốn nói thẳng: **mô hình học từ dữ liệu công khai không tự chuyển sang mạng khác**. Khi đem thẳng sang lab, nó **sót toàn bộ botnet (0/9) và sinh 58 báo động giả**. Chỉ sau khi **học lại trên chính mạng cần bảo vệ**, mới bắt đủ 24/24 đợt và 0 báo động giả. Đây là bài học lớn nhất của đồ án: mô hình phải được huấn luyện trên chính mạng nó bảo vệ."

**Điểm nhấn:** chủ động nêu điểm yếu này — thầy thường đánh giá cao sự trung thực và hiểu bản chất.

---

## Slide 7 — Demo trực tiếp (≈1,5 phút)

**Nói:** "Đây là màn hình thật của cửa sổ giám sát khi em chạy demo. Mỗi loại tấn công chạy ở một cửa sổ riêng, cửa sổ giám sát `.10` phát hiện ngay và in ra: giờ, loại tấn công, và máy liên quan. Ảnh trái: quét cổng vào máy chủ `.30`. Ảnh giữa: DoS và quét cổng cùng lúc, cảm biến phân biệt được hai loại. Ảnh phải: botnet ngang hàng, hệ thống báo đúng ba bot `.41`–`.43` và nhận ra topology ngang hàng."

**Nếu demo trực tiếp:** quét cổng và DoS hiện sau 1–3 giây; botnet cần ~10–20 giây. Mọi lưu lượng chỉ chạy trong lab ảo, không ra ngoài.

**Điểm nhấn:** nói rõ an toàn — đây là mạng ảo cô lập (yêu cầu B24).

---

## Slide 8 — Hạn chế và hướng phát triển (≈1 phút)

**Nói:** "Về hạn chế: lab mới chạy trên máy ảo WSL2 chứ chưa trên Kali và mạng vật lý thật; bot là chương trình mô phỏng gọi định kỳ chứ không phải mã độc thật; mới có ba lớp tấn công; và mô hình học trên lab cho recall 0 trên CTU-13 nên chỉ khẳng định trong lab. Hướng phát triển: triển khai trên mạng vật lý thật, bổ sung lớp brute-force và khai thác web, tự động học lại định kỳ, và thêm bước chặn tự động sau cảnh báo."

**Điểm nhấn:** trung thực về giới hạn, nhưng mỗi hạn chế đi kèm một hướng khắc phục.

---

## Slide 9 — Kết luận (≈45 giây)

**Nói:** "Tóm lại, nhóm em đã xây dựng một hệ thống hoàn chỉnh từ gói tin tới cảnh báo realtime, tự viết toàn bộ các bước. Phân loại scan/DoS đạt macro-F1 0,908, học sâu GRU 0,94–0,95, botnet 0,798. Cảnh báo realtime giống hệt offline; trên lab đạt 51/51 đợt, 0 báo động giả, trễ khoảng 4 giây. Và bài học rút ra là mô hình phải học trên chính mạng cần bảo vệ mới đáng tin. Em xin cảm ơn thầy và các bạn đã lắng nghe."

---

# Câu hỏi thầy hay hỏi và cách trả lời

| Câu hỏi | Trả lời ngắn |
|---|---|
| **Khác gì Snort/Suricata (IDS dựa luật)?** | IDS luật chỉ bắt được tấn công đã có chữ ký. Hệ thống này học *hành vi* (số cổng đích, tỷ lệ kết nối dở dang, số kết nối mỗi giây…) nên bắt được cả biến thể chưa từng thấy; đổi lại cần dữ liệu huấn luyện của chính mạng đó. |
| **Vì sao dùng Random Forest, không dùng deep learning?** | RF nhẹ, giải thích được, ít dữ liệu vẫn tốt, hợp realtime. Em vẫn có so sánh: GRU cao hơn (0,94–0,95) nhưng nặng hơn; RF là lựa chọn cân bằng. |
| **51/51 có phải học thuộc (overfit) không?** | Không. Các lần test là bản thu *sau* khi học, mô hình chưa từng thấy; còn đổi vai trò máy, SYN flood gói thô, DDoS năm nguồn đều mới mà vẫn bắt. Nhưng em thừa nhận mô hình lab cho recall 0 trên CTU-13 — nên chỉ khẳng định trong phạm vi lab. |
| **Vì sao không dùng accuracy?** | Dữ liệu mất cân bằng 1:111 và 1:357; đoán toàn "bình thường" đã accuracy 0,986. Dùng macro-F1 để mỗi lớp tính ngang nhau. |
| **Botnet mô phỏng thì có ý nghĩa gì?** | Lab không được chạy mã độc thật (an toàn B24). Em học đặc trưng botnet thật từ CTU-13; bot trong lab chỉ mô phỏng hành vi *gọi định kỳ* để đo độ trễ và topology. Đó là lý do có cả hai nguồn. |
| **Phát lại PCAP có giống realtime thật không?** | Có — cùng một đoạn mã cảm biến. Đo thật trên lab cho độ trễ 3,9–4,2 giây, khớp với khi phát lại. |
| **Vì sao mô hình công khai sót botnet của lab?** | Bot CTU-13 là mã độc ồn ào (spam, quét, DDoS); bot lab chỉ gọi định kỳ rất ít lưu lượng, nên điểm dưới ngưỡng. Học lại trên lab thì bắt được. |
| **Hệ thống có an toàn không?** | Mọi lưu lượng chỉ chạy giữa các máy ảo trong 192.168.50.0/24, bridge không có đường ra ngoài; DoS tối đa 60 giây; bot gửi tin vô hại; không có mã độc. |
| **Còn thiếu gì / làm tiếp gì?** | Chạy trên Kali và lab vật lý; thêm lớp brute-force, khai thác; học lại định kỳ tự động; chặn/ứng phó tự động sau cảnh báo. |
| **Dữ liệu lấy ở đâu, có đủ tin cậy?** | CIC-IDS2017 và CTU-13 là bộ công khai được dùng rộng rãi trong nghiên cứu; lab là mạng tự dựng có nhật ký lần chạy làm nhãn chuẩn, độc lập với mô hình. |

# Chuẩn bị trước khi lên

- Mở sẵn `Thuyet_trinh.pptx` (Presenter view để thấy ghi chú), và `docs/Bao_cao_mon_hoc.pdf` để tra số khi cần.
- Nếu demo trực tiếp: chạy thử trước một lần (lần đầu WSL khởi động chậm). Thứ tự: giám sát `.10` trước, rồi mở cửa sổ tấn công.
- Thuộc 4 con số "vàng": **macro-F1 0,908 · GRU 0,94–0,95 · 51/51 đợt, 0 báo giả · độ trễ ~4 giây**.
- Câu chốt nên nhớ: *"Mô hình phải học trên chính mạng cần bảo vệ mới đáng tin."*
