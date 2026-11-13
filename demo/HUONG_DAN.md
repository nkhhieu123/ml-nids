# Hướng dẫn báo cáo tiến độ và demo

Tài liệu dùng cho buổi báo cáo: nói gì, theo thứ tự nào, và bấm file nào để demo. Mọi con số lấy từ
[Bao_cao_Chang_11.md](../docs/Bao_cao_Chang_11.md), [76_khai_quat_lab.md](../docs/76_khai_quat_lab.md) và
[72_do_nhay_tham_so.md](../docs/72_do_nhay_tham_so.md). Các file demo đã được chạy thử ngày 13/11/2026 trên máy này.

Tổng thời gian đề xuất: **khoảng 19 phút** (14 phút báo cáo, 5 phút demo). Nếu chỉ có 15 phút, mục 2.2 và
2.5 nói ý chính, phần chi tiết để trả lời câu hỏi.

## 1. Chuẩn bị trước buổi báo cáo (10 phút)

1. Cắm sạc, tắt các chương trình nặng. Demo chạy trong WSL2 nên máy cần rảnh CPU.
2. Mở thư mục `demo` của dự án, bấm đúp **`0_kiem_tra.bat`**. Cả 8 dòng phải ghi `[ĐẠT]` và dòng cuối là
   `Sẵn sàng demo.` Nếu có `[LỖI]`, xem mục 5.
3. Bấm đúp **`1_demo_quet_cong.bat`** một lần để chạy thử (khoảng 3 phút). Lần chạy đầu sau khi bật máy chậm
   hơn vì WSL phải khởi động.
4. Mở sẵn hai file để chiếu: `docs/Bao_cao_Chang_11.md` và hình `docs/hinh/thuc_nghiem/lab/lab_do_tre.png`.

Không cần mạng Internet. Lab ảo không có đường ra ngoài.

## 2. Nội dung báo cáo (14 phút)

### 2.1. Bài toán và kiến trúc (1 phút)

- Đề tài: ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng.
- Hệ thống đọc gói tin (file PCAP hoặc bắt trực tiếp), gom thành flow, rồi tính đặc trưng theo từng host trong
  cửa sổ 10 giây và 120 giây.
- Ba module chấm trên các đặc trưng đó:

| Module | Mô hình | Trả lời câu hỏi |
|---|---|---|
| Bất thường | Gaussian đa biến | Host này có khác bình thường không? |
| Phân loại tấn công | Random Forest | Là `benign`, `port_scan` hay `dos`? |
| Botnet | Random Forest và quy tắc topology | Host có phải bot không; bot liên lạc kiểu tập trung hay ngang hàng? |

### 2.2. Dữ liệu và lý do chọn (1,5 phút)

| Dữ liệu | Dùng cho | Vì sao chọn |
|---|---|---|
| **CIC-IDS2017**, thứ Hai, thứ Tư, thứ Sáu | Học và đánh giá quét cổng, DoS; thứ Hai (không có tấn công) cho module Gaussian | Công bố kèm **PCAP gốc** và **lịch tấn công**, nên chạy được qua bộ trích xuất của chính đề tài thay vì dùng đặc trưng người khác tính sẵn. Có đúng hai loại cần: bốn công cụ DoS (thứ Tư) và Nmap quét cổng (thứ Sáu). Được dùng rộng rãi nên so được với các nghiên cứu khác |
| **CTU-13**, 13 kịch bản | Học và đánh giá botnet | Là bộ dữ liệu botnet **thật** (mã độc chạy trong mạng trường đại học), có nhãn từng flow và có cả kiểu tập trung lẫn ngang hàng. Lab không được phép chạy mã độc (yêu cầu B24) nên đây là nguồn bot thật duy nhất |
| **Lab ảo 7 máy**, 177 lần chạy | Kiểm thử thực nghiệm; học lại mô hình cho mạng lab | Hai bộ trên là dữ liệu của mạng khác, thu năm 2011 và 2017. Đề tài yêu cầu đo trên mạng do mình dựng, có nhãn chuẩn do mình ghi (nhật ký lần chạy), và đo được độ trễ realtime, điều mà dữ liệu có sẵn không cho phép |

Các lựa chọn cụ thể và lý do:

- **Chỉ lấy ba ngày của CIC-IDS2017.** Thứ Ba và thứ Năm là brute-force và tấn công web, ngoài ba lớp của đề
  tài. Trong thứ Tư bỏ Heartbleed, trong thứ Sáu bỏ DDoS LOIT và Bot: mỗi loại chỉ có một đợt, không đủ để vừa
  học vừa đánh giá (QĐ-009, QĐ-033).
- **Dùng PCAP, không dùng file CSV có sẵn của CIC.** Hệ thống realtime phải tính đặc trưng từ gói tin bằng đúng
  đoạn mã lúc huấn luyện (yêu cầu B12). File CSV chỉ dùng để đối chiếu nhãn.
- **CTU-13 dùng file flow hai chiều có nhãn** vì PCAP đầy đủ của toàn mạng không được công bố (QĐ-010). Vì vậy
  đặc trưng của module botnet được thiết kế để tính được từ bản ghi flow.
- **Chia tập theo thời gian, không trộn ngẫu nhiên.** Các cửa sổ liền nhau gần giống nhau; trộn ngẫu nhiên sẽ
  để mô hình thấy gần như cùng một mẫu ở cả train lẫn test và cho điểm cao giả (QĐ-027). Với CTU-13 chia theo
  kịch bản, với lab chia theo lần chạy.
- **Lab ảo thay cho lab vật lý** vì nhóm chưa có 7 máy và switch có cổng mirror. Gói tin vẫn là gói thật của
  nhân Linux, Nginx và Nmap (QĐ-061).

### 2.3. Những gì đã làm được (3 phút)

Đã xong 11/12 chặng của kế hoạch. Còn Chặng 12 (báo cáo cuối, bàn giao). Kho mã có khoảng 45 module Python và
**444 kiểm thử tự động đều đạt**, 73 quyết định kỹ thuật được ghi lại kèm lý do
(`docs/03_nhat_ky_quyet_dinh.md`), mỗi chặng có một báo cáo riêng (`docs/Bao_cao_Chang_1.md` tới `_11.md`).

**Đường đi của dữ liệu, cũng là thứ tự các chặng:**

```
gói tin ─> flow ─> đặc trưng theo host ─> gán nhãn, chia tập ─> ba mô hình ─> pipeline ─> cảm biến realtime ─> lab
(Chặng 3)  (Chặng 4)                      (Chặng 5)             (Chặng 6–8)   (Chặng 9)   (Chặng 10)        (Chặng 11)
```

| Chặng | Đã làm được gì | Kết quả đo được |
|---|---|---|
| 1. Yêu cầu | Rút đề bài thành bảng yêu cầu (B01–B24), chốt đầu ra của ba module, dựng kho mã và file cấu hình chung | — |
| 2. Dữ liệu | Khảo sát và chọn CIC-IDS2017, CTU-13; lập bảng kê mọi nguồn dữ liệu; tải đủ dữ liệu | PCAP ba ngày CIC, 13 file flow CTU-13 |
| 3. Đọc gói tin | **Tự viết** bộ đọc PCAP/PCAPNG và bóc header Ethernet/IP/TCP/UDP bằng thư viện chuẩn của Python; bộ đọc access log Nginx | Khớp Wireshark ở **mọi trường của 4,57 triệu gói**; khớp mọi ô của log Nginx |
| 4. Flow và đặc trưng | Ghép gói thành flow hai chiều; tính đặc trưng theo host trong cửa sổ 10 giây trượt 2 giây (số cổng đích, tỷ lệ kết nối không hoàn tất, số kết nối mỗi giây...) | Bảng flow và bảng cửa sổ host kèm mô tả từng cột; đối chiếu độc lập với Wireshark |
| 5. Nhãn và chia tập | Gán nhãn theo lịch tấn công; chia train/validation/test **theo thời gian** để không rò rỉ; phân tích dữ liệu | 1,44 triệu flow, 465 nghìn cửa sổ host của ba ngày CIC |
| 6. Module bất thường | Gaussian đa biến trên 14 đặc trưng, học từ traffic bình thường | Test CIC: F1 0,730, báo động giả 1,42% cửa sổ |
| 7. Module phân loại | Random Forest ba lớp `benign` / `port_scan` / `dos`; so với Logistic Regression và chọn Random Forest | Macro-F1: validation 0,935, test 0,908 |
| 8. Module botnet | Đồ thị liên lạc theo cửa sổ 120 giây, đặc trưng gọi định kỳ, Random Forest phát hiện host bot, quy tắc nhận dạng topology | Test CTU-13 (họ bot chưa thấy lúc học): precision 0,971, recall 0,678 |
| 9. Pipeline offline | Một lệnh: đưa vào file PCAP, ra file cảnh báo của cả ba module theo một định dạng chung, gộp cảnh báo lặp thành sự kiện | Chạy trên 1,1 triệu gói CIC; không bỏ sót quét, Slowloris, Hulk ở chế độ độc lập |
| 10. Realtime | Cảm biến bắt gói trực tiếp từ card mạng, chấm khi cửa sổ đóng, chạy nền bằng systemd, dừng êm | Cảnh báo realtime **giống hệt** offline khi phát lại 4 đoạn PCAP |
| 11. Kiểm thử lab | Dựng lab ảo 7 máy; 5 nhóm kịch bản; nhật ký làm nhãn chuẩn; đo phát hiện, độ trễ, báo động giả, hiệu năng; học lại mô hình cho lab | 177 lần chạy; 24/24 đợt, 0 báo động giả (mục 2.4) |

**Riêng Chặng 11 và phần bổ sung (09–13/11/2026), kể chi tiết vì là phần mới nhất:**

1. **Dựng lab ảo** bằng network namespace trên WSL2: 7 máy, một bridge, cổng mirror về máy giám sát. Kiểm tra
   mirror thấy đủ hai chiều, không mất gói.
2. **Viết bộ chạy kịch bản** tự ghi nhật ký (giờ bắt đầu, kết thúc, máy nguồn, máy đích của từng tấn công). Bộ
   chạy không đọc kết quả mô hình, nên nhãn chuẩn độc lập với mô hình.
3. **Thu 11 biến thể** của 5 kịch bản: bình thường; quét chậm, quét nhanh; DoS ba mức tải; botnet tập trung
   chu kỳ cố định và biến thiên; botnet ngang hàng; hai kịch bản đối chứng (traffic lành tính trông giống bot).
4. **Chấm mô hình cũ trên lab:** 15/24 đợt, sót hết botnet, 58 báo động giả. Tìm ra ba nguyên nhân (mục 2.5).
5. **Học lại cả ba module trên dữ liệu lab**, hai lần: lần đầu một lần `train` mỗi biến thể (24/24 đợt nhưng
   còn 4 báo động giả); lần hai ba lần `train` (24/24 đợt, 0 báo động giả). Mỗi lần đều thu lần `test` mới.
6. **Kiểm tra khái quát:** đổi vai trò máy (6/6 đợt), SYN flood gói thô bằng hping3 (9/9 đợt), chấm chéo với
   CTU-13 (recall 0, ghi nhận là hạn chế).
7. **Cải tiến sau khi đo:** quy tắc topology theo nhóm (đúng 98,2%); giảm thời gian chờ bắt tay từ 3 xuống 1
   giây (cảnh báo sớm hơn khoảng 2 giây); lớp giữ nhãn `dos` cho DoS HTTP chậm (recall Slowhttptest 0,66 lên
   0,82, chưa bật).
8. **Thí nghiệm bổ sung:** cảm biến bắt trực tiếp trong lab (không mất gói tới khoảng 2 900 gói mỗi giây); máy
   tấn công có cả traffic bình thường; đường truyền có trễ 200 ms; ghép access log Nginx với flow (33 003 dòng,
   lệch 0); so với Wireshark cho IPv6, gói phân mảnh, đường hầm.
9. **Đo độ nhạy tham số:** tham số gán nhãn; tham số flow bằng cách trích xuất lại CIC và huấn luyện lại 7 cấu
   hình (macro-F1 0,932–0,938, giữ nguyên bộ hiện tại).
10. **Bộ demo bấm là chạy** và tài liệu này.

### 2.4. Kết quả Chặng 11 (4 phút) — phần chính

Bấm đúp **`4_ket_qua_da_luu.bat`** để hiện đúng bảng dưới đây và mở hai hình.

| Thử nghiệm trên 33 lần `test` mới | Phát hiện | Báo động giả |
|---|---|---|
| Mô hình học từ CIC-IDS2017 và CTU-13, đem thẳng sang lab | 15/24 đợt (quét 6/6, DoS 9/9, botnet 0/9) | 58 sự kiện |
| Mô hình học lại trên dữ liệu lab | **24/24 đợt** | **0** |
| Mô hình lab, đổi vai trò máy (chưa từng học) | 6/6 đợt | 0 |
| Mô hình lab, SYN flood gói thô (chưa từng học) | 9/9 đợt | 0 |

Các ý cần nói:

1. Mô hình học từ bộ dữ liệu công khai **không tự chuyển sang mạng khác**: quét và DoS vẫn bắt được, botnet sót
   hết, báo động giả nhiều. Đây là kết quả quan trọng nhất, không nên giấu.
2. Sau khi học lại trên dữ liệu lab (3 lần `train` mỗi biến thể), chấm trên các lần `test` hoàn toàn mới: bắt
   đủ 24/24 đợt, không báo động giả, macro-F1 theo cửa sổ 0,9989.
3. Độ trễ: cảnh báo quét và DoS phát sau khoảng 1,5–3 giây kể từ lúc tấn công bắt đầu (sẽ thấy trong demo).
   Với botnet, cửa sổ cảnh báo đầu tiên kết thúc khoảng 10–17 giây (trung vị) sau khi bot bắt đầu hoạt động.
4. Topology: gán đúng kiểu ngang hàng 98,2% bằng quy tắc "các host bị nghi gọi lẫn nhau".
5. Không mất gói: 0 gói nhân bỏ ở tải tới khoảng 2 900 gói mỗi giây.

### 2.5. Vì sao có kết quả đó (2 phút)

**Vì sao mô hình học từ CIC-IDS2017 vẫn bắt được quét cổng và DoS trên lab (15/15)?**
Hai loại này có dấu hiệu giống nhau ở mọi mạng. Quét cổng: một host mở kết nối tới hàng trăm cổng khác nhau
trong vài giây, phần lớn không hoàn tất. DoS tải kết nối: hàng trăm kết nối ngắn mỗi giây dồn vào một cổng.
Các đặc trưng như số cổng đích, tỷ lệ kết nối không hoàn tất, số kết nối mỗi giây không phụ thuộc mạng nào.

**Vì sao mô hình học từ CTU-13 sót hết botnet của lab (0/9)?**

- Bot của CTU-13 là mã độc thật: gửi spam, quét, DDoS, nên ồn ào. Bot của lab chỉ **gọi định kỳ** về máy điều
  khiển mỗi 30–60 giây, rất ít traffic. Mô hình học "bot là máy ồn ào" nên cho bot lab điểm cao nhất 0,084,
  dưới ngưỡng 0,1; điểm trung vị của bot (0,003) còn thấp hơn máy chỉ duyệt web (0,052).
- CTU-13 chỉ có 4 máy bình thường đã xác nhận, nên mô hình ít mẫu để hiểu "bình thường" trông ra sao.
- Quy tắc topology cũ đòi ít nhất 5 máy gọi vào mới coi là ngang hàng; lab chỉ có 3 bot.

**Vì sao mô hình cũ báo động giả nhiều (58 sự kiện)?**

- Module Gaussian học "bình thường" từ các máy trạm của CIC. Máy chủ web `.30` của lab nhận kết nối liên tục,
  khác hẳn các máy đó, nên bị báo suốt cả bản thu ở mọi lần chạy.
- Bộ phân loại chưa từng thấy máy trạm truyền khối dữ liệu lớn cho nhau, nên coi đó là DoS.

Cả hai đều là cùng một nguyên nhân: **mô hình chưa từng thấy mạng này**.

**Vì sao học lại trên lab thì được 24/24 và không báo động giả?**

- Mô hình được thấy đúng mạng mình sẽ giám sát: máy chủ `.30` trông thế nào lúc bình thường, truyền file nội bộ
  trông thế nào, bot gọi định kỳ trông thế nào. Lần học đầu chỉ có một lần `train` mỗi biến thể và còn 4 báo
  động giả; tăng lên ba lần `train` thì hết.
- Chuyển sang chế độ `doc_lap`: module botnet xét mọi host, không chờ module Gaussian báo trước. Bot chậm không
  làm host "bất thường" nên ở chế độ cũ module botnet không bao giờ được hỏi.
- Quy tắc topology mới xét theo nhóm (các host bị nghi gọi lẫn nhau là ngang hàng), không cần ngưỡng số máy.
- Phải nói rõ: lab **dễ hơn mạng thật**. Chỉ 7 máy, traffic bình thường do một bộ sinh tạo ra nên đều đặn; các
  lần `test` khác lần `train` ở thời điểm, chu kỳ và hạt giống ngẫu nhiên chứ không khác về bản chất.

**Vì sao đổi vai trò máy và SYN flood vẫn bắt được, dù chưa từng học?**
Mô hình học **hành vi**, không học địa chỉ: đổi máy nào làm bot, đổi cổng, đổi chu kỳ thì đặc trưng gọi định kỳ
vẫn còn. SYN flood bằng gói thô vẫn là rất nhiều lần mở kết nối tới một cổng, giống DoS đã học.

**Vì sao mô hình lab lại cho recall 0 trên CTU-13?**
Lý do đối xứng với câu thứ hai: mô hình lab chỉ biết bot gọi định kỳ, không biết bot thật gửi spam hay DDoS.
Kết luận trung thực là: **mô hình phải được học trên chính mạng cần bảo vệ**, và kết quả 24/24 chỉ đúng trong
lab với bot mô phỏng.

**Vì sao độ trễ là 1,5–3 giây với quét và DoS, còn botnet chậm hơn nhiều?**
Quét và DoS chấm trên cửa sổ 10 giây trượt mỗi 2 giây, cộng 1 giây chờ bắt tay TCP. Botnet cần cửa sổ 120
giây vì phải thấy vài lần gọi định kỳ mới nhận ra nhịp.

**Vì sao macro-F1 trên CIC thấp hơn trên lab?**
Trên CIC bộ phân loại đạt macro-F1 0,935 ở validation và 0,908 ở test. CIC khó hơn: DoS HTTP chậm (Slowhttptest, Slowloris) giữ kết nối mở thật lâu nên giữa hai đợt gửi, cửa sổ 10
giây trông như bình thường; validation `port_scan` chỉ có 164 cửa sổ nên vài cửa sổ sai đã kéo điểm xuống.

### 2.6. Hạn chế (1,5 phút) — nói thẳng

- Mới đo trên **lab ảo**; chưa có lab vật lý 7 máy và chưa cài trên Kali Linux.
- Mô hình botnet của lab cho **recall 0 trên CTU-13**: kết quả 24/24 chỉ có nghĩa trong lab với bot mô phỏng.
- DoS HTTP chậm còn sót (recall Slowhttptest 0,66 trên CIC). Lớp giữ nhãn `dos` theo host nâng lên 0,82 nhưng
  chưa bật trong hệ thống.
- Module Gaussian trên CIC báo động giả khoảng 17 đợt mỗi giờ, không dùng một mình được.
- Chưa có dữ liệu brute-force và exploit.

### 2.7. Việc tiếp theo (0,5 phút)

Theo [Viec_con_thieu.md](../docs/Viec_con_thieu.md) mục 4: dựng lab vật lý và cài trên Kali; nối lớp giữ nhãn `dos` vào
hệ thống; Chặng 12 viết báo cáo cuối và bàn giao.

## 3. Demo (5 phút)

Mỗi file `.bat` trong thư mục `demo` mở một cửa sổ, tự làm bốn bước rồi dừng ở `Press any key`:

1. dựng lab ảo 7 máy;
2. bật cảm biến realtime trên máy giám sát `.10`, dùng mô hình lab;
3. chạy kịch bản và in cảnh báo **ngay khi cảm biến phát ra**;
4. in tổng kết: giờ tấn công thật theo nhật ký, giờ cảnh báo đầu tiên, độ trễ, số báo động giả.

| File | Kịch bản | Thời gian | Kết quả lúc chạy thử |
|---|---|---|---|
| `0_kiem_tra.bat` | Kiểm tra máy đủ điều kiện demo | 20 giây | 8/8 đạt |
| `1_demo_quet_cong.bat` | Nmap quét cổng 1–1024 từ `.20` vào `.30` | khoảng 3 phút | Cảnh báo `port_scan` sau 3,1 giây |
| `2_demo_dos.bat` | Tải kết nối 60 giây từ `.20` vào `.30` | khoảng 3 phút | Cảnh báo `dos` sau 1,5 giây |
| `3_demo_binh_thuong.bat` | Chỉ có traffic bình thường (đối chứng) | khoảng 2,5 phút | Không có cảnh báo nào |
| `4_ket_qua_da_luu.bat` | In bảng kết quả đã lưu, mở hai hình | vài giây | — |

### 3.1. Trình tự đề xuất

1. Bấm **`1_demo_quet_cong.bat`** ngay khi bắt đầu mục 2.4 của phần báo cáo, để nó chạy trong lúc nói.
   Thời điểm quét là ngẫu nhiên, trong khoảng 25–75 giây sau bước 3.
2. Khi các dòng `>> ... CẢNH BÁO PORT_SCAN host 192.168.50.20` hiện ra, chỉ vào màn hình và giải thích:
   - `.20` là máy quét, `.30` là máy bị quét; cả hai đều bị báo;
   - "điểm" là xác suất lớp `port_scan` do Random Forest trả về;
   - mỗi 2 giây có một cửa sổ mới nên cảnh báo lặp lại trong lúc quét.
3. Đọc phần `[4/4] Tổng kết`: dòng `=> PHÁT HIỆN ... sau khi tấn công bắt đầu 3.1 giây` là độ trễ thật, tính
   từ giờ ghi trong nhật ký lần chạy. Dòng báo động giả phải là 0.
4. Nếu còn thời gian, bấm **`2_demo_dos.bat`**. DoS kéo dài 60 giây nên cảnh báo `DOS` chạy liên tục khoảng một
   phút rồi dừng khi tải dừng.
5. Nếu được hỏi "có báo nhầm khi mạng bình thường không", bấm **`3_demo_binh_thuong.bat`**: không có dòng cảnh
   báo nào.

Không chạy hai file demo cùng lúc: chúng dùng chung một lab.

### 3.2. Màn hình trông thế nào: chưa bị tấn công, đang bị tấn công, sau tấn công

Các đoạn dưới đây là màn hình thật của lần chạy thử ngày 13/11/2026.

**a) Chưa bị tấn công: màn hình đứng yên, không có dòng nào.**

Sau bước `[3/4]`, các máy trạm `.41`–`.43` duyệt web bình thường tới máy chủ `.30`. Cảm biến vẫn chấm mỗi host
2 giây một lần, nhưng mọi cửa sổ đều được xếp là `benign` nên **không in gì**:

```
[3/4] Chạy kịch bản: traffic bình thường, rồi tấn công từ .20 vào .30. Cảnh báo hiện bên dưới khi có.
      (chỉ in cảnh báo có loại tấn công; cảnh báo bất thường chung được đếm ở phần tổng kết)

                                   <-- trống: hệ thống đang chạy, chưa thấy tấn công
```

Giai đoạn này kéo dài 25–75 giây với demo quét cổng, 20–30 giây với demo DoS. Im lặng ở đây là kết quả đúng:
có traffic nhưng không có báo động giả. Nên nói với người xem: "lúc này mạng đang hoạt động bình thường, hệ
thống không báo gì".

Với `3_demo_binh_thuong.bat`, màn hình trống như vậy suốt khoảng 2 phút rồi sang thẳng phần tổng kết:

```
[4/4] Tổng kết: so nhật ký lần chạy (giờ tấn công thật) với cảnh báo của cảm biến
  Bản thu: 1674 gói, nhân bỏ 0 gói
  Cảnh báo có loại tấn công nằm ngoài đợt tấn công (báo động giả): 0
  Cảnh báo bất thường chung (module Gaussian, không nêu loại): 0
```

Không có dòng `Tấn công thật` vì kịch bản này không có tấn công; cả hai số cảnh báo đều là 0.

**b) Đang bị quét cổng (`1_demo_quet_cong.bat`): các dòng `PORT_SCAN` hiện ra sau khoảng 3 giây.**

```
  >> 10:33:17  CẢNH BÁO PORT_SCAN  host 192.168.50.20   điểm 0.9533
  >> 10:33:17  CẢNH BÁO PORT_SCAN  host 192.168.50.30   điểm 0.9933
  >> 10:33:19  CẢNH BÁO PORT_SCAN  host 192.168.50.20   điểm 0.9533
  >> 10:33:19  CẢNH BÁO PORT_SCAN  host 192.168.50.30   điểm 1
  >> 10:33:21  CẢNH BÁO PORT_SCAN  host 192.168.50.20   điểm 0.9533
```

| Phần của dòng | Ý nghĩa |
|---|---|
| `10:33:17` | Giờ thật lúc cảm biến phát cảnh báo |
| `PORT_SCAN` | Loại tấn công do bộ phân loại Random Forest xác định |
| `host 192.168.50.20` | Máy quét (kẻ tấn công) |
| `host 192.168.50.30` | Máy bị quét (nạn nhân). Mỗi cửa sổ có hai dòng vì cả hai phía đều được chấm |
| `điểm 0.9533` | Xác suất lớp `port_scan` mô hình trả về, từ 0 tới 1; càng gần 1 càng chắc |

Nmap quét 1 024 cổng xong trong chưa đầy 1 giây, nhưng cảnh báo lặp lại khoảng 10 dòng trong 10 giây: lần quét
nằm trong 5 cửa sổ 10 giây liên tiếp (mỗi 2 giây trượt một lần), mỗi cửa sổ báo hai host. Sau đó màn hình lại
đứng yên vì quét đã dừng.

**c) Đang bị DoS (`2_demo_dos.bat`): các dòng `DOS` chạy liên tục suốt 60 giây.**

```
  >> 10:26:51  CẢNH BÁO DOS        host 192.168.50.20   điểm 0.9439
  >> 10:26:51  CẢNH BÁO DOS        host 192.168.50.30   điểm 1
  >> 10:26:53  CẢNH BÁO DOS        host 192.168.50.20   điểm 0.9967
  >> 10:26:53  CẢNH BÁO DOS        host 192.168.50.30   điểm 0.9967
  ...
  >> 10:27:59  CẢNH BÁO DOS        host 192.168.50.20   điểm 1
  >> 10:27:59  CẢNH BÁO DOS        host 192.168.50.30   điểm 1
```

Cứ 2 giây có thêm hai dòng (máy tấn công `.20` và máy chủ `.30`), tổng cộng khoảng 70 dòng. Tải bắt đầu lúc
10:26:49 và dừng lúc 10:27:49; dòng đầu tiên hiện lúc 10:26:51, dòng cuối lúc 10:27:59, tức 10 giây sau khi
tải dừng (cửa sổ 10 giây cuối cùng còn chứa tải). Đây là điểm nên chỉ ra: **cảnh báo bắt đầu và kết thúc theo
đúng tấn công**.

**d) Sau tấn công: phần `[4/4] Tổng kết`.**

Demo quét cổng:

```
  Bản thu: 3739 gói, nhân bỏ 0 gói
  Tấn công thật: port_scan (quet) từ 192.168.50.20 vào 192.168.50.30, 10:24:48 - 10:24:48 (0 giây)
  => PHÁT HIỆN: 10 cảnh báo port_scan; cảnh báo đầu tiên lúc 10:24:51, sau khi tấn công bắt đầu 3.1 giây
  Cảnh báo có loại tấn công nằm ngoài đợt tấn công (báo động giả): 0
  Cảnh báo bất thường chung (module Gaussian, không nêu loại): 10
```

Demo DoS:

```
  Bản thu: 73570 gói, nhân bỏ 0 gói
  Tấn công thật: dos (tai-ket-noi) từ 192.168.50.20 vào 192.168.50.30, 10:26:49 - 10:27:49 (60 giây)
  => PHÁT HIỆN: 70 cảnh báo dos; cảnh báo đầu tiên lúc 10:26:51, sau khi tấn công bắt đầu 1.5 giây
  Cảnh báo có loại tấn công nằm ngoài đợt tấn công (báo động giả): 0
  Cảnh báo bất thường chung (module Gaussian, không nêu loại): 35
```

| Dòng | Đọc thế nào |
|---|---|
| `Bản thu: ... nhân bỏ 0 gói` | Số gói máy giám sát bắt được; `nhân bỏ 0` nghĩa là cảm biến không mất gói nào |
| `Tấn công thật: ...` | Lấy từ **nhật ký lần chạy**, do bộ chạy kịch bản ghi, không phải do mô hình đoán. Đây là đáp án |
| `=> PHÁT HIỆN ... sau ... giây` | Mô hình có báo đúng loại, đúng host, đúng lúc; con số cuối là độ trễ phát hiện |
| `=> BỎ SÓT` | Nếu hiện dòng này thay cho `PHÁT HIỆN`: tấn công đã xảy ra mà không có cảnh báo đúng loại |
| `... (báo động giả): 0` | Số cảnh báo `port_scan`/`dos` phát ra khi không có tấn công. Phải là 0 |
| `Cảnh báo bất thường chung ...` | Số lần module Gaussian thấy host "khác thường" trong lúc bị tấn công. Module này không nói loại tấn công nên không in từng dòng; nó xác nhận thêm rằng lúc đó có điều bất thường |

Số liệu mỗi lần chạy khác nhau đôi chút (số gói, giờ, độ trễ 1,5–3,5 giây) vì thời điểm tấn công là ngẫu nhiên.

**Tóm tắt để nói khi demo:**

| Tình trạng mạng | Màn hình | Tổng kết |
|---|---|---|
| Bình thường | Không có dòng nào | Báo động giả 0, bất thường 0 |
| Bị quét cổng | Khoảng 10 dòng `PORT_SCAN` trong 10 giây, cho `.20` và `.30` | `PHÁT HIỆN`, trễ khoảng 3 giây |
| Bị DoS | Dòng `DOS` liên tục trong 60 giây, cho `.20` và `.30` | `PHÁT HIỆN`, trễ khoảng 1,5 giây |
| Tấn công dừng | Các dòng dừng sau khoảng 10 giây | — |

### 3.3. Vì sao không demo botnet trực tiếp

Kịch bản botnet cần ít nhất 10 phút (bot gọi máy điều khiển mỗi 30–60 giây, module chấm trên cửa sổ 120
giây). Phần này trình bày bằng bảng của `4_ket_qua_da_luu.bat` và [76_khai_quat_lab.md](../docs/76_khai_quat_lab.md).

### 3.4. Kết quả demo nằm ở đâu

Mỗi lần demo ghi vào `output/demo/<kịch bản>-test-99/`: file `*.alerts.csv` (mọi cảnh báo) và
`nhat_ky_lan_chay.json` (giờ tấn công thật). Các lần demo **không** ghi vào `data/`, nên không lẫn với dữ liệu
dùng để đánh giá.

## 4. Câu hỏi có thể gặp

| Câu hỏi | Trả lời ngắn |
|---|---|
| Vì sao dùng lab ảo? | Nhóm chưa có 7 máy và switch có cổng mirror. Lab ảo dùng gói thật của nhân Linux, Nginx, Nmap; khác lab vật lý ở độ trễ đường truyền và hành vi của switch (QĐ-061) |
| 24/24 có phải học thuộc không? | Các lần `test` được thu sau khi học, chưa từng xem. Đổi vai trò máy và SYN flood (chưa từng học) vẫn bắt 6/6 và 9/9. Nhưng trên CTU-13 mô hình botnet của lab cho recall 0, nên chỉ khẳng định được trong lab |
| Vì sao mô hình cũ sót hết botnet? | Bot của CTU-13 là mã độc thật năm 2011; bot của lab là bot mô phỏng gọi định kỳ. Điểm cao nhất mô hình cũ cho bot lab là 0,084, dưới ngưỡng 0,1 |
| Độ trễ 3 giây từ đâu ra? | Cửa sổ 10 giây trượt mỗi 2 giây, cộng 1 giây chờ bắt tay TCP, cộng thời gian chấm |
| Tấn công trong demo có nguy hiểm không? | Không. Chỉ chạy giữa các network namespace trên máy này, không có đường ra ngoài; DoS tối đa 60 giây; không dùng mã độc hay exploit (yêu cầu B24) |
| Vì sao chỉ ba lớp? | Phạm vi đề tài là quét cổng, DoS và botnet. Brute-force, exploit chưa có dữ liệu |

## 5. Xử lý sự cố khi demo

| Hiện tượng | Cách xử lý |
|---|---|
| `0_kiem_tra.bat` báo `[LỖI] Dựng được lab ảo` | Mở PowerShell, chạy `wsl --shutdown`, đợi 10 giây, chạy lại file kiểm tra |
| Cửa sổ đứng lâu ở bước `[1/4]` | WSL đang khởi động, đợi tới 1 phút. Nếu quá, đóng cửa sổ và chạy `wsl --shutdown` như trên |
| Báo `Cảm biến không chạy được` | Chạy lại file `.bat`; nếu vẫn lỗi, dùng phương án dự phòng |
| Đóng cửa sổ giữa chừng | Không sao: lần demo sau tự dọn lab cũ trước khi dựng lại |
| Chữ tiếng Việt bị lỗi phông | Bấm chuột phải vào thanh tiêu đề cửa sổ, chọn Properties, đổi phông sang Consolas |

**Phương án dự phòng** nếu WSL không chạy được: bấm `4_ket_qua_da_luu.bat` (chỉ cần Python trên Windows), và
mở file `output/demo/k2-quet-nhanh-test-99/k2-quet-nhanh-test-99.alerts.csv` của lần chạy thử để cho xem cảnh
báo thật đã ghi.

## 6. Chạy bằng lệnh thay cho file `.bat`

```bash
# trong WSL, quyền root, tại thư mục dự án
bash scripts/demo_kiem_tra.sh
bash scripts/demo_lab.sh k2-quet-nhanh      # hoặc k3-dos-muc2, k1-binh-thuong
python3 scripts/demo_ket_qua.py
```

Tham số thứ hai của `demo_lab.sh` là tỉ lệ co thời gian chờ (mặc định 0.2). Đặt 1 để chạy đúng thời lượng của
lần chạy đánh giá (5–10 phút).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| File `.bat` | File lệnh của Windows; bấm đúp là chạy |
| WSL2 | Linux chạy ngay trong Windows; lab ảo và cảm biến chạy ở đây |
| Lab ảo, network namespace | Mạng thử nghiệm 7 máy dựng trong một máy Linux; mỗi "máy" là một ngăn mạng riêng của nhân Linux |
| Máy giám sát, mirror | Máy nhận bản sao mọi gói tin của lab để cảm biến phân tích |
| Cảm biến realtime | Chương trình bắt gói trực tiếp và phát cảnh báo ngay, không chờ ghi file |
| Flow, cửa sổ | Flow: các gói của cùng một kết nối. Cửa sổ: khoảng thời gian cố định để gom số liệu của một host |
| Nhật ký lần chạy | File ghi giờ bắt đầu và kết thúc thật của mỗi tấn công; căn cứ để chấm đúng sai |
| Đợt tấn công | Một lần tấn công có giờ bắt đầu và kết thúc; đơn vị đếm "phát hiện" và "bỏ sót" |
| Độ trễ phát hiện | Thời gian từ lúc tấn công bắt đầu tới lúc cảnh báo đúng loại đầu tiên được phát |
| Báo động giả | Cảnh báo không ứng với tấn công nào |
| Recall, macro-F1 | Tỷ lệ tấn công bắt được; điểm tổng hợp độ chính xác và độ phủ, lấy trung bình đều các lớp |
| Port scan, DoS, SYN flood | Dò cổng đang mở; làm máy chủ quá tải; gửi ồ ạt gói mở kết nối |
| Botnet tập trung / ngang hàng | Các bot cùng gọi một máy điều khiển / các bot gọi lẫn nhau |
| Topology | Cấu trúc liên lạc giữa các bot |
| Gaussian, Random Forest | Mô hình mô tả dữ liệu bình thường để tìm điểm lạ; mô hình phân loại gồm nhiều cây quyết định |
| Train / test | Lần chạy để mô hình học / lần chạy để đánh giá, mô hình chưa từng thấy |
| CIC-IDS2017, CTU-13 | Hai bộ dữ liệu công khai về tấn công mạng và botnet |
| Nmap, Nginx, hping3 | Công cụ quét cổng; máy chủ web; công cụ gửi gói TCP tùy chỉnh |
| Gọi định kỳ (beaconing) | Bot liên lạc với máy điều khiển theo chu kỳ đều, mỗi lần rất ít dữ liệu |
| Chế độ `ket_hop` / `doc_lap` | `ket_hop`: module botnet chỉ xét host bị module Gaussian báo. `doc_lap`: ba module chấm độc lập mọi host |
| Ngưỡng | Mức điểm mà từ đó trở lên mô hình phát cảnh báo |
| Bắt tay TCP | Ba gói đầu tiên để mở một kết nối TCP |
| B12 | Yêu cầu huấn luyện và realtime dùng cùng cách tính đặc trưng |
| Header | Phần đầu của gói tin, chứa địa chỉ, cổng và thông tin điều khiển |
| Precision, F1 | Precision: trong các cảnh báo, bao nhiêu phần là đúng. F1: điểm gộp precision và recall |
| Rò rỉ dữ liệu | Mô hình vô tình thấy dữ liệu đánh giá trong lúc học, làm điểm cao giả |
| systemd | Trình quản lý dịch vụ của Linux; cho chương trình chạy nền và tự khởi động lại |
| Đối chứng | Kịch bản không có tấn công, dùng để kiểm tra hệ thống có báo nhầm không |
| B24, QĐ-061 | Yêu cầu an toàn của dự án (traffic thử không ra ngoài lab); quyết định dùng lab ảo |
