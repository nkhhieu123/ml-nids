# Hướng dẫn báo cáo tiến độ và demo

Tài liệu dùng cho buổi báo cáo: nói gì, theo thứ tự nào, và bấm file nào để demo. Mọi con số lấy từ
[Bao_cao_Chang_11.md](Bao_cao_Chang_11.md), [76_khai_quat_lab.md](76_khai_quat_lab.md) và
[72_do_nhay_tham_so.md](72_do_nhay_tham_so.md). Các file demo đã được chạy thử ngày 13/11/2026 trên máy này.

Tổng thời gian đề xuất: **15 phút** (10 phút báo cáo, 5 phút demo).

## 1. Chuẩn bị trước buổi báo cáo (10 phút)

1. Cắm sạc, tắt các chương trình nặng. Demo chạy trong WSL2 nên máy cần rảnh CPU.
2. Mở thư mục `demo` của dự án, bấm đúp **`0_kiem_tra.bat`**. Cả 8 dòng phải ghi `[ĐẠT]` và dòng cuối là
   `Sẵn sàng demo.` Nếu có `[LỖI]`, xem mục 5.
3. Bấm đúp **`1_demo_quet_cong.bat`** một lần để chạy thử (khoảng 3 phút). Lần chạy đầu sau khi bật máy chậm
   hơn vì WSL phải khởi động.
4. Mở sẵn hai file để chiếu: `docs/Bao_cao_Chang_11.md` và hình `docs/hinh/thuc_nghiem/lab/lab_do_tre.png`.

Không cần mạng Internet. Lab ảo không có đường ra ngoài.

## 2. Nội dung báo cáo (10 phút)

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

### 2.2. Dữ liệu (1 phút)

- **CIC-IDS2017** (thứ Hai, thứ Tư, thứ Sáu): học và đánh giá quét cổng, DoS.
- **CTU-13** (13 kịch bản): học và đánh giá botnet.
- **Lab ảo 7 máy** tự dựng trên WSL2: 177 lần chạy, mỗi lần có nhật ký ghi giờ tấn công thật để làm nhãn chuẩn.
  Traffic tấn công chỉ chạy trong mạng cô lập `192.168.50.0/24`, DoS giới hạn 60 giây.

### 2.3. Những gì đã làm được (2 phút)

- Chặng 1–10: bộ đọc gói tự viết (khớp Wireshark), trích xuất flow và đặc trưng, gán nhãn, chia tập, huấn luyện
  ba module, pipeline offline, cảm biến realtime, đóng gói dịch vụ. 444 kiểm thử tự động đều đạt.
- Chặng 11: dựng lab ảo, chạy 5 nhóm kịch bản (bình thường, quét cổng, DoS, botnet tập trung, botnet ngang
  hàng), đo tỷ lệ phát hiện, độ trễ, báo động giả, hiệu năng.

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

### 2.5. Hạn chế (1,5 phút) — nói thẳng

- Mới đo trên **lab ảo**; chưa có lab vật lý 7 máy và chưa cài trên Kali Linux.
- Mô hình botnet của lab cho **recall 0 trên CTU-13**: kết quả 24/24 chỉ có nghĩa trong lab với bot mô phỏng.
- DoS HTTP chậm còn sót (recall Slowhttptest 0,66 trên CIC). Lớp giữ nhãn `dos` theo host nâng lên 0,82 nhưng
  chưa bật trong hệ thống.
- Module Gaussian trên CIC báo động giả khoảng 17 đợt mỗi giờ, không dùng một mình được.
- Chưa có dữ liệu brute-force và exploit.

### 2.6. Việc tiếp theo (0,5 phút)

Theo [Viec_con_thieu.md](Viec_con_thieu.md) mục 4: dựng lab vật lý và cài trên Kali; nối lớp giữ nhãn `dos` vào
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

### 3.2. Vì sao không demo botnet trực tiếp

Kịch bản botnet cần ít nhất 10 phút (bot gọi máy điều khiển mỗi 30–60 giây, module chấm trên cửa sổ 120
giây). Phần này trình bày bằng bảng của `4_ket_qua_da_luu.bat` và [76_khai_quat_lab.md](76_khai_quat_lab.md).

### 3.3. Kết quả demo nằm ở đâu

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
| B24, QĐ-061 | Yêu cầu an toàn của dự án (traffic thử không ra ngoài lab); quyết định dùng lab ảo |
