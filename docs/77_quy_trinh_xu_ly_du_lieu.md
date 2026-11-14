# Quy trình xử lý dữ liệu: từ gói tin tới kết quả

Tài liệu mô tả một mạch toàn bộ đường đi của dữ liệu: dữ liệu thô là gì, tiền xử lý thế nào, chia tập bao
nhiêu phần trăm, mỗi thuật toán nhận gì và trả gì, và kết quả được đo ra sao. Mỗi bước có ghi file mã nguồn và
tài liệu chi tiết để tra thêm.

## 1. Sơ đồ tổng quát

```
 (1) Dữ liệu thô         (2) Đọc gói        (3) Ghép flow       (4) Đặc trưng theo cửa sổ
 PCAP / card mạng  ──>  header từng gói ──>  flow hai chiều ──>  bảng cửa sổ host 10 giây  ─┐
                                                   │                                        │
                                                   └──────────>  bảng host–cửa sổ 120 giây ─┤
                                                                 (đồ thị, gọi định kỳ)      │
                                                                                            v
 (8) Đánh giá   <──  (7) Cảnh báo   <──  (6) Ba mô hình   <──  (5) Gán nhãn, chia tập, tiền xử lý
 trên test           và sự kiện          học trên train         60 / 20 / 20
```

Bước 1 tới 4 và bước 6, 7 chạy **giống hệt nhau** lúc huấn luyện, lúc chạy offline trên file PCAP và lúc chạy
realtime trên card mạng (yêu cầu B12). Bước 5 và 8 chỉ có lúc huấn luyện và đánh giá.

## 2. Bước 1: dữ liệu thô

| Nguồn | Dạng | Dùng cho |
|---|---|---|
| CIC-IDS2017, thứ Hai, thứ Tư, thứ Sáu | File PCAP (gói tin gốc) và lịch tấn công | Module bất thường và module phân loại |
| CTU-13, 13 kịch bản | File flow hai chiều có nhãn (`.binetflow`) | Module botnet |
| Lab ảo 7 máy, 177 lần chạy | File PCAP và nhật ký lần chạy | Kiểm thử, học lại mô hình cho lab |

Lý do chọn từng nguồn: `demo/HUONG_DAN.md` mục 2.2.

## 3. Bước 2: đọc gói tin

Mã: `src/nids/pcap_reader.py`, `packets.py`. Tài liệu: docs/11–14.

- Đọc từng gói trong file PCAP hoặc PCAPNG, hoặc bắt trực tiếp từ card mạng.
- Bóc phần đầu Ethernet, IP, TCP, UDP. Giữ lại: thời điểm, IP nguồn, IP đích, cổng nguồn, cổng đích, giao
  thức, cờ TCP, kích thước gói.
- **Không đọc nội dung gói.** Hệ thống chỉ dùng thông tin điều khiển, nên vẫn chạy được khi traffic mã hóa.
- Gói không phải IP (ví dụ ARP) bị bỏ qua và được đếm.

Kiểm chứng: mọi trường của 4,57 triệu gói khớp với Wireshark (docs/17).

## 4. Bước 3: ghép gói thành flow

Mã: `src/nids/flows.py`, `flow_features.py`. Tài liệu: docs/18–21.

Các gói có cùng bộ năm (IP nguồn, IP đích, cổng nguồn, cổng đích, giao thức) thuộc về một flow hai chiều, tức
một cuộc kết nối. Một flow kết thúc khi:

| Điều kiện | Giá trị (`config/default.yaml`) |
|---|---|
| Có gói đóng kết nối (FIN cả hai chiều hoặc RST), chờ thêm gói cuối | 10 giây |
| Im lặng không có gói nào | 60 giây |
| Flow kéo dài quá lâu thì cắt, phần sau thành flow tiếp nối | 120 giây |
| Lần mở kết nối TCP không được trả lời thì coi là không hoàn tất sau | 3 giây (lab: 1 giây) |

Mỗi flow ghi: số gói và số byte mỗi chiều, thời lượng, các cờ TCP đã thấy, kết nối có hoàn tất không, lý do kết
thúc. Kết quả của ba ngày CIC: 1,44 triệu flow.

## 5. Bước 4: tính đặc trưng

Mô hình không nhìn từng flow mà nhìn **hành vi của từng máy trong một khoảng thời gian**.

### 5.1. Cửa sổ host 10 giây (module bất thường và phân loại)

Mã: `src/nids/host_windows.py`, `window_features.py`. Tài liệu: docs/22–24.

Với mỗi máy trong mạng giám sát, cứ **2 giây** một lần, gom các flow của **10 giây** gần nhất và tính 20 đặc
trưng:

| Nhóm | Đặc trưng | Ý nghĩa |
|---|---|---|
| Khối lượng | `packets_out`, `packets_in`, `bytes_out`, `bytes_in` | Số gói, số byte máy gửi đi và nhận về |
| Độ rộng | `dst_hosts`, `dst_ports`, `dst_host_ports`, `src_hosts` | Máy liên lạc với bao nhiêu máy, bao nhiêu cổng; bao nhiêu máy gọi tới nó |
| Tốc độ kết nối | `new_conn_out`, `new_conn_in` | Số kết nối mới máy mở ra và nhận vào |
| Phân bố cổng | `dst_port_entropy` | Kết nối dồn vào một cổng (thấp) hay rải nhiều cổng (cao) |
| Kết nối TCP chiều đi | `tcp_attempts_out`, `incomplete_out`, `no_reply_out`, `rejected_out`, `half_open_out`, `incomplete_ratio_out` | Số lần thử mở kết nối; bao nhiêu lần không hoàn tất, không được trả lời, bị từ chối, mở dở |
| Kết nối TCP chiều đến | `tcp_attempts_in`, `incomplete_in`, `incomplete_ratio_in` | Như trên nhưng cho kết nối tới máy này |

Kết quả của ba ngày CIC: 465 nghìn cửa sổ host.

### 5.2. Host–cửa sổ 120 giây (module botnet)

Mã: `src/nids/graph_features.py`. Tài liệu: docs/45–47.

Cứ **10 giây** một lần, nhìn lại **120 giây** và dựng đồ thị "máy nào nói chuyện với máy nào". Với mỗi máy tính:
số máy đối tác chiều đi và chiều đến, mức tập trung vào một đối tác, tỷ lệ đối tác mới, tỷ lệ UDP, tỷ lệ kết nối
không được trả lời, và **độ đều của nhịp gọi**: nhìn lại 600 giây, nếu một cặp máy liên lạc ít nhất 5 lần với
khoảng cách dao động không quá 30% thì đó là gọi định kỳ.

## 6. Bước 5: gán nhãn, chia tập, tiền xử lý

### 6.1. Gán nhãn

Mã: `src/nids/labeling.py`. Tài liệu: docs/26–28.

- Nguồn nhãn là **lịch tấn công** (CIC) hoặc **nhật ký lần chạy** (lab): giờ bắt đầu, giờ kết thúc, máy tấn
  công, máy nạn nhân, loại tấn công. Khung giờ của CIC được nới 60 giây mỗi đầu.
- Flow khớp cả giờ lẫn địa chỉ thì mang nhãn tấn công; còn lại là bình thường.
- Cửa sổ có dưới 20% flow là tấn công được coi là **mơ hồ** và bị loại khỏi huấn luyện lẫn đánh giá.
- CTU-13 có sẵn nhãn từng flow.

### 6.2. Chia tập: 60% train, 20% validation, 20% test

Mã: `src/nids/splits.py`. Tài liệu: docs/29.

| Tập | Tỷ lệ | Dùng để |
|---|---|---|
| Train | 60% | Mô hình học |
| Validation | 20% | Chọn tham số, chọn ngưỡng, chọn mô hình |
| Test | 20% | Đánh giá cuối, đọc sau khi đã chốt mọi thứ |

- **CIC-IDS2017:** chia theo **thời gian** trong từng đợt tấn công và từng khoảng bình thường. Phần đầu của mỗi
  đợt vào train, phần giữa vào validation, phần cuối vào test. Không trộn ngẫu nhiên, vì các cửa sổ liền nhau
  gần giống nhau; trộn sẽ để mô hình thấy gần như cùng một mẫu ở cả train lẫn test.
- **Khoảng đệm 10 giây:** bỏ các cửa sổ sát ranh giới hai tập, vì cửa sổ dài 10 giây nên hai cửa sổ kề nhau
  chứa chung dữ liệu.
- **CTU-13:** chia theo **kịch bản**: train 3, 5, 7, 10, 11, 12; validation 4, 13; test 1, 2, 6, 8, 9. Tập test
  có họ bot mà mô hình chưa thấy.
- **Lab:** chia theo **lần chạy**; mỗi biến thể có các lần `train`, `val`, `test` thu riêng.

Số cửa sổ của module phân loại (CIC thứ Tư và thứ Sáu):

| Tập | `benign` | `dos` | `port_scan` | Tổng |
|---|---|---|---|---|
| Train (gốc) | — | — | — | 166 269 |
| Train (sau khi bỏ mẫu trùng) | 83 346 | 2 165 | 478 | 85 989 |
| Validation | 53 949 | 648 | 164 | 54 761 |
| Test | 67 713 | 727 | 220 | 68 660 |

### 6.3. Tiền xử lý

Mã: `src/nids/preprocessing.py`, `gaussian.py`, `botnet.py`. Tài liệu: docs/32, 34.

Nguyên tắc chung: **mọi tham số tiền xử lý chỉ tính trên train**, rồi áp nguyên cho validation, test và
realtime. Các tham số này được lưu cùng mô hình trong file `.joblib`.

| Bước | Module phân loại | Module bất thường (Gaussian) | Module botnet |
|---|---|---|---|
| Chọn mẫu | Cửa sổ có nhãn chắc chắn thuộc ba lớp | Train chỉ lấy cửa sổ bình thường | Host–cửa sổ của bot và của máy bình thường |
| Bỏ mẫu trùng | Bỏ cửa sổ train trùng hệt cả đặc trưng lẫn nhãn: 166 269 còn 85 989 | — | — |
| Ô trống | Điền **trung vị** của train, thêm cột đánh dấu "ô này vốn trống" | Điền 0 | Điền 0 cho các cột đếm |
| Giảm lệch | **Logarit** `log(1 + x)` cho các cột đếm, byte; giữ nguyên cột tỷ lệ và entropy | **Yeo-Johnson** hoặc logarit, chọn theo từng đặc trưng | Logarit cho các cột đếm |
| Chuẩn hóa | Về trung bình 0, độ lệch chuẩn 1 | Về trung bình 0, độ lệch chuẩn 1 | Chỉ cho Logistic Regression |
| Cân bằng lớp | Đã thử giảm mẫu `benign` (tỷ lệ 10, 100) và trọng số lớp; validation chọn **không cân bằng** | Không áp dụng | Không dùng trọng số lớp |

Vì sao cần giảm lệch: số đếm trên mạng lệch rất mạnh, đa số cửa sổ có vài kết nối còn vài cửa sổ có hàng nghìn.
Logarit kéo các giá trị lớn lại gần. Với Gaussian việc này là bắt buộc, vì mô hình giả định dữ liệu có dạng
hình chuông. Với Random Forest thì không ảnh hưởng kết quả (cây chỉ so sánh lớn hơn hay nhỏ hơn), nhưng vẫn làm
để mọi mô hình dùng chung một bộ tiền xử lý và so sánh được với nhau (docs/78).

## 7. Bước 6: ba thuật toán

### 7.1. Gaussian đa biến: phát hiện bất thường

Mã: `src/nids/gaussian.py`. Tài liệu: docs/33–38.

- **Đầu vào:** 14 trong 20 đặc trưng của cửa sổ host.
- **Học:** chỉ từ 252 221 cửa sổ **bình thường** của train. Tính vector trung bình và ma trận hiệp phương sai
  (mức dao động của từng đặc trưng và quan hệ giữa chúng). Ma trận được ước lượng bằng phương pháp Ledoit-Wolf
  để luôn ổn định.
- **Chấm điểm:** với mỗi cửa sổ mới, tính **khoảng cách Mahalanobis bình phương** `d²` tới tâm của vùng bình
  thường. Khoảng cách này tính tới cả quan hệ giữa các đặc trưng.
- **Quyết định:** `d² > 64,65` thì báo `anomaly`. Ngưỡng 64,65 được chọn trên validation, tại điểm F1 cao và ổn
  định khi ngưỡng lệch ±20%.
- **Đầu ra:** "máy này khác thường", không nói loại tấn công.

### 7.2. Random Forest: phân loại tấn công

Mã: `src/nids/classifier.py`. Tài liệu: docs/39–44.

- **Đầu vào:** cả 20 đặc trưng của cửa sổ host.
- **Học:** từ 85 989 cửa sổ train có nhãn. Dựng 300 cây quyết định, sâu tối đa 20. Mỗi cây học trên một mẫu
  lấy ngẫu nhiên có lặp lại từ train, và tại mỗi nút chỉ xét một phần đặc trưng ngẫu nhiên. Nhờ vậy các cây
  khác nhau và sai sót của từng cây bù cho nhau.
- **Chọn tham số:** thử lưới tham số (độ sâu, số mẫu tối thiểu ở lá, số đặc trưng xét ở mỗi nút, cách cân bằng
  lớp), chọn bộ có macro-F1 cao nhất trên validation.
- **Chấm điểm:** mỗi cây bỏ phiếu cho một trong ba lớp. Xác suất của một lớp là tỷ lệ phiếu của lớp đó.
- **Quyết định:** lấy lớp có xác suất cao nhất. Con số `điểm` trên màn hình demo chính là xác suất này.
- **So sánh:** đã so với 8 mô hình baseline trên cùng dữ liệu, Random Forest đứng đầu (docs/78).

### 7.3. Random Forest và quy tắc: phát hiện botnet

Mã: `src/nids/botnet.py`. Tài liệu: docs/48–52.

- **Đầu vào:** đặc trưng đồ thị và gọi định kỳ của host–cửa sổ 120 giây.
- **Học:** từ 226 360 host–cửa sổ của 6 kịch bản train CTU-13 (216 785 bình thường, 9 575 bot). Random Forest
  300 cây, mỗi lá ít nhất 5 mẫu.
- **Quyết định:** điểm từ 0,1 trở lên thì báo `suspect_host`. Ngưỡng chọn trên validation.
- **Topology:** với host bị nghi, một bộ quy tắc xếp kiểu mạng bot: nhiều bot cùng gọi về một máy là tập trung
  (`centralized`), các host bị nghi gọi lẫn nhau là ngang hàng (`p2p`).

### 7.4. Ba module ghép với nhau

Mã: `src/nids/pipeline.py`. Tài liệu: docs/54–58.

| Chế độ | Cách chạy | Dùng ở đâu |
|---|---|---|
| `doc_lap` | Ba module chấm độc lập mọi host | Lab |
| `ket_hop` | Phân loại chấm mọi cửa sổ; botnet chỉ kiểm tra host bị Gaussian báo mà phân loại không giải thích được | Mặc định trên CIC |
| `tuan_tu` | Gaussian lọc trước, phân loại và botnet chỉ xét phần bị báo | Để so sánh |

## 8. Bước 7: cảnh báo và sự kiện

Mã: `src/nids/alerts.py`, `pipeline.py`. Tài liệu: docs/55, 58.

- Mỗi cửa sổ bị báo sinh một dòng cảnh báo theo một định dạng chung cho cả ba module: module, nhãn, khoảng thời
  gian, máy, điểm, ngưỡng.
- Tấn công kéo dài sinh nhiều cảnh báo liên tiếp. Các cảnh báo cùng module, cùng nhãn, cùng máy, cách nhau không
  quá 30 giây được gộp thành **một sự kiện**, để người vận hành thấy "một đợt tấn công" thay vì hàng chục dòng.

## 9. Bước 8: đánh giá

| Dữ liệu | Thước đo | Kết quả |
|---|---|---|
| Test CIC, module phân loại | Macro-F1 | 0,908 (validation 0,935) |
| Test CIC, module bất thường | F1 | 0,730; báo nhầm 1,42% cửa sổ |
| Test CTU-13, module botnet | Precision, recall theo host | 0,971 và 0,678 |
| Lab, lần `test` 9–11, mô hình học lại cho lab | Số đợt tấn công phát hiện, báo động giả | 24/24 đợt, 0 báo động giả |
| Lab | Độ trễ phát hiện | Quét và DoS 1,5–3,5 giây |

Trên lab, đáp án là nhật ký lần chạy do bộ chạy kịch bản ghi, độc lập với mô hình. Một đợt tấn công được tính
là phát hiện khi có cảnh báo đúng loại, đúng máy, trong đúng khoảng thời gian.

## 10. Một ví dụ đi hết quy trình

Máy `.20` chạy Nmap quét 1 024 cổng của máy `.30` trong lab:

1. **Gói:** `.20` gửi khoảng một nghìn gói SYN tới các cổng khác nhau của `.30`; phần lớn bị trả lời bằng RST.
2. **Flow:** mỗi cổng thành một flow rất ngắn, kết thúc vì bị từ chối.
3. **Đặc trưng:** cửa sổ 10 giây của `.20` có `dst_ports` khoảng 1 000, `rejected_out` rất cao,
   `incomplete_ratio_out` gần 1. Cửa sổ của `.30` có `tcp_attempts_in` rất cao.
4. **Tiền xử lý:** lấy logarit, chuẩn hóa bằng tham số của train.
5. **Mô hình:** Gaussian thấy `d²` vượt ngưỡng, báo `anomaly`. Random Forest có khoảng 95% số cây bỏ phiếu
   `port_scan`.
6. **Cảnh báo:** hai dòng `port_scan` cho `.20` và `.30`, lặp lại ở 5 cửa sổ liên tiếp, gộp thành một sự kiện.
7. **Đánh giá:** so với nhật ký lần chạy: đúng loại, đúng máy, trễ khoảng 2–3 giây.

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| PCAP | File lưu nguyên các gói tin đã bắt được trên mạng |
| Header | Phần đầu của gói tin, chứa địa chỉ, cổng và thông tin điều khiển |
| Flow | Một cuộc kết nối giữa hai máy, gom từ nhiều gói |
| Cờ TCP (SYN, FIN, RST) | Dấu hiệu trong gói TCP: xin mở kết nối, đóng kết nối, từ chối hoặc hủy kết nối |
| Cửa sổ | Một khoảng thời gian cố định (10 hoặc 120 giây) dùng để tóm tắt hành vi của một máy |
| Đặc trưng | Một con số mô tả hành vi, ví dụ số cổng đích khác nhau |
| Entropy | Thước đo độ phân tán: thấp là dồn vào một chỗ, cao là rải đều |
| Trung vị | Giá trị đứng giữa khi sắp các số theo thứ tự |
| Logarit, Yeo-Johnson | Hai phép biến đổi kéo giá trị lớn lại gần, làm dữ liệu bớt lệch |
| Chuẩn hóa | Đưa mỗi đặc trưng về trung bình 0, độ lệch chuẩn 1 |
| Hiệp phương sai | Thước đo hai đặc trưng tăng giảm cùng nhau tới mức nào |
| Khoảng cách Mahalanobis | Khoảng cách tới tâm dữ liệu, có tính tới mức dao động và quan hệ giữa các đặc trưng |
| Ngưỡng | Mức điểm mà từ đó trở lên mô hình phát cảnh báo |
| Train / validation / test | Tập để học / để chọn tham số / để đánh giá cuối |
| Macro-F1, precision, recall | Trung bình F1 các lớp; trong các cảnh báo bao nhiêu đúng; trong các tấn công bắt được bao nhiêu |
| Baseline | Mô hình mốc dùng để so sánh |
| Gọi định kỳ (beaconing) | Bot liên lạc với máy điều khiển theo chu kỳ đều |
| Topology | Cấu trúc liên lạc của mạng bot: tập trung hoặc ngang hàng |
| Sự kiện | Nhiều cảnh báo liên tiếp của cùng một đợt tấn công, gộp lại thành một |
| B12 | Yêu cầu huấn luyện và realtime dùng cùng cách tính đặc trưng |
