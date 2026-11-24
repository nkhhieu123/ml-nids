# Báo cáo Chặng 12 — Báo cáo và bàn giao

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 14/11/2026 – 25/11/2026 |
| Trạng thái | **Xong 7/7 task.** Mọi yêu cầu bắt buộc có sản phẩm và bằng chứng; 22/25 yêu cầu Xong, 3 Một phần vì chưa có máy Kali và lab vật lý (`86`) |
| Chặng trước | [Bao_cao_Chang_11.md](Bao_cao_Chang_11.md) |

## 1. Tóm tắt

Chặng 12 hoàn thiện bằng chứng, hướng dẫn và sản phẩm bàn giao. Ngoài bảy task của kế hoạch, chặng này bổ sung
những phần đề cương bốn giai đoạn yêu cầu mà trước đó còn thiếu hoặc chưa đo, và kiểm lại toàn bộ dự án từ một bản
clone mới.

| Task | Sản phẩm | Tài liệu |
|---|---|---|
| C12-T01 Notebook cho ba hướng tiếp cận | `notebooks/05_eda`, `06_gaussian`, `07_phan_loai`, `08_botnet`, đã chạy sẵn kết quả; sinh lại bằng `scripts/tao_notebook.py` | README |
| C12-T02 Bảng kết quả offline và realtime riêng | Bảng offline (CIC, CTU-13, lab) và realtime (nhất quán, độ trễ thật, tài nguyên) | [85_bang_ket_qua.md](85_bang_ket_qua.md) mục 1–3 |
| C12-T03 Kiến trúc, triển khai, tái lập | Sơ đồ, bảng mô-đun, cấu hình, cài đặt, triển khai Kali, 11 bước tái lập | [84_kien_truc_trien_khai.md](84_kien_truc_trien_khai.md) |
| C12-T04 Báo động giả, bỏ sót, giới hạn | 6 nguồn báo nhầm và 7 trường hợp bỏ sót: nguyên nhân, cách đã sửa, còn lại gì | [85_bang_ket_qua.md](85_bang_ket_qua.md) mục 4–6 |
| C12-T05 Yêu cầu → mã nguồn → bằng chứng | Bảng B01–B25 | [86_yeu_cau_bang_chung.md](86_yeu_cau_bang_chung.md) |
| C12-T06 Clone và chạy từ môi trường mới | Clone mới, môi trường Python mới (pandas 3.1, scikit-learn 1.9): 461 kiểm thử đạt sau khi sửa 2 lỗi | [84](84_kien_truc_trien_khai.md) mục 2 |
| C12-T07 Kịch bản bảo vệ, bản phát lại PCAP | Kịch bản 20 phút, ba đường dự phòng; `5_phat_lai_ban_thu.bat` phát lại bản thu lab qua cảm biến realtime trên Windows | [demo/KICH_BAN_BAO_VE.md](../demo/KICH_BAN_BAO_VE.md) |

Ánh xạ từng dòng của bốn giai đoạn trong đề cương tới mã nguồn, tài liệu và kết quả:
[83_bon_giai_doan.md](83_bon_giai_doan.md).

## 2. Bổ sung theo đề cương bốn giai đoạn

| Giai đoạn | Còn thiếu trước Chặng 12 | Đã bổ sung | Kết quả | Tài liệu |
|---|---|---|---|---|
| 1 | Chọn Scapy/PyShark/dpkt chỉ bằng lập luận | Đo cả bốn trên cùng 20 000 gói | Cùng kết quả; tự viết ≈ 110 000 gói/s, dpkt 62 000, Scapy 4 400, PyShark 320 | `11` mục 6, QĐ-088 |
| 2 | EDA chỉ cho CIC | EDA ba bộ dữ liệu, chất lượng, độ lệch, AUC một biến, lệch CIC–lab | 46% cửa sổ train trùng; không đặc trưng nào một mình đủ | `81` |
| 2 | Giá trị vô hạn chưa xử lý tường minh | Coi ±∞ như ô trống | Dữ liệu CIC có 0 giá trị vô hạn; kết quả không đổi | `32`, QĐ-089 |
| 2, 3 | So sánh chỉ RF với LR | 8 baseline, LightGBM, MLP, GRU | GRU 0,940–0,950 > RF 0,908 | `78`, `82` |
| 3, 4 | Lab 3 bot; SYN phía nạn nhân yếu; bot đổi vai bị sót | 2 máy bot mới, kịch bản 5 bot, DoS HTTP chậm; bộ mô hình lab lần ba | 5 bot 15/15 mỗi kiểu; SYN nạn nhân 0,10 → 0,97 | `80` |
| 4 | DDoS chưa thử nhiều nguồn | DDoS năm nguồn | 3/3, recall cửa sổ 1,0 | `80` mục 4.4 |
| 4 | Dashboard (tùy chọn) | Trang HTML tĩnh | | `84` mục 5, QĐ-090 |
| 4 | ARP, đường hầm, gói trùng | Phát hiện giả mạo ARP (cả realtime), bóc đường hầm, khử gói trùng (tùy chọn) | 0 báo nhầm ARP trên 174 bản thu | `79`, `17`, `60` |

## 3. Số liệu cuối cùng

| Module / kiểm thử | Kết quả | Tài liệu |
|---|---|---|
| Gaussian, test CIC | F1 0,730; báo nhầm 1,42% cửa sổ | `37` |
| Random Forest, test CIC | Macro-F1 0,908 | `43` |
| GRU học sâu, test CIC | Macro-F1 0,940 ± 0,007 | `82` |
| Botnet RF, test CTU-13 | F1 0,798 (P 0,971, R 0,678) | `52` |
| Lab ảo, 66 lần chạy test mới | 51/51 đợt, 0 sự kiện báo động giả | `80`, `85` |
| Realtime thật trên lab | Độ trễ quét/DoS 3,9–4,2 s; 0 gói bỏ | `74` |
| Nhất quán realtime – offline | Cùng nhãn ở mọi cửa sổ trên 15 467 cửa sổ | `66` |

## 4. Lỗi tìm ra trong chặng này

| Lỗi | Phát hiện nhờ | Đã sửa |
|---|---|---|
| Đổi thời gian CTU-13 sai 1 000 lần trên pandas 3 | Clone và chạy trên môi trường mới | Đổi bằng phép trừ mốc thời gian, không phụ thuộc độ phân giải |
| Thiếu `matplotlib` trong thư viện bắt buộc | Như trên | Thêm vào `pyproject.toml`; tách thư viện tùy chọn |
| Cảm biến dừng khi chạy `--im-lang` trên Windows (bảng mã cp1252) | Nối ARP vào realtime | Mở luồng bỏ đi bằng UTF-8 |
| `docs/81` viết sai chiều của đặc trưng gọi định kỳ trên CTU-13 | Notebook botnet | Sửa: trong CTU-13 máy bình thường gọi đều, bot thật thì không |
| Bản thu thí nghiệm trễ 200 ms bị ghi đè (trùng số lần chạy) | Rà `git status` | Khôi phục nhật ký từ git; `lab_ao.py` từ chối ghi đè nếu không có `--ghi-de` |

## 5. Còn lại

- Chạy trên máy Kali thật và lab vật lý 7 máy có switch mirror (B01, B13).
- Lớp brute-force, exploit (cần CIC thứ Ba, thứ Năm; lab không được chạy exploit).
- GRU chưa nối vào cảm biến realtime; hệ thống đang chạy dùng Random Forest.
- Không tích hợp firewall chặn IP (tùy chọn, chưa đánh giá rủi ro chặn nhầm).

Danh sách đầy đủ: [Viec_con_thieu.md](Viec_con_thieu.md).

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| Bàn giao | Giao lại mã nguồn, tài liệu, mô hình và hướng dẫn để người khác dùng tiếp |
| Notebook | File Jupyter gồm mã và kết quả chạy xen kẽ |
| Tái lập | Làm lại từ đầu và ra cùng kết quả |
| Clone | Tải toàn bộ kho mã về một thư mục mới |
| Phát lại bản thu | Đưa file gói tin đã lưu vào cảm biến như đang bắt trực tiếp |
| Dashboard | Trang tóm tắt cảnh báo bằng bảng và hình |
| GRU | Mạng nơ-ron hồi quy đọc chuỗi cửa sổ liên tiếp |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp tính ngang nhau |
