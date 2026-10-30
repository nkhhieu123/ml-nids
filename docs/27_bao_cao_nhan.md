# C05-T02 — Báo cáo mẫu khớp, không khớp và mơ hồ

Mã nguồn: `src/nids/label_report.py`. Kiểm thử: `tests/test_label_report.py`. Nhãn theo
[26_gan_nhan.md](26_gan_nhan.md) (flow) và [28_nhan_cua_so.md](28_nhan_cua_so.md) (cửa sổ).

```bash
python -m nids.label_report output/features/cic17_friday.flows.csv \
    --cic-csv data/cic-ids2017/TrafficLabelling/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

Báo cáo gồm ba phần:
1. Số flow và số gói theo trạng thái nhãn và theo đợt tấn công.
2. Các nhóm flow mơ hồ, gom theo cặp IP và giờ, kèm lý do.
3. **Đối chiếu với CSV có nhãn của CIC**: một nguồn nhãn độc lập (do CICFlowMeter tạo).

Kết quả ghi ra `<tên>.flows.label_report.json`.

## 1. Cách đối chiếu với CSV của CIC

Mỗi dòng CSV là một flow của CICFlowMeter: IP và cổng hai đầu, giao thức, thời điểm (chỉ
tới phút), nhãn. Ghép với flow của dự án khi:
- cùng giao thức và cùng hai đầu (IP, cổng), theo chiều bất kỳ;
- khoảng thời gian của flow dự án chạm phút của dòng CSV, nới 2 phút mỗi đầu.

Cột `Timestamp` của CSV là giờ địa phương kiểu 12 giờ, mất SA/CH (docs/06 mục 7.5), nên
giờ 1–7 được cộng 12 rồi đổi sang UTC (+3 giờ). Nhãn CSV đổi sang nhãn đồ án: `DoS *` →
`dos`, `PortScan` → `port_scan`, `DDoS`, `Heartbleed`, `Bot` → `loai`, `BENIGN` → `benign`.
Một dòng CSV có thể ứng với nhiều flow của dự án (hai bên cắt flow khác nhau); khi đó lấy
nhãn chiếm đa số.

## 2. Kết quả

### 2.1. Theo trạng thái

| Phiên | Flow | `khong_khop` (benign) | `khop` (tấn công) | `loai` | `mo_ho` |
|---|---|---|---|---|---|
| Thứ Hai | 381 707 | 381 707 | 0 | 0 | 0 |
| Thứ Tư | 506 163 | 325 096 | 180 768 (`dos`) | 11 (Heartbleed) | 288 |
| Thứ Sáu | 555 024 | 293 215 | 161 268 (`port_scan`) | 100 529 (DDoS 95 726, bot 4 803) | 12 |

Theo số gói: thứ Tư, flow `dos` có 2 439 842 gói; thứ Sáu, flow `port_scan` có 324 062 gói
(quét: trung bình 2 gói một flow).

### 2.2. Mẫu mơ hồ

Mọi flow mơ hồ đều là traffic giữa `172.16.0.1` và nạn nhân, nằm **ngay ngoài khung giờ**
của lịch:

| Phiên | Nhóm lớn nhất | Giải thích |
|---|---|---|
| Thứ Tư | 150 flow lúc 11:06–11:07 (giờ địa phương), 127 flow lúc 10:37 | Đuôi của Hulk (lịch ghi tới 11:00, CSV ghi tới 11:07) và khoảng giữa Slowhttptest với Hulk |
| Thứ Sáu | 6 flow lúc 11:47–11:54, 5 flow rải rác buổi chiều | Thử kết nối trước lượt quét đầu và sau DDoS |

Tổng cộng 300 / 1 442 894 flow của ba ngày (0,02%). Chúng bị bỏ khỏi huấn luyện và đánh giá.

### 2.3. Đối chiếu với CSV của CIC

| File CSV | Flow CSV ghép được | Không ghép được | Đồng ý |
|---|---|---|---|
| Thứ Hai (`Monday-WorkingHours`) | 529 442 | 476 | **100%** |
| Thứ Tư (`Wednesday-workingHours`) | 692 293 | 410 (benign) | **98,98%** |
| Thứ Sáu sáng (bot) | 190 872 | 161 | **99,99%** |
| Thứ Sáu chiều, PortScan | 286 366 | 101 | **99,44%** |
| Thứ Sáu chiều, DDoS | 225 523 | 222 | 85,95% |

Bảng chéo (hàng: nhãn CSV, cột: nhãn dự án), chỉ các ô khác đường chéo:

| File | CSV `benign` → dự án tấn công | CSV tấn công → dự án khác |
|---|---|---|
| Thứ Tư | 6 782 → `dos`; 18 → `mo_ho`; 1 → `loai` | 278 `dos` → `mo_ho` |
| Thứ Sáu sáng | 14 → `mo_ho` | 4 `Bot` → `benign` |
| Thứ Sáu PortScan | 958 → `port_scan`; 623 → `loai` | 8 `PortScan` → `mo_ho` |
| Thứ Sáu DDoS | 31 690 → `loai` | 0 |

**Giải thích các chỗ lệch:**
- **CSV ghi `BENIGN` cho flow giữa bên tấn công và nạn nhân trong khung tấn công**
  (6 782 ở thứ Tư, 958 ở PortScan, 31 690 ở DDoS). Đây là lỗi đã biết của CICFlowMeter:
  khi kết thúc flow ở gói FIN đầu tiên, các gói còn lại của cùng kết nối thành flow mới
  và bị gán `BENIGN` (Engelen và cộng sự, 2021). Dự án gán theo lịch và cặp IP nên các
  flow này là tấn công, và dự án ghép flow theo cách khác (QĐ-017).
- **278 flow CSV `DoS` thành `mo_ho`**: CSV kéo Hulk tới 11:07, còn lịch dừng ở 11:00 (mục
  2.2). Dự án không mở rộng lịch theo CSV.
- **623 flow CSV `BENIGN` thành `loai` ở chiều thứ Sáu**: là luồng gọi về của bot ARES
  vào buổi chiều. CSV chỉ gán `Bot` buổi sáng, nhưng bot vẫn gọi về tới khoảng 13:00 (docs/26).
- **Flow CSV không ghép được** (vài trăm mỗi file, hầu hết `BENIGN`): CICFlowMeter tạo
  flow từ gói mà bộ đọc của dự án bỏ qua hoặc ghép khác (ví dụ dòng CSV có giao thức 0).

CSV có nhiều flow hơn dự án (thứ Hai: 529 442 dòng so với 381 707 flow) vì CICFlowMeter
cắt flow ngay ở FIN và không gom gói trễ (QĐ-017), nên một kết nối của dự án có thể ứng
nhiều dòng CSV.

**Kết luận.** Hai nguồn nhãn độc lập đồng ý 99–100% ở mọi file dùng cho phân loại. Chỗ
lệch còn lại có nguyên nhân rõ, phần lớn do lỗi đã biết của CSV gốc. Vì vậy nhãn của dự
án (theo lịch) được dùng; CSV chỉ để đối chiếu, đúng như QĐ-009.

### 2.4. Cửa sổ host

| Phiên | Cửa sổ | `khong_khop` | `khop` | `loai` | `mo_ho` |
|---|---|---|---|---|---|
| Thứ Hai | 152 513 | 152 513 | 0 | 0 | 0 |
| Thứ Tư | 163 431 | 157 995 | 3 978 (`dos`) | 1 238 | 220 |
| Thứ Sáu | 149 449 | 134 990 | 1 259 (`port_scan`) | 13 067 | 133 |

Ở thứ Sáu, 13 067 cửa sổ `loai` là cửa sổ của 5 máy bot (luồng gọi về kéo dài) và của
`172.16.0.1`, `.50` trong 20 phút DDoS.

## 3. Kiểm thử

Kiểm thử tự động (`tests/test_label_report.py`): đọc thời điểm CSV kiểu 12 giờ (sáng,
chiều, đổi sang UTC); khóa 5-tuple không phụ thuộc chiều; đối chiếu ghép đúng, chọn nhãn
đa số khi một dòng CSV ứng nhiều flow, đếm dòng không ghép được; báo cáo trạng thái và
nhóm mơ hồ từ file thật nhỏ.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Khớp / không khớp / mơ hồ | Mẫu khớp một đợt tấn công / không khớp đợt nào (bình thường) / không đủ căn cứ để gán |
| Đối chiếu | So nhãn của dự án với một nguồn nhãn khác để tìm sai sót |
| Bảng chéo | Bảng đếm mỗi nhãn của nguồn này ứng với nhãn nào của nguồn kia |
| Tỷ lệ đồng ý | Phần mẫu hai nguồn gán cùng nhãn |
| CICFlowMeter | Công cụ tạo CSV flow có nhãn của CIC-IDS2017 |
| Gói FIN | Gói báo đóng kết nối TCP |
| Nhãn đa số | Nhãn xuất hiện nhiều nhất trong một nhóm |
| 12 giờ không SA/CH | Cách ghi giờ chỉ từ 1 đến 12, không cho biết sáng hay chiều |
