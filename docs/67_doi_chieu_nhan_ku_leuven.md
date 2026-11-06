# Đối chiếu nhãn Chặng 5 với bộ nhãn đã sửa của KU Leuven

Mã nguồn: `src/nids/label_report.py` (`compare_with_ku_leuven`, tùy chọn `--ku-csv`). Kiểm thử:
`tests/test_label_report.py`. Kết quả: `docs/hinh/ku_leuven.json`. Việc này nằm trong danh sách việc còn thiếu
(`docs/Viec_con_thieu.md` mục 2, việc 4).

```bash
cd src
python -m nids.label_report ../output/features/cic17_wednesday.flows.csv \
    --ku-csv ../data/cic-ids2017/ku_leuven/wednesday.csv --out ../output/ku_leuven/wednesday.json
```

## 1. Dữ liệu

| Mục | Giá trị |
|---|---|
| Nguồn | https://intrusion-detection.distrinet-research.be/CNS2022/ (Engelen 2021, Liu 2022) |
| File | `CICIDS2017_improved.zip`, 344 MB, 5 CSV theo ngày; manifest `cic17-ku-leuven` kèm SHA-256 |
| Dùng | `monday.csv`, `wednesday.csv`, `friday.csv`: ba ngày dự án dùng |
| Khác CSV gốc của CIC | Sửa lỗi CICFlowMeter (kết thúc flow ở FIN đầu, mất SA/CH); `Timestamp` UTC tới micro giây; nhãn mới `<tấn công> - Attempted` cho flow của bên tấn công không chở nội dung tấn công |

## 2. Cách ghép

Như đối chiếu với CSV gốc (docs/27): cùng giao thức, cùng hai đầu (IP, cổng) theo chiều bất kỳ. Thời điểm KU
là gói đầu của flow, chính xác tới micro giây. Vì vậy chỉ nới 2 giây quanh khoảng `[first_ts, last_ts]` của flow
dự án, thay vì nới 2 phút. Nếu một dòng KU ứng với nhiều flow của dự án thì lấy nhãn chiếm đa số.

Nhãn KU đổi sang nhãn đồ án:
- `DoS *` → `dos`;
- `Portscan` → `port_scan`;
- `DDoS`, `Botnet`, `Heartbleed` → `loai`;
- `BENIGN` → `benign`;
- `* - Attempted` → `attempted`.

## 3. Kết quả

| Ngày | Dòng KU ghép được | Không ghép được | Đồng ý | Đồng ý khi bỏ `attempted` |
|---|---|---|---|---|
| Thứ Hai | 371 227 | 397 (0,11%) | **100%** | 100% |
| Thứ Tư | 496 299 | 342 (0,07%) | 98,80% | **99,98%** |
| Thứ Sáu | 547 087 | 470 (0,09%) | 99,04% | **99,78%** |

Bảng chéo, chỉ các ô lệch (hàng: nhãn KU, cột: nhãn dự án):

| Ngày | KU `benign` → dự án khác | KU tấn công → dự án khác | KU `attempted` |
|---|---|---|---|
| Thứ Tư | 79 → `dos`; 11 → `mo_ho` | **0** (171 634 `dos` → `dos`, 11 Heartbleed → `loai`) | 5 599 → `dos`; 277 → `mo_ho` |
| Thứ Sáu | 635 → `port_scan`; 539 → `loai`; 12 → `mo_ho` | **0** (159 040 `port_scan`, 95 880 DDoS/bot → `loai`) | 4 067 (bot) → `loai` |

**Mọi flow KU gán tấn công đều được dự án gán cùng loại.** Các chỗ lệch có nguyên nhân rõ:

1. **`attempted` → `dos`** (5 599 ở thứ Tư). Đây là flow của bên tấn công tới nạn nhân trong khung tấn công,
   nhưng không chở nội dung tấn công: bắt tay hỏng, kết nối bị từ chối khi máy chủ đã quá tải
   (`Attempted Category` 0), Slowhttptest bị đóng sớm (category 6, 2 804 flow). Dự án gán theo lịch và cặp IP
   (QĐ-009), nên các flow này là `dos`. Xem mục 4.
2. **KU `benign` → dự án tấn công** (79 ở thứ Tư, 1 174 ở thứ Sáu). Tất cả đều có chiều **nạn nhân → bên tấn
   công** (`192.168.10.50 → 172.16.0.1`), trong giờ quét (17–18 giờ UTC) hoặc giờ DDoS (18:56–19:16 UTC). Bản
   CICFlowMeter đã sửa vẫn tách phần trả lời đến sau khi flow đã hết hạn thành flow mới, bắt đầu từ nạn nhân,
   và gán lành tính. Dự án ghép hai chiều thành một flow, nên vẫn là tấn công.
3. **`mo_ho`** (288 ở thứ Tư, 12 ở thứ Sáu): flow ngay ngoài khung giờ của lịch (docs/27 mục 2.2). KU gán 277
   trong số đó là `attempted`, nghĩa là chúng cũng không chở nội dung tấn công.
4. **Dòng KU không ghép được** (dưới 0,11%): gần hết là `benign`. 26 dòng `Portscan` ở thứ Sáu là flow chỉ có
   một gói mà bộ trích xuất của dự án gộp vào flow khác cùng 5-tuple.

So với CSV gốc (docs/27 mục 2.3), lỗi đã biết của CSV gốc biến mất:
- DDoS thứ Sáu: 31 690 flow CSV gốc gán `BENIGN`, nay KU gán `DDoS`, khớp dự án.
- Đồng ý khi bỏ `attempted`: thứ Tư 98,98% → 99,98%; thứ Sáu chiều 85,95–99,44% → 99,78%.

## 4. Ảnh hưởng tới dự án

- **Nhãn theo lịch của Chặng 5 đứng vững** khi so với nguồn nhãn tốt nhất hiện có: không flow tấn công nào của
  KU bị dự án gán lành tính; mọi lệch là do cách cắt flow hoặc do quy ước `attempted`.
- **Quy ước `attempted`**: KU coi các flow này là lành tính khi huấn luyện mô hình theo flow. Dự án phát hiện
  theo **cửa sổ host 10 giây**: một cửa sổ của bên tấn công trong khung DoS luôn có cả flow tấn công lẫn flow
  `attempted`, nên đổi nhãn flow không đổi nhãn cửa sổ. Giữ nhãn hiện tại (QĐ-057). 5 876 flow `attempted`
  của thứ Tư chiếm 1,2% số flow và 3,3% số flow `dos`.
- Chưa dùng KU để đánh giá riêng mô hình. Nếu sau này huấn luyện theo flow, cần xét lại quy ước này.

## 5. Kiểm thử

- `ku_label`: nhãn `- Attempted`, `Portscan`, `Botnet`, `BENIGN`.
- `parse_ku_timestamp`: đọc UTC có micro giây.
- `compare_with_ku_leuven`:
  - ghép không phụ thuộc chiều;
  - lệch quá 2 giây thì không ghép;
  - bảng chéo có `attempted`;
  - tính hai tỷ lệ đồng ý.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| KU Leuven | Nhóm nghiên cứu ở Bỉ đã sửa lỗi nhãn và lỗi tạo flow của CIC-IDS2017 |
| Attempted | Flow do bên tấn công gửi trong lúc tấn công nhưng không chở nội dung tấn công |
| Đối chiếu nhãn | So nhãn của dự án với một nguồn nhãn khác để tìm sai sót |
| Bảng chéo | Bảng đếm mỗi nhãn của nguồn này ứng với nhãn nào của nguồn kia |
| 5-tuple | Giao thức cùng IP và cổng của hai đầu kết nối |
| Gán theo lịch | Gán nhãn tấn công cho traffic giữa bên tấn công và nạn nhân trong khung giờ đã công bố |
