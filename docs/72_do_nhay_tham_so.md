# Độ nhạy của các tham số tạm thời, đo trên validation

Tài liệu này đóng các mục "tham số tạm thời, chỉnh trên validation" của `docs/Viec_con_thieu.md` mục 4b. Mỗi
tham số được đổi **từng cái một** quanh giá trị hiện tại, giữ nguyên mọi thứ khác, và chỉ đo trên
**validation**; không đọc test.

## 1. Tham số gán nhãn (QĐ-025, QĐ-026, QĐ-028)

Mã nguồn: `src/nids/do_nhay_nhan.py`. Số liệu: `docs/hinh/nhan_do_nhay.json`.

```bash
cd src
python -m nids.do_nhay_nhan ../output/features/cic17_wednesday ../output/features/cic17_friday \
    --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
```

Ba tham số được ghi là tạm thời:

| Tham số | Giá trị | Ý nghĩa |
|---|---|---|
| `labeling.tolerance_s` | 60 | Nới khung giờ tấn công mỗi đầu khi gán nhãn flow |
| `labeling.window_min_attack_share` | 0,2 | Cửa sổ có phần flow tấn công dưới mức này là mơ hồ, bị bỏ |
| `preprocess.balance_max_ratio` | 10 | Giảm mẫu mỗi lớp của train xuống tối đa 10 lần lớp ít nhất |

**Tỷ lệ cân bằng đã được chọn trên validation từ Chặng 7** (QĐ-035): thử 10, 100 và không giảm mẫu; Random
Forest tốt nhất khi **không giảm mẫu** (macro-F1 validation 0,9352). Giá trị 10 trong cấu hình chỉ còn là mặc
định của bước tiền xử lý chung, bộ phân loại không dùng. Không cần làm thêm.

Hai tham số còn lại được thử như sau: gán nhãn lại trong bộ nhớ (không ghi đè file nhãn), giữ nguyên cách chia
tập và tham số Random Forest đã chọn, fit lại trên train, đo trên validation. Đổi tham số gán nhãn cũng đổi
nhãn của validation, nên mỗi cấu hình đo hai cách: **riêng** (validation gán nhãn theo chính cấu hình đó) và
**chuẩn** (validation gán nhãn theo cấu hình hiện tại, cố định cho mọi cấu hình, nên so được với nhau).

| Nới lịch | Ngưỡng cửa sổ | Train dos / port_scan | Validation dos / port_scan | Macro-F1 riêng | Macro-F1 chuẩn | Recall port_scan (chuẩn) | Recall dos (chuẩn) |
|---|---|---|---|---|---|---|---|
| 0 s | 0,2 | 2 165 / 478 | 648 / 164 | 0,9352 | 0,9352 | 0,7744 | 0,9136 |
| 30 s | 0,2 | 2 165 / 478 | 648 / 164 | 0,9352 | 0,9352 | 0,7744 | 0,9136 |
| **60 s** | **0,2** | 2 165 / 478 | 648 / 164 | **0,9352** | **0,9352** | 0,7744 | 0,9136 |
| 120 s | 0,2 | 2 172 / 478 | 648 / 164 | 0,9360 | 0,9360 | 0,7744 | 0,9167 |
| 300 s | 0,2 | 2 209 / 478 | 648 / 164 | 0,9346 | 0,9346 | 0,7744 | 0,9198 |
| 60 s | 0,05 | 2 173 / 485 | 648 / 164 | 0,9341 | 0,9341 | 0,7683 | 0,9151 |
| 60 s | 0,1 | 2 171 / 485 | 648 / 164 | 0,9351 | 0,9351 | 0,7744 | 0,9198 |
| 60 s | 0,3 | 2 134 / 467 | 648 / 161 | 0,9395 | 0,9360 | 0,7805 | 0,9151 |
| 60 s | 0,5 | 2 113 / 435 | 643 / 154 | 0,9473 | 0,9365 | 0,7744 | 0,9167 |

Đọc kết quả:

- **Nới lịch từ 0 tới 60 giây cho đúng cùng một bộ nhãn** ở bảng cửa sổ (số mẫu và mọi chỉ số giống hệt): lịch
  tấn công của CIC khớp dữ liệu tới phút, không có flow tấn công nào nằm trong khoảng nới thêm. Nới tới 120 và
  300 giây chỉ thêm 7 và 44 cửa sổ `dos` vào train, macro-F1 đổi dưới 0,001.
- **Ngưỡng cửa sổ từ 0,05 tới 0,5 đổi macro-F1 chuẩn trong khoảng 0,9341–0,9365** (chênh 0,0024), nhỏ hơn nhiều
  so với khoảng tin cậy của chính chỉ số này trên validation có 164 cửa sổ `port_scan`.
- Macro-F1 **riêng** tăng tới 0,9473 ở ngưỡng 0,5, nhưng đó là vì ngưỡng cao **bỏ các cửa sổ khó khỏi
  validation** (154 thay vì 164 cửa sổ `port_scan`), không phải vì mô hình tốt hơn: trên validation cố định nó
  chỉ đạt 0,9365.

**Kết luận: giữ `tolerance_s` = 60 và `window_min_attack_share` = 0,2, khóa bằng QĐ-063.** Không giá trị nào
trong khoảng thử cho cải thiện vượt nhiễu, và giữ nguyên thì không phải gán nhãn và huấn luyện lại. Với dữ
liệu lab, nhật ký lần chạy ghi thời điểm tới mili giây nên phần nới lịch càng ít quan trọng.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Độ nhạy | Kết quả đổi bao nhiêu khi đổi một tham số |
| Validation | Phần dữ liệu dùng để chọn tham số, tách riêng với train và test |
| Nới lịch | Mở rộng khung giờ tấn công ghi trong lịch thêm một khoảng ở mỗi đầu khi gán nhãn |
| Ngưỡng cửa sổ | Tỷ lệ flow tấn công tối thiểu trong một cửa sổ để cửa sổ đó nhận nhãn tấn công |
| Cửa sổ mơ hồ | Cửa sổ có flow tấn công nhưng dưới ngưỡng; không dùng để học và đánh giá |
| Tỷ lệ cân bằng | Giới hạn số mẫu mỗi lớp của train so với lớp ít mẫu nhất |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp tính ngang nhau |
| Recall | Trong các mẫu thật sự thuộc một lớp, tỷ lệ được nhận ra |
| Random Forest | Mô hình gồm nhiều cây quyết định bỏ phiếu |
