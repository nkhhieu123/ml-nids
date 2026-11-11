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

## 2. Tham số flow (QĐ-006, QĐ-017, QĐ-023)

Mã nguồn: `src/nids/do_nhay_flow.py`, `src/nids/do_tre_realtime.py`. Số liệu: `docs/hinh/flow_do_nhay.json`,
`docs/hinh/flow_bat_tay_realtime.json`.

```bash
cd src
python -m nids.do_nhay_flow ../data/pcap/lab/*-val-01.pcap --nhat-ky ../data/run_logs --out ../docs/hinh
```

Bốn tham số được ghi là tạm thời:

| Tham số | Giá trị | Ý nghĩa |
|---|---|---|
| `flow.idle_timeout_s` | 60 | Flow kết thúc khi không có gói trong khoảng này |
| `flow.active_timeout_s` | 120 | Flow dài hơn thì cắt thành đoạn |
| `flow.close_grace_s` | 10 | Sau khi TCP đóng, còn nhận gói cuối trong khoảng này |
| `flow.handshake_observe_s` | 3 | Chờ trả lời bắt tay TCP trước khi coi lần thử là không hoàn tất |

### 2.1. Kết quả phát hiện khi đổi từng tham số

Mỗi lần đổi một tham số, **trích xuất lại** đặc trưng của 11 lần chạy `val` của lab (thu 12/11/2026, 5 đợt
`port_scan`/`dos`, 3 đợt botnet, 3 đối chứng) rồi chấm bằng mô hình đã khóa, so với nhật ký lần chạy.

| Tham số đổi | Số flow | `port_scan` phát hiện (cửa sổ cảnh báo) | `dos` phát hiện (cửa sổ cảnh báo) | Độ trễ `dos` | Sự kiện báo động giả |
|---|---|---|---|---|---|
| (hiện tại 60 / 120 / 10 / 3) | 52 537 | 2/2 (532) | 3/3 (152) | 3,0 / 1,9 / 1,7 s | 24 |
| `idle_timeout_s` 30 | 52 641 | 2/2 (532) | 3/3 (152) | như trên | 24 |
| `idle_timeout_s` 120 | 52 532 | 2/2 (532) | 3/3 (152) | như trên | 24 |
| `active_timeout_s` 60 | 52 634 | 2/2 (532) | 3/3 (152) | như trên | 24 |
| `active_timeout_s` 300 | 52 519 | 2/2 (532) | 3/3 (152) | như trên | 24 |
| `close_grace_s` 5 | 52 537 | 2/2 (532) | 3/3 (152) | như trên | 24 |
| `close_grace_s` 20 | 52 537 | 2/2 (532) | 3/3 (152) | như trên | 24 |
| `handshake_observe_s` 1 | 52 537 | 2/2 (532) | 3/3 (152) | như trên | 24 |
| `handshake_observe_s` 5 | 52 537 | 2/2 (532) | 3/3 (152) | như trên | 24 |

- **Kết quả giống hệt nhau ở cả 9 cấu hình**: cùng số đợt phát hiện, cùng số cửa sổ cảnh báo, cùng độ trễ, cùng
  24 sự kiện báo động giả (12 anomaly, 12 `dos` nhầm ở `k5-doi-chung`); botnet bỏ sót 3/3 ở mọi cấu hình.
- Timeout nhàn rỗi và active timeout chỉ đổi số flow khoảng ±0,2% (flow dài bị cắt nhiều hay ít đoạn hơn),
  không đủ để đổi đặc trưng cửa sổ 10 giây. Traffic của lab toàn kết nối ngắn nên gần như không flow nào chạm
  các timeout này.
- `close_grace_s` và `handshake_observe_s` không đổi cả số flow: trên lab ảo, trả lời bắt tay và gói đóng kết
  nối tới trong chưa đầy 1 mili giây.

### 2.2. Thời gian chờ bắt tay quyết định độ trễ realtime

`handshake_observe_s` không đổi kết quả phát hiện nhưng cộng thẳng vào độ trễ của cảm biến realtime, vì cửa sổ
phải chờ thêm đúng khoảng này mới được trả ra (QĐ-023). Phát lại đúng nhịp hai lần chạy `val`:

| `handshake_observe_s` | `k2-quet-nhanh-val-01` | `k3-dos-muc2-val-01` | Chờ sau cuối cửa sổ |
|---|---|---|---|
| 1 | 1,5 s | 2,9 s | 1,0–1,4 s |
| **3 (hiện tại)** | **3,1 s** | **5,0 s** | 3,0–3,1 s |
| 5 | 6,2 s | 6,9 s | 5,0–6,1 s |

Giảm từ 3 xuống 1 giây sẽ bớt khoảng 2 giây độ trễ mà không đổi số cửa sổ cảnh báo (10 và 64 ở cả ba giá trị).

### 2.3. Kết luận

**Giữ nguyên cả bốn giá trị, khóa bằng QĐ-066**, kèm cửa sổ 10 giây bước 2 giây và 120 giây bước 10 giây của
QĐ-006.

- Không tham số nào đổi kết quả phát hiện trong khoảng thử, nên không có lý do đổi ba timeout.
- `handshake_observe_s` = 1 hấp dẫn về độ trễ, nhưng **không đổi** vì hai lý do. Một: mô hình hiện tại được học
  từ đặc trưng CIC-IDS2017 trích với 3 giây; đổi giá trị thì phải trích xuất và huấn luyện lại toàn bộ để huấn
  luyện và realtime dùng cùng cách tính (B12). Hai: lab ảo không có độ trễ đường truyền nên không cho biết 1
  giây có đủ cho bắt tay trên mạng thật hay không.

Giới hạn của phép đo: dùng mô hình đã khóa và chỉ dữ liệu lab. Nó cho biết kết quả **không nhạy** với các tham
số này, không chứng minh bộ hiện tại là tối ưu; muốn vậy phải trích xuất lại ba ngày CIC (36 triệu gói) và
huấn luyện lại cho từng cấu hình, việc này chưa làm.

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
| Flow | Chuỗi gói tin giữa hai đầu cùng địa chỉ, cổng và giao thức |
| Timeout nhàn rỗi | Khoảng im lặng mà sau đó flow được coi là đã kết thúc |
| Active timeout | Độ dài tối đa của một flow trước khi bị cắt thành đoạn mới |
| Bắt tay TCP | Ba gói đầu tiên để mở một kết nối TCP |
| Độ trễ realtime | Thời gian từ lúc tấn công bắt đầu tới lúc cảm biến realtime phát cảnh báo |
| Phát lại đúng nhịp | Đưa các gói đã bắt vào chương trình theo đúng khoảng cách thời gian lúc bắt |
