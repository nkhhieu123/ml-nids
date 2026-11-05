# C10-T04 — Hàng đợi giới hạn và dọn state

Mã nguồn: `ThreadedRunner`, `RealtimeEngine.tick`, `RealtimeEngine.state_size`, `realtime_config`
trong `src/nids/realtime.py`; `FlowAssigner.evict_oldest`, `active_flows`, `active_count` trong
`src/nids/flows.py`. Cấu hình: mục `realtime` trong `config/default.yaml`. Kiểm thử:
`tests/test_realtime.py`.

## 1. Hàng đợi giới hạn

```
luồng "doc-goi": nguồn gói ──put_nowait──> Queue(maxsize = realtime.queue_size)
                                   │ đầy: bỏ gói mới, đếm "dropped"
luồng chính:                       └──get(timeout = tick_s)──> RealtimeEngine.process
                                        không có gói trong tick_s: RealtimeEngine.tick(thời điểm ước tính)
```

- **Đầy thì bỏ gói mới và đếm**, không chặn luồng đọc (QĐ-052). Nếu chặn, bộ đệm socket sẽ tràn và kernel
  bỏ gói mà không ghi lại gói nào. Bỏ ở hàng đợi thì biết chính xác số gói bỏ; số gói kernel bỏ đếm riêng
  (C10-T05).
- Mọi gói nhận được hoặc đã xử lý, hoặc được đếm là bỏ (kiểm thử: `xử lý + bỏ = nhận`).
- Mặc định 100 000 gói. Với khung Ethernet trung bình vài trăm byte, hàng đợi đầy tốn cỡ vài chục MB.
- Lỗi ở nguồn (ví dụ card bị gỡ) được chuyển sang luồng chính sau khi xử lý hết gói còn trong hàng đợi.

## 2. Nhịp thời gian khi mạng im lặng

Bộ ghép flow và bộ lập cửa sổ chỉ đóng flow và cửa sổ khi **có gói mới** cho thấy thời gian đã trôi. Khi
bắt trực tiếp, mạng có thể im lặng lâu: cửa sổ cuối không bao giờ được chấm, flow không hết hạn.

`ThreadedRunner` gọi `engine.tick(t)` khi không có gói trong `tick_s` = 1 giây. Thời điểm `t` = thời điểm
gói cuối + thời gian thật đã trôi × `clock_rate`:
- `clock_rate = 1` khi bắt trực tiếp (dấu thời gian kernel cùng đồng hồ với máy);
- bằng hệ số `--toc-do` khi phát lại theo nhịp;
- 0 (không đẩy) khi phát lại nhanh nhất có thể, vì thời gian lúc đó do file quyết định.

`tick` làm đúng những việc một gói mới sẽ làm: hết hạn flow (`FlowAssigner.expire`), đóng cửa sổ
(`_close_until`), chấm cửa sổ 10 giây vừa đóng, chấm botnet các cửa sổ 120 giây đã đủ dữ liệu, đóng sự kiện
quá hạn. Thời điểm lùi thì bỏ qua.

## 3. Dọn state

| State | Dọn khi nào | Trần (`realtime.*`) |
|---|---|---|
| Flow đang mở (`FlowAssigner._active`) | Hết hạn theo timeout như offline | `max_active_flows` = 200 000; vượt thì kết thúc flow **lâu nhất chưa có gói**, lý do `gioi_han_bo_nho` |
| Flow đã kết thúc giữ cho cửa sổ 120 giây và beaconing | Bỏ khi bắt đầu và kết thúc trước `bây giờ − max(600, 240) − 120` giây | `max_flow_rows` = 500 000; vượt thì bỏ dòng cũ nhất |
| Cửa sổ 10 giây đang mở | Đóng khi hết cửa sổ + 3 giây (theo gói hoặc theo nhịp) | Tự giới hạn: số host × 5 cửa sổ chồng nhau |
| Bất thường chưa giải thích theo host | Bỏ khi cũ hơn 240 giây | |
| Sự kiện đang mở | Đóng khi quá 30 giây không có cảnh báo cùng khóa | |
| Bộ nhớ chiều flow, mảnh IP | Đã có từ Chặng 4 (`expire`) | |

Bản chạy offline **không** dùng hai trần trên, nên kết quả offline không đổi. Lý do `gioi_han_bo_nho` thêm
vào `END_REASONS` và docs/19.

**Sửa lỗi của C10-T03**: ảnh chụp flow đang mở trước đây gộp `_active` và `_closing`. Nhưng flow đang
đóng (đã có FIN/RST, chờ gói cuối) nằm trong **cả hai**, nên bị đếm hai lần trong bảng flow của cửa sổ 120
giây. Nay chỉ lấy `_active`, và có kiểm thử chặn lỗi này.

## 4. Kết quả

Phát lại `wed_slowloris` (73 284 gói) qua hai luồng, nhanh nhất có thể:
- không bỏ gói nào; hàng đợi sâu nhất 69 877 gói (luồng đọc file nhanh hơn luồng xử lý nhiều);
- vẫn ra 654 cảnh báo, 9 sự kiện như C10-T03;
- state cuối: 0 flow mở, 0 cửa sổ mở, 0 sự kiện mở.

Thời gian tăng từ 17,5 lên 37,5 giây so với một luồng: hai luồng Python tranh khóa GIL khi luồng đọc chạy
hết tốc độ. Khi bắt theo nhịp thật, luồng đọc gần như luôn chờ gói, nên tranh chấp nhỏ (đo ở C10-T05).

## 5. Kiểm thử

- Bộ máy xử lý chậm, hàng đợi 5 gói: gói bị bỏ và được đếm; xử lý + bỏ = nhận; hàng đợi không vượt 5.
- Sau 1 000 giây im lặng, một nhịp làm hết hạn mọi flow, đóng mọi cửa sổ, dọn bảng flow và sự kiện; thời
  điểm lùi bị bỏ qua.
- Trần 10 flow mở và 50 flow gần đây không bao giờ bị vượt.
- 20 kết nối chưa đóng với trần 5: đúng 15 flow cũ nhất bị kết thúc với lý do `gioi_han_bo_nho`.
- Flow đang đóng chỉ xuất hiện một lần trong bảng flow của cửa sổ 120 giây.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Hàng đợi giới hạn | Hàng chờ có số chỗ tối đa; đầy thì phải bỏ hoặc chờ |
| Luồng (thread) | Hai phần chương trình chạy song song: một đọc gói, một xử lý |
| State | Dữ liệu chương trình phải nhớ giữa các gói: flow đang mở, cửa sổ đang mở... |
| Nhịp (tick) | Lần đẩy thời gian khi không có gói, để việc theo thời gian vẫn diễn ra |
| Trần | Giới hạn trên của bộ nhớ; vượt thì bỏ phần cũ nhất |
| GIL | Khóa của Python cho phép mỗi lúc chỉ một luồng chạy mã Python |
| Bộ đệm socket | Vùng kernel giữ gói đã nhận mà chương trình chưa đọc |
