# C04-T02 — Timeout, FIN/RST và tái sử dụng 5-tuple

Mã nguồn: `src/nids/flows.py` (`FlowAssigner`, `FlowSettings`). Kiểm thử:
`tests/test_flows.py`. Quyết định: QĐ-017 (và QĐ-006 cho timeout nhàn rỗi) trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md). Định nghĩa flow và chiều:
[18_flow_hai_chieu.md](18_flow_hai_chieu.md).

```bash
python -m nids.flows data/pcap/<file>.pcap --csv output/flows.csv --stats output/flows_stats.json
```

Ở C04-T01 mỗi khóa flow (giao thức và cặp IP, cổng) ứng một flow trong cả file. Task này quy
định **khi nào một flow kết thúc** và gói tiếp theo cùng khóa mở flow mới.

## 1. Tham số

Đặt trong mục `flow` của `config/default.yaml`:

| Tham số | Giá trị | Ý nghĩa |
|---|---|---|
| `idle_timeout_s` | 60 | Không có gói mới quá khoảng này thì flow kết thúc (QĐ-006, tạm thời) |
| `active_timeout_s` | 120 | Flow kéo dài quá khoảng này tính từ gói đầu thì cắt; phần sau là flow tiếp nối |
| `close_grace_s` | 10 | Sau khi TCP đóng bằng FIN hai chiều hoặc RST, còn nhận gói cuối trong khoảng này |
| `direction_memory_s` | 3600 | Nhớ chiều của flow đã kết thúc để flow sau cùng khóa giữ chiều |
| `fragment_timeout_s` | 30 | Nhớ mảnh IP đầu (QĐ-016) |

Mọi khoảng thời gian tính theo **thời điểm ghi trong gói**, không theo đồng hồ
máy. Vì vậy đọc lại file hay bắt realtime đều cho cùng kết quả. Một khoảng đúng
bằng giới hạn chưa bị tính là quá (dùng phép so sánh "lớn hơn").

## 2. Khi nào flow kết thúc

Khi một gói tới, flow đang mở của khóa đó được kiểm tra theo thứ tự dưới đây.
Điều kiện đầu tiên đúng quyết định lý do kết thúc (`end_reason`), rồi gói mở flow
mới.

| Thứ tự | Tình huống | `end_reason` của flow cũ |
|---|---|---|
| 1 | Flow TCP **đã đóng** (cả hai bên gửi FIN, hoặc một bên gửi RST) và gói mới có cờ SYN (SYN hoặc SYN+ACK), hoặc tới sau lúc đóng hơn `close_grace_s` | `fin` hoặc `rst` |
| 2 | Từ gói trước của flow tới gói này lâu hơn `idle_timeout_s` | `idle_timeout` |
| 3 | Gói **bắt tay mới** (SYN hoặc SYN+ACK) trên flow chưa đóng, không phải gói gửi lại | `tai_su_dung` |
| 4 | Từ gói đầu của flow tới gói này lâu hơn `active_timeout_s` | `active_timeout` |
| — | Hết file mà flow chưa kết thúc | `het_du_lieu` |

Chi tiết từng trường hợp:

**FIN và RST.** Flow được đánh dấu đã đóng khi cả hai đầu đều đã gửi FIN, hoặc
khi có một gói RST. Chỉ FIN một chiều (half-close) thì flow vẫn mở, vì bên kia
còn gửi được dữ liệu. Sau khi đóng, gói tới trong `close_grace_s` vẫn thuộc flow
cũ: gói ACK cuối của bắt tay đóng, FIN gửi lại, dữ liệu đang trên đường khi có
RST. Cách này tránh lỗi đã biết của CICFlowMeter: kết thúc flow ngay ở gói FIN
đầu tiên, khiến gói ACK cuối thành một flow riêng chỉ có một gói (Engelen và
cộng sự, 2021). Gói có cờ SYN tới sau khi đóng luôn mở flow mới, dù còn trong
`close_grace_s`, vì kết nối cũ đã kết thúc.

**Tái sử dụng 5-tuple.** Một gói bắt tay mới trên flow chưa đóng nghĩa là có kết
nối mới với cùng IP và cổng (FIN/RST của kết nối cũ không được bắt, hoặc bên kia
mở lại từ phía ngược). Để phân biệt với **gói bắt tay gửi lại** (gửi lại vì chưa
nhận được trả lời), bộ trích xuất packet đọc thêm **số thứ tự TCP** (`tcp_seq`).
Mỗi lần mở kết nối, mỗi bên chọn một số thứ tự đầu tiên (ISN) mới; gói gửi lại
giữ nguyên số đó. Quy tắc:

| Gói tới | Kết nối mới khi |
|---|---|
| SYN từ phía server của flow | Luôn luôn (bên kia mở kết nối ngược chiều) |
| SYN từ client, hoặc SYN+ACK | Số thứ tự khác số của gói cùng loại mà bên đó đã gửi trước trong flow |
| SYN+ACK không so được số (lần đầu bên đó gửi SYN+ACK trong flow, hoặc gói bị cắt) | Chỉ khi gói không có số thứ tự và bên gửi đã gửi gói không có SYN trong flow; SYN+ACK đầu tiên có số thứ tự là trả lời bình thường |
| SYN của client không so được số | Client đã gửi gói không có SYN trong flow, hoặc flow không mở bằng SYN/SYN+ACK (bắt giữa chừng) |

Các trường hợp thật trong bản thu CTU-13 đã dẫn tới quy tắc này:
- Client gửi lại SYN ba lần cùng số thứ tự, 21 giây sau thử lại với số mới: hai lần thử kết nối.
- Chỉ thấy SYN+ACK của server (chiều đi của máy đó không được bắt), mỗi lần một
  số thứ tự mới: mỗi lần là một kết nối server đã nhận.
- Server đã gửi ACK rồi gửi lại SYN+ACK cùng số (donbot): vẫn là một kết nối.
- Client thử lại với số thứ tự mới; server gửi ACK rồi mới gửi SYN+ACK đầu tiên
  của lần thử đó: SYN+ACK này là trả lời, không phải kết nối thứ ba.
- Flow mở bằng SYN+ACK, sau đó mới thấy SYN của client (gửi lại hoặc bắt lệch
  thứ tự): cùng một lần bắt tay.

Số thứ tự chỉ được đọc khi header TCP còn tới byte cờ, giống Wireshark; trường này
được đối chiếu với `tcp.seq_raw` của Wireshark
([17_doi_chieu_wireshark.md](17_doi_chieu_wireshark.md)).

**Timeout nhàn rỗi.** Đo từ gói trước của flow, theo cả hai chiều.

**Active timeout.** Kết nối dài (tải file, SSH, slowloris) bị cắt thành nhiều
flow dài tối đa 120 giây. Giá trị 120 giây giống CICFlowMeter, công cụ tạo CSV
của CIC-IDS2017, để flow của dự án so được với CSV của CIC. Active timeout chỉ được xét khi có
gói tới, nên mỗi flow bắt đầu đúng ở một gói thật.

## 3. Chiều của flow mở lại

Flow mới mở theo quy tắc của C04-T01, với một bổ sung: nếu khóa đó vừa có flow
kết thúc trong vòng `direction_memory_s`, và gói mở flow **không phải** SYN hay
SYN+ACK, thì flow mới **giữ chiều của flow trước** và có `continuation = 1`.

Lý do: gói đầu của phần tiếp theo sau một timeout thường là gói giữa chừng, có
thể do server gửi. Đoán lại chiều từ gói đó (nhất là với UDP và P2P, dùng
`goi_dau`) có thể đảo client và server so với phần trước của cùng kết nối. Bộ nhớ
chỉ chứa thông tin từ gói đã tới, nên không dùng dữ liệu tương lai.

Flow mở bằng SYN hoặc SYN+ACK luôn xác định chiều lại từ đầu, vì đó là kết nối
mới.

## 4. Trả flow ra khi chạy liên tục

`FlowAssigner` đưa flow đã kết thúc vào hàng chờ, lấy ra bằng `pop_finished()`.
Chương trình realtime không cần đợi gói tiếp theo của chính flow đó: cứ mỗi giây
(theo thời điểm gói), `expire()` kết thúc các flow nhàn rỗi quá `idle_timeout_s`
và các flow đã đóng quá `close_grace_s`. Hai điều kiện này không phụ thuộc gói
tới sau, nên kết quả giống hệt khi kiểm tra lúc gói tới. Kiểm thử
`test_streaming_matches_batch` xác nhận điều đó. Khi hết dữ liệu, gọi
`finish_all()`.

Các bảng nội bộ xếp theo thời gian (`OrderedDict`), nên mỗi lần dọn chỉ xem
các flow ở đầu bảng. Bản thu 4,5 triệu gói chạy trong khoảng 90 giây.

Mảnh IP chỉ được gắn vào flow chưa trả ra. Mảnh của flow đã trả ra là mảnh mồ côi.

## 5. Đầu ra

Bảng CSV thêm hai cột so với C04-T01:

| Cột | Ý nghĩa |
|---|---|
| `continuation` | 1 nếu chiều lấy từ flow trước cùng khóa (mục 3) |
| `end_reason` | `fin`, `rst`, `idle_timeout`, `active_timeout`, `tai_su_dung`, `het_du_lieu` |

Thống kê JSON thêm số flow theo lý do kết thúc, số flow tiếp nối và bộ tham số
đã dùng (`tham_so`), để biết bảng flow được tạo với cấu hình nào.

## 6. Chọn giá trị: đo trên dữ liệu thật

**Gói tới sau khi TCP đã đóng** (không tính SYN mới), khoảng cách tới lúc đóng:

| File | Gói sau khi đóng | ≤ 0,5 giây | ≤ 2 giây | ≤ 10 giây | > 10 giây |
|---|---|---|---|---|---|
| donbot | 462 | 456 | 459 | 462 | 0 |
| sogou | 52 | 38 | 39 | 49 | 3 |
| Virut | 905 | 893 | 897 | 903 | 2 |
| Scenario 5 toàn mạng | 27 457 | 25 457 | 25 993 | 26 566 | 891 |

Khoảng 97% gói này tới trong 10 giây, chủ yếu là gói ACK/RST cuối. Chờ lâu hơn
không mở nhầm kết nối mới, vì kết nối mới luôn bắt đầu bằng SYN, nhưng làm chậm
lúc trả flow ra khi chạy realtime. Vì vậy chọn 10 giây. Các gói tới muộn hơn phần
lớn là FIN gửi lại theo chu kỳ tăng dần khi bên kia đã im (ví dụ 5,8 giây rồi
11,6 giây). Chúng thành một flow tiếp nối nhỏ, vẫn đúng chiều.

**Khoảng trống giữa hai gói liên tiếp cùng 5-tuple TCP** (để xem timeout 60 giây
cắt bao nhiêu): ở scenario 5 có 4 042 440 khoảng trống, trong đó 9 474 khoảng dài hơn 60 giây
(0,23%); ở sogou có 25 trên 20 472.

## 7. Kiểm tra

**So với Wireshark** (cùng script tạm của C04-T01, chạy với cấu hình mặc định).
Wireshark tách stream TCP mới khi 5-tuple được dùng lại, nhưng không có timeout.
Vì vậy mong đợi: không flow nào của dự án chứa hai stream, và một stream chỉ bị
chia thành nhiều flow do timeout.

| File | Stream Wireshark | Flow chứa > 1 stream | Stream bị chia | Lần cắt, theo lý do | Gói kiểm tra chiều theo SYN | Sai chiều |
|---|---|---|---|---|---|---|
| donbot | 4 565 | 0 | 5 | `idle_timeout` 21 | 24 234 | 0 |
| sogou | 46 | 0 | 29 | `idle_timeout` 28, `active_timeout` 1, `fin` 1 | 20 512 | 0 |
| Virut | 1 446 | 0 | 9 | `idle_timeout` 29, `active_timeout` 2, `rst` 1 | 45 527 | 0 |
| WSL | 82 | 0 | 0 | — | 147 | 0 |
| Scenario 5 toàn mạng (*) | 119 444 | 2 | 19 577 | `idle_timeout` 33 813, `active_timeout` 8 013, `rst` 180, `fin` 140, `tai_su_dung` 11 | 3 204 767 | 0 |

Ở C04-T01 có 26 flow donbot và 291 flow Virut chứa nhiều stream; giờ là 0. Hai
lần cắt do `fin`/`rst` ở sogou và Virut là FIN gửi lại sau hơn 10 giây (mục 6).

(*) Bản thu toàn mạng được dùng để chỉnh quy tắc gói bắt tay ở mục 2, qua ba lần chạy:
1. Chưa dùng số thứ tự: 77 flow chứa hơn một stream, chủ yếu là các SYN+ACK có số
   thứ tự mới bị gộp vào một flow.
2. Dùng số thứ tự (số trong bảng trên): còn 2 flow chứa hai stream, và 11 lần cắt
   `tai_su_dung` mà Wireshark vẫn coi là một stream.
   - 2 flow là SYN+ACK gửi lại, cùng số thứ tự và cùng số ACK, sau khi client gửi
     FIN một chiều. Đó vẫn là một kết nối: Wireshark tách vì thấy SYN sau FIN,
     còn dự án giữ chung là đúng.
   - 11 lần cắt là hai mẫu cuối trong danh sách ở mục 2. Quy tắc dự phòng đã được
     sửa cho hai mẫu này.
3. Chạy lại với quy tắc cuối: số flow kết thúc do `tai_su_dung` giảm từ 63 xuống
   52, đúng bằng 11 trường hợp trên. Lần đối chiếu Wireshark sau cùng trên file
   này bị dừng giữa chừng vì máy thiếu bộ nhớ; cần chạy lại khi máy rảnh. Kết quả
   đối chiếu của bốn file còn lại là với quy tắc cuối.

**Lý do kết thúc trên dữ liệu thật:**

| File | Flow | `fin` | `rst` | `idle_timeout` | `active_timeout` | `tai_su_dung` | `het_du_lieu` | Tiếp nối |
|---|---|---|---|---|---|---|---|---|
| donbot | 4 588 | 179 | 100 | 4 267 | 0 | 0 | 42 | 19 |
| sogou | 77 | 10 | 22 | 43 | 1 | 0 | 1 | 30 |
| Virut | 1 487 | 400 | 880 | 193 | 2 | 0 | 12 | 32 |
| WSL | 84 | 2 | 59 | 0 | 0 | 0 | 23 | 0 |
| Scenario 5 toàn mạng | 163 588 | 21 446 | 8 401 | 120 905 | 8 084 | 52 | 4 700 | 42 906 |

Ở donbot, `idle_timeout` chiếm phần lớn vì bot quét cổng: gửi SYN không nhận được
trả lời, flow một gói kết thúc do nhàn rỗi. Đây chính là loại flow mà C04-T07 sẽ
đếm là "kết nối không hoàn tất". Ở WSL, `rst` là các lần kết nối tới cổng đóng
mà nhóm tự tạo. Ở bản thu toàn mạng, 111 491 trong 163 588 flow là UDP. UDP
không có FIN/RST nên chỉ kết thúc do timeout, vì vậy `idle_timeout` chiếm phần
lớn. Có 8 084 lần kết nối dài bị cắt bởi active timeout.

**Kiểm thử tự động** (24 ca mới, tổng 151 ca của dự án): FIN hai chiều giữ gói
ACK cuối; FIN một chiều không đóng flow; SYN sau FIN mở flow mới; gói sau thời gian
chờ thành flow tiếp nối đúng chiều; RST giữ dữ liệu đang trên đường; quét SYN/RST
mỗi lần thử là một flow; SYN trên flow đang mở; SYN gửi lại; SYN với số thứ tự mới;
SYN+ACK với số thứ tự mới và cùng số; SYN+ACK gửi lại sau khi server đã ACK;
SYN+ACK đầu tiên của lần thử mới; SYN tới sau SYN+ACK; gói bắt tay sau RST; SYN ngược chiều trên
flow bắt giữa chừng (trường hợp BitTorrent ở
[18_flow_hai_chieu.md](18_flow_hai_chieu.md)); timeout nhàn rỗi đúng bằng và lớn
hơn giới hạn; active timeout; bộ nhớ chiều hết hạn; đọc tham số từ cấu hình; gói
không có thời điểm; trả flow ra khi nhàn rỗi và sau thời gian chờ đóng; chạy liên
tục cho cùng kết quả với chạy một lần; mảnh của flow đã trả ra.

## 8. Giới hạn

- Gói bắt tay bị cắt trước byte cờ không có số thứ tự, nên chỉ phân biệt gửi lại
  với kết nối mới bằng các quy tắc dự phòng ở mục 2.
- Hai bên cùng mở kết nối một lúc (simultaneous open, rất hiếm) cho hai flow.
- Active timeout cắt kết nối dài. Đặc trưng theo kết nối (C04-T03) vì vậy là
  đặc trưng của từng đoạn 120 giây; cột `continuation` cho biết đoạn nào là phần
  tiếp.
- Gói có thời điểm nhỏ hơn gói trước (mục 5 của docs/18) không làm cắt flow; các
  khoảng thời gian âm bị bỏ qua.

## Tài liệu tham khảo

- G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an Intrusion Detection
  Dataset: the CICIDS2017 Case Study", IEEE SPW 2021.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Timeout nhàn rỗi (idle timeout) | Không thấy gói mới của flow trong khoảng này thì coi flow đã kết thúc |
| Active timeout | Độ dài tối đa của một flow; kết nối dài hơn bị cắt thành nhiều flow nối tiếp |
| FIN, RST | Cờ TCP: FIN báo một bên đã gửi xong và muốn đóng; RST hủy kết nối ngay |
| Half-close | Chỉ một bên gửi FIN; bên kia vẫn còn gửi dữ liệu được |
| Thời gian chờ sau khi đóng | Khoảng vẫn nhận gói cuối vào flow đã đóng, ví dụ gói ACK trả lời FIN |
| 5-tuple, tái sử dụng 5-tuple | Năm giá trị nhận diện kết nối; dùng lại là mở kết nối mới với đúng IP và cổng của kết nối cũ |
| SYN gửi lại | Client gửi lại SYN vì chưa nhận được trả lời; vẫn là cùng một lần thử kết nối |
| Flow tiếp nối | Flow giữ chiều của flow trước cùng khóa, vì là phần sau của cùng một kết nối |
| Trả flow ra | Đưa flow đã kết thúc cho bước tính đặc trưng; khi chạy realtime việc này phải làm ngay, không đợi hết file |
| Hàng chờ | Danh sách flow đã kết thúc, chờ chương trình lấy ra |
| `OrderedDict` | Kiểu từ điển của Python giữ thứ tự thêm vào; dùng để luôn biết flow cũ nhất ở đầu bảng |
| Số thứ tự TCP (sequence number), ISN | Số trong header TCP đánh dấu vị trí byte của dữ liệu; ISN là số đầu tiên mỗi bên chọn khi mở kết nối |
| Gói bắt tay gửi lại | SYN hoặc SYN+ACK được gửi lại vì chưa nhận được trả lời; giữ nguyên số thứ tự |
| Quét cổng | Gửi gói tới nhiều cổng để xem cổng nào mở |
| Slowloris | Kiểu DoS giữ kết nối HTTP mở thật lâu bằng cách gửi yêu cầu rất chậm |
| Simultaneous open | Hai bên cùng gửi SYN cho nhau một lúc; TCP cho phép nhưng rất hiếm gặp |
| CICFlowMeter | Công cụ tạo file flow CSV của CIC-IDS2017 |
| Realtime | Xử lý ngay khi gói tới, không đợi có cả file |
