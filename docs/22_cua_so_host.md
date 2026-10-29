# C04-T05 — Cửa sổ host theo thời gian packet

Mã nguồn: `src/nids/host_windows.py` (`HostWindower`, `HostWindow`). Kiểm thử:
`tests/test_host_windows.py`. Quyết định: QĐ-021 (và QĐ-006 cho kích thước cửa sổ)
trong [03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md).

```bash
python -m nids.host_windows data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/host_windows.csv
```

Flow (C04-T01 đến T04) mô tả một kết nối. Nhiều hành vi chỉ thấy được khi nhìn **một
máy trong một khoảng thời gian**: một máy quét gửi SYN tới hàng trăm cổng, mỗi
flow rất nhỏ nhưng gộp lại thì lộ ra. Cửa sổ host là khung thời gian đó. Task này
dựng cơ chế cửa sổ; các đặc trưng trên cửa sổ (số đích, cổng đích, kết nối mới,
entropy, tỷ lệ kết nối không hoàn tất) tính ở C04-T06 và C04-T07.

## 1. Định nghĩa

| Khái niệm | Quy tắc |
|---|---|
| Host | Một địa chỉ IP (IPv4 hoặc IPv6) |
| Cửa sổ | Khoảng `[start, start + size)`: tính cả đầu, không tính cuối |
| Kích thước, bước | `size = 10` giây, `step = 2` giây (`windows.flow` trong `config/default.yaml`, QĐ-006) |
| Vị trí cửa sổ | `start` là bội số của `step` tính từ epoch (00:00:00 UTC ngày 1/1/1970) |
| Gói thuộc cửa sổ | Gói có thời điểm `ts` với `start <= ts < start + size` |
| Gói của host | Host là IP nguồn (chiều **ra**) hoặc IP đích (chiều **vào**) |

Vì cửa sổ dài 10 giây, bước 2 giây, mỗi gói thuộc đúng 5 cửa sổ chồng nhau của máy
gửi và 5 cửa sổ của máy nhận. Ví dụ gói lúc 13,0 giây thuộc các cửa sổ bắt đầu ở
4, 6, 8, 10, 12 giây. Gói đúng bằng thời điểm kết thúc của một cửa sổ thì không
thuộc cửa sổ đó.

**Vì sao đặt cửa sổ theo epoch** chứ không theo gói đầu tiên của file: khi đó cùng
một gói luôn rơi vào cùng các cửa sổ, dù đọc cả file, đọc từ giữa file hay bắt
realtime (B12). Dữ liệu lab và CIC dùng chung một lưới cửa sổ.

## 2. Thời gian theo gói

Thời gian trôi theo **thời điểm ghi trong gói**, không theo đồng hồ máy chạy chương
trình. "Bây giờ" là thời điểm lớn nhất đã thấy. Cửa sổ `[start, end)` **đóng và được
trả ra** khi "bây giờ" ≥ `end`. Khi đó không còn gói nào hợp lệ có thể thuộc về nó,
trừ gói sai thứ tự (mục 3).

- Đọc file 10 giờ trong vài phút vẫn cho cùng cửa sổ như khi bắt realtime 10 giờ.
- Khi chạy realtime, cửa sổ được trả ra ngay khi có gói đầu tiên sau `end`. Nếu
  mạng im lặng hẳn thì phải chờ gói tiếp theo; C04-T07 và chương trình realtime
  sẽ thêm việc đóng theo đồng hồ khi cần.
- `finish_all()` trả ra các cửa sổ còn mở khi hết file. Các cửa sổ cuối có thể chưa
  đủ 10 giây dữ liệu; bảng vẫn giữ chúng, việc lọc để cho bước gán nhãn.

## 3. Trường hợp biên

| Trường hợp | Xử lý |
|---|---|
| Host không có gói nào trong một cửa sổ | Không có dòng cho host đó trong cửa sổ đó (bảng không có dòng toàn số 0) |
| Gói sai thứ tự thời gian, thuộc cửa sổ **đã đóng** | Không cộng vào cửa sổ đã đóng; vẫn cộng vào các cửa sổ chứa nó còn mở; đếm ở `goi_tre` |
| Gói sai thứ tự sau khoảng lặng, khi có thời gian chờ (`emit_delay_s`, C04-T07) | Có thể tạo cửa sổ nằm trước cửa sổ đang mở; bảng cửa sổ được sắp lại để vẫn trả ra theo thứ tự |
| Gói không có thời điểm | Không vào cửa sổ nào; đếm ở `goi_khong_co_thoi_diem` |
| Khoảng lặng dài (không có gói) | Không sinh cửa sổ rỗng |
| Bước không chia hết kích thước | Vẫn đúng; mỗi gói thuộc ⌈size/step⌉ hoặc ⌊size/step⌋ cửa sổ |
| Cùng IP là cả nguồn và đích | Gói được tính một lần ra, một lần vào |

**Giới hạn theo dải mạng** (`--net`, tham số `networks`). Chỉ lập cửa sổ cho host
thuộc các dải đã cho, ví dụ mạng nội bộ `192.168.10.0/24` của CIC hay
`192.168.50.0/24` của lab. Gói giữa một host trong dải và một máy ngoài Internet
vẫn được tính cho host trong dải. Không có `--net` thì mọi IP đều có cửa sổ. Trên
PCAP CIC điều này có nghĩa là hàng nghìn IP Internet, mỗi IP chỉ vài gói.

## 4. Đầu ra

Mỗi dòng là một cặp (host, cửa sổ):

| Cột | Ý nghĩa | Đơn vị |
|---|---|---|
| `host` | Địa chỉ IP | |
| `window_start`, `window_end` | Đầu và cuối cửa sổ, giây từ epoch UTC | giây |
| `packets_out`, `packets_in` | Số gói host gửi / nhận trong cửa sổ | gói |
| `bytes_out`, `bytes_in` | Tổng `ip_len` gửi / nhận (QĐ-018) | byte |
| `first_ts`, `last_ts` | Thời điểm gói đầu và cuối của host trong cửa sổ | giây |

Trong mỗi cửa sổ, các host được xếp theo thứ tự chữ. Các cửa sổ ra theo thứ tự
`window_start` tăng dần.

`HostWindower` nhận tham số `window_factory`, để C04-T06 và C04-T07 dùng lớp cửa sổ
có thêm đặc trưng mà không phải viết lại cơ chế. Tham số `emit_delay_s` (thêm ở
C04-T07) cho cửa sổ chờ thêm một khoảng sau `end` mới trả ra; mặc định 0.

## 5. Kiểm tra

**Tính vét cạn từ Wireshark.** Một script tạm đọc thời điểm, IP và `ip.len` của
từng gói bằng tshark. Với mỗi gói, script lùi từng bước 2 giây để liệt kê mọi cửa
sổ chứa gói đó, rồi cộng cho cả hai đầu. Script không dùng mã của dự án. Sau đó
so từng cặp (host, cửa sổ) với CSV của dự án:

| File | Cửa sổ host | Thiếu | Thừa | Lệch số gói/byte |
|---|---|---|---|---|
| donbot | 26 937 | 0 | 0 | 0 |
| sogou | 505 | 0 | 0 | 0 |
| WSL | 86 | 0 | 0 | 0 |

donbot có 2 gói sai thứ tự nhưng đều không thuộc cửa sổ đã đóng, nên không có gói trễ.

**Kiểm thử tự động** (15 ca mới, tổng 202 ca của dự án): danh sách cửa sổ của một
gói, gói ở đúng biên, bước không chia hết, tham số sai; đếm cả hai đầu, cửa sổ
chồng nhau, lọc theo dải mạng (cả IPv6), host im lặng, gói không có thời điểm; cửa
sổ đóng đúng lúc, gói trễ khi mọi cửa sổ đã đóng và khi còn cửa sổ mở, trả dần
cho cùng kết quả với trả một lần; dòng lệnh ghi CSV.

## 6. Giới hạn

- Gói sai thứ tự quá 10 giây bị mất khỏi các cửa sổ đã đóng. Muốn giữ được thì phải
  chờ thêm trước khi đóng cửa sổ (làm chậm cảnh báo). Chưa làm, vì trên dữ liệu đang có
  độ lệch thứ tự dưới 1 giây.
- Host là địa chỉ IP: máy đổi IP (DHCP) hoặc nhiều máy sau NAT bị coi là một host. Ở
  CIC, mọi traffic tấn công hiện là `172.16.0.1` (docs/06, mục 7.3).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Cửa sổ thời gian | Một khoảng thời gian cố định để gom gói và tính đặc trưng |
| Cửa sổ trượt, bước | Các cửa sổ chồng lên nhau, cửa sổ sau bắt đầu muộn hơn cửa sổ trước một bước |
| Host | Một máy trong mạng, xác định bằng địa chỉ IP |
| Chiều ra / chiều vào | Gói host gửi đi / gói host nhận được |
| Epoch | Mốc 00:00:00 UTC ngày 1/1/1970; thời điểm trong PCAP tính bằng giây từ mốc này |
| `[start, end)` | Khoảng tính cả `start`, không tính `end` |
| Gói trễ | Gói có thời điểm thuộc cửa sổ đã được trả ra, do file hoặc mạng sai thứ tự |
| Dải mạng (CIDR) | Một nhóm địa chỉ liền nhau, ví dụ `192.168.10.0/24` là 256 địa chỉ `192.168.10.x` |
| NAT, DHCP | Nhiều máy dùng chung một IP khi ra ngoài / máy được cấp IP tự động, có thể đổi |
| Vét cạn | Cách tính đơn giản, thử hết mọi khả năng, dùng làm đáp án để kiểm tra |
| B12 | Yêu cầu huấn luyện và realtime dùng cùng cách tính đặc trưng (docs/01) |
