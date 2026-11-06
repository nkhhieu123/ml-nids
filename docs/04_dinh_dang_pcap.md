# C02-T01 — Định dạng PCAP và phân biệt với PCAPNG

Tài liệu mô tả ba phần của file PCAP (Global Header, Packet Header, Packet
Data) và các điểm khác với PCAPNG. Đây là cơ sở cho script đọc PCAP của các
bước sau (yêu cầu B01, B23).

## 1. Cấu trúc tổng thể của file PCAP

Một file PCAP gồm đúng một Global Header ở đầu file, theo sau là dãy bản ghi
gói tin. Mỗi bản ghi gồm một Packet Header và phần Packet Data.

```
+---------------+---------------+-------------+---------------+-------------+-----
| Global Header | Packet Header | Packet Data | Packet Header | Packet Data | ...
|    24 byte    |    16 byte    | incl_len    |    16 byte    | incl_len    |
+---------------+---------------+-------------+---------------+-------------+-----
```

- File không có chỉ mục và không có dấu kết thúc. Muốn tới gói thứ *n* phải đọc
  tuần tự từ đầu; file kết thúc khi hết byte.
- Các bản ghi nằm theo thứ tự ghi vào file. Định dạng không bắt buộc timestamp
  tăng dần.
- Mọi trường số trong Global Header và Packet Header dùng thứ tự byte của máy
  đã ghi file. Phần Packet Data giữ nguyên byte như trên đường truyền.

## 2. Global Header (24 byte)

| Offset | Kích thước | Trường | Ý nghĩa |
|---|---|---|---|
| 0 | 4 | `magic_number` | Nhận diện định dạng, thứ tự byte và độ phân giải thời gian |
| 4 | 2 | `version_major` | Phiên bản chính của định dạng, hiện là 2 |
| 6 | 2 | `version_minor` | Phiên bản phụ, hiện là 4 |
| 8 | 4 | `thiszone` | Độ lệch múi giờ so với UTC (giây). Thực tế luôn bằng 0 |
| 12 | 4 | `sigfigs` | Độ chính xác của timestamp. Thực tế luôn bằng 0 |
| 16 | 4 | `snaplen` | Số byte tối đa được lưu cho mỗi gói |
| 20 | 4 | `network` | Kiểu tầng liên kết (link-layer type) của mọi gói trong file |

### `magic_number`

Trình đọc đọc 4 byte đầu như một số nguyên rồi so với các giá trị sau:

| Giá trị đọc được | Byte trên đĩa | Thứ tự byte của file | Phần lẻ của timestamp |
|---|---|---|---|
| `0xA1B2C3D4` | `A1 B2 C3 D4` hoặc `D4 C3 B2 A1` | Trùng với máy đọc | Micro giây |
| `0xD4C3B2A1` | (ngược lại) | Ngược với máy đọc, phải đảo byte mọi trường | Micro giây |
| `0xA1B23C4D` | `A1 B2 3C 4D` hoặc `4D 3C B2 A1` | Trùng với máy đọc | Nano giây |
| `0x4D3CB2A1` | (ngược lại) | Ngược với máy đọc, phải đảo byte mọi trường | Nano giây |

File ghi trên máy x86/x86-64 (little-endian) bắt đầu bằng `D4 C3 B2 A1`
(micro giây) hoặc `4D 3C B2 A1` (nano giây).

### `snaplen`

Gói dài hơn `snaplen` bị cắt khi ghi: chỉ `snaplen` byte đầu được lưu. tcpdump
hiện đặt mặc định 262144; các bản cũ dùng 65535. Nếu đặt `snaplen` nhỏ (ví dụ
96) file sẽ chỉ còn phần header của gói, đủ cho đặc trưng flow nhưng mất
payload.

### `network`

Giá trị là mã LINKTYPE do nhóm tcpdump quản lý. Nó cho biết byte đầu tiên của
Packet Data thuộc header nào. Cả file chỉ có **một** giá trị, nên một file PCAP
không chứa được gói từ hai giao diện khác kiểu liên kết.

| Mã | Tên | Packet Data bắt đầu bằng |
|---|---|---|
| 0 | `LINKTYPE_NULL` | Header loopback BSD 4 byte |
| 1 | `LINKTYPE_ETHERNET` | Header Ethernet 14 byte |
| 101 | `LINKTYPE_RAW` | Header IPv4/IPv6, không có tầng liên kết |
| 105 | `LINKTYPE_IEEE802_11` | Header 802.11 |
| 113 | `LINKTYPE_LINUX_SLL` | Header "cooked" của Linux 16 byte (bắt trên giao diện `any`) |
| 127 | `LINKTYPE_IEEE802_11_RADIOTAP` | Header radiotap rồi tới 802.11 |
| 276 | `LINKTYPE_LINUX_SLL2` | Header "cooked" v2 của Linux 20 byte |

Bắt trên giao diện Ethernet như `eth0` cho giá trị 1. Bắt bằng `tcpdump -i any`
cho 113 hoặc 276, khi đó không có header Ethernet và địa chỉ MAC đích.

Theo đặc tả hiện hành, mã LINKTYPE nằm ở 16 bit thấp của trường; các bit cao
có thể mang thông tin độ dài FCS. Hầu hết file có các bit cao bằng 0.

## 3. Packet Header (16 byte)

Đứng trước mỗi gói tin. Đây là header của bản ghi trong file, không phải header
của giao thức mạng.

| Offset | Kích thước | Trường | Ý nghĩa |
|---|---|---|---|
| 0 | 4 | `ts_sec` | Thời điểm bắt gói: số giây từ 00:00:00 UTC ngày 01/01/1970 |
| 4 | 4 | `ts_usec` | Phần lẻ của giây: micro giây hoặc nano giây tùy `magic_number` |
| 8 | 4 | `incl_len` | Số byte của gói thực sự được lưu trong file |
| 12 | 4 | `orig_len` | Độ dài của gói trên đường truyền |

- Thời điểm bắt gói = `ts_sec + ts_usec / 10^6` (hoặc `/ 10^9` với file nano
  giây). Timestamp do máy bắt gói gán, không phải thời điểm gói được gửi đi.
- `incl_len <= orig_len` và `incl_len <= snaplen`. Khi `incl_len < orig_len`
  gói đã bị cắt.
- Đặc trưng về dung lượng (số byte của flow) phải tính từ `orig_len`, không
  phải `incl_len`, để không bị sai khi file được bắt với `snaplen` nhỏ.
- `ts_sec` chỉ có 32 bit không dấu nên biểu diễn được tới năm 2106.
- Packet Header không ghi giao diện bắt gói, hướng gói hay số gói bị mất.

## 4. Packet Data

Là `incl_len` byte ngay sau Packet Header, không có đệm và không có byte căn
lề. Bản ghi kế tiếp bắt đầu ngay sau byte cuối cùng.

Nội dung là gói tin tính từ header tầng liên kết do trường `network` chỉ định.
Với `LINKTYPE_ETHERNET`:

```
+----------------+-------------+-------------------+---------+
| Ethernet 14 B  | IPv4 >=20 B | TCP >=20 B/UDP 8 B | Payload |
+----------------+-------------+-------------------+---------+
```

- Phần mở đầu (preamble) của khung Ethernet không được lưu; FCS 4 byte ở cuối
  khung thường cũng không có.
- Khung có thẻ VLAN 802.1Q dài thêm 4 byte sau địa chỉ MAC nguồn, làm lệch vị
  trí header IP. Trình đọc phải xét EtherType thay vì giả định offset cố định.
- Khi gói bị cắt, các header phía sau có thể thiếu. Trình đọc phải kiểm tra độ
  dài trước khi phân tích từng tầng.

## 5. Ví dụ đọc từng byte

File dưới đây dài 82 byte, chứa một gói ARP request từ 192.168.50.20 hỏi địa
chỉ MAC của 192.168.50.30:

```
00000000  d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00
00000010  00 00 04 00 01 00 00 00 88 9a cc 6a 40 e2 01 00
00000020  2a 00 00 00 2a 00 00 00 ff ff ff ff ff ff 08 00
00000030  27 aa bb 01 08 06 00 01 08 00 06 04 00 01 08 00
00000040  27 aa bb 01 c0 a8 32 14 00 00 00 00 00 00 c0 a8
00000050  32 1e
```

Global Header (offset `0x00`–`0x17`):

| Byte | Trường | Giá trị |
|---|---|---|
| `d4 c3 b2 a1` | `magic_number` | `0xA1B2C3D4`: little-endian, micro giây |
| `02 00` | `version_major` | 2 |
| `04 00` | `version_minor` | 4 |
| `00 00 00 00` | `thiszone` | 0 |
| `00 00 00 00` | `sigfigs` | 0 |
| `00 00 04 00` | `snaplen` | `0x00040000` = 262144 |
| `01 00 00 00` | `network` | 1 = `LINKTYPE_ETHERNET` |

Packet Header (offset `0x18`–`0x27`):

| Byte | Trường | Giá trị |
|---|---|---|
| `88 9a cc 6a` | `ts_sec` | `0x6ACC9A88` = 1791793800 = 12/10/2026 08:30:00 UTC |
| `40 e2 01 00` | `ts_usec` | `0x0001E240` = 123456 micro giây |
| `2a 00 00 00` | `incl_len` | 42 |
| `2a 00 00 00` | `orig_len` | 42, gói không bị cắt |

Packet Data (offset `0x28`–`0x51`, 42 byte):

| Byte | Nội dung |
|---|---|
| `ff ff ff ff ff ff` | MAC đích: broadcast |
| `08 00 27 aa bb 01` | MAC nguồn |
| `08 06` | EtherType: ARP |
| `00 01 08 00 06 04 00 01` | ARP: Ethernet, IPv4, địa chỉ 6/4 byte, opcode 1 (request) |
| `08 00 27 aa bb 01` | MAC bên gửi |
| `c0 a8 32 14` | IP bên gửi: 192.168.50.20 |
| `00 00 00 00 00 00` | MAC bên nhận: chưa biết |
| `c0 a8 32 1e` | IP bên nhận: 192.168.50.30 |

Lưu ý hai thứ tự byte trong cùng một file: các trường của PCAP ở đây là
little-endian (`2a 00 00 00` = 42), còn các trường trong Packet Data theo thứ
tự mạng big-endian (`08 06` = `0x0806`).

## 6. PCAPNG

PCAPNG (PCAP Next Generation) không có header cố định ở đầu file. File là một
dãy **block**, mọi block có cùng khung:

```
+------------+--------------------+-------------------+--------------------+
| Block Type | Block Total Length | Block Body        | Block Total Length |
|   4 byte   |       4 byte       | đệm tới bội của 4 |       4 byte       |
+------------+--------------------+-------------------+--------------------+
```

Độ dài được ghi ở cả đầu và cuối block nên có thể duyệt file theo hai chiều và
bỏ qua block không hiểu. Phần lớn block có thể mang thêm các **option** dạng
mã–độ dài–giá trị ở cuối phần thân.

| Block | Mã | Vai trò |
|---|---|---|
| Section Header Block (SHB) | `0x0A0D0D0A` | Mở đầu một section; chứa Byte-Order Magic `0x1A2B3C4D`, phiên bản 1.0, độ dài section; option về phần cứng, hệ điều hành, chương trình bắt gói |
| Interface Description Block (IDB) | `0x00000001` | Mô tả một giao diện: kiểu liên kết, `snaplen`; option về tên giao diện, độ phân giải thời gian, bộ lọc |
| Enhanced Packet Block (EPB) | `0x00000006` | Một gói tin: chỉ số giao diện, timestamp 64 bit, độ dài đã lưu, độ dài gốc, dữ liệu gói; option về hướng gói, chú thích |
| Simple Packet Block (SPB) | `0x00000003` | Một gói tin tối giản: chỉ có độ dài gốc và dữ liệu, không có timestamp |
| Name Resolution Block (NRB) | `0x00000004` | Bảng ánh xạ địa chỉ IP sang tên |
| Interface Statistics Block (ISB) | `0x00000005` | Thống kê của giao diện: số gói nhận được, số gói bị mất |
| Decryption Secrets Block (DSB) | `0x0000000A` | Khóa giải mã, ví dụ khóa phiên TLS |

Một file tối thiểu có dạng `SHB, IDB, EPB, EPB, ...`. Mỗi EPB tham chiếu tới
một IDB qua chỉ số giao diện, nên một file chứa được gói từ nhiều giao diện có
kiểu liên kết khác nhau. Một file cũng có thể có nhiều section, mỗi section bắt
đầu bằng một SHB và có thứ tự byte riêng.

Timestamp trong EPB là số nguyên 64 bit chia làm hai nửa 32 bit, đơn vị do
option `if_tsresol` của giao diện quy định; mặc định là micro giây.

## 7. So sánh PCAP và PCAPNG

| Tiêu chí | PCAP | PCAPNG |
|---|---|---|
| Tổ chức file | Một header 24 byte, sau đó là các bản ghi gói | Dãy block có kiểu và độ dài |
| 4 byte đầu file | `D4 C3 B2 A1`, `A1 B2 C3 D4`, `4D 3C B2 A1` hoặc `A1 B2 3C 4D` | `0A 0D 0D 0A` |
| Nhận biết thứ tự byte | Qua `magic_number` | Qua Byte-Order Magic `0x1A2B3C4D` trong SHB |
| Số giao diện | Một | Nhiều, mỗi giao diện một IDB |
| Kiểu liên kết | Một giá trị cho cả file | Riêng cho từng giao diện |
| Timestamp | 32 bit giây + 32 bit phần lẻ; micro hoặc nano giây cho cả file | 64 bit; độ phân giải riêng cho từng giao diện |
| Thông tin kèm theo gói | Không có | Giao diện bắt gói, hướng gói, chú thích |
| Thông tin về phiên bắt | Không có | Hệ điều hành, chương trình bắt gói, bộ lọc, số gói bị mất |
| Phân giải tên, khóa giải mã | Không có | NRB, DSB |
| Mở rộng | Không; thêm trường là phá định dạng | Thêm kiểu block và option mới, trình đọc cũ bỏ qua được |
| Căn lề dữ liệu gói | Không đệm | Đệm tới bội của 4 byte |
| Đọc ngược từ cuối file | Không | Được, nhờ độ dài lặp lại ở cuối block |
| Độ phức tạp khi tự viết trình đọc | Thấp: hai cấu trúc cố định | Cao hơn: phải xử lý nhiều kiểu block và option |
| Mặc định của công cụ | tcpdump | Wireshark, dumpcap, tshark |
| Phần mở rộng file | `.pcap` (cũ: `.cap`, `.dmp`) | `.pcapng` |

Điểm chung: cả hai lưu gói tin thô kèm thời điểm bắt, độ dài đã lưu và độ dài
gốc; dùng chung bảng mã LINKTYPE; không nén và không có chỉ mục.

Phần mở rộng file không đáng tin, vì Wireshark có thể lưu PCAPNG với tên
`.pcap`. Cách nhận biết chắc chắn là đọc 4 byte đầu file.

Bản thu nén: nhiều nguồn (như CTU-13) phát hành PCAP/PCAPNG nén gzip hoặc bzip2.
`PcapReader` của dự án nhận ra file nén qua magic (`1f 8b` cho gzip, `42 5a 68`
= `BZh` cho bzip2, cũng không phụ thuộc tên file) và giải nén trong luồng, nên
đọc thẳng `.pcap.gz` / `.pcap.bz2` mà không cần giải nén trước. Mọi module đọc
gói (trích xuất đặc trưng, khảo sát, đối chiếu Wireshark, cảm biến) dùng chung
bộ đọc này nên cũng đọc được file nén. Khi tính mã băm thì vẫn băm chính file
nén trên đĩa.

## 8. Ghi chú cho dự án

- Kiểm tra định dạng: `capinfos <file>` hoặc `file <file>`.
- Chuyển PCAPNG sang PCAP: `editcap -F pcap vao.pcapng ra.pcap`. Việc chuyển
  làm mất chú thích, thông tin giao diện và thống kê mất gói, và không thực
  hiện được nếu file chứa các giao diện khác kiểu liên kết.
- Scapy đọc được cả hai định dạng: `rdpcap()` và `PcapReader` tự nhận dạng qua
  4 byte đầu file.
- tcpdump trên Kali ghi PCAP với `-w`; thêm `--time-stamp-precision=nano` nếu
  cần nano giây.
- Số gói bị mất (yêu cầu B20) không có trong file PCAP. Cần lấy từ dòng thống
  kê tcpdump in ra khi dừng, hoặc từ ISB nếu bắt bằng dumpcap ra PCAPNG.

## 9. Tài liệu tham khảo

- IETF, *PCAP Capture File Format*, draft-ietf-opsawg-pcap.
- IETF, *PCAP Next Generation (pcapng) Capture File Format*, draft-ietf-opsawg-pcapng.
- The Tcpdump Group, *Link-Layer Header Types*, https://www.tcpdump.org/linktypes.html
- Trang hướng dẫn `pcap-savefile(5)`.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| PCAP | Định dạng file cũ và phổ biến nhất để lưu gói tin bắt được; do tcpdump tạo ra |
| PCAPNG | PCAP Next Generation: định dạng mới hơn, linh hoạt hơn, là mặc định của Wireshark |
| Header | Phần đầu chứa thông tin mô tả; ở đây là header của file và của từng bản ghi, khác với header của giao thức mạng |
| Byte, offset | Byte là 8 bit; offset là vị trí tính từ đầu, đếm bằng byte và bắt đầu từ 0 |
| Hệ 16 (hex), 0x | Cách viết số dùng 0–9 và a–f; `0x` đứng trước để báo là số hệ 16. Một byte viết bằng hai chữ số hex, ví dụ `2a` = 42 |
| Thứ tự byte (endian) | Cách xếp các byte của một số nhiều byte. Little-endian để byte nhỏ trước (máy x86), big-endian để byte lớn trước (chuẩn của mạng) |
| Timestamp | Thời điểm, ở đây là lúc máy giám sát bắt được gói |
| Epoch | Mốc 00:00:00 UTC ngày 01/01/1970; thời điểm được ghi bằng số giây tính từ mốc này |
| Micro giây / nano giây | Một phần triệu / một phần tỷ giây |
| snaplen | Số byte tối đa được lưu cho mỗi gói; phần thừa bị cắt bỏ |
| Payload | Phần dữ liệu thật mà gói mang theo, nằm sau các header |
| Tầng liên kết (link layer) | Tầng thấp nhất trong file, như Ethernet hay Wi-Fi; quyết định gói bắt đầu bằng header nào |
| LINKTYPE | Mã số chỉ kiểu tầng liên kết, ví dụ 1 là Ethernet |
| Loopback | Card mạng ảo để máy nói chuyện với chính nó (127.0.0.1) |
| 802.11, radiotap | 802.11 là chuẩn Wi-Fi; radiotap là header thêm thông tin sóng vô tuyến khi bắt gói Wi-Fi |
| Linux cooked (SLL) | Header giả do Linux tạo khi bắt trên mọi card mạng cùng lúc (`tcpdump -i any`); thay cho header Ethernet |
| FCS | Mã kiểm tra lỗi 4 byte ở cuối khung Ethernet; thường không được lưu |
| incl_len / orig_len | Số byte thực sự lưu trong file / độ dài thật của gói trên đường truyền |
| Ethernet, khung (frame) | Ethernet là chuẩn mạng có dây; một gói ở tầng Ethernet gọi là khung |
| MAC | Địa chỉ phần cứng 6 byte của card mạng, ví dụ `08:00:27:aa:bb:01` |
| Broadcast | Gửi cho mọi máy trong mạng; địa chỉ MAC broadcast là `ff:ff:ff:ff:ff:ff` |
| EtherType | 2 byte trong header Ethernet cho biết bên trong là gì: `0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP |
| VLAN 802.1Q | Thẻ 4 byte chèn vào khung Ethernet để chia một mạng thành nhiều mạng logic |
| Preamble | Chuỗi bit đồng bộ đứng trước mỗi khung Ethernet trên dây; card mạng bỏ đi nên không có trong file |
| IPv4, IPv6 | Hai phiên bản giao thức địa chỉ Internet: IPv4 dạng `192.168.50.20`, IPv6 dạng `fe80::1` |
| TCP, UDP | TCP: giao thức có kết nối, bảo đảm dữ liệu tới đủ và đúng thứ tự (web, SSH). UDP: gửi đi không cần kết nối, không bảo đảm (DNS, video) |
| ARP | Giao thức hỏi "IP này là máy có MAC nào" trong mạng nội bộ |
| Opcode | Mã thao tác trong gói ARP: 1 là hỏi, 2 là trả lời |
| Block, option | Block là một khối dữ liệu có kiểu và độ dài trong PCAPNG; option là thông tin phụ dạng mã–độ dài–giá trị gắn vào block |
| Section | Một phần của file PCAPNG, mở đầu bằng SHB |
| SHB, IDB, EPB, SPB, NRB, ISB, DSB | Các kiểu block của PCAPNG: mở đầu section; mô tả card mạng; gói tin đầy đủ; gói tin tối giản không có thời điểm; bảng tên miền; thống kê card mạng; khóa giải mã |
| Giao diện (interface) | Một card mạng, thật hoặc ảo, ví dụ `eth0` |
| if_tsresol | Option của IDB cho biết đơn vị thời gian của giao diện đó |
| TLS | Giao thức mã hóa dùng cho HTTPS |
| tcpdump, Wireshark, dumpcap, tshark | Công cụ bắt và xem gói tin: tcpdump chạy dòng lệnh; Wireshark có giao diện đồ họa; dumpcap và tshark là bản dòng lệnh đi kèm Wireshark |
| capinfos, editcap | Công cụ đi kèm Wireshark: xem thông tin file / chuyển đổi và cắt file |
| Scapy | Thư viện Python để bắt và tạo gói tin |
| Mất gói | Gói đi qua mạng nhưng máy giám sát không kịp ghi |
