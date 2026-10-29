# C04-T06 — Số đích, cổng đích, kết nối mới và entropy cổng

Mã nguồn: `src/nids/window_features.py` (`HostWindowFeatures`, `WindowPipeline`).
Kiểm thử: `tests/test_window_features.py`. Quyết định: QĐ-022 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md). Cửa sổ host theo
[22_cua_so_host.md](22_cua_so_host.md); flow và chiều theo
[18_flow_hai_chieu.md](18_flow_hai_chieu.md), [19_ket_thuc_flow.md](19_ket_thuc_flow.md).

```bash
python -m nids.window_features data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/windows.csv
```

Lệnh đọc gói một lượt, vừa ghép flow vừa lập cửa sổ host, nên biết được với mỗi
gói host đang ở vai **client** (gửi gói forward của flow) hay **server**.

## 1. Đặc trưng

Tính cho mỗi cặp (host, cửa sổ 10 giây), thêm vào các cột của C04-T05:

| Cột | Công thức | Đơn vị |
|---|---|---|
| `dst_hosts` | Số IP đích khác nhau trong các gói host gửi **trong vai client** | host |
| `dst_ports` | Số cổng đích TCP/UDP khác nhau trong các gói đó | cổng |
| `dst_host_ports` | Số cặp (IP đích, cổng đích) khác nhau | cặp |
| `new_conn_out` | Số flow mới **do host mở** (host là client) có gói đầu nằm trong cửa sổ | kết nối |
| `src_hosts` | Số IP nguồn khác nhau gửi gói forward tới host (host là server) | host |
| `new_conn_in` | Số flow mới **mở tới host** (host là server) có gói đầu nằm trong cửa sổ | kết nối |
| `dst_port_entropy` | Entropy Shannon của cổng đích trên các gói host gửi trong vai client | bit |

**Entropy cổng:** `H = −Σ p_i · log2(p_i)`, với `p_i` là tỷ lệ số gói tới cổng i
trong các gói TCP/UDP host gửi trong vai client. H = 0 khi mọi gói tới cùng một
cổng; H = log2(k) khi gói chia đều cho k cổng. Ví dụ 20 cổng đều nhau thì H ≈ 4,32
bit. Tính theo gói chứ không theo kết nối, nên một kết nối tải file lớn tới cổng
443 kéo H về gần 0, đúng với hành vi bình thường.

Ý nghĩa với các kiểu tấn công:

| Hành vi | Dấu hiệu |
|---|---|
| Quét dọc (nhiều cổng, một máy) | `dst_ports`, `dst_port_entropy` cao, `dst_hosts` = 1 |
| Quét ngang (một cổng, nhiều máy), sâu lan truyền, spam | `dst_hosts` cao, `dst_ports` thấp, entropy ≈ 0 |
| DoS / DDoS vào một server | Ở server: `new_conn_in` rất cao; DDoS thêm `src_hosts` cao |
| Botnet gọi về máy chủ điều khiển | `dst_hosts` nhỏ, ổn định theo thời gian (dùng ở chặng botnet) |

## 2. Vì sao chỉ đếm gói trong vai client

Server web trả lời nhiều client sẽ gửi gói tới **cổng tạm** của từng client
(49152–65535), mỗi client một cổng. Nếu đếm cả gói trả lời, `dst_ports` và entropy
của server sẽ cao như máy quét cổng. Vì vậy:
- Gói host gửi đi được tính vào `dst_*` **chỉ khi gói đó đi theo chiều forward**,
  tức host là client của flow. Chiều do C04-T01 xác định.
- Gói forward host nhận được tính vào `src_hosts`, tức host là server của flow.
- Gói trả lời (backward) vẫn được đếm trong `packets_out`, `bytes_out` của C04-T05.

## 3. Kết nối mới

- Kết nối mới = gói đầu tiên của một flow **không phải phần tiếp nối** (`continuation
  = 0`, QĐ-017). Phần sau của kết nối dài bị active timeout cắt, hoặc phần tiếp sau
  khoảng nhàn rỗi, không bị tính là kết nối mới.
- Kết nối được tính cho cửa sổ chứa gói đầu của flow; các cửa sổ chồng nhau chứa
  gói đó đều tính.
- Mỗi kết nối được tính cho client (`new_conn_out`) và cho server (`new_conn_in`),
  theo đầu mút forward/backward của flow, không theo IP của gói đầu. Flow mở bằng
  SYN+ACK vẫn tính cho đúng client.
- Lần thử kết nối TCP bị từ chối (SYN rồi RST) vẫn là một kết nối mới. Việc nó không
  hoàn tất là đặc trưng của C04-T07 ([24_ket_noi_khong_hoan_tat.md](24_ket_noi_khong_hoan_tat.md)).

## 4. Trường hợp biên

| Trường hợp | Kết quả |
|---|---|
| Host chỉ trả lời, không mở kết nối nào | `dst_hosts = dst_ports = 0`, `dst_port_entropy` trống |
| Gói ICMP, IGMP (không có cổng) | Tính vào `dst_hosts`, `src_hosts`; không vào `dst_ports`, entropy |
| Host không gửi gói TCP/UDP nào trong vai client | `dst_port_entropy` trống (không phải 0) |
| Một cổng duy nhất | `dst_port_entropy = 0` |
| Flow giữa hai cổng cùng ≥ 1024 bắt giữa chừng | Vai client theo quy tắc `goi_dau` của QĐ-016 |

## 5. Kiểm tra

**Tính lại từ Wireshark.** Một script tạm đọc IP, cổng, cờ và thời điểm của từng gói
bằng tshark, rồi tự xác định client theo quy tắc của QĐ-016:
- TCP: bên gửi SYN, hoặc bên nhận SYN+ACK, của `tcp.stream`; bắt giữa chừng thì
  dùng cổng dịch vụ.
- UDP: bên gửi gói đầu của `udp.stream`.
- ICMP: bên gửi gói đầu giữa hai IP.

Sau đó script lập cửa sổ vét cạn và so 5 cột với CSV của dự án. Không so
`new_conn_*`, vì Wireshark tách kết nối khác dự án (không có timeout).

| File | Host | Cửa sổ so | Lệch |
|---|---|---|---|
| CIC thứ Sáu, đoạn port scan 14:51–14:57 (344 181 gói) | `172.16.0.1`, `192.168.10.50` | 294 | 0 |
| donbot (bot spam) | `147.32.84.165` | 3 157 | 0 |
| WSL (có IPv6, ICMPv6) | mọi host | 86 | 0 |

Lần chạy đầu trên đoạn port scan có lệch, do chính script kiểm tra: script chưa tính
ICMP và chưa dùng quy tắc cổng dịch vụ cho kết nối bắt giữa chừng (đoạn được cắt
giữa ngày). Sửa script cho đúng QĐ-016 thì hết lệch.

Kết quả trên đoạn port scan (cửa sổ có nhiều cổng đích nhất): `172.16.0.1` tới 1
host, 998 cổng, 6 986 kết nối mới trong 10 giây, entropy 9,95 bit (gần log2(998) ≈
9,96, tức các cổng được gõ gần như đều nhau). Đó là dấu hiệu quét dọc rõ ràng.

**Kiểm thử tự động** (10 ca mới, tổng 212 ca của dự án): entropy của phân bố đều,
một giá trị, rỗng; quét dọc (cả phía nạn nhân); quét ngang; server trả lời không bị
tính là đích; entropy theo số gói; ICMP; phần tiếp nối không phải kết nối mới; kết
nối tính ở cửa sổ của gói đầu; mọi cột có đơn vị; dòng lệnh ghi CSV.

## 6. Giới hạn

- Vai client dựa vào chiều của C04-T01. Với flow bắt giữa chừng giữa hai cổng cao
  (P2P) có thể sai chiều.
- Mọi máy sau NAT bị coi là một host (ở CIC: `172.16.0.1`).

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Vai client / server | Bên mở kết nối / bên nhận kết nối của một flow |
| Gói forward | Gói đi từ client sang server |
| Cổng tạm (ephemeral port) | Cổng số cao client tự chọn cho mỗi kết nối, ví dụ 49152–65535 |
| Entropy Shannon | Độ "đa dạng" của một phân bố, tính bằng bit; 0 là chỉ một giá trị, càng nhiều giá trị chia đều càng cao |
| Quét dọc / quét ngang | Dò nhiều cổng của một máy / dò một cổng trên nhiều máy |
| Kết nối mới | Flow mới bắt đầu, không phải phần tiếp của kết nối đã có |
| Phần tiếp nối (continuation) | Flow nối tiếp của cùng một kết nối sau timeout (QĐ-017) |
| DDoS | Tấn công từ chối dịch vụ từ nhiều nguồn cùng lúc |
| Sâu (worm) lan truyền | Mã độc tự quét các máy khác để lây sang |
| P2P | Mạng ngang hàng, hai bên đều dùng cổng cao |
| NAT | Nhiều máy dùng chung một IP khi đi qua tường lửa |
