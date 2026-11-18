# Phát hiện dấu hiệu giả mạo ARP

Mã nguồn: `src/nids/arp_gia_mao.py`. Kiểm thử: `tests/test_arp_gia_mao.py`. Kết quả trên lab:
`docs/hinh/arp_lab.json`. Quyết định: QĐ-078.

```bash
cd src
python -m nids.arp_gia_mao ../data/pcap/lab/*.pcap --out ../docs/hinh/arp_lab.json
```

## 1. Vì sao cần

Bộ trích xuất của ba module chỉ đọc gói IP; gói ARP bị bỏ qua và chỉ được đếm (docs/14). Vì vậy hệ thống không
thấy được giả mạo ARP: kẻ tấn công gửi gói ARP nói "IP của cổng mạng (hoặc của máy khác) là MAC của tôi" để
traffic đi qua máy mình. Tấn công này nằm ngoài ba lớp `benign` / `port_scan` / `dos` và không cần học máy: dấu
hiệu của nó là một quan hệ "IP → MAC" bị đổi, kiểm tra được bằng quy tắc.

## 2. Cách làm

Module đọc riêng các gói ARP trong bản thu (khung Ethernet, có thể có thẻ VLAN, hoặc Linux cooked) và giữ bảng
"IP → MAC" học từ trường **người gửi** của mỗi gói ARP. Gói thăm dò (IP người gửi `0.0.0.0`) không được học.

| Dấu hiệu | Khi nào báo | Mức |
|---|---|---|
| `doi_mac` | IP đã gắn với MAC A, nay một gói ARP nói IP đó thuộc MAC B | Dấu hiệu chính của giả mạo ARP. Cũng xảy ra khi thay card mạng, nên cảnh báo ghi MAC cũ, MAC mới và lần cuối thấy MAC cũ để người vận hành kiểm tra |
| `mot_mac_nhieu_ip` | Một MAC nhận là chủ của từ 3 IP trở lên | Nghi vấn: kẻ giả mạo nhiều máy có dấu hiệu này, bộ định tuyến làm proxy ARP cũng vậy |
| `khung_khong_khop` | MAC nguồn của khung Ethernet khác MAC người gửi ghi trong gói ARP | Nghi vấn: gói ARP được dựng tay |

Module chỉ đọc bản thu, không phát gói nào.

## 3. Kết quả

| Kiểm tra | Kết quả |
|---|---|
| Kiểm thử với gói ARP dựng tay: bình thường, thăm dò, đổi MAC, một MAC nhận nhiều IP, khung không khớp | Báo đúng ba dấu hiệu, không báo trên gói bình thường và gói thăm dò |
| 174 bản thu lab đã có (mọi kịch bản, 8 373 gói ARP) | **0 cảnh báo** |

Lab không có lần chạy giả mạo ARP thật: yêu cầu B24 cấm gói giả mạo nguồn trong lab, nên phần "bắt được" chỉ mới
kiểm bằng gói dựng tay trong kiểm thử. Phần "không báo nhầm" đã kiểm trên traffic ARP thật của lab.

## 4. Giới hạn

- ~~Chạy trên file PCAP, chưa nối vào cảm biến realtime.~~ Đã nối (18/11/2026, QĐ-085): cảm biến realtime đưa mọi
  gói không phải IP qua `ArpWatch`; mỗi dấu hiệu được ghi một dòng vào `<tên>.arp.jsonl` và một dòng cảnh báo vào
  log; `so_lieu_tong.json` có mục `arp` (số gói ARP, số cảnh báo). Phát lại `k6-p2p-test-13` qua cảm biến: 434 gói
  ARP, 0 cảnh báo. Cảnh báo ARP không vào `alerts.csv` vì không thuộc ba module học máy.
- Nếu kẻ tấn công giả mạo ngay từ gói ARP đầu tiên của một IP (trước khi máy thật lên tiếng), bảng học sai từ đầu
  và chỉ báo khi máy thật trả lời.
- Chưa đọc ARP trong IPv6 (IPv6 dùng Neighbor Discovery qua ICMPv6, không dùng ARP).

## Thuật ngữ

| Thuật ngữ | Giải thích |
|---|---|
| ARP | Giao thức hỏi "IP này là của card mạng nào" trong mạng cục bộ |
| MAC | Địa chỉ phần cứng của card mạng, dùng trong mạng cục bộ |
| Giả mạo ARP (ARP spoofing) | Gửi gói ARP sai để máy khác gửi traffic về máy mình |
| Gói thăm dò ARP | Gói ARP máy gửi trước khi dùng một IP, để xem có ai đang dùng IP đó không |
| Proxy ARP | Bộ định tuyến trả lời ARP thay cho máy ở mạng khác; hợp lệ nhưng trông giống giả mạo |
| VLAN | Chia một mạng vật lý thành nhiều mạng logic; khung có thêm thẻ 4 byte |
| Linux cooked | Dạng khung mà tcpdump ghi khi bắt trên mọi card cùng lúc |
| B24 | Yêu cầu an toàn: traffic lab vô hại, không giả mạo nguồn, không ra ngoài lab |
