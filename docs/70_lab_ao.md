# C11-T01 — Lab ảo 7 node và nhật ký ground truth

Mã nguồn: `scripts/lab_ao.py` (dựng lab, chạy kịch bản, ghi nhật ký), `scripts/chay_chang_11.sh` (chạy mọi
biến thể), `src/nids/thuc_nghiem.py` (đọc nhật ký làm ground truth). Kiểm thử: `tests/test_thuc_nghiem.py`.
Quyết định: QĐ-061.

## 1. Vì sao dùng lab ảo

Kế hoạch (docs/09) cần mạng lab 7 node với máy giám sát bắt gói qua cổng mirror. Nhóm chưa có 7 máy thật, nên
lab được dựng **ảo trên một máy Linux** (đã chạy trên WSL2 Ubuntu 26.04, nhân 6.18):

| Thành phần lab thật | Trong lab ảo |
|---|---|
| 7 máy `192.168.50.10`–`.50` | 7 network namespace, mỗi cái có ngăn xếp TCP/IP riêng của nhân Linux |
| Switch | Bridge `nlb<N>` |
| Cổng mirror (B13) | `tc mirred`: mọi khung **đi vào** switch từ một máy được sao sang máy giám sát, đúng một lần |
| Máy giám sát Kali | Namespace `.10`, **không cắm vào switch**, chỉ nhận bản sao; chạy `tcpdump` |
| Mạng cô lập (B24) | Bridge không có địa chỉ IP, không có đường đi ra ngoài |
| Máy chủ dịch vụ | Nginx thật trong namespace `.30`, access log định dạng `nids` (docs/05) |

Gói tin là **gói thật** do nhân Linux, Nginx, Nmap và các script sinh traffic tạo ra; không phải gói tổng hợp.
Card ảo được tắt gộp/tách gói (TSO/GSO/GRO) và tắt tính checksum hộ, để gói bắt được giống gói trên dây.

**Giới hạn so với lab vật lý** (phải ghi khi dùng số liệu):
- Độ trễ đường truyền gần bằng 0 và không mất gói trên "dây".
- Mọi máy dùng chung một đồng hồ nên độ lệch đồng hồ bằng 0 (lab thật phải đo).
- Mọi máy là Linux; không có hệ điều hành khác, không có thiết bị mạng thật.
- Máy giám sát là namespace Ubuntu trên WSL2, không phải Kali; số gói nhân bỏ đo được là của máy này.

## 2. Cách dùng

Chạy bằng root trên Linux (cần `iproute2`, `tcpdump`, `nmap`, `nginx`, `ethtool`):

```bash
python3 scripts/lab_ao.py dung --lab 1          # dựng lab số 1
python3 scripts/lab_ao.py kiem-tra --lab 1      # bắt thử -> data/pcap/lab/kiem_tra_mirror.pcap
python3 scripts/lab_ao.py chay --lab 1 --bien-the k3-dos-muc2 --vai-tro test --lan 1 2 3
python3 scripts/lab_ao.py go --lab 1            # gỡ lab
bash scripts/chay_chang_11.sh                   # mọi biến thể, test, lần 1 2 3 (11 lab song song)
```

Nhiều lab chạy song song được: mỗi lab có bridge và namespace riêng nên dùng cùng dải địa chỉ mà không thấy nhau.

Kiểm tra mirror (điều kiện 2 của docs/09 mục 6) bằng công cụ của Chặng 10:

```bash
cd src && python -m nids.cam_bien ../data/pcap/lab/kiem_tra_mirror.pcap --net 192.168.50.0/24
```

Kết quả (`docs/hinh/thuc_nghiem/lab/kiem_tra_mirror.json`): 382 gói, 21 kết nối TCP, **100% thấy hai chiều**,
không có cặp máy nào chỉ thấy một chiều, kết luận `dat`.

## 3. Một lần chạy

Lệnh `chay` làm đúng thứ tự của docs/09:

1. Bật Nginx trên `.30` với access log mới (thay cho bước xoay vòng log) và các máy nhận của kịch bản.
2. Bật `tcpdump` trên máy giám sát, chờ nó mở xong card.
3. Bật **traffic nền bình thường**: client duyệt web nghỉ 1–6 giây, kiểm tra trạng thái `api/status` mỗi ~30 giây.
4. Tới thời điểm đã định thì chạy **hành vi** của biến thể; ghi giờ bắt đầu và kết thúc thật.
5. Chờ hết thời lượng, luôn để lại một đoạn bình thường sau hành vi; dừng `tcpdump` và đọc số gói bắt/bỏ.
6. Chép PCAP, access log, nhật ký về thư mục dự án.

| Biến thể | Nền | Hành vi | Thời lượng bản thu |
|---|---|---|---|
| `k1-binh-thuong` | `.41`–`.43` | (chỉ có nền) | 600 s |
| `k2-quet-cham` | `.41`–`.43` | `.20` chạy `nmap -sT -p 1-1024 --scan-delay 500ms` tới `.30`, bắt đầu sau 90–150 s | khoảng 13 phút |
| `k2-quet-nhanh` | `.41`–`.43` | `.20` chạy `nmap -sT -p 1-1024 -T4` tới `.30`, bắt đầu sau 120–360 s | 600 s |
| `k3-dos-muc1/2/3` | `.41`–`.43` | `.20` chạy `sinh_traffic.py tai-ket-noi` 60 s, 50/200/600 kết nối mỗi giây, bắt đầu sau 90–150 s | 300 s |
| `k4-co-dinh` | `.20`, `.41`–`.43` | ba bot gọi `.50:8080` 600 s; chu kỳ 30/60/45 s theo lần, jitter 0 | 700 s |
| `k4-bien-thien` | như trên | như trên, jitter ±20/40/30% | 700 s |
| `k4-doi-chung` | như trên | ba máy gọi máy chủ dịch vụ `.30:80` định kỳ (lành tính); jitter 0/10/30% | 700 s |
| `k5-p2p` | như trên | ba bot gửi UDP `:40000` cho nhau 600 s; chu kỳ 8/20/30 s; peer: lưới/vòng/lưới | 700 s |
| `k5-doi-chung` | như trên | ba máy chia sẻ khối dữ liệu TCP `:6881` theo đợt (lành tính) | 700 s |

**Lịch mỗi lần khác nhau (B19)**: thời điểm bắt đầu hành vi, độ dài đoạn bình thường sau cùng và seed của từng
máy sinh traffic lấy ngẫu nhiên theo seed suy từ mã lần chạy; số lần (`--lan`) đổi chu kỳ và danh sách peer.
Mọi tham số chốt trong mã trước khi chạy; vai trò (`train`/`val`/`test`) bắt buộc phải khai khi gọi (B11).

An toàn (B24): traffic chỉ do `sinh_traffic.py`, `sinh_topology.py` (vô hại, từ chối đích ngoài lab) và Nmap
connect scan tới máy chủ dịch vụ của lab sinh ra; tải kết nối bị chặn cứng ở 60 giây (B16).

## 4. Nhật ký lần chạy — ground truth độc lập với dự đoán (B10)

Mỗi lần chạy ghi `data/run_logs/<run_id>.json`. `lab_ao.py` **không đọc bất kỳ kết quả nào của mô hình**: nhật
ký chỉ chứa những gì bộ chạy đã làm và lúc nào. Nội dung khớp danh sách bắt buộc ở docs/09 mục 5:

| Trường | Nội dung |
|---|---|
| `ma_lan_chay`, `bien_the`, `vai_tro`, `lan`, `seed` | Mã lần chạy `<biến thể>-<vai trò>-<số>` và seed của lịch |
| `ban_thu` | File PCAP, giờ bắt đầu/kết thúc bản thu, SHA-256, số gói bắt được, số gói qua bộ lọc, **số gói nhân bỏ** |
| `hanh_vi[]` | Từng hành vi: kiểu, nhãn (`port_scan`/`dos`/`botnet`/`benign`), giờ bắt đầu/kết thúc (ISO và epoch), IP nguồn, IP đích, tham số, lệnh đã chạy, mã thoát |
| `nen` | Traffic nền bình thường: máy nguồn, đích, khoảng thời gian |
| `lech_dong_ho_s` | 0 (các máy ảo chung đồng hồ) |
| `moi_truong` | Kiểu lab, nhân, phiên bản Nmap |
| `nhat_ky_may_sinh[]` | Các dòng nhật ký do chính script sinh traffic ghi (đối chiếu) |

Access log của Nginx lưu ở `data/service_logs/<run_id>/access_nids.log`, chỉ để đối chiếu, không dùng gán nhãn.

Bộ đo đọc nhật ký này bằng `--nhat-ky data/run_logs` (lấy file theo tên PCAP):

```bash
cd src
python -m nids.thuc_nghiem ../data/pcap/lab/k3-dos-muc2-test-01.pcap --net 192.168.50.0/24 \
    --nhat-ky ../data/run_logs --giu ../output/thuc_nghiem_lab --out ../docs/hinh/thuc_nghiem/lab
```

Quy tắc dựng ground truth từ nhật ký (`attacks_from_runlog`):

- Hành vi nhãn `benign` (nền, đối chứng) **không** thành đợt tấn công; mọi cảnh báo trên chúng là báo động giả.
- `dos`, `port_scan`: host của đợt là máy nguồn và máy nạn nhân (giống cách tính với lịch nhãn CIC).
- `botnet`: host của đợt là các bot. Cảnh báo trên máy điều khiển không tính là phát hiện bot, nhưng cũng
  không tính là báo động giả.
- Thời điểm bắt đầu lấy theo epoch (mili giây) ghi lúc chạy lệnh.
- Mỗi đợt ghi thêm `anomaly_do_tre_s`: module anomaly có báo trên host của đợt không. Anomaly không nêu loại
  tấn công nên **không** tính là phát hiện, chỉ dùng để phân tích bỏ sót.

## 5. Kiểm thử

`tests/test_thuc_nghiem.py` (10 ca): thêm đọc nhật ký theo tên PCAP; đối chứng `benign` không thành đợt; bot là
host của đợt còn máy điều khiển chỉ để giải thích; cảnh báo anomaly ghi riêng, không tính là phát hiện. Toàn bộ:
421 ca đạt.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Network namespace | Cơ chế của Linux cho mỗi nhóm tiến trình một bộ card mạng, địa chỉ và bảng định tuyến riêng, như một máy riêng |
| Bridge | Switch ảo trong nhân Linux |
| veth | Cặp card ảo nối với nhau như một sợi dây mạng |
| tc mirred | Tính năng của Linux sao chép gói đi qua một card sang card khác |
| Cổng mirror (SPAN) | Cổng switch nhận bản sao mọi gói, dùng cho máy giám sát |
| TSO/GSO/GRO | Card gộp nhiều gói thành một gói lớn để xử lý nhanh; tắt đi để gói bắt được giống trên dây |
| Ground truth | Sự thật đã biết trước (hành vi nào, máy nào, lúc nào), dùng để chấm kết quả phát hiện |
| Nhật ký lần chạy | File ghi mọi việc bộ chạy đã làm trong một lần chạy; căn cứ gán nhãn |
| Traffic nền | Lưu lượng bình thường chạy suốt bản thu, để hành vi cần phát hiện lẫn trong đó |
| Đối chứng | Hành vi lành tính có hình dạng giống tấn công, để đo báo nhầm |
| Seed | Số khởi tạo ngẫu nhiên; cùng seed thì lịch chạy giống hệt |
| Epoch | Số giây tính từ 01/01/1970 UTC |
| WSL2 | Linux chạy trong Windows bằng máy ảo nhẹ |
