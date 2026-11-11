# C11-T02..T07 — Kết quả kiểm thử trên lab ảo

Dữ liệu: 33 lần chạy `test` (11 biến thể × 3 lần, docs/09) thu ngày 11/11/2026 trên lab ảo 7 node
([70_lab_ao.md](70_lab_ao.md)). Mô hình và ngưỡng đã khóa từ Chặng 6–9 (học trên CIC-IDS2017 và CTU-13), **không
chỉnh gì theo dữ liệu lab**. Pipeline chạy chế độ `ket_hop`.

```bash
sudo bash scripts/chay_chang_11.sh                      # thu 33 lần chạy (11 lab song song, khoảng 40 phút)
cd src
python -m nids.thuc_nghiem ../data/pcap/lab/k3-*.pcap --net 192.168.50.0/24 --nhat-ky ../data/run_logs \
    --giu ../output/thuc_nghiem_lab --out ../docs/hinh/thuc_nghiem/lab --ten k3
```

| Sản phẩm | Vị trí | Trên git |
|---|---|---|
| PCAP | `data/pcap/lab/<run_id>.pcap` (33 file, 181 MB) | Không (quy ước của repo); SHA-256 ghi trong nhật ký |
| Nhật ký lần chạy (ground truth) | `data/run_logs/<run_id>.json` | Có |
| Access log Nginx | `data/service_logs/<run_id>/access_nids.log` | Không; số đối chiếu ở `docs/hinh/thuc_nghiem/lab/access_log.json` |
| Cảnh báo và sự kiện | `output/thuc_nghiem_lab/<run_id>.alerts.csv`, `.su_kien.csv` | Không |
| Số liệu | `docs/hinh/thuc_nghiem/lab/*.json` | Có |

Cách tính (docs/70 mục 4, `src/nids/thuc_nghiem.py`):

- **Phát hiện**: đợt tấn công có ít nhất một cảnh báo đúng loại, trên host của đợt, trong khoảng thời gian của
  đợt. Không có thì là **bỏ sót**.
- **Độ trễ**: cuối cửa sổ của cảnh báo đầu tiên − thời điểm bắt đầu hành vi ghi trong nhật ký. Đã gồm thời
  gian tích lũy cửa sổ. Cửa sổ 10 giây trượt mỗi 2 giây, nên cửa sổ đầu tiên chứa hành vi kết thúc trong vòng
  2 giây sau khi hành vi bắt đầu; con số này **chưa gồm** thời gian cảm biến realtime chờ và xử lý (đo riêng ở
  C11-T08).
- **Báo động giả**: sự kiện cảnh báo (đã gộp) không do đợt tấn công nào gây ra. Một sự kiện chỉ được coi là
  do đợt tấn công gây ra nếu cùng host, chồng thời gian, và không bắt đầu sớm hơn đầu đợt quá 40 giây (module
  botnet: 150 giây). Cảnh báo kéo dài từ đầu bản thu vì vậy vẫn là báo động giả.

## 1. C11-T02 — Traffic bình thường, có tác vụ định kỳ hợp lệ

Biến thể `k1-binh-thuong`: ba client `.41`–`.43` duyệt web tới máy chủ dịch vụ `.30` trong 10 phút, nghỉ 1–6
giây giữa hai yêu cầu, và gọi `api/status` (kiểm tra trạng thái) mỗi ~30 giây. Không có tấn công.

| Lần | Thời lượng | Gói bắt được | Gói nhân bỏ | Yêu cầu HTTP (access log) | Trong đó `api/status` | Sự kiện báo động giả |
|---|---|---|---|---|---|---|
| test-01 | 602 s | 8 493 | 0 | 521 (đều mã 200) | 123 | 1 |
| test-02 | 602 s | 7 745 | 0 | 516 (đều mã 200) | 126 | 1 |
| test-03 | 602 s | 7 941 | 0 | 521 (đều mã 200) | 130 | 1 |

Kết quả (`docs/hinh/thuc_nghiem/lab/k1.json`):

- **Bộ phân loại và module botnet không báo gì** trên cả ba lần: không có cảnh báo `port_scan`, `dos` hay
  `suspect_host` nào. Tác vụ kiểm tra trạng thái định kỳ **không** bị coi là beaconing của bot.
- **Ba client không có cảnh báo nào** từ cả ba module.
- **Module anomaly báo máy chủ dịch vụ `.30` suốt cả bản thu** ở cả ba lần: đúng một sự kiện dài 604 giây mỗi
  lần, tức 5,8 sự kiện mỗi giờ nhưng thực chất là **báo liên tục 100% thời gian trên một host**.

Nguyên nhân: Gaussian học "bình thường" từ ngày thứ Hai của CIC-IDS2017, nơi không có host nào chỉ nhận kết
nối HTTP ngắn từ vài client như máy chủ của lab. Đây đúng là thiếu hụt đã nêu ở docs/09 mục 1 ("Gaussian học
trên CIC không mô tả được trạng thái bình thường của lab"). Việc cần làm: fit lại Gaussian trên các lần chạy
`train` của kịch bản 1.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Lần chạy `test` | Lần chạy chỉ để đánh giá cuối, không dùng để chỉnh mô hình hay ngưỡng |
| Biến thể | Một cách chạy cụ thể của kịch bản, ví dụ quét chậm và quét nhanh |
| Ground truth | Sự thật đã biết trước (hành vi nào, máy nào, lúc nào), lấy từ nhật ký lần chạy |
| Đợt tấn công | Một hành vi tấn công của một lần chạy, trên các host và khoảng thời gian ghi trong nhật ký |
| Phát hiện / bỏ sót | Đợt tấn công có / không có cảnh báo đúng loại |
| Độ trễ phát hiện | Thời gian từ lúc hành vi bắt đầu tới cuối cửa sổ của cảnh báo đầu tiên |
| Cửa sổ trượt | Khoảng 10 giây dùng để tính đặc trưng, cứ 2 giây lại dịch một bước |
| Báo động giả | Cảnh báo không do đợt tấn công nào gây ra |
| Sự kiện | Nhiều cảnh báo liên tiếp cùng module, nhãn, host được gộp làm một |
| Chế độ `ket_hop` / `doc_lap` | `ket_hop`: bộ phân loại chấm mọi cửa sổ, module botnet chỉ xét host bị anomaly báo. `doc_lap`: ba module chấm độc lập mọi host |
| Connect scan | Kiểu quét cổng mở kết nối TCP đầy đủ tới từng cổng |
| Tải kết nối | Mở rồi đóng liên tục nhiều kết nối TCP tới một máy chủ |
| Beaconing | Bot gọi về máy điều khiển theo chu kỳ |
| Jitter | Độ lệch ngẫu nhiên quanh chu kỳ |
| Peer | Máy ngang hàng mà một máy trao đổi trực tiếp |
| Đối chứng | Hành vi lành tính có hình dạng giống tấn công, để đo báo nhầm |
| Access log | File của máy chủ web ghi mỗi yêu cầu nhận được |
| Gaussian | Mô hình của module anomaly, học hình dạng của traffic bình thường |
