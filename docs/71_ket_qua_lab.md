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

## 2. C11-T03 — Port scan

Máy thử nghiệm `.20` chạy **Nmap 7.98 connect scan** (`-sT`) tới 1 024 cổng đầu của máy chủ `.30`, có traffic
bình thường của ba client trước, trong và sau. Chậm: `--scan-delay 500ms` (2 cổng mỗi giây, quét mất 512 giây).
Nhanh: `-T4` (cả 1 024 cổng trong chưa tới 0,1 giây).

| Lần | Bắt đầu quét sau | Thời gian quét | Phát hiện | Độ trễ | Cửa sổ cảnh báo `port_scan` | Host bị báo |
|---|---|---|---|---|---|---|
| `k2-quet-cham-test-01` | 119 s | 512,3 s | ✓ | **1,8 s** | 521 | `.20` và `.30` |
| `k2-quet-cham-test-02` | 98 s | 512,4 s | ✓ | **2,5 s** | 520 | `.20` và `.30` |
| `k2-quet-cham-test-03` | 94 s | 512,4 s | ✓ | **1,4 s** | 522 | `.20` và `.30` |
| `k2-quet-nhanh-test-01` | 167 s | 0,05 s | ✓ | **1,8 s** | 10 | `.20` và `.30` |
| `k2-quet-nhanh-test-02` | 236 s | 0,06 s | ✓ | **0,9 s** | 10 | `.20` và `.30` |
| `k2-quet-nhanh-test-03` | 132 s | 0,06 s | ✓ | **1,5 s** | 10 | `.20` và `.30` |

Kết quả (`docs/hinh/thuc_nghiem/lab/k2.json`):

- **Phát hiện 6/6 lượt quét, 0 bỏ sót**, ở cả hai tốc độ. Bộ phân loại học từ quét cổng của CIC-IDS2017
  (một máy quét một máy trên mạng khác) vẫn nhận ra Nmap trong lab.
- **Độ trễ 0,9–2,5 giây** tính tới cuối cửa sổ đầu tiên có cảnh báo. Với quét chậm, cửa sổ đó mới chỉ chứa
  3–5 lần thử cổng: bộ phân loại báo rất sớm vì `.20` không có traffic nào khác ngoài các kết nối bị từ chối.
- Quét chậm được báo **liên tục suốt 512 giây** (520–522 cửa sổ); quét nhanh nằm trọn trong 10 cửa sổ (5 cửa
  sổ trượt chồng lên thời điểm quét, trên mỗi host).
- Cả bên quét `.20` lẫn nạn nhân `.30` đều được gán `port_scan`.
- **Không có báo động giả nào từ bộ phân loại và module botnet.** Báo động giả duy nhất mỗi lần vẫn là sự kiện
  anomaly kéo dài cả bản thu trên `.30` (mục 1).

## 3. C11-T04 — DoS có giới hạn trong lab

Máy thử nghiệm `.20` chạy bộ sinh tải kết nối (`sinh_traffic.py tai-ket-noi`, docs/68) tới `.30:80` trong
**đúng 60 giây** (B16; đo được 60,1–60,3 giây), ba mức tải, có traffic bình thường của ba client suốt bản thu
5 phút.

| Mức | Kết nối mỗi giây (đặt) | Kết nối đã thử trong 60 s | Nối được | Độ trễ phát hiện (3 lần) | Cửa sổ cảnh báo `dos` | Host bị báo |
|---|---|---|---|---|---|---|
| 1 | 50 | 3 000 | 3 000 | 2,5 / 2,9 / 1,7 s | 34 | chỉ `.20` |
| 2 | 200 | 12 000 | 12 000 | 2,2 / 1,0 / 0,6 s | 64–65 | `.20` và `.30` |
| 3 | 600 | khoảng 34 000 (570 mỗi giây) | khoảng 28 240 | 1,1 / 1,2 / 0,4 s | 56 | `.20` và `.30` |

Kết quả (`docs/hinh/thuc_nghiem/lab/k3.json`, `access_log.json`):

- **Phát hiện 9/9 đợt, 0 bỏ sót**, ở cả ba mức tải; **độ trễ 0,4–2,9 giây** tới cuối cửa sổ đầu tiên. Mức tải
  cao hơn được báo sớm hơn một chút (trung vị 2,5 → 1,0 → 1,1 giây).
- Ở mức 1, chỉ bên tấn công `.20` bị gán `dos`; nạn nhân `.30` không bị. Từ mức 2 thì cả hai.
- Ở mức 3, máy tấn công chỉ đạt khoảng 570 kết nối mỗi giây và khoảng 17% lần thử không nối được (hết cổng
  nguồn tạm thời), tức đã có kết nối không hoàn tất thật.
- **Dịch vụ không bị ảnh hưởng**: trong 60 giây tấn công, client hợp lệ vẫn gửi 48–57 yêu cầu mỗi lần, tất cả
  mã 200, thời gian phục vụ ghi trong access log không đổi (dưới 1 ms). Trên lab ảo, Nginx thừa sức nhận 600
  kết nối rỗng mỗi giây; đây là **tải kết nối phát hiện được**, chưa phải DoS làm sập dịch vụ.
- Không có báo động giả nào từ bộ phân loại và module botnet. Báo động giả mỗi lần vẫn là sự kiện anomaly cả
  bản thu trên `.30` (11,4 sự kiện mỗi giờ vì bản thu chỉ dài 5 phút).

Lưu ý khi đọc: bộ phân loại học DoS tầng HTTP của CIC-IDS2017 nhưng vẫn nhận ra kiểu tải kết nối của lab. Tuy
vậy nguồn tấn công trong lab chỉ là một máy, và `.20` không có traffic bình thường xen kẽ; chưa thử trường hợp
máy tấn công đồng thời là máy làm việc bình thường.

## 4. C11-T05 — Giao tiếp tập trung mô phỏng

Ba bot `.41`–`.43` gọi máy điều khiển mô phỏng `.50:8080` bằng thông điệp vô hại trong 10 phút, đồng thời vẫn
duyệt web bình thường; `.20` chỉ duyệt web. `k4-co-dinh`: chu kỳ 30/60/45 giây (lần 1/2/3), không jitter.
`k4-bien-thien`: cùng chu kỳ, jitter ±20/40/30%.

| Lần | Chu kỳ, jitter | Thời gian hành vi | Phát hiện (`suspect_host`) | Anomaly báo bot | Điểm botnet cao nhất của bot |
|---|---|---|---|---|---|
| `k4-co-dinh-test-01` | 30 s, 0 | 593 s | ✗ bỏ sót | không | 0,071 |
| `k4-co-dinh-test-02` | 60 s, 0 | 594 s | ✗ bỏ sót | không | — |
| `k4-co-dinh-test-03` | 45 s, 0 | 582 s | ✗ bỏ sót | không | — |
| `k4-bien-thien-test-01` | 30 s, ±20% | 590 s | ✗ bỏ sót | không | — |
| `k4-bien-thien-test-02` | 60 s, ±40% | 588 s | ✗ bỏ sót | không | 0,067 |
| `k4-bien-thien-test-03` | 45 s, ±30% | 597 s | ✗ bỏ sót | không | — |

Kết quả (`docs/hinh/thuc_nghiem/lab/k4.json`, `botnet_doc_lap.json`, `botnet_diem.json`):

- **Bỏ sót 6/6 đợt.** Không có cảnh báo `suspect_host` nào trên ba bot trong cả sáu lần.
- Ở chế độ `ket_hop`, module botnet chỉ xét host mà module anomaly đã báo (QĐ-047). Anomaly **không báo bot
  lần nào**: mỗi 30–60 giây thêm một kết nối ngắn là quá ít để lệch khỏi "bình thường". Vì vậy module botnet
  thậm chí không được hỏi.
- Chạy lại ở chế độ `doc_lap` (module botnet chấm mọi host) vẫn **bỏ sót 6/6**: điểm cao nhất của bot là
  0,061–0,071, dưới ngưỡng 0,1. Bot còn có điểm trung vị **thấp hơn** máy chỉ duyệt web `.20` (0,003 so với
  0,052). Máy điều khiển `.50` có điểm 0.
- Kết quả này khớp với dự báo từ Chặng 8: mô hình học trên CTU-13 không chuyển sang bot mô phỏng (recall
  0,017 trên dữ liệu giả lập, docs/52). Chặng 11 xác nhận điều đó trên gói tin thật.

Việc cần làm: thu các lần chạy `train` và `val` của kịch bản 4, 5 và học lại module botnet trên dữ liệu lab;
xét lại việc module botnet phụ thuộc vào anomaly ở chế độ `ket_hop`, vì beaconing chậm không làm host bất thường.

## 5. C11-T06 — Giao tiếp ngang hàng mô phỏng

Ba bot `.41`–`.43` gửi thông điệp UDP vô hại cho nhau qua cổng 40000 trong 10 phút, đồng thời vẫn duyệt web.
Chu kỳ và danh sách peer đổi giữa các lần (B18).

| Lần | Chu kỳ, jitter | Danh sách peer | Phát hiện (`suspect_host`) | Anomaly báo bot | Điểm botnet cao nhất của bot |
|---|---|---|---|---|---|
| `k5-p2p-test-01` | 8 s, ±30% | lưới đầy đủ (mỗi bot gọi hai bot kia) | ✗ bỏ sót | không | 0,084 |
| `k5-p2p-test-02` | 20 s, ±50% | vòng (41→42→43→41) | ✗ bỏ sót | không | — |
| `k5-p2p-test-03` | 30 s, ±40% | lưới đầy đủ | ✗ bỏ sót | không | — |

Kết quả (`docs/hinh/thuc_nghiem/lab/k5.json`, `botnet_doc_lap.json`, `botnet_diem.json`):

- **Bỏ sót 3/3 đợt**, ở cả chế độ `ket_hop` lẫn `doc_lap`. Điểm cao nhất của bot 0,074–0,084, dưới ngưỡng 0,1.
- Không có nhãn topology `p2p` nào. Quy tắc nhận diện ngang hàng (QĐ-042) đòi ít nhất 5 peer gọi vào một host;
  lab chỉ có 3 bot nên mỗi bot nhiều nhất có 2 peer. **Với 7 node, quy tắc này không thể thỏa** dù bộ phát
  hiện có báo.
- Anomaly cũng không báo bot: vài gói UDP nhỏ mỗi 8–30 giây không làm host lệch khỏi bình thường.

Việc cần làm: như mục 4, cộng thêm hạ ngưỡng số peer của quy tắc topology cho phù hợp quy mô lab (chọn trên
lần chạy `val`).

## 6. C11-T07 — Đối chứng lành tính và lặp lại tình huống

### 6.1. Đối chứng lành tính

| Biến thể | Hành vi lành tính | Báo động giả 3 lần | Từ module nào |
|---|---|---|---|
| `k1-binh-thuong` | Duyệt web + kiểm tra trạng thái định kỳ | 1 / 1 / 1 | anomaly trên `.30` (cả bản thu) |
| `k4-doi-chung` | Ba máy gọi máy chủ dịch vụ `.30:80` theo chu kỳ 30/60/45 s (cùng hình dạng với bot tập trung) | 1 / 1 / 1 | anomaly trên `.30` (cả bản thu) |
| `k5-doi-chung` | Ba máy chia sẻ khối dữ liệu 200 KB–2 MB qua TCP `:6881` theo đợt | **13 / 8 / 13** | bộ phân loại 10 / 5 / 9 (nhãn `dos`); anomaly 3 / 3 / 4 |

- **`k4-doi-chung`: module botnet không báo nhầm** dịch vụ hợp lệ gọi định kỳ. Nhưng **không kết luận được**
  rằng mô hình phân biệt được bot với đối chứng, vì nó cũng không báo bot thật (mục 4): điểm của hai bên đều
  dưới ngưỡng (đối chứng cao nhất 0,087, bot 0,071).
- **`k5-doi-chung`: bộ phân loại báo nhầm `dos` trên cả ba máy** mỗi khi có đợt truyền khối dữ liệu lớn: 24 sự
  kiện trong ba lần (39,8–65,4 sự kiện mỗi giờ), phần lớn dài khoảng 18 giây. Truyền nhiều byte liên tiếp
  giữa hai máy nội bộ trông giống DoS tầng HTTP của CIC-IDS2017 với bộ phân loại. Anomaly cũng báo các máy này
  trong lúc truyền (7 sự kiện). **Đây là nguồn báo động giả chính của bộ phân loại trong lab.**
- Tác vụ định kỳ hợp lệ (`api/status` ở kịch bản 1, gọi định kỳ ở `k4-doi-chung`) không gây báo động nào từ
  bộ phân loại và module botnet.

### 6.2. Lặp lại tình huống (B19)

Mỗi biến thể chạy ba lần với lịch khác nhau: thời điểm bắt đầu hành vi và seed khác nhau ở mọi biến thể; chu
kỳ, jitter và danh sách peer khác nhau ở kịch bản 4, 5 (docs/70 mục 3).

| Biến thể | Bắt đầu hành vi sau (3 lần) | Kết quả 3 lần | Độ trễ 3 lần | Báo động giả 3 lần |
|---|---|---|---|---|
| `k1-binh-thuong` | — | — | — | 1 / 1 / 1 |
| `k2-quet-cham` | 119 / 98 / 94 s | ✓ ✓ ✓ | 1,8 / 2,5 / 1,4 s | 1 / 1 / 1 |
| `k2-quet-nhanh` | 167 / 236 / 132 s | ✓ ✓ ✓ | 1,8 / 0,9 / 1,5 s | 1 / 1 / 1 |
| `k3-dos-muc1` | 92 / 120 / 96 s | ✓ ✓ ✓ | 2,5 / 2,9 / 1,7 s | 1 / 1 / 1 |
| `k3-dos-muc2` | 98 / 122 / 117 s | ✓ ✓ ✓ | 2,2 / 1,0 / 0,6 s | 1 / 1 / 1 |
| `k3-dos-muc3` | 111 / 148 / 106 s | ✓ ✓ ✓ | 1,1 / 1,2 / 0,4 s | 1 / 1 / 1 |
| `k4-co-dinh` | 36 / 55 / 36 s | ✗ ✗ ✗ | — | 1 / 1 / 1 |
| `k4-bien-thien` | 52 / 60 / 30 s | ✗ ✗ ✗ | — | 1 / 1 / 1 |
| `k4-doi-chung` | 35 / 31 / 54 s | — | — | 1 / 1 / 1 |
| `k5-p2p` | 53 / 44 / 44 s | ✗ ✗ ✗ | — | 1 / 1 / 1 |
| `k5-doi-chung` | 52 / 55 / 37 s | — | — | 13 / 8 / 13 |

**Kết quả lặp lại nhất quán**: trong mỗi biến thể, ba lần cho cùng kết luận (phát hiện cả ba hoặc bỏ sót cả
ba). Độ trễ dao động trong khoảng 2 giây, đúng bằng bước trượt cửa sổ: nó phụ thuộc hành vi bắt đầu ở đâu so
với lưới cửa sổ. Số báo động giả chỉ dao động ở `k5-doi-chung`, theo số đợt truyền dữ liệu của từng lần.

Các lần chạy này đều có vai trò `test` và chỉ dùng để báo cáo: không tham số hay ngưỡng nào được chỉnh theo
chúng.

## 7. Bộ phân loại theo từng cửa sổ host (bổ sung 12/11/2026)

Các mục trên chấm theo đợt tấn công. Mục này chấm theo **cửa sổ host**, đúng cách đã chấm trên CIC-IDS2017 ở
Chặng 7 (docs/43), để so được hai mạng và để xem riêng máy tấn công với máy nạn nhân. Mã nguồn:
`src/nids/lab_cua_so.py`; số liệu: `docs/hinh/thuc_nghiem/lab/cua_so_test.json`.

```bash
cd src
python -m nids.lab_cua_so ../data/pcap/lab/k*-test-0*.pcap --nhat-ky ../data/run_logs \
    --out ../docs/hinh/thuc_nghiem/lab --ten cua_so_test
```

Nhãn cửa sổ lấy từ nhật ký lần chạy bằng chính `nids.labeling` (cùng ngưỡng phần flow tấn công 0,2); 3 cửa sổ mơ
hồ bị bỏ. Cửa sổ của bot mô phỏng và của đối chứng là `benign` với bộ phân loại ba lớp.

| | CIC-IDS2017 test (docs/43) | Lab test (33 lần, 46 411 cửa sổ) |
|---|---|---|
| Macro-F1 | 0,908 | **0,923** |
| `port_scan`: precision / recall (số mẫu) | 0,947 / 0,736 (220) | **1,000 / 0,999** (1 592) |
| `dos`: precision / recall (số mẫu) | 0,964 / 0,838 (727) | 0,762 / 0,781 (593) |
| `benign`: recall (số mẫu) | 0,9996 (67 713) | 0,9967 (44 226) |

Recall theo vai trò của host trong lab:

| Lớp | Máy tấn công `.20` | Máy nạn nhân `.30` |
|---|---|---|
| `port_scan` | **1,000** (797 cửa sổ) | 0,999 (795 cửa sổ) |
| `dos` | **0,987** (297 cửa sổ) | 0,574 (296 cửa sổ) |

Đọc kết quả:

- **Kết quả không kém đi trên mạng và công cụ chưa từng thấy.** Bộ phân loại học từ CIC-IDS2017 đạt macro-F1
  0,923 trên lab, so với 0,908 trên test của chính CIC. Quét cổng bằng Nmap trong lab còn dễ nhận hơn trên CIC.
- **Máy tấn công là một host thật, không phải địa chỉ NAT gộp nhiều máy như ở CIC**, và được nhận ra gần như
  mọi cửa sổ (1,000 và 0,987). Đây là con số theo host phía tấn công mà dữ liệu CIC không cho được.
- **Máy nạn nhân của DoS chỉ được báo 57% số cửa sổ**: phần lớn cửa sổ sót nằm ở mức tải 1 (50 kết nối mỗi
  giây), nơi nạn nhân không bị báo lần nào. Đợt tấn công vẫn được phát hiện nhờ cửa sổ của máy tấn công.
- **Precision của `dos` giảm còn 0,762** vì 144 cửa sổ `benign` bị báo `dos`, **tất cả thuộc `k5-doi-chung`**
  (chia sẻ khối dữ liệu lớn). Ngoài biến thể đó không có cửa sổ lành tính nào bị báo trong 30 lần chạy còn lại.

Giới hạn: máy tấn công `.20` không có traffic bình thường xen kẽ, nên cửa sổ của nó "sạch" hơn thực tế.

### 7.1. Lần chạy `train` và `val` (thu 12/11/2026)

Mỗi biến thể có thêm một lần `train` và một lần `val` (22 lần, 0 gói nhân bỏ). Chấm bằng cùng mô hình đã khóa,
**không dùng để chỉnh gì** (`docs/hinh/thuc_nghiem/lab/cua_so_train_val.json`):

| Vai trò | Lần chạy | Cửa sổ | Macro-F1 | `port_scan` recall (số mẫu) | `dos` precision / recall (số mẫu) | `benign` bị báo |
|---|---|---|---|---|---|---|
| `train` | 11 | 15 795 | 0,916 | 1,000 (532) | 0,720 / 0,786 (196) | 60, đều ở `k5-doi-chung` |
| `val` | 11 | 15 725 | 0,914 | 1,000 (531) | 0,717 / 0,776 (196) | 60, đều ở `k5-doi-chung` |
| `test` | 33 | 46 411 | 0,923 | 0,999 (1 592) | 0,762 / 0,781 (593) | 144, đều ở `k5-doi-chung` |

Ba vai trò cho cùng một bức tranh, tức kết quả không phụ thuộc lịch của từng lần chạy. Lần `val` của lab có
**531 cửa sổ `port_scan` và 196 cửa sổ `dos`**, nhiều hơn validation `port_scan` của CIC (164 cửa sổ); khi học
lại mô hình trên dữ liệu lab, việc chọn ngưỡng và tham số nên dùng thêm các cửa sổ này.

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
