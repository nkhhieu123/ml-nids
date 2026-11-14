# Giữ nhãn `dos` theo host để vớt DoS HTTP chậm

Mã nguồn: `src/nids/dos_cham.py`. Kiểm thử: `tests/test_dos_cham.py`. Số liệu: `docs/hinh/dos_cham.json`.
Quyết định: QĐ-071, QĐ-074.

```bash
cd src
python -m nids.dos_cham ../output/features/cic17_wednesday ../output/features/cic17_friday \
    --model ../models/phan_loai_rf_windows.joblib --out ../docs/hinh
```

## 1. Vấn đề

Trên test CIC-IDS2017, bộ phân loại chỉ nhận ra 66% cửa sổ Slowhttptest (docs/43, docs/44). DoS HTTP chậm giữ
kết nối mở thật lâu; giữa hai đợt gửi, cửa sổ 10 giây của nạn nhân gần như không có kết nối mới nên trông
bình thường. Hướng đã ghi trước đây là thêm đặc trưng dài hơn cửa sổ, nhưng việc đó đòi trích xuất lại toàn bộ
CIC và huấn luyện lại.

## 2. Cách làm

Thêm một lớp **sau** bộ phân loại, cùng ý tưởng với lớp gộp theo host của module botnet (docs/69):

> Một cửa sổ `benign` của host H được nâng lên `dos` nếu trong `lookback_s` giây ngay trước nó, H đã có ít
> nhất `min_count` cửa sổ được bộ phân loại gán `dos`.

- Chỉ nhìn về quá khứ, nên dùng được realtime.
- Chỉ đếm dự đoán gốc của bộ phân loại; cửa sổ đã được nâng không được đếm tiếp, nên nhãn không lan dây chuyền.
- Không đổi nhãn `port_scan`; không cần trích xuất hay huấn luyện lại.

Hai tham số chọn trên **validation** theo macro-F1 (lưới 20 cấu hình), rồi đọc test một lần.

| `lookback_s` | `min_count` 1 | 2 | 3 | 5 |
|---|---|---|---|---|
| 20 | 0,9324 | 0,9378 | 0,9406 | **0,9463** |
| 30 | 0,9247 | 0,9326 | 0,9355 | 0,9447 |
| 60 | 0,9100 | 0,9198 | 0,9251 | 0,9404 |
| 120 | 0,8859 | 0,8988 | 0,9090 | 0,9353 |
| 300 | 0,8246 | 0,8426 | 0,8595 | 0,9165 |

Macro-F1 validation không có lớp này là 0,9352. Chọn **20 giây, 5 cửa sổ**. Nhìn lại càng xa hoặc đòi càng ít
cửa sổ thì recall `dos` lên 1,0 nhưng precision tụt (tới 0,44), vì nhãn bị giữ quá lâu sau khi tấn công dừng.

## 3. Kết quả

| | Validation gốc | Validation có lớp giữ | **Test gốc** | **Test có lớp giữ** |
|---|---|---|---|---|
| Macro-F1 | 0,9352 | 0,9463 | 0,9078 | **0,9241** |
| `dos` precision | 0,961 | 0,948 | 0,964 | 0,951 |
| `dos` recall | 0,914 | 0,992 | 0,838 | **0,938** |
| Recall Slowhttptest | 0,865 | 0,974 | 0,662 | **0,815** |
| Recall Hulk | 0,826 | 1,000 | 0,837 | 0,990 |
| Recall GoldenEye | 1,000 | 1,000 | 0,708 | 1,000 |
| Recall slowloris | 1,000 | 1,000 | 0,956 | 0,978 |
| `benign` recall | — | — | 0,9996 | 0,9994 |

- **Recall `dos` trên test tăng từ 0,838 lên 0,938**, đổi lại precision giảm 0,013. Slowhttptest tăng từ 0,66
  lên 0,82; phần còn sót là các khoảng im lặng dài hơn 20 giây giữa hai đợt gửi.
- Hulk và GoldenEye cũng được lợi: các cửa sổ xen kẽ bị bỏ sót giữa đợt tấn công được lấp.

## 4. Trạng thái và giới hạn

- Lớp này **đã nối vào pipeline offline và cảm biến realtime** (mục 5), **mặc định tắt**.
- Mới đo trên CIC-IDS2017. Trên lab không có DoS chậm để kiểm tra, nên `config/lab.yaml` không bật.
- Cửa sổ ngay sau khi tấn công dừng (trong 20 giây) có thể bị giữ nhãn `dos`.
- Tập test đã được đọc hai lần cho lớp này (cấu hình 20/5 và cấu hình 30/7 ở mục 6).

## 5. Nối vào pipeline và realtime (14/11/2026, QĐ-074)

Bật bằng một dòng trong file cấu hình, dùng chung cho cả hai đường chạy:

```yaml
pipeline:
  dos_hold: {lookback_s: 20, min_count: 5}
```

- `dos_cham.DosHolder` là bản tăng dần của `hold_dos`: nhớ thời điểm các cửa sổ `dos` gần đây của từng host, nên
  dùng được khi cửa sổ tới từng lô như trong cảm biến. Pipeline offline cũng đi qua lớp này
  (`pipeline.score_attack`), nên hai đường chạy dùng cùng một đoạn mã.
- Cửa sổ được nâng có thêm `giu_dos=1` trong cột `detail` của cảnh báo; điểm là `p_dos` gốc của bộ phân loại
  (thường thấp), để người đọc phân biệt với cửa sổ được gán `dos` trực tiếp.
- Ở chế độ `ket_hop`, cửa sổ được nâng không còn là "bất thường chưa giải thích" nên không kích hoạt kiểm tra
  botnet cho host đó.

Kiểm tra trên bốn đoạn PCAP của CIC (`nids.nhat_quan`, chế độ `ket_hop`), số cảnh báo `dos`:

| Đoạn PCAP | Tắt | Bật | Nhãn offline khác realtime |
|---|---|---|---|
| `wed_slowloris` | 312 | 320 | 0 |
| `wed_hulk` | 162 | 194 | 0 |
| `fri_quet` (quét cổng) | 4 | 4 | 0 |
| `fri_binh_thuong` | 0 | 0 | 0 |

Lớp này chỉ thêm cảnh báo `dos` ở hai đoạn có DoS; đoạn quét cổng và đoạn bình thường không đổi. Số cảnh báo
`port_scan`, `anomaly`, botnet và số sự kiện giữ nguyên ở cả bốn đoạn. Offline và realtime cho cùng nhãn ở mọi
cửa sổ khi bật.

## 6. Lưới tham số rộng hơn

Cấu hình 20/5 nằm ở mép lưới ban đầu, nên đã thử thêm `lookback_s` 10, 14 và `min_count` 6, 7, 8, 10
(`docs/hinh/dos_cham_luoi_rong.json`). Macro-F1 validation:

| `lookback_s` | `min_count` 3 | 5 | 6 | 7 | 8 | 10 |
|---|---|---|---|---|---|---|
| 10 | 0,9448 | 0,9419 | 0,9352 | 0,9352 | 0,9352 | 0,9352 |
| 14 | 0,9434 | 0,9465 | 0,9459 | 0,9399 | 0,9352 | 0,9352 |
| 20 | 0,9406 | **0,9463** | 0,9468 | 0,9475 | 0,9454 | 0,9371 |
| 30 | 0,9355 | 0,9447 | 0,9466 | **0,9491** | 0,9483 | 0,9475 |

Cấu hình tốt nhất trên validation là 30 giây, 7 cửa sổ (0,9491), hơn 20/5 chỉ 0,003. Trên test hai cấu hình
ngang nhau: macro-F1 0,9237 so với 0,9241, recall `dos` 0,931 so với 0,938. **Giữ 20/5**: chênh lệch trên
validation nằm trong mức nhiễu, và nhìn lại ngắn hơn thì nhãn `dos` kéo dài sau tấn công ít hơn.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| DoS HTTP chậm | Giữ nhiều kết nối HTTP mở thật lâu để chiếm chỗ của máy chủ, không cần gửi nhiều gói |
| Slowhttptest, slowloris, Hulk, GoldenEye | Bốn công cụ DoS tầng HTTP trong CIC-IDS2017; hai cái đầu là kiểu chậm |
| Cửa sổ | Khoảng 10 giây của một host dùng để tính đặc trưng và phân loại |
| Lớp giữ nhãn | Bước xử lý sau bộ phân loại: giữ nhãn `dos` cho host vừa bị gán `dos` nhiều lần |
| `lookback_s`, `min_count` | Nhìn lại bao nhiêu giây; cần bao nhiêu cửa sổ `dos` trong khoảng đó |
| Validation / test | Phần dữ liệu để chọn tham số / để đánh giá cuối |
| Precision / recall | Trong các cảnh báo, tỷ lệ đúng / trong các mẫu tấn công thật, tỷ lệ được nhận ra |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp tính ngang nhau |
| `ket_hop` | Chế độ chạy mặc định: phân loại chấm mọi cửa sổ, botnet chỉ kiểm tra host có bất thường chưa giải thích |
| Mép lưới | Giá trị tốt nhất nằm ở biên của các giá trị đã thử, nên có thể còn giá trị tốt hơn ở ngoài |
