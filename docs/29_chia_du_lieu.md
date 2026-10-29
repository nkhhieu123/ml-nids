# C05-T04 — Chia train / validation / test theo phiên và khối tấn công

Mã nguồn: `src/nids/splits.py`. Kiểm thử: `tests/test_splits.py`. Quyết định: QĐ-027 trong
[03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md). Khối tấn công lấy từ cột `khoi`
của `config/label_schedule.csv` ([26_gan_nhan.md](26_gan_nhan.md)).

```bash
python -m nids.splits output/features/cic17_wednesday.flows.csv
```

Lệnh ghi `<tên>.flows.split.csv` và `<tên>.windows.split.csv` (cột `split`: `train`,
`validation`, `test` hoặc `bo`), và `<tên>.flows.split.json` liệt kê các đoạn thời gian.

## 1. Vì sao chia theo thời gian, không chia ngẫu nhiên

Chia ngẫu nhiên từng mẫu sẽ làm **rò rỉ** (yêu cầu B11):
- Hai cửa sổ chồng nhau (10 giây, bước 2 giây) chung 80% gói. Một cửa sổ ở train, cửa sổ
  kế bên ở test thì mô hình đã "thấy" gần hết mẫu test.
- Các flow của cùng một lượt quét hay một đợt DoS gần như giống hệt nhau (C05-T05). Chia
  ngẫu nhiên thì test chỉ là bản sao của train, kết quả đẹp mà không nói gì về khả năng
  gặp tấn công mới.

Vì vậy đơn vị chia là **đoạn thời gian liền**, và test luôn nằm **sau** train trong cùng
một khối.

## 2. Cách chia

**Phiên** là một bản thu: một ngày CIC, hay một lần chạy lab. Trong mỗi phiên, dòng thời
gian được tách thành các **khoảng**:
- mỗi **khối tấn công** (`khoi` trong lịch; các đợt cùng khối được gộp);
- mỗi **khoảng không có khối** giữa chúng, kể cả đầu và cuối phiên.

Mỗi khoảng được cắt theo thời gian: **60% đầu train, 20% kế validation, 20% cuối test**
(`split.train`, `split.validation`, `split.test`).

Một mẫu (flow `[first_ts, last_ts]` hoặc cửa sổ `[start, end)`) được gán vào tập của đoạn
chứa trọn nó. Mẫu bị **bỏ** (`bo`) khi:
- vắt qua ranh giới giữa hai đoạn; hoặc
- cách ranh giới giữa hai tập khác nhau dưới `split.embargo_s` = 10 giây (vùng đệm).

Vùng đệm bằng đúng độ dài cửa sổ, nên hai cửa sổ thuộc hai tập khác nhau **không bao giờ
chung gói**. Ban đầu thử 60 giây, nhưng khối ngắn nhất (GoldenEye, 13 phút) chỉ còn 2,6
phút validation, mất gần hết vào vùng đệm.

**Vì sao không gán nguyên khối vào một tập** (cách đã dự kiến ở docs/06 mục 5): `port_scan`
chỉ có 2 khối, trong đó khối "tường lửa bật" gần như không có gói. Gán nguyên khối thì
validation hoặc test sẽ thiếu lớp. Cắt trong khối giữ được cả ba lớp ở cả ba tập, và vẫn
không rò rỉ nhờ thứ tự thời gian và vùng đệm. Đánh giá khả năng gặp **công cụ chưa từng
thấy** (ví dụ huấn luyện không có GoldenEye rồi thử GoldenEye) là một thí nghiệm riêng ở
Chặng 7, không dùng làm cách chia chính.

**Phiên không có tấn công** (thứ Hai CIC): cả phiên là một khoảng, cắt 60/20/20. Gaussian
học trên train của phiên này; ngưỡng chọn trên validation.

## 3. Kết quả trên CIC thứ Tư

27 đoạn (giờ địa phương UTC−3; mỗi đợt DoS là một khối):

| Khoảng | Train | Validation | Test |
|---|---|---|---|
| Đầu ngày 08:42–09:47 (bình thường) | 08:42–09:21 | 09:21–09:34 | 09:34–09:47 |
| slowloris 09:47–10:11 | 09:47–10:01 | 10:01–10:06 | 10:06–10:11 |
| Slowhttptest 10:14–10:36 | 10:14–10:27 | 10:27–10:31 | 10:31–10:36 |
| Hulk 10:43–11:01 | 10:43–10:53 | 10:53–10:57 | 10:57–11:01 |
| GoldenEye 11:10–11:24 | 11:10–11:18 | 11:18–11:21 | 11:21–11:24 |
| Cuối ngày 11:24–17:10 (có Heartbleed, đã loại) | 11:24–14:51 | 14:51–16:01 | 16:01–17:10 |
| (và ba khoảng ngắn giữa các đợt) | | | |

| Bảng | Train | Validation | Test | Bỏ |
|---|---|---|---|---|
| Flow | 290 292 | 105 496 | 88 868 | 21 507 (4,2%) |
| — trong đó `dos` | 106 098 | 31 675 | 32 613 | 10 382 |
| Cửa sổ | 96 159 | 32 872 | 29 814 | 4 586 (2,8%) |
| — trong đó `dos` | 2 374 | 692 | 638 | 274 |

Số liệu thứ Sáu và thứ Hai, và phân bố lớp đầy đủ theo tập, ở
[30_kiem_tra_du_lieu.md](30_kiem_tra_du_lieu.md).

## 4. Rò rỉ còn lại và cách xử lý

| Nguồn rò rỉ | Xử lý |
|---|---|
| Cửa sổ chồng nhau ở hai tập | Mẫu vắt qua ranh giới bị bỏ; vùng đệm 10 giây |
| Flow dài (slowloris giữ kết nối nhiều phút) ở hai tập | Flow vắt qua ranh giới bị bỏ |
| Train và test của cùng một đợt tấn công giống nhau | Không tránh hết được; test nằm sau train. Báo cáo kết quả kèm số mẫu trùng giữa train và test (C05-T05) |
| Tham số tiền xử lý học từ test | Tiền xử lý chỉ fit trên train (C05-T07) |
| Nhìn phân bố test khi chọn đặc trưng | EDA chỉ vẽ trên train (C05-T06) |
| IP, cổng, thời điểm làm mô hình học thuộc | Không đưa vào mô hình (vai trò `dinh_danh`, QĐ-024) |

## 5. Kiểm thử

Kiểm thử tự động (7 ca): đoạn của một khối và hai khoảng bình thường; phiên không có tấn
công; các đợt cùng khối gộp lại, đợt không có khối bị bỏ qua; khối ngoài phiên bị bỏ
qua; gán mẫu trong đoạn, vắt qua ranh giới, trong vùng đệm, ở cuối phiên; không có vùng
đệm; dòng lệnh ghi hai file chia.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Train / validation / test | Dữ liệu để học / để chọn tham số, ngưỡng / để đánh giá cuối cùng |
| Phiên | Một bản thu liền: một ngày CIC hoặc một lần chạy lab |
| Khối tấn công | Khoảng thời gian của một đợt tấn công trong lịch |
| Rò rỉ (leakage) | Thông tin của test lọt vào lúc huấn luyện, làm kết quả đẹp giả |
| Vùng đệm (embargo) | Khoảng bỏ trống ở ranh giới giữa hai tập để mẫu hai bên không dính nhau |
| Mẫu vắt qua ranh giới | Mẫu có thời gian nằm ở cả hai đoạn |
| Công cụ chưa từng thấy | Đánh giá trên loại tấn công mà mô hình không được học, để xem khả năng tổng quát |
| B11 | Yêu cầu tách dữ liệu theo lần thu, không để mẫu chồng lấn ở cả train và test (docs/01) |
