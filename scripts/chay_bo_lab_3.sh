#!/usr/bin/env bash
# Thu dữ liệu cho bộ mô hình lab lần ba (QĐ-076, QĐ-077), mỗi biến thể một lab ảo riêng chạy song song.
# Chạy bằng root trên Linux/WSL2:  bash scripts/chay_bo_lab_3.sh
#   - biến thể mới (5 bot, DoS HTTP chậm, SYN flood, đổi vai): train lần 1 2 3, val lần 1, test lần 12 13 14;
#   - 11 biến thể chính: chỉ test lần 12 13 14 (lần test mới, chưa mô hình nào thấy; QĐ-072).
# Nhật ký từng lab ở output/lab_log/bo3-<biến thể>.log. Khoảng 90 phút.
set -u
cd "$(dirname "$0")/.."
moi="k6-tap-trung k6-p2p k6-doi-chung x3-dos-cham x3-syn-muc1 x3-syn-muc2 x3-syn-muc3 x4-doi-vai x4-doi-chung-doi-vai x5-doi-vai"
chinh="k1-binh-thuong k2-quet-cham k2-quet-nhanh k3-dos-muc1 k3-dos-muc2 k3-dos-muc3 k4-co-dinh k4-bien-thien k4-doi-chung k5-p2p k5-doi-chung"
mkdir -p output/lab_log
i="${LAB_DAU:-60}"
chay() {   # lab, biến thể, rồi các cặp "vai_trò:lần lần"
  local lab="$1" v="$2"; shift 2
  python3 scripts/lab_ao.py dung --lab "$lab" || return
  for muc in "$@"; do
    python3 scripts/lab_ao.py chay --lab "$lab" --bien-the "$v" --vai-tro "${muc%%:*}" --lan ${muc#*:}
  done
  python3 scripts/lab_ao.py go --lab "$lab"
}
for v in $moi; do
  i=$((i + 1))
  chay "$i" "$v" "train:1 2 3" "val:1" "test:12 13 14" >"output/lab_log/bo3-$v.log" 2>&1 &
done
for v in $chinh; do
  i=$((i + 1))
  chay "$i" "$v" "test:12 13 14" >"output/lab_log/bo3-$v.log" 2>&1 &
done
wait
grep -h "^Xong" output/lab_log/bo3-*.log | sort
echo "Đã xong bộ lab 3."
