#!/usr/bin/env bash
# Chặng 11: thu các lần chạy lab, mỗi biến thể một lab ảo riêng chạy song song (docs/09, docs/70).
# Chạy bằng root trên Linux/WSL2:  bash scripts/chay_chang_11.sh [vai_tro] [các lần]
#   bash scripts/chay_chang_11.sh              # test, lần 1 2 3 của 11 biến thể chính (33 lần chạy, khoảng 40 phút)
#   bash scripts/chay_chang_11.sh val 1        # một lần val cho mỗi biến thể
#   BIEN_THE="x4-doi-vai x5-doi-vai" LAB_DAU=30 bash scripts/chay_chang_11.sh test 1 2 3
# BIEN_THE: danh sách biến thể (mặc định 11 biến thể chính). LAB_DAU: số lab đầu tiên trừ 1, để nhiều đợt chạy
# song song không dùng trùng lab.
set -u
cd "$(dirname "$0")/.."
vai_tro="${1:-test}"
shift || true
lan="${*:-1 2 3}"
bien_the="${BIEN_THE:-k1-binh-thuong k2-quet-cham k2-quet-nhanh k3-dos-muc1 k3-dos-muc2 k3-dos-muc3 k4-co-dinh k4-bien-thien k4-doi-chung k5-p2p k5-doi-chung}"
mkdir -p output/lab_log
i="${LAB_DAU:-0}"
for v in $bien_the; do
  i=$((i + 1))
  (
    python3 scripts/lab_ao.py dung --lab "$i" &&
      python3 scripts/lab_ao.py chay --lab "$i" --bien-the "$v" --vai-tro "$vai_tro" --lan $lan
    python3 scripts/lab_ao.py go --lab "$i"
  ) >"output/lab_log/$v-$vai_tro.log" 2>&1 &
done
wait
for v in $bien_the; do grep -h "^Xong" "output/lab_log/$v-$vai_tro.log"; done | sort
echo "Đã xong ($vai_tro: lần $lan): $bien_the"
