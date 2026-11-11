#!/usr/bin/env bash
# Chặng 11: thu toàn bộ lần chạy kiểm thử của 11 biến thể (docs/09), mỗi biến thể một lab ảo riêng chạy song song.
# Chạy bằng root trên Linux/WSL2:  bash scripts/chay_chang_11.sh [vai_tro] [các lần]
#   bash scripts/chay_chang_11.sh              # test, lần 1 2 3 (33 lần chạy, khoảng 40 phút)
#   bash scripts/chay_chang_11.sh val 1        # một lần val cho mỗi biến thể
set -u
cd "$(dirname "$0")/.."
vai_tro="${1:-test}"
shift || true
lan="${*:-1 2 3}"
mkdir -p output/lab_log
i=0
for v in k1-binh-thuong k2-quet-cham k2-quet-nhanh k3-dos-muc1 k3-dos-muc2 k3-dos-muc3 \
         k4-co-dinh k4-bien-thien k4-doi-chung k5-p2p k5-doi-chung; do
  i=$((i + 1))
  (
    python3 scripts/lab_ao.py dung --lab "$i" &&
      python3 scripts/lab_ao.py chay --lab "$i" --bien-the "$v" --vai-tro "$vai_tro" --lan $lan
    python3 scripts/lab_ao.py go --lab "$i"
  ) >"output/lab_log/$v-$vai_tro.log" 2>&1 &
done
wait
grep -h "^Xong" output/lab_log/*-"$vai_tro".log | sort
echo "Đã xong mọi biến thể ($vai_tro: lần $lan)"
