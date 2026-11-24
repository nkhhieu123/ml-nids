#!/usr/bin/env bash
# DDoS nhiều nguồn trong lab ảo (QĐ-087): biến thể x3-ddos, lần test 21 22 23, mỗi lần một lab riêng song song.
# Chạy bằng root trên Linux/WSL2:  bash scripts/chay_ddos.sh
set -u
cd "$(dirname "$0")/.."
mkdir -p output/lab_log
i=80
for lan in 21 22 23; do
  i=$((i + 1))
  ( python3 scripts/lab_ao.py dung --lab "$i" && python3 scripts/lab_ao.py chay --lab "$i" --bien-the x3-ddos --vai-tro test --lan "$lan"
    python3 scripts/lab_ao.py go --lab "$i" ) >"output/lab_log/ddos-$lan.log" 2>&1 &
done
wait
grep -h "^Xong\|Error\|rỗng" output/lab_log/ddos-*.log
