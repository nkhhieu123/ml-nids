#!/usr/bin/env bash
# Chạy một lần kịch bản lab với cảm biến realtime BẮT TRỰC TIẾP trên máy giám sát (không phát lại PCAP).
# Cảm biến (nids.realtime --iface eth0) chạy trong namespace .10 suốt lần chạy; cảnh báo ghi kèm giờ thật lúc
# phát, cùng đồng hồ với nhật ký lần chạy, nên đo được độ trễ phát hiện thật và số gói nhân bỏ của cảm biến.
# Chạy bằng root trên Linux/WSL2; cần Python có numpy, pandas, scikit-learn (biến PY).
#   bash scripts/chay_cam_bien_lab.sh <số lab> <biến thể> <lần> [cấu hình]
set -u
cd "$(dirname "$0")/.."
lab="$1"; v="$2"; lan="$3"; cfg="${4:-config/lab.yaml}"
PY="${PY:-/opt/c11-venv/bin/python}"
run="$v-test-$(printf '%02d' "$lan")"
out="/root/nids_lab/cam_bien_$run"
rm -rf "$out"; mkdir -p "$out" output/cam_bien_lab output/lab_log
python3 scripts/lab_ao.py dung --lab "$lab" || exit 1
( cd src && exec ip netns exec "nl${lab}h10" "$PY" -W ignore -m nids.realtime --iface eth0 --net 192.168.50.0/24 \
    --out "$out" --ten "$run" --config "../$cfg" --im-lang ) >"$out/cam_bien.txt" 2>&1 &
sleep 20                                   # chờ cảm biến nạp mô hình và mở card
python3 scripts/lab_ao.py chay --lab "$lab" --bien-the "$v" --vai-tro test --lan "$lan"
sleep 150                                  # để cửa sổ 120 giây cuối cùng được chấm
pkill -INT -f "nids.realtime --iface eth0 .*--ten $run " ; sleep 40
pkill -KILL -f "nids.realtime --iface eth0 .*--ten $run " 2>/dev/null
rm -rf "output/cam_bien_lab/$run"; cp -r "$out" "output/cam_bien_lab/$run"
python3 scripts/lab_ao.py go --lab "$lab"
echo "Xong cảm biến trực tiếp $run"
