#!/usr/bin/env bash
# Cài dự án ml-nids trên Kali Linux (C10-T01). Chạy bằng user thường có quyền sudo.
#
#   bash cai_dat_kali.sh [--thu-muc /opt/ml-nids] [--mo-hinh <thư mục chứa *.joblib và *.json>] [--iface eth1]
#
# Các bước: cài gói hệ thống, clone (hoặc cập nhật) repo, tạo môi trường ảo, cài thư viện, chép mô hình,
# cấp quyền bắt gói cho python của môi trường ảo, rồi chạy kiểm tra môi trường. Không tải dữ liệu nào.
set -euo pipefail

REPO_URL="https://github.com/nkhhieu123/ml-nids.git"
DIR="/opt/ml-nids"
MODELS=""
IFACE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --thu-muc) DIR="$2"; shift 2 ;;
    --mo-hinh) MODELS="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Tham số lạ: $1" >&2; exit 2 ;;
  esac
done

echo "== 1. Gói hệ thống"
sudo apt-get update -qq
sudo apt-get install -y -qq git python3 python3-venv python3-pip libcap2-bin tcpdump

echo "== 2. Mã nguồn tại $DIR"
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull --ff-only
else
  sudo mkdir -p "$DIR"
  sudo chown "$(id -u):$(id -g)" "$DIR"
  git clone "$REPO_URL" "$DIR"
fi
cd "$DIR"
echo "   commit: $(git rev-parse --short HEAD)"

echo "== 3. Môi trường ảo và thư viện"
# --copies: .venv có bản python riêng, để setcap ở bước 5 không cấp quyền cho python của cả hệ thống
python3 -m venv --copies .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -e .
.venv/bin/pip install -q psutil || echo "   (không cài được psutil: số liệu CPU/RAM sẽ đọc từ /proc)"

echo "== 4. Mô hình"
mkdir -p models output data/run_logs
if [ -n "$MODELS" ]; then
  cp -v "$MODELS"/*.joblib "$MODELS"/*.json models/
else
  echo "   Chưa chép mô hình. Chép models/*.joblib và *.json từ máy huấn luyện, ví dụ:"
  echo "   scp may-huan-luyen:ml-nids/models/{gaussian_windows,phan_loai_rf_windows,botnet_rf}.{joblib,json} $DIR/models/"
fi

echo "== 5. Quyền bắt gói cho python của môi trường ảo (không cần chạy bằng root)"
PY="$(readlink -f .venv/bin/python)"
case "$PY" in
  "$DIR"/.venv/*) ;;
  *) echo "   $PY nằm ngoài môi trường ảo: không setcap (sẽ cấp quyền cho python hệ thống). Chạy cảm biến bằng sudo."; PY="" ;;
esac
[ -n "$PY" ] && sudo setcap cap_net_raw,cap_net_admin+eip "$PY" && getcap "$PY" || echo "   setcap thất bại: chạy cảm biến bằng sudo"

echo "== 6. Kiểm tra môi trường"
ARGS=(--out output/moi_truong.json)
if [ -n "$IFACE" ]; then ARGS+=(--iface "$IFACE"); fi
.venv/bin/python -m nids.moi_truong "${ARGS[@]}" || true
echo "Xong. Báo cáo: $DIR/output/moi_truong.json"
