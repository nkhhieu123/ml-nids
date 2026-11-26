#!/usr/bin/env bash
# Demo trên Linux bằng một file: tự cài đặt lần đầu, rồi hiện menu demo.
#
#   bash demo_linux.sh            # menu
#   bash demo_linux.sh cai-dat    # chỉ cài đặt (nên làm trước buổi báo cáo, cần Internet)
#   bash demo_linux.sh 7          # chạy thẳng một mục của menu, ví dụ 7 = demo đầy đủ
#
# Chạy bằng người dùng thường; script tự gọi sudo khi cần (cài gói, dựng lab ảo).
# Lần đầu cần Internet để cài gói và thư viện Python; sau đó demo chạy không cần mạng.
# Mô hình lab và 6 bản thu demo nằm sẵn trong demo/du_lieu/ (git), script tự giải nén vào models/lab và data/pcap/lab.
set -u
cd "$(dirname "$(readlink -f "$0")")"
ROOT="$PWD"

# Bấm đúp từ trình quản lý file (không có terminal): tự mở lại trong một cửa sổ terminal.
if [ ! -t 0 ] && [ -z "${DEMO_TRONG_TERMINAL:-}" ]; then
  for t in x-terminal-emulator gnome-terminal konsole xfce4-terminal qterminal xterm; do
    if command -v "$t" >/dev/null 2>&1; then
      export DEMO_TRONG_TERMINAL=1
      case "$t" in
        gnome-terminal) exec gnome-terminal -- bash "$ROOT/demo_linux.sh" "$@" ;;
        *)              exec "$t" -e bash "$ROOT/demo_linux.sh" "$@" ;;
      esac
    fi
  done
fi

export PYTHONIOENCODING=utf-8 LANG="${LANG:-C.UTF-8}"
VENV="$ROOT/.venv"
PY="$VENV/bin/python"
DATA="$ROOT/demo/du_lieu"
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo"; fi

xanh() { printf '\033[1;32m%s\033[0m\n' "$*"; }
vang() { printf '\033[1;33m%s\033[0m\n' "$*"; }
do_()  { printf '\033[1;31m%s\033[0m\n' "$*"; }
cho()  { echo; read -r -p "Nhấn Enter để tiếp tục..." _ || true; }

# ---------------------------------------------------------------- cài đặt
cai_goi_he_thong() {
  local thieu=()
  for c in python3 tcpdump ip ethtool nginx nmap hping3 gzip; do command -v "$c" >/dev/null 2>&1 || thieu+=("$c"); done
  python3 -c "import venv, ensurepip" >/dev/null 2>&1 || thieu+=("python3-venv")
  [ ${#thieu[@]} -eq 0 ] && return 0
  vang "Thiếu: ${thieu[*]}. Cài bằng apt-get (cần Internet và mật khẩu sudo)..."
  if ! command -v apt-get >/dev/null 2>&1; then
    do_ "Máy không có apt-get. Tự cài: python3, python3-venv, tcpdump, iproute2, ethtool, nginx, nmap, hping3."; return 1
  fi
  $SUDO apt-get update -q && \
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 python3-venv python3-pip tcpdump \
      iproute2 ethtool nginx nmap hping3 gzip xdg-utils libcap2-bin
}

cai_python() {
  if [ ! -x "$PY" ]; then
    xanh "Tạo môi trường Python tại .venv ..."
    python3 -m venv "$VENV" || { do_ "Không tạo được .venv (cài python3-venv)."; return 1; }
  fi
  if ! "$PY" -c "import nids, numpy, pandas, sklearn, joblib, yaml, networkx" >/dev/null 2>&1; then
    xanh "Cài thư viện Python (pip install -e .) ..."
    "$PY" -m pip install -q --upgrade pip && "$PY" -m pip install -q -e . || { do_ "pip install lỗi."; return 1; }
  fi
  # Mô hình lab được lưu bằng scikit-learn 1.8.0; dùng đúng bản đó để nạp mô hình không bị cảnh báo hay lỗi.
  local can; can=$(sed -n 's/.*"scikit-learn": *"\([^"]*\)".*/\1/p' "$DATA/models_lab/phan_loai_rf_windows.json" | head -1)
  local co; co=$("$PY" -c "import sklearn; print(sklearn.__version__)" 2>/dev/null)
  if [ -n "$can" ] && [ "$co" != "$can" ]; then
    xanh "Cài scikit-learn==$can cho khớp mô hình (đang có $co) ..."
    "$PY" -m pip install -q "scikit-learn==$can" || \
      vang "Không cài được scikit-learn $can (cần Python 3.11 trở lên). Vẫn thử chạy với bản $co."
  fi
}

khoi_phuc_du_lieu() {
  mkdir -p models/lab data/pcap/lab output
  ( cd "$DATA" && sha256sum -c --quiet SHA256SUMS ) || { do_ "Gói dữ liệu demo/du_lieu bị hỏng (sai SHA256)."; return 1; }
  for f in "$DATA"/models_lab/*; do
    [ -f "models/lab/$(basename "$f")" ] || cp "$f" models/lab/
  done
  for f in "$DATA"/pcap/*.pcap.gz; do
    local dich="data/pcap/lab/$(basename "$f" .gz)"
    [ -s "$dich" ] || gzip -dc "$f" > "$dich"
  done
}

cai_dat() {
  xanh "=== Cài đặt (chỉ làm lần đầu, các lần sau bỏ qua phần đã có) ==="
  cai_goi_he_thong && cai_python && khoi_phuc_du_lieu || { do_ "Cài đặt chưa xong."; return 1; }
  # Mô-đun nhân cho cổng mirror của lab ảo; thiếu thì lab không dựng được.
  $SUDO modprobe -a act_mirred sch_ingress cls_matchall 2>/dev/null || true
  xanh "Cài đặt xong."
}

# ---------------------------------------------------------------- các mục demo
mo_dashboard() {                       # mo_dashboard <file html>
  local f="$1"
  [ -f "$f" ] || return 0
  echo "Dashboard: $f"
  if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then
    if [ -n "$SUDO" ] || [ -z "${SUDO_USER:-}" ]; then xdg-open "$f" >/dev/null 2>&1 &
    else sudo -u "$SUDO_USER" xdg-open "$f" >/dev/null 2>&1 & fi
  fi
}

lab() {                                # lab <biến thể>: lab ảo chạy trực tiếp, cần root
  $SUDO modprobe -a act_mirred sch_ingress cls_matchall 2>/dev/null || true
  $SUDO env PY="$PY" PYTHONIOENCODING=utf-8 bash scripts/demo_lab.sh "$1"
  local rc=$?
  [ -n "$SUDO" ] && [ -d output/demo ] && $SUDO chown -R "$(id -u):$(id -g)" output/demo data 2>/dev/null
  return $rc
}

phat_lai() {                           # phat_lai <bản thu>: không cần root
  "$PY" scripts/phat_lai_demo.py "$1" || return 1
  local run; run=$("$PY" -c "import sys; sys.path.insert(0,'scripts'); import phat_lai_demo as p; print(p.CHOICES['$1'][0])")
  mo_dashboard "$ROOT/output/phat_lai/$run/dashboard.html"
}

kiem_tra() {
  xanh "=== Kiểm tra môi trường demo ==="
  local ok=0
  "$PY" scripts/phat_lai_demo.py --danh-sach
  $SUDO env PY="$PY" bash scripts/demo_kiem_tra.sh || ok=1
  [ $ok = 0 ] && xanh "Lab ảo chạy được: dùng mục 1–3 trực tiếp." \
              || vang "Lab ảo chưa chạy được: dùng mục 8 (phát lại toàn bộ, không cần lab)."
}

buoc() { echo; xanh "────────── $* ──────────"; }

demo_day_du() {
  buoc "Bước 1/5: Bình thường (lab trực tiếp, khoảng 2 phút)";  lab k1-binh-thuong; cho
  buoc "Bước 2/5: Quét cổng (lab trực tiếp, khoảng 3 phút)";    lab k2-quet-nhanh;  cho
  buoc "Bước 3/5: DoS (lab trực tiếp, khoảng 3 phút)";          lab k3-dos-muc2;    cho
  buoc "Bước 4/5: Botnet tập trung (phát lại ×10, khoảng 70 giây)"; phat_lai bot5-tap-trung; cho
  buoc "Bước 5/5: Botnet ngang hàng (phát lại ×10, khoảng 70 giây)"; phat_lai bot5-p2p
  xanh "Xong demo đầy đủ."
}

demo_phat_lai() {
  local i=1
  for k in binh-thuong quet dos bot5-tap-trung bot5-p2p; do
    buoc "Bước $i/5: phát lại $k"; phat_lai "$k"; i=$((i + 1)); [ $i -le 5 ] && cho
  done
  xanh "Xong demo phát lại."
}

ket_qua() {
  "$PY" scripts/demo_ket_qua.py
  for h in docs/hinh/thuc_nghiem/lab/lab_do_tre.png docs/hinh/thuc_nghiem/lab/lab_bao_gia.png docs/hinh/dashboard_mau.html; do
    mo_dashboard "$ROOT/$h"
  done
}

chay_muc() {
  case "$1" in
    0) kiem_tra ;;
    1) lab k1-binh-thuong ;;
    2) lab k2-quet-nhanh ;;
    3) lab k3-dos-muc2 ;;
    4) phat_lai bot5-tap-trung ;;
    5) phat_lai bot5-p2p ;;
    6) phat_lai ddos ;;
    7) demo_day_du ;;
    8) demo_phat_lai ;;
    9) ket_qua ;;
    c|cai-dat) cai_dat ;;
    q|Q) exit 0 ;;
    *) vang "Lựa chọn không hợp lệ: $1" ;;
  esac
}

menu() {
  clear 2>/dev/null
  cat <<'EOF'
==================== DEMO NIDS HỌC MÁY (Linux) ====================
  0. Kiểm tra môi trường (làm trước buổi báo cáo)

  Từng bước (thứ tự trình bày: 1 → 2 → 3 → 4 → 5)
  1. Bình thường        – lab ảo trực tiếp, ~2 phút, không được có cảnh báo
  2. Quét cổng (Nmap)   – lab ảo trực tiếp, ~3 phút
  3. DoS                – lab ảo trực tiếp, ~3 phút
  4. Botnet tập trung   – phát lại bản thu ×10, ~70 giây
  5. Botnet ngang hàng  – phát lại bản thu ×10, ~70 giây
  6. DDoS năm nguồn     – phát lại (thêm, nếu còn giờ)

  Chạy liền
  7. Demo đầy đủ 1 → 5 (dừng chờ Enter giữa các bước)
  8. Dự phòng: phát lại cả 5 bước, không cần lab ảo
  9. Dự phòng cuối: bảng kết quả đã lưu và hình

  c. Cài đặt lại         q. Thoát
====================================================================
EOF
}

# ---------------------------------------------------------------- chạy
if [ "${1:-}" = cai-dat ]; then cai_dat; exit $?; fi
if [ ! -x "$PY" ] || ! "$PY" -c "import nids, sklearn" >/dev/null 2>&1 || [ ! -s data/pcap/lab/k6-p2p-test-12.pcap ] \
   || [ ! -f models/lab/phan_loai_rf_windows.joblib ]; then
  cai_dat || { cho; exit 1; }
fi

if [ -n "${1:-}" ]; then chay_muc "$1"; cho; exit 0; fi
while true; do
  menu
  read -r -p "Chọn: " c || exit 0
  chay_muc "$c"
  cho
done
