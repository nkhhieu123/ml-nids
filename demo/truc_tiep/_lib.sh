#!/usr/bin/env bash
# Hàm dùng chung cho bộ demo trực tiếp nhiều cửa sổ (demo/truc_tiep/).
# Không chạy trực tiếp file này; các script khác source nó.
set -u

LIB_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ROOT="$(cd "$LIB_DIR/../.." && pwd)"
cd "$ROOT"
export PYTHONIOENCODING=utf-8 LANG="${LANG:-C.UTF-8}"
PY="${PY:-$ROOT/.venv/bin/python}"
LAB=8                                         # một lab cố định dùng chung cho mọi cửa sổ của demo trực tiếp
OUT="$ROOT/output/truc_tiep"
ALERTS="$OUT/alerts/giam_sat.alerts.csv"

NL() { echo "nl${LAB}h$1"; }                  # tên namespace của máy có đuôi IP $1 (ví dụ NL 20 -> nl8h20)
TREN() { ip netns exec "$(NL "$1")" "${@:2}"; }   # chạy một lệnh "trên máy .$1"

xanh() { printf '\033[1;32m%s\033[0m\n' "$*"; }
vang() { printf '\033[1;33m%s\033[0m\n' "$*"; }
do_()  { printf '\033[1;31m%s\033[0m\n' "$*"; }

can_root() {
  if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null 2>&1 || { do_ "Cần chạy bằng root."; exit 1; }
    exec sudo -E PY="$PY" bash "$0" "$@"       # tự xin quyền root, giữ nguyên biến PY
  fi
}

# Bấm đúp từ trình quản lý file (không có terminal): tự mở lại trong một cửa sổ terminal.
mo_trong_terminal() {
  [ -t 1 ] && return 0
  [ -n "${DA_MO_TERMINAL:-}" ] && return 0
  export DA_MO_TERMINAL=1
  for t in x-terminal-emulator gnome-terminal konsole xfce4-terminal qterminal xterm; do
    command -v "$t" >/dev/null 2>&1 || continue
    case "$t" in
      gnome-terminal) exec "$t" --title "$1" -- bash "$2" ;;
      konsole)        exec "$t" -p tabtitle="$1" -e bash "$2" ;;
      *)              exec "$t" -T "$1" -e bash "$2" ;;
    esac
  done
}

lab_dang_chay() { ip netns list 2>/dev/null | grep -q "$(NL 10)"; }

can_lab() {
  if ! lab_dang_chay; then
    do_ "Lab chưa chạy. Hãy mở cửa sổ GIÁM SÁT trước: bash demo/truc_tiep/giam_sat.sh"
    echo; read -r -p "Nhấn Enter để đóng..." _ || true
    exit 1
  fi
}
