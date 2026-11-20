#!/usr/bin/env bash
# ==============================================================================
#  MAX DARK TUNNEL - installer
#
#  menu:          bash <(curl -Ls https://raw.githubusercontent.com/darktunnelmika/max-dark-tunnel/main/install.sh)
#  kharej, 1 line: bash <(curl -Ls .../install.sh) --pair MDT-xxxxxxxx
#  own mirror:     ... install.sh --mirror https://your.host/mdt     (folder with mdt-linux-amd64/arm64)
# ==============================================================================
set -u

REPO="darktunnelmika/max-dark-tunnel"
MGR_REL="https://github.com/$REPO/releases/latest/download/max-dark-tunnel.sh"
MGR_RAW="https://raw.githubusercontent.com/$REPO/main/max-dark-tunnel.sh"
DEST="/usr/local/bin/maxdark"
BASE_DIR="/etc/max-dark-tunnel"

R=$'\e[38;5;203m'; G=$'\e[38;5;114m'; C=$'\e[38;5;81m'; D=$'\e[38;5;244m'; N=$'\e[0m'
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$1"; }
bad()  { printf '  %s✗%s %s\n' "$R" "$N" "$1" >&2; }
info() { printf '  %s·%s %s\n' "$C" "$N" "$1"; }

PAIR=""; MIRROR="${MDT_MIRROR:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --pair)   PAIR="${2:-}"; shift 2 ;;
    --mirror) MIRROR="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done

echo
printf '  %sMAX DARK TUNNEL%s  installer\n' "$C" "$N"
echo

[ "$(id -u)" -eq 0 ] || { bad "must run as root"; exit 1; }

need=""
command -v curl >/dev/null 2>&1 || need="$need curl"
command -v ip >/dev/null 2>&1 || need="$need iproute2"
if [ -n "$need" ]; then
  info "installing:$need"
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq $need
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q $need
  elif command -v yum     >/dev/null 2>&1; then yum install -y -q $need
  else bad "install these manually:$need"; exit 1; fi
fi

tmp="$(mktemp)" || { bad "cannot create temp file"; exit 1; }
trap 'rm -f "$tmp"' EXIT

# The release asset is served fresh; raw.githubusercontent.com caches for
# minutes, which is why a re-run could update the core but not the manager.
info "downloading manager"
if ! curl -fsSL --retry 2 --max-time 60 -o "$tmp" "$MGR_REL" \
   || ! grep -q 'MAXDARK-TUNNEL-SCRIPT' "$tmp"; then
  curl -fsSL --retry 3 --max-time 60 -o "$tmp" "$MGR_RAW?cb=$(date +%s)" \
    || { bad "download failed - check connectivity to github"; exit 1; }
fi
sed -i 's/\r$//' "$tmp"
grep -q 'MAXDARK-TUNNEL-SCRIPT' "$tmp" || { bad "downloaded file is not the manager"; exit 1; }
bash -n "$tmp" 2>/dev/null || { bad "downloaded file has syntax errors"; exit 1; }
ver="$(grep -m1 '^SCRIPT_VER=' "$tmp" | cut -d'"' -f2)"

mkdir -p "$BASE_DIR" && chmod 700 "$BASE_DIR"
[ -f "$DEST" ] && cp -f "$DEST" "$DEST.bak" 2>/dev/null
install -m 0755 "$tmp" "$DEST" || { bad "could not write $DEST"; exit 1; }
echo "$MGR_REL" > "$BASE_DIR/update.url"
[ -n "$MIRROR" ] && echo "${MIRROR%/}" > "$BASE_DIR/core.mirror"
ok "manager v${ver:-?} installed as: maxdark"

# Always refresh the core to the latest release, so re-running this one-liner
# upgrades an existing install. If the download fails but a core is already
# here, keep it.
if ! "$DEST" --install-core </dev/null; then
  if [ -x /usr/local/bin/mdt ]; then info "kept existing core $(/usr/local/bin/mdt version)"
  else bad "core not installed yet - use [1] Core in the menu"; fi
fi

if [ -n "$PAIR" ]; then
  exec "$DEST" --pair "$PAIR"
fi

echo
printf '  %srun it any time with:%s  maxdark\n' "$D" "$N"
echo
if (exec </dev/tty) 2>/dev/null; then exec "$DEST" </dev/tty; fi
