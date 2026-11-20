#!/usr/bin/env bash
# ==============================================================================
#  MAX DARK TUNNEL
#  Manager for the mdt core: TCP Forward, Tun (MDTprotocol / ICMP / TCP / UDP),
#  DNS and SSH tunnels between an IRAN and a KHAREJ server.
#  Support: @mikakhadm
#
#  ROLES:
#    IRAN   = where users connect. You create the tunnel here and get a
#             PAIR CODE.
#    KHAREJ = reaches the open internet. Paste the pair code, nothing else
#             to answer.
#
#  MAXDARK-TUNNEL-SCRIPT
# ==============================================================================

SCRIPT_VER="1.0.0"
DEV_ID="@mikakhadm"

GH_REPO="darktunnelmika/max-dark-tunnel"
RAW_BASE="https://raw.githubusercontent.com/$GH_REPO/main"
BASE_DIR="/etc/max-dark-tunnel"
TUN_DIR="$BASE_DIR/tunnels"
LOG_DIR="/var/log/max-dark-tunnel"
BIN_PATH="/usr/local/bin/mdt"
UNIT_FILE="/etc/systemd/system/mdt@.service"
RS_UNIT="/etc/systemd/system/mdt-restart@.service"
UPDATE_URL_FILE="$BASE_DIR/update.url"
MIRROR_FILE="$BASE_DIR/core.mirror"
SELF_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "$0")"

# Started as `curl ... | bash`: stdin is the pipe, reattach the terminal.
if [ ! -t 0 ] && (exec </dev/tty) 2>/dev/null; then
  exec </dev/tty
fi

# ================================================================== UI ======
R=$'\e[38;5;203m'; G=$'\e[38;5;114m'; Y=$'\e[38;5;221m'
C=$'\e[38;5;81m';  M=$'\e[38;5;177m'; W=$'\e[1;97m'
D=$'\e[38;5;244m'; N=$'\e[0m';        BD=$'\e[1m'
L1=$'\e[38;5;93m'; L2=$'\e[38;5;99m'; L3=$'\e[38;5;105m'
L4=$'\e[38;5;111m'; L5=$'\e[38;5;117m'; L6=$'\e[38;5;123m'
BG_OK=$'\e[48;5;22m'; BG_ERR=$'\e[48;5;52m'
UIW=62

shopt -s extglob 2>/dev/null
if ! locale charmap 2>/dev/null | grep -qi 'utf-\?8'; then
  for L in C.UTF-8 C.utf8 en_US.UTF-8 en_US.utf8; do
    if locale -a 2>/dev/null | grep -qix "${L//./\\.}"; then export LC_ALL="$L"; break; fi
  done
fi
_probe='é'; [ ${#_probe} -eq 1 ] && UTF_OK=1 || UTF_OK=0

vislen() {
  local s="${1//$'\e['*([0-9;])m/}"
  if [ "$UTF_OK" = 1 ]; then printf '%s' "${#s}"; return; fi
  local b c
  b="$(LC_ALL=C; printf '%s' "$s" | wc -c)"
  c="$(printf '%s' "$s" | LC_ALL=C grep -o $'[\x80-\xbf]' 2>/dev/null | wc -l)"
  printf '%s' $(( b - c ))
}
rep() { local ch="$1" n="$2"; [ "${n:-0}" -gt 0 ] 2>/dev/null || return 0
        printf "${ch}%.0s" $(seq 1 "$n"); }
top()   { printf '  %s╭%s╮%s\n' "$C" "$(rep '─' $((UIW+2)))" "$N"; }
mid()   { printf '  %s├%s┤%s\n' "$C" "$(rep '─' $((UIW+2)))" "$N"; }
bot()   { printf '  %s╰%s╯%s\n' "$C" "$(rep '─' $((UIW+2)))" "$N"; }
row()   { local t="$1" l p; l=$(vislen "$t"); p=$((UIW-l)); ((p<0))&&p=0
          printf '  %s│%s %s%*s %s│%s\n' "$C" "$N" "$t" "$p" "" "$C" "$N"; }
blank() { row ""; }
item()  { row "$(printf '%s%s%s  %s%-22s%s %s%s%s' "$Y" "[$1]" "$N" "$W" "$2" "$N" "$D" "${3:-}" "$N")"; }
kv()    { row "$(printf '%s%-13s%s %s' "$D" "$1" "$N" "$2")"; }
sect()  { row "$(printf '%s%s%s' "$M$BD" "$1" "$N")"; }
badge() { printf '%s %s %s' "$2$BD" "$1" "$N"; }

ok()   { printf '  %s+%s %s\n' "$G" "$N" "$*"; }
bad()  { printf '  %sx%s %s\n' "$R" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
info() { printf '  %s>%s %s\n' "$C" "$N" "$*"; }
dim()  { printf '    %s%s%s\n' "$D" "$*" "$N"; }

ask() {
  local p="$1" d="${2:-}" v
  if [ -n "$d" ]; then read -r -p "$(printf '  %s>%s %s %s[%s]%s: ' "$C" "$N" "$p" "$D" "$d" "$N")" v || eof_exit
  else read -r -p "$(printf '  %s>%s %s: ' "$C" "$N" "$p")" v || eof_exit; fi
  ANS="${v:-$d}"
}
yesno() {
  local p="$1" d="$2" v
  read -r -p "$(printf '  %s>%s %s %s[%s]%s: ' "$C" "$N" "$p" "$D" \
      "$([ "$d" = y ] && echo 'Y/n' || echo 'y/N')" "$N")" v || eof_exit
  v="${v:-$d}"; [[ "$v" =~ ^[Yy]$ ]]
}
eof_exit() { echo; exit 0; }  # input closed: never spin on an empty read
getkey() { local k; printf '  %s>%s Select: ' "$C" "$N"; read -rsn1 k || eof_exit
           [ -z "$k" ] && k="_"; printf '%s\n\n' "$k"; KEY="$k"; }
pause()  { printf '\n  %spress any key%s' "$D" "$N"; read -rsn1 _ || eof_exit; echo; }

core_version() { [ -x "$BIN_PATH" ] && "$BIN_PATH" version 2>/dev/null || echo "-"; }
core_badge() {
  if [ -x "$BIN_PATH" ]; then badge "READY" "$BG_OK$W"; else badge "NO CORE" "$BG_ERR$W"; fi
}

header() {
  clear
  top
  row "$(printf '%s███╗   ███╗ %s█████╗ %s██╗  ██╗%s' "$L1" "$L2" "$L3" "$N")"
  row "$(printf '%s████╗ ████║%s██╔══██╗%s╚██╗██╔╝%s' "$L1" "$L2" "$L3" "$N")"
  row "$(printf '%s██╔████╔██║%s███████║%s ╚███╔╝ %s' "$L2" "$L3" "$L4" "$N")"
  row "$(printf '%s██║╚██╔╝██║%s██╔══██║%s ██╔██╗ %s' "$L3" "$L4" "$L5" "$N")"
  row "$(printf '%s██║ ╚═╝ ██║%s██║  ██║%s██╔╝ ██╗%s' "$L4" "$L5" "$L6" "$N")"
  row "$(printf '%s╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝%s' "$D" "$N")"
  row "$(printf '%sD%s A%s R%s K%s   T U N N E L%s   %stcp · tun · icmp · dns · ssh%s' \
        "$L2" "$L3" "$L4" "$L5" "$W$BD" "$N" "$D" "$N")"
  mid
  row "$(printf '%s %score %s%s   %sv%s%s   %s%s%s' \
        "$(core_badge)" "$D" "$N$W" "$(core_version)" "$D" "$SCRIPT_VER" "$N" "$M" "$DEV_ID" "$N")"
  bot
  [ -n "${1:-}" ] && { echo; printf '  %s>%s %s%s%s\n' "$L4" "$N" "$W$BD" "$1" "$N"; }
  echo
}

# ============================================================== HELPERS ====
need_root() { [ "$(id -u)" -eq 0 ] || { bad "run as root"; exit 1; }; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_name() { [[ "$1" =~ ^[a-zA-Z0-9_-]{1,24}$ ]]; }
valid_ip4()  {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1:4}"; do
    [ "${#o}" -gt 1 ] && [ "${o:0:1}" = 0 ] && return 1
    [ "$o" -le 255 ] || return 1
  done
}
# "443, 2083>8443" -> "443,2083>8443"; every entry checked
valid_ports_csv() {
  local csv="${1// /}" e l t
  [ -z "$csv" ] && return 0
  IFS=',' read -r -a _e <<<"$csv"
  for e in "${_e[@]}"; do
    [ -z "$e" ] && continue
    l="${e%%>*}"; t="${e#*>}"
    valid_port "$l" || return 1
    [ "$t" = "$e" ] && continue
    valid_port "$t" && continue
    [[ "$t" =~ ^[A-Za-z0-9.-]+:[0-9]+$ ]] && valid_port "${t##*:}" || return 1
  done
}

install_deps() {
  local need="" c
  for c in curl ip systemctl; do command -v "$c" >/dev/null 2>&1 || need="$need $c"; done
  [ -z "$need" ] && return
  need="${need/ ip/ iproute2}"; need="${need/ systemctl/}"
  [ -z "${need// /}" ] && return
  info "installing:$need"
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq $need
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q $need
  elif command -v yum     >/dev/null 2>&1; then yum install -y -q $need
  else warn "install manually:$need"; fi
}

ensure_dirs() { mkdir -p "$TUN_DIR" "$LOG_DIR"; chmod 700 "$BASE_DIR" "$TUN_DIR"; }

ensure_units() {
  if [ ! -f "$UNIT_FILE" ] || ! grep -q 'MAXDARK-UNIT-2' "$UNIT_FILE"; then
    cat > "$UNIT_FILE" <<EOF
# MAXDARK-UNIT-2
[Unit]
Description=Max Dark Tunnel (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH run -c $TUN_DIR/%i.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    cat > "$RS_UNIT" <<'EOF'
[Unit]
Description=Max Dark Tunnel scheduled restart (%i)
[Service]
Type=oneshot
ExecStart=/bin/systemctl restart mdt@%i.service
EOF
    systemctl daemon-reload
  fi
}

arch_name() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "" ;;
  esac
}

public_ip() {
  local u ip
  for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip https://ip.sb; do
    ip="$(curl -4 -fsS --max-time 4 "$u" 2>/dev/null | tr -d '[:space:]')"
    valid_ip4 "$ip" && { echo "$ip"; return; }
  done
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

tunnel_names() { local f; for f in "$TUN_DIR"/*.json; do [ -e "$f" ] && basename "$f" .json; done; }
tunnel_count() { tunnel_names | grep -c .; }
cfg_get() {  # cfg_get NAME KEY -> value from the json (flat, one key per line, written by mdt)
  local f="$TUN_DIR/$1.json" v
  v="$(sed -n "s/^ *\"$2\": *\"\(.*\)\",\{0,1\}$/\1/p" "$f" | head -1)"
  [ -z "$v" ] && v="$(sed -n "s/^ *\"$2\": *\([0-9]*\),\{0,1\}$/\1/p" "$f" | head -1)"
  printf '%s' "$v"
}
svc_state() { systemctl is-active "mdt@$1" 2>/dev/null; }
link_state() { "$BIN_PATH" status -c "$TUN_DIR/$1.json" 2>/dev/null | sed -n 's/^state=//p'; }

state_badge() {
  local s; s="$(svc_state "$1")"
  if [ "$s" != active ]; then printf '%s%s%s' "$R" "${s:-stopped}" "$N"; return; fi
  case "$(link_state "$1")" in
    connected) printf '%srunning · connected%s' "$G" "$N" ;;
    *)         printf '%srunning · %snot connected%s' "$G" "$Y" "$N" ;;
  esac
}

next_subnet() {
  local used n s
  used=" "
  for n in $(tunnel_names); do
    s="$(cfg_get "$n" subnet)"; used="$used${s:-0} "
  done
  for s in $(seq 0 250); do [[ "$used" == *" $s "* ]] || { echo "$s"; return; }; done
  echo 251
}

open_fw() {  # open_fw tcp|udp PORT  (only when ufw is active)
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -q 'Status: active' || return 0
  ufw allow "$2/$1" >/dev/null 2>&1 && dim "ufw: opened $2/$1"
}

start_tunnel() {
  systemctl enable --now "mdt@$1" >/dev/null 2>&1
  systemctl restart "mdt@$1" >/dev/null 2>&1
}
stop_tunnel() { systemctl disable --now "mdt@$1" >/dev/null 2>&1; }

set_restart_timer() {  # NAME off|1h|6h|12h|24h
  local name="$1" every="$2" tf="/etc/systemd/system/mdt-restart@$1.timer"
  systemctl disable --now "mdt-restart@$name.timer" >/dev/null 2>&1
  rm -f "$tf"
  if [ "$every" != off ]; then
    cat > "$tf" <<EOF
[Unit]
Description=Max Dark Tunnel restart timer ($name)
[Timer]
OnBootSec=$every
OnUnitActiveSec=$every
Unit=mdt-restart@$name.service
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "mdt-restart@$name.timer" >/dev/null 2>&1
  else
    systemctl daemon-reload
  fi
}
restart_timer_of() {
  local tf="/etc/systemd/system/mdt-restart@$1.timer"
  [ -f "$tf" ] && sed -n 's/^OnUnitActiveSec=//p' "$tf" || echo off
}

wait_connected() {  # wait up to N seconds for the link
  local i
  for i in $(seq 1 "${2:-15}"); do
    [ "$(link_state "$1")" = connected ] && return 0
    sleep 1
  done
  return 1
}

# ================================================================ CORE =====
install_core() {
  local arch url tmp mirror
  arch="$(arch_name)"
  [ -z "$arch" ] && { bad "unsupported cpu: $(uname -m)"; return 1; }
  mirror="$(cat "$MIRROR_FILE" 2>/dev/null)"
  tmp="$(mktemp)"
  for url in ${mirror:+"$mirror/mdt-linux-$arch"} \
             "https://github.com/$GH_REPO/releases/latest/download/mdt-linux-$arch"; do
    info "downloading core: $url"
    if curl -fL --retry 2 --max-time 120 -o "$tmp" "$url" 2>/dev/null && [ -s "$tmp" ]; then
      chmod +x "$tmp"
      if "$tmp" version >/dev/null 2>&1; then
        install -m 0755 "$tmp" "$BIN_PATH"; rm -f "$tmp"
        ok "core $(core_version) installed"
        return 0
      fi
    fi
  done
  rm -f "$tmp"
  bad "core download failed"
  dim "IRAN servers often cannot reach github.com. Options:"
  dim "  - copy the mdt-linux-$arch file to /root/mdt and use [2] in the Core menu"
  dim "  - or set a mirror URL with [3] in the Core menu"
  return 1
}

install_core_local() {
  ask "path to the mdt binary" "/root/mdt"
  [ -f "$ANS" ] || { bad "not found: $ANS"; return 1; }
  chmod +x "$ANS"
  "$ANS" version >/dev/null 2>&1 || { bad "that file is not an mdt binary for this cpu"; return 1; }
  install -m 0755 "$ANS" "$BIN_PATH" && ok "core $(core_version) installed from $ANS"
}

ensure_core() {
  [ -x "$BIN_PATH" ] && return 0
  warn "core is not installed"
  install_core
}

screen_core() {
  while :; do
    header "CORE"
    top
    kv "installed" "$(core_version)"
    kv "binary" "$BIN_PATH"
    kv "mirror" "$(cat "$MIRROR_FILE" 2>/dev/null || echo none)"
    mid
    item 1 "Install / update" "from github or mirror"
    item 2 "Install from file" "offline, e.g. /root/mdt"
    item 3 "Set mirror URL" "folder holding mdt-linux-*"
    item 4 "Optimize network" "bbr + socket buffers"
    item 0 "Back" ""
    bot; echo; getkey
    case "$KEY" in
      1) install_core && restart_all; pause ;;
      2) install_core_local && restart_all; pause ;;
      3) ask "mirror base URL (empty to clear)" ""
         if [ -z "$ANS" ]; then rm -f "$MIRROR_FILE"; ok "mirror cleared"
         else echo "${ANS%/}" > "$MIRROR_FILE"; ok "mirror set"; fi; pause ;;
      4) optimize_net; pause ;;
      0|q|Q) return ;;
    esac
  done
}

restart_all() {
  local n
  for n in $(tunnel_names); do
    [ "$(svc_state "$n")" = active ] && systemctl restart "mdt@$n"
  done
}

optimize_net() {
  cat > /etc/sysctl.d/99-max-dark-tunnel.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1
net.ipv4.ip_forward=1
fs.file-max=1048576
EOF
  sysctl -p /etc/sysctl.d/99-max-dark-tunnel.conf >/dev/null 2>&1
  ok "applied: bbr, fq, 16MB buffers, mtu probing"
}

# ============================================================ PAIR CODE ====
show_pair_code() {
  local code; code="$(cat "$TUN_DIR/$1.pair" 2>/dev/null)"
  [ -z "$code" ] && { bad "no pair code stored (pair codes are made on IRAN)"; return; }
  echo; top; sect "PAIR CODE  -  $1"
  row "$(printf '%son the KHAREJ server, run this one line:%s' "$D" "$N")"; bot
  echo
  printf '%sbash <(curl -Ls %s/install.sh) --pair %s%s\n' "$W" "$RAW_BASE" "$code" "$N"
  echo
  dim "or open the menu there, choose [3] and paste only the code:"
  echo
  printf '%s%s%s\n' "$W" "$code" "$N"
  echo
}

# ========================================================= NEW: IRAN =======
screen_new_iran() {
  header "NEW TUNNEL - IRAN"
  ensure_core || { pause; return; }

  local name tr car dir port proto kip iip tcpp udpp needk sub mtu dd args itype irep icode
  local def="t$(( $(tunnel_count) + 1 ))"
  while :; do
    ask "tunnel name" "$def"; name="$ANS"
    valid_name "$name" || { bad "letters, digits, _ and - only (max 24)"; continue; }
    [ -e "$TUN_DIR/$name.json" ] && { bad "a tunnel named $name exists"; continue; }
    break
  done

  echo; top; sect "TRANSPORT"
  item 1 "TCP Forward" "multiplexed, encrypted - best start"
  item 2 "Tun" "layer 3: MDTprotocol / ICMP / TCP / UDP"
  item 3 "DNS" "tun over udp/53"
  item 4 "SSH" "tcp forward over ssh"
  bot
  ask "transport" "1"
  case "$ANS" in 2) tr=tun ;; 3) tr=dns ;; 4) tr=ssh ;; *) tr=tcp ;; esac

  car=""
  if [ "$tr" = tun ]; then
    echo; top; sect "TUN CARRIER"
    item 1 "MDTprotocol" "raw IP protocol (GRE 47, ESP 50, ...)"
    item 2 "ICMP" "looks like ping"
    item 3 "TCP" "tun inside encrypted tcp"
    item 4 "UDP" "tun inside encrypted udp"
    bot
    ask "carrier" "1"
    case "$ANS" in 2) car=icmp ;; 3) car=tcp ;; 4) car=udp ;; *) car=mdtp ;; esac
  fi

  # direction only matters where one side dials the other
  dir=""
  if [ "$tr" = tcp ] || [ "$tr" = ssh ] || [ "$car" = tcp ] || [ "$car" = udp ]; then
    local ddef=1; [ "$tr" = ssh ] && ddef=2
    echo
    dim "reverse: IRAN listens, KHAREJ dials in (works when IRAN blocks outbound)"
    dim "direct : KHAREJ listens, IRAN dials out"
    ask "direction  1) reverse  2) direct" "$ddef"
    [ "$ANS" = 2 ] && dir=direct || dir=reverse
  fi

  port=""
  if [ "$tr" != tun ] || [ "$car" = tcp ] || [ "$car" = udp ]; then
    local pdef=443
    [ "$tr" = dns ] && pdef=53
    [ "$tr" = ssh ] && pdef=2020
    while :; do
      ask "carrier port" "$pdef"; port="$ANS"
      valid_port "$port" || { bad "1-65535"; continue; }
      [ "$tr" = ssh ] && [ "$port" = 22 ] && { bad "22 is the real sshd - pick another"; continue; }
      break
    done
  fi

  proto=""; itype=""; irep=""; icode=""
  if [ "$car" = mdtp ]; then
    dim "47=GRE  50=ESP  4=IPIP  41=6in4 - or any 1-255 your route lets through"
    while :; do ask "IP protocol number" "47"; proto="$ANS"
      [[ "$proto" =~ ^[0-9]+$ ]] && [ "$proto" -ge 1 ] && [ "$proto" -le 255 ] && break; bad "1-255"; done
  fi
  if [ "$car" = icmp ]; then
    itype=8; irep=0; icode=0
    if yesno "custom ICMP type/code? (default: echo request / reply)" n; then
      ask "type IRAN sends" "8"; itype="$ANS"
      ask "type KHAREJ sends" "0"; irep="$ANS"
      ask "code" "0"; icode="$ANS"
    fi
  fi

  if [ "$tr" = dns ]; then
    ask "query domain (any name, used for camouflage)" "cdn.cloudfront.net"; dd="$ANS"
  fi

  # Who needs what address
  needk=0
  [ "$dir" = direct ] && needk=1
  [ "$tr" = dns ] && needk=1
  [ "$car" = mdtp ] || [ "$car" = icmp ] && needk=1

  echo
  info "detecting this server's public IP"
  iip="$(public_ip)"
  while :; do
    ask "IRAN public IP" "$iip"; iip="$ANS"
    valid_ip4 "$iip" && break; bad "invalid IPv4"
  done
  kip=""
  while :; do
    if [ "$needk" = 1 ]; then ask "KHAREJ public IP"
    else ask "KHAREJ public IP (optional for reverse)" ""; fi
    kip="$ANS"
    [ -z "$kip" ] && [ "$needk" = 0 ] && break
    valid_ip4 "$kip" && break; bad "invalid IPv4"
  done

  echo
  dim "ports your users connect to on this server. 443  or  443>8443 (lands on 8443)"
  while :; do
    ask "TCP ports (comma separated)" "443"; tcpp="${ANS// /}"
    valid_ports_csv "$tcpp" && break; bad "invalid list"
  done
  while :; do
    ask "UDP ports (empty for none)" ""; udpp="${ANS// /}"
    valid_ports_csv "$udpp" && break; bad "invalid list"
  done

  sub=""; mtu=""
  if [ "$tr" = tun ] || [ "$tr" = dns ]; then
    sub="$(next_subnet)"
    mtu=1380; [ "$tr" = dns ] && mtu=1200
  fi

  args=(-name "$name" -role iran -transport "$tr" -iran-ip "$iip" -tcp-ports "$tcpp")
  [ -n "$car" ]   && args+=(-carrier "$car")
  [ -n "$dir" ]   && args+=(-direction "$dir")
  [ -n "$port" ]  && args+=(-port "$port")
  [ -n "$kip" ]   && args+=(-kharej-ip "$kip")
  [ -n "$udpp" ]  && args+=(-udp-ports "$udpp")
  [ -n "$proto" ] && args+=(-proto "$proto")
  [ -n "$itype" ] && args+=(-icmp-type "$itype" -icmp-reply "$irep" -icmp-code "$icode")
  [ -n "$sub" ]   && args+=(-subnet "$sub" -mtu "$mtu")
  [ -n "$dd" ]    && args+=(-dns-domain "$dd")

  if ! "$BIN_PATH" new "${args[@]}" -o "$TUN_DIR/$name.json"; then
    bad "could not create the tunnel"; rm -f "$TUN_DIR/$name.json"; pause; return
  fi
  chmod 600 "$TUN_DIR/$name.json"
  "$BIN_PATH" pair -c "$TUN_DIR/$name.json" > "$TUN_DIR/$name.pair"
  chmod 600 "$TUN_DIR/$name.pair"

  # firewall: the carrier port (when we listen) and every user port
  if [ -n "$port" ] && { [ "$dir" = reverse ] && [ "$tr" != dns ]; }; then
    [ "$car" = udp ] && open_fw udp "$port" || open_fw tcp "$port"
  fi
  local p
  for p in ${tcpp//,/ }; do open_fw tcp "${p%%>*}"; done
  for p in ${udpp//,/ }; do open_fw udp "${p%%>*}"; done

  start_tunnel "$name"
  sleep 1
  if [ "$(svc_state "$name")" = active ]; then ok "tunnel $name is running - waiting for KHAREJ"
  else bad "service failed to start - check logs:"; journalctl -u "mdt@$name" -n 15 --no-pager; fi
  show_pair_code "$name"
  pause
}

# ======================================================= NEW: KHAREJ =======
join_code() {  # join_code CODE [quiet]
  local code="$1" name tmp
  ensure_core || return 1
  tmp="$(mktemp)"
  if ! name="$("$BIN_PATH" join -code "$code" -o "$tmp" 2>&1)"; then
    bad "invalid pair code: $name"; rm -f "$tmp"; return 1
  fi
  if [ -e "$TUN_DIR/$name.json" ]; then
    warn "tunnel $name already exists here - replacing it"
    stop_tunnel "$name"
  fi
  install -m 600 "$tmp" "$TUN_DIR/$name.json"; rm -f "$tmp"

  local tr car dir port
  tr="$(cfg_get "$name" transport)"; car="$(cfg_get "$name" carrier)"
  dir="$(cfg_get "$name" direction)"; port="$(cfg_get "$name" port)"
  if [ "$tr" = dns ]; then open_fw udp "$port"
  elif [ "$dir" = direct ] && [ -n "$port" ]; then
    [ "$car" = udp ] && open_fw udp "$port" || open_fw tcp "$port"
  fi
  if [ "$car" = icmp ] && [ "$(cfg_get "$name" icmp_type)" = 8 ] && [ "${2:-}" != quiet ]; then
    dim "the kernel answers every ICMP echo too, doubling upstream traffic."
    if yesno "stop the kernel answering ping on this server?" n; then
      echo 'net.ipv4.icmp_echo_ignore_all=1' > /etc/sysctl.d/98-mdt-icmp.conf
      sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null; ok "kernel ping replies off"
    fi
  fi

  start_tunnel "$name"
  info "tunnel $name started ($tr${car:+/$car}), waiting for the link"
  if wait_connected "$name" 20; then ok "connected - tunnel is live"
  else
    warn "not connected yet. check: the IRAN side is running, ports/protocol are open"
    dim "logs: tail -f $LOG_DIR/$name.log"
  fi
}

screen_new_kharej() {
  header "NEW TUNNEL - KHAREJ"
  info "paste the pair code from the IRAN server"
  ask "pair code"
  [ -z "$ANS" ] && { info "cancelled"; pause; return; }
  join_code "$ANS"
  pause
}

# ============================================================== MANAGE =====
pick_tunnel() {
  local names=() n i=1
  for n in $(tunnel_names); do names+=("$n"); done
  [ ${#names[@]} -eq 0 ] && { warn "no tunnels yet"; PICK=""; return 1; }
  top; sect "TUNNELS"
  for n in "${names[@]}"; do
    row "$(printf '%s[%d]%s %s%-12s%s %s%-7s%s %s' "$Y" "$i" "$N" "$W" "$n" "$N" "$D" "$(cfg_get "$n" role)" "$N" "$(state_badge "$n")")"
    i=$((i+1))
  done
  bot
  ask "number" "1"
  [[ "$ANS" =~ ^[0-9]+$ ]] && [ "$ANS" -ge 1 ] && [ "$ANS" -le ${#names[@]} ] || { bad "invalid"; PICK=""; return 1; }
  PICK="${names[$((ANS-1))]}"
}

screen_manage() {
  header "MANAGE"
  pick_tunnel || { pause; return; }
  local name="$PICK"
  while :; do
    header "TUNNEL  $name"
    local role tr car st
    role="$(cfg_get "$name" role)"; tr="$(cfg_get "$name" transport)"; car="$(cfg_get "$name" carrier)"
    top
    kv "status" "$(state_badge "$name")"
    kv "role" "$role"
    kv "transport" "$tr${car:+ / $car}  $(cfg_get "$name" direction)"
    kv "port" "$(cfg_get "$name" port)"
    kv "iran" "$(cfg_get "$name" iran_ip)"
    kv "kharej" "$(cfg_get "$name" kharej_ip)"
    [ "$role" = iran ] && kv "tcp ports" "$(cfg_get "$name" tcp_ports)"
    [ "$role" = iran ] && [ -n "$(cfg_get "$name" udp_ports)" ] && kv "udp ports" "$(cfg_get "$name" udp_ports)"
    if [ "$tr" = tun ] || [ "$tr" = dns ]; then
      local s; s="$(cfg_get "$name" subnet)"; kv "tun ips" "10.20.${s:-0}.1 <-> 10.20.${s:-0}.2"
    fi
    st="$("$BIN_PATH" status -c "$TUN_DIR/$name.json" 2>/dev/null)"
    kv "traffic" "rx $(sed -n 's/^rx=//p' <<<"$st")  tx $(sed -n 's/^tx=//p' <<<"$st")"
    kv "restart" "every $(restart_timer_of "$name")"
    mid
    item 1 "Status" "live link state"
    item 2 "Live log" "ctrl+c to leave"
    item 3 "Restart" ""
    item 4 "Stop / start" ""
    item 5 "Edit user ports" "iran only"
    item 6 "Scheduled restart" ""
    item 7 "Ping peer" "tun / dns only"
    [ "$role" = iran ] && item p "Pair code" "for the kharej side"
    item d "Delete" ""
    item 0 "Back" ""
    bot; echo; getkey
    case "$KEY" in
      1) "$BIN_PATH" status -c "$TUN_DIR/$name.json" | sed 's/^/    /'; pause ;;
      2) info "ctrl+c to stop"; trap 'true' INT; tail -n 40 -f "$LOG_DIR/$name.log"; trap on_interrupt INT ;;
      3) systemctl restart "mdt@$name"; ok "restarted"; sleep 1 ;;
      4) if [ "$(svc_state "$name")" = active ]; then stop_tunnel "$name"; ok "stopped"
         else start_tunnel "$name"; ok "started"; fi; sleep 1 ;;
      5) edit_ports "$name"; pause ;;
      6) ask "restart every: off 1h 6h 12h 24h" "$(restart_timer_of "$name")"
         case "$ANS" in off|1h|6h|12h|24h) set_restart_timer "$name" "$ANS"; ok "set: $ANS" ;; *) bad "invalid" ;; esac
         pause ;;
      7) if [ "$tr" = tun ] || [ "$tr" = dns ]; then
           local s; s="$(cfg_get "$name" subnet)"
           local peer="10.20.${s:-0}.2"; [ "$role" = kharej ] && peer="10.20.${s:-0}.1"
           ping -c 4 -W 2 "$peer"
         else info "tcp / ssh tunnels have no inner address - check status instead"; fi
         pause ;;
      p|P) [ "$role" = iran ] && show_pair_code "$name"; pause ;;
      d|D) if yesno "delete tunnel $name?" n; then
             stop_tunnel "$name"; set_restart_timer "$name" off
             rm -f "$TUN_DIR/$name.json" "$TUN_DIR/$name.pair" "$LOG_DIR/$name.log" "/run/max-dark-tunnel/$name.json"
             ok "deleted"; pause; return
           fi ;;
      0|q|Q) return ;;
    esac
  done
}

edit_ports() {
  local name="$1" f="$TUN_DIR/$1.json" tcpp udpp
  [ "$(cfg_get "$name" role)" = iran ] || { info "user ports live on the IRAN side"; return; }
  while :; do ask "TCP ports" "$(cfg_get "$name" tcp_ports)"; tcpp="${ANS// /}"
    valid_ports_csv "$tcpp" && break; bad "invalid list"; done
  while :; do ask "UDP ports (- for none)" "$(cfg_get "$name" udp_ports)"; udpp="${ANS// /}"
    [ "$udpp" = - ] && udpp=""; valid_ports_csv "$udpp" && break; bad "invalid list"; done
  # rewrite through python-free sed: both keys are plain strings written by mdt
  if grep -q '"tcp_ports"' "$f"; then sed -i "s|\"tcp_ports\": *\"[^\"]*\"|\"tcp_ports\": \"$tcpp\"|" "$f"
  else sed -i "s|\"psk\":|\"tcp_ports\": \"$tcpp\",\n  \"psk\":|" "$f"; fi
  if grep -q '"udp_ports"' "$f"; then sed -i "s|\"udp_ports\": *\"[^\"]*\"|\"udp_ports\": \"$udpp\"|" "$f"
  else sed -i "s|\"psk\":|\"udp_ports\": \"$udpp\",\n  \"psk\":|" "$f"; fi
  "$BIN_PATH" check -c "$f" >/dev/null || { bad "config check failed"; return; }
  local p; for p in ${tcpp//,/ }; do open_fw tcp "${p%%>*}"; done
  for p in ${udpp//,/ }; do open_fw udp "${p%%>*}"; done
  systemctl restart "mdt@$name"
  ok "ports updated - the kharej side does not need re-pairing"
}

# ============================================================ DASHBOARD ====
screen_dashboard() {
  header "DASHBOARD"
  local n st
  [ "$(tunnel_count)" -eq 0 ] && { warn "no tunnels yet"; pause; return; }
  top
  row "$(printf '%s%-12s %-7s %-12s %-20s%s' "$D" "NAME" "ROLE" "TRANSPORT" "STATE" "$N")"
  mid
  for n in $(tunnel_names); do
    local tr car; tr="$(cfg_get "$n" transport)"; car="$(cfg_get "$n" carrier)"
    row "$(printf '%s%-12s%s %-7s %-12s %s' "$W" "$n" "$N" "$(cfg_get "$n" role)" "$tr${car:+/$car}" "$(state_badge "$n")")"
    st="$("$BIN_PATH" status -c "$TUN_DIR/$n.json" 2>/dev/null)"
    row "$(printf '%s  peer %s  up %s  rx %s  tx %s%s' "$D" "$(sed -n 's/^peer=//p' <<<"$st")" \
      "$(sed -n 's/^uptime=//p' <<<"$st")" "$(sed -n 's/^rx=//p' <<<"$st")" "$(sed -n 's/^tx=//p' <<<"$st")" "$N")"
  done
  bot
  pause
}

# ========================================================== MAINTENANCE ====
update_script() {
  local url tmp nv
  url="$(cat "$UPDATE_URL_FILE" 2>/dev/null)"; url="${url:-$RAW_BASE/max-dark-tunnel.sh}"
  tmp="$(mktemp)"
  info "downloading manager"
  curl -fsSL --retry 3 --max-time 60 -o "$tmp" "$url" || { bad "download failed"; rm -f "$tmp"; return; }
  sed -i 's/\r$//' "$tmp"
  grep -q 'MAXDARK-TUNNEL-SCRIPT' "$tmp" || { bad "not the manager script - aborted"; rm -f "$tmp"; return; }
  bash -n "$tmp" 2>/dev/null || { bad "syntax errors - aborted"; rm -f "$tmp"; return; }
  nv="$(grep -m1 '^SCRIPT_VER=' "$tmp" | cut -d'"' -f2)"
  cp -f "$SELF_PATH" "$SELF_PATH.bak" 2>/dev/null
  install -m 0755 "$tmp" "$SELF_PATH"; rm -f "$tmp"
  ok "manager updated to v${nv:-?}"
  if yesno "update the core too?" y; then install_core && restart_all; fi
  sleep 1; exec bash "$SELF_PATH"
}

screen_uninstall() {
  header "UNINSTALL"
  warn "removes every tunnel, service and the core"
  echo; ask "type UNINSTALL to confirm"
  [ "$ANS" = UNINSTALL ] || { info "cancelled"; pause; return; }
  local n
  for n in $(tunnel_names); do stop_tunnel "$n"; set_restart_timer "$n" off; done
  rm -f "$UNIT_FILE" "$RS_UNIT" /etc/sysctl.d/98-mdt-icmp.conf; systemctl daemon-reload
  rm -f "$BIN_PATH"; rm -rf "$BASE_DIR" "$LOG_DIR" /run/max-dark-tunnel
  ok "uninstalled (the manager itself: rm $SELF_PATH)"
  pause; exit 0
}

on_interrupt() { echo; info "bye"; exit 130; }

# =============================================================== MAIN MENU =
main_menu() {
  while :; do
    header
    local tot run
    tot="$(tunnel_count)"
    run="$(systemctl list-units 'mdt@*' --state=running --no-legend 2>/dev/null | grep -c .)"
    top
    row "$(printf '%s%s%s tunnels   %s%s%s running   %s%s%s' "$W$BD" "$tot" "$N" "$G$BD" "$run" "$N" "$D" \
        "$([ -x "$BIN_PATH" ] && echo 'core ready' || echo 'core missing')" "$N")"
    mid; sect "SETUP"
    item 1 "Core" "install / update mdt"
    item 2 "New tunnel - IRAN" "makes the pair code"
    item 3 "New tunnel - KHAREJ" "paste the pair code"
    mid; sect "OPERATE"
    item 4 "Manage tunnels" "status, logs, ports, pair code"
    item 5 "Dashboard" "all tunnels at a glance"
    mid; sect "MAINTENANCE"
    item 6 "Update" "manager + core"
    item 7 "Uninstall" ""
    item 0 "Exit" ""
    bot; echo; getkey
    case "$KEY" in
      1) screen_core ;;       2) screen_new_iran ;;   3) screen_new_kharej ;;
      4) screen_manage ;;     5) screen_dashboard ;;
      6) update_script; pause ;;  7) screen_uninstall ;;
      0|q|Q) clear; printf '  %sMAX DARK TUNNEL%s  %s%s%s\n\n' "$C" "$N" "$D" "$DEV_ID" "$N"; exit 0 ;;
    esac
  done
}

need_root
install_deps
ensure_dirs
ensure_units
trap on_interrupt INT TERM

case "${1:-}" in
  --pair)    shift; [ -z "${1:-}" ] && { bad "usage: --pair CODE"; exit 1; }
             join_code "$1" quiet; exit $? ;;
  --status)  for n in $(tunnel_names); do printf '%-14s %s\n' "$n" "$(link_state "$n")"; done; exit 0 ;;
  --install-core) install_core; exit $? ;;
esac
main_menu
