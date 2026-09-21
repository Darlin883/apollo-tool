#!/bin/bash
# apollo-fix-all.sh — one command to get Apollo's scored services healthy and locked down.
#   sudo bash apollo-fix-all.sh
# Order: (1) purge Red persistence + start the guard  (2) distcc: limit to your subnet
#        (3) DNS: listen on all interfaces, no zone transfers, no open recursion (validated, rolls back)
#        (4) restart SSH / DNS / distcc / DNS panel + open their firewall ports + UP/DOWN report
# Override the distcc allow-list:  sudo ALLOWED="127.0.0.1 <team-subnet> <scorer-ip>" bash apollo-fix-all.sh
[ "$(id -u)" = 0 ] || [ -n "${FIX_TEST:-}" ] || { echo "Run as root."; exit 1; }
RAW=https://raw.githubusercontent.com/Darlin883/apollo-tool/main
HERE=$(dirname "$(readlink -f "$0")")
DISTCC_CONF=${DISTCC_CONF:-/etc/default/distcc}
BIND_OPTS=${BIND_OPTS:-/etc/bind/named.conf.options}
TS=$(date +%s)
ok()   { echo "  [ok]   $*"; }
warn() { echo "  [warn] $*"; }
step() { echo; echo "== $* =="; }

fetch() {   # fetch <script> -> path (uses a sibling copy if present, else downloads)
  local f=$1
  if [ -f "$HERE/$f" ]; then echo "$HERE/$f"; return; fi
  curl -fsSL "$RAW/$f" -o "/root/$f" 2>/dev/null && echo "/root/$f"
}

step "1/4 Remove Red persistence, start guard"
g=$(fetch apollo-guard.sh)
if [ -n "$g" ]; then bash "$g" once; bash "$g" bg; else warn "couldn't get apollo-guard.sh (no network?)"; fi

step "2/4 distcc: restrict who can connect"
if [ -z "${ALLOWED:-}" ]; then
  ip4=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)
  [ -n "$ip4" ] && ALLOWED="127.0.0.1 ${ip4%.*}.0/24"
fi
if [ -f "$DISTCC_CONF" ] && [ -n "${ALLOWED:-}" ]; then
  cp "$DISTCC_CONF" "$DISTCC_CONF.bak.$TS"
  if grep -q '^ALLOWEDNETS=' "$DISTCC_CONF"; then sed -i "s|^ALLOWEDNETS=.*|ALLOWEDNETS=\"$ALLOWED\"|" "$DISTCC_CONF"
  else echo "ALLOWEDNETS=\"$ALLOWED\"" >> "$DISTCC_CONF"; fi
  ok "ALLOWEDNETS=\"$ALLOWED\"  (add the scorer's IP if it's outside that subnet)"
else warn "distcc restriction skipped: no $DISTCC_CONF, or no IPv4 found to derive a subnet (set ALLOWED=...)"; fi

step "3/4 DNS: bind on all interfaces, no zone transfers, no recursion"
if [ -f "$BIND_OPTS" ]; then
  cp "$BIND_OPTS" "$BIND_OPTS.bak.$TS"
  sed -i -E '/^[[:space:]]*(listen-on|listen-on-v6|allow-transfer|recursion)[[:space:]]/d' "$BIND_OPTS"
  sed -i '/^options {/a\    listen-on { any; };\n    listen-on-v6 { any; };\n    allow-transfer { none; };\n    recursion no;' "$BIND_OPTS"
  if [ -n "${NOCHECK:-}" ] || ! command -v named-checkconf >/dev/null 2>&1 || named-checkconf 2>/dev/null; then
    ok "named.conf.options updated (backup: $BIND_OPTS.bak.$TS)"
  else
    cp "$BIND_OPTS.bak.$TS" "$BIND_OPTS"; warn "named-checkconf FAILED — restored the original, DNS config unchanged"
  fi
else warn "$BIND_OPTS not found — DNS step skipped"; fi
[ -n "${FIX_TEST:-}" ] && exit 0

step "4/4 Restart services + open ports + status"
u=$(fetch apollo-up.sh)
if [ -n "$u" ]; then bash "$u"; else
  warn "couldn't get apollo-up.sh — restarting by hand"
  systemctl restart ssh named distccd dns-gui 2>&1 | sed 's/^/  /'
fi
echo; echo "Done. Log of what the guard removed: tail /root/apollo-guard.log"
