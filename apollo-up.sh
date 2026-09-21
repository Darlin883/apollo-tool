#!/bin/bash
# apollo-up.sh — bring the 4 scored services back up fast. Run: sudo bash apollo-up.sh
# Restarts SSH, DNS, distcc, HTTP-DNSGui; opens their ports in the firewall (adds rules only,
# never removes any); prints UP/DOWN per port. Safe to rerun.
[ "$(id -u)" = 0 ] || { echo "Run as root."; exit 1; }

unit_exists() { systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$1.service"; }
revive() {   # revive <label> <unit> [unit...]
  local label=$1 u; shift
  for u in "$@"; do
    if unit_exists "$u"; then
      systemctl unmask "$u" >/dev/null 2>&1
      systemctl enable "$u" >/dev/null 2>&1
      if systemctl restart "$u" 2>/dev/null; then echo "[ok]   $label: restarted $u"
      else echo "[FAIL] $label: $u won't start -> journalctl -u $u -n 15 --no-pager"; fi
      return
    fi
  done
  echo "[??]   $label: no service found (tried: $*)"
}

revive SSH ssh sshd
revive DNS named bind9
revive distcc distccd distcc
gui=$(systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -iE 'dns.?gui' | sed 's/\.service$//' | head -1)
if [ -n "$gui" ]; then revive DNSGui "$gui"
else echo "[??]   DNSGui: no service found -> ls /opt/dns-gui and start it by hand"; fi

# DNS panel fallback: if the service didn't bring up 8053, run the app directly (detached).
sleep 3
if ! ss -lnt 2>/dev/null | grep -qE '[:.]8053[[:space:]]' && [ -f /opt/dns-gui/app.py ]; then
  echo "[fix]  DNSGui: service didn't open 8053 — starting /opt/dns-gui/app.py directly"
  pkill -f '/opt/dns-gui/app.py' 2>/dev/null
  ( cd /opt/dns-gui && setsid nohup python3 app.py > /root/dnsgui.log 2>&1 < /dev/null & )
  sleep 3
  ss -lnt 2>/dev/null | grep -qE '[:.]8053[[:space:]]' || echo "[FAIL] DNSGui: still not listening — read: cat /root/dnsgui.log"
fi

for p in 22/tcp 53/tcp 53/udp 8053/tcp 3632/tcp; do
  port=${p%/*}; proto=${p#*/}
  command -v iptables >/dev/null 2>&1 && ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null &&
    iptables -I INPUT 1 -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
  command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active' && ufw allow "$p" >/dev/null 2>&1
done

sleep 2
echo; echo "--- listening check ---"
for pair in "SSH:22:t" "DNS:53:t" "DNS:53:u" "DNSGui:8053:t" "distcc:3632:t"; do
  IFS=: read -r n port k <<< "$pair"
  if ss -ln"$k"p 2>/dev/null | grep -qE "[:.]$port[[:space:]]"; then echo "  UP    $n ($port/${k/t/tcp})" | sed 's#/u$#/udp#'
  else echo "  DOWN  $n ($port/${k/t/tcp})"; fi
done
echo; echo "--- DNS answers? ---"
for z in artemis.space status.artemis.space; do
  r=$(dig +short +time=3 +tries=1 @127.0.0.1 "$z" SOA 2>/dev/null | head -1)
  [ -n "$r" ] && echo "  OK    $z answers" || echo "  FAIL  $z gives no answer -> named-checkconf; named-checkzone $z /etc/bind/db.$z"
done
echo; echo "Reminder: reachable only if the firewall isn't dropping the scorer, and DNS/DNSGui bind to the box's competition IP, not just 127.0.0.1."
