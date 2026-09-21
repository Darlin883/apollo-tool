#!/bin/bash
# apollo-guard.sh — auto-kills Red's known persistence every few seconds:
#   * any non-root UID-0 account (and its passwd/shadow/group/sudoers entries)
#   * rogue python "http.server" processes (anything not on the scored panel port 8053)
#   * cron jobs that re-add users, touch passwd/shadow/sudoers, or start http.server
# Usage:  sudo bash apollo-guard.sh          run in the foreground (Ctrl+C to stop)
#         sudo bash apollo-guard.sh bg       run in the background (survives closing the terminal)
#         sudo bash apollo-guard.sh install  systemd service: starts on boot, restarts if killed
#         sudo bash apollo-guard.sh once     one pass and exit
# Log: /root/apollo-guard.log   Evidence copies: /root/evidence/
[ "$(id -u)" = 0 ] || [ -n "${GUARD_TEST:-}" ] || { echo "Run as root."; exit 1; }
ETC=${ETC:-/etc}
LOG=${LOG:-/root/apollo-guard.log}; EVID=${EVID:-/root/evidence}; INTERVAL=${INTERVAL:-5}
BAD_NAMES="NeilArmstron"
CRON_BAD='NeilArmstron|http\.server|/etc/passwd|/etc/shadow|/etc/sudoers|>> ?/etc/'
mkdir -p "$EVID" 2>/dev/null
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }

purge_user() {   # remove a user's lines from the account files and sudoers
  local u=$1 f
  who | awk -v u="$u" '$1==u{print $2}' | while read -r t; do pkill -9 -t "$t" 2>/dev/null; done
  chattr -i "$ETC"/passwd "$ETC"/shadow "$ETC"/group "$ETC"/gshadow 2>/dev/null
  sed -i "/^$u:/d" "$ETC"/passwd "$ETC"/shadow "$ETC"/group "$ETC"/gshadow 2>/dev/null
  for f in "$ETC"/sudoers "$ETC"/sudoers.d/*; do
    [ -f "$f" ] && grep -q "^[[:space:]]*$u[[:space:]]" "$f" 2>/dev/null || continue
    cp "$f" "$EVID/$(basename "$f").$(date +%s)"
    cp "$f" "$f.guardtmp"
    sed -i "/^[[:space:]]*$u[[:space:]]/d" "$f.guardtmp"
    if command -v visudo >/dev/null 2>&1 && ! visudo -cf "$f.guardtmp" >/dev/null 2>&1; then
      rm -f "$f.guardtmp"; log "WARN sudoers edit for $u failed validation — left $f alone"
    else cat "$f.guardtmp" > "$f"; rm -f "$f.guardtmp"; fi
  done
}

tick() {
  local u pid cmd f base
  # 1. extra UID-0 accounts + known backdoor names
  for u in $( { awk -F: '$3==0 && $1!="root"{print $1}' "$ETC"/passwd; for n in $BAD_NAMES; do grep "^$n:" "$ETC"/passwd | cut -d: -f1; done; } | sort -u); do
    log "REMOVED account '$u' (UID-0 backdoor)"; purge_user "$u"
  done
  for u in $BAD_NAMES; do grep -q "^[[:space:]]*$u[[:space:]]" "$ETC"/sudoers 2>/dev/null && { log "REMOVED sudoers entry for $u"; purge_user "$u"; }; done
  # 2. rogue http.server (the scored DNS panel on 8053 is left alone)
  for pid in $(pgrep -f 'http\.server' 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
    case "$cmd" in *8053*) continue ;; esac
    log "KILLED http.server pid $pid: $cmd"; kill -9 "$pid" 2>/dev/null
  done
  # 2b. reverse/bind shells: python socket+dup2/execv one-liners, /dev/tcp, nc/ncat -e
  for pid in $(pgrep -f 'socket.*(dup2|execv)|/dev/tcp/|nc(at)? .*-e |bash -i' 2>/dev/null); do
    [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ] && continue
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
    case "$cmd" in *apollo-guard*|*pgrep*|*journalctl*|*grep*) continue ;; esac
    log "KILLED shell process pid $pid: ${cmd:0:160}"; kill -9 "$pid" 2>/dev/null
  done
  [ -n "${NOCRON:-}" ] && return
  # 3. malicious cron lines (per-user crontabs, /etc/cron.d)
  for f in /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    grep -qE "$CRON_BAD" "$f" || continue
    base=$(basename "$f"); cp "$f" "$EVID/crontab-$base.$(date +%s)"
    grep -vE "$CRON_BAD|^#Ansible" "$f" > "$f.guardtmp"
    if [ -s "$f.guardtmp" ]; then crontab -u "$base" "$f.guardtmp" 2>/dev/null; else crontab -r -u "$base" 2>/dev/null; fi
    rm -f "$f.guardtmp"; log "CLEANED malicious cron lines from $base's crontab"
  done
  for f in /etc/cron.d/*; do
    [ -f "$f" ] && grep -qE "$CRON_BAD" "$f" && { mv "$f" "$EVID/"; log "MOVED malicious /etc/cron.d/$(basename "$f") to $EVID"; }
  done
}

case "${1:-run}" in
  once)    tick ;;
  bg)      nohup bash "$(readlink -f "$0")" run >/dev/null 2>&1 & echo "guard running in background (pid $!). Log: $LOG" ;;
  install) cat > /etc/systemd/system/apollo-guard.service <<UNIT
[Unit]
Description=Apollo guard — auto-remove Red persistence
[Service]
ExecStart=/bin/bash $(readlink -f "$0") run
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
           systemctl daemon-reload && systemctl enable --now apollo-guard.service && echo "installed + started: systemctl status apollo-guard" ;;
  run|*)   log "guard started (every ${INTERVAL}s)"; while true; do tick; sleep "$INTERVAL"; done ;;
esac
