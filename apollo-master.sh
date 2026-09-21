#!/bin/bash
# apollo-master.sh — APOLLO: hardening + baseline + live anomaly watch
# PSUCCSO Red v. Blue 2026 — Box: Apollo, Debian 12, 10.x.2.10 (practice: apollo-practice)
# Scored services: SSH(22) DNS(53) HTTP-DNSGui(8053) distcc(3632)
#
# Run as root (sudo bash apollo-master.sh <mode>). TEST on apollo-practice first.
#
# Modes:
#   harden    one-shot hardening pass (SSH/DNS/distcc/HTTP-DNSGui/UFW) + account/cron/SUID report.
#             Asks before anything that could lock you out or fail a scored check.
#   baseline  snapshot current "known good" state to diff against later — run this
#             immediately after harden, once you've confirmed everything looks right
#   watch     diff live state against the baseline, print ONLY what's new.
#             New remote IPs are called out first — block one from monitor -> 0) IPs & firewall.
#             Repeats every N seconds if you pass -n <seconds>, otherwise runs once.
#   start     launch a BACKGROUND monitor daemon. Detaches from your terminal (setsid) so it
#             keeps running after you close the SSH session — only 'stop' stops it. Also runs
#             the language/keyboard guard every cycle (see 'fixlang' below) — it fixes a flip
#             on its own, logged as LANG CHANGE, whether or not anyone opens the console.
#   view      open the LIVE DASHBOARD (read-only, redraws every second). Shows logged-in users,
#             account/sudo/SSH-key/passwd changes vs. baseline, processes that weren't running
#             ~30 min ago, and remote IPs. Closing it (q or Ctrl+C) does NOT stop the daemon.
#   stop      stop the background monitor daemon (if installed as a service, it stays enabled
#             and will come back on the next reboot — use 'uninstall' to remove that too).
#   status    is the daemon running, and how (manual vs. boot service)?
#   install   register the monitor as a systemd service: starts on boot, restarts if it crashes.
#   uninstall remove the systemd service. Snapshot/log data is left in place.
#   monitor   interactive MASTER CONSOLE:
#               f) fix language/keyboard NOW — same key on every layout, works before you've
#                  read anything else on screen
#               0) IPs & firewall — see who's connected, block/unblock an IP (ufw/iptables,
#                  inserted ahead of existing allow rules; won't let you block your own session)
#               1-4) accounts / passwords (incl. numbered-picker MASS password change) /
#                  privileges / cron & timers
#               5) processes & sessions — ps auxf / ss -antp / ss -tulnp viewers (suspicious
#                  lines flagged), kill by PID/name/user, kick a session
#               6-9) delete a user (backed up first) / changes vs baseline / activity log /
#                  language & keyboard (same as 'f')
#             Every destructive action asks first and is logged to
#             /root/apollo-monitor/actions.log; backups go to /root/apollo-monitor/removed/.
#   closeports  close every port that isn't scored (22, 53, 8053, 3632): deletes stale UFW allow
#             rules, then lists non-loopback listeners and (after asking) stops + disables the
#             owning service. Never touches cloudbase-init or a service that also owns a scored port. 'harden'
#             runs this in step 5; rerun any time.
#   fixlang   revert system locale/console-keymap to English/US if Red changes them, and hunt
#             down + (with confirmation) kill/disable whatever is re-applying the change —
#             a process, a cron job, a systemd unit, or sshd's AcceptEnv. Safe to re-run any
#             time. The daemon (see 'start' above) also runs this pass automatically.
#
# Recommended order:
#   harden  ->  verify the 4 scored services from ANOTHER machine  ->  baseline  ->
#   start  ->  view (watch it live) / monitor (respond)  ->  install (optional, survives reboot)
#
# Nothing here auto-blocks or auto-kills anything except the language/keyboard guard (config
# files only, never a process) and the daemon's own bookkeeping. Everything else surfaces what
# changed; you decide.

set -u
APOLLO_VERSION="2.2"
BASE_DIR="/root/apollo-baseline"
MON_DIR="/root/apollo-monitor"
SNAP_DIR="$MON_DIR/snapshots"
LIVE_VIEW="$MON_DIR/live.view"
LIVE_COL="$MON_DIR/live.collector"
PIDFILE="$MON_DIR/collector.pid"
LOGFILE="$MON_DIR/collector.log"
IP_SEEN="$MON_DIR/remote_ips.seen"
PROC_ALERTED="$MON_DIR/procs.alerted"
ACCT_LOGGED="$MON_DIR/accounts.logged"
MON_INTERVAL=5         # seconds between collector snapshots (background daemon)
VIEW_INTERVAL=1        # seconds between dashboard redraws
PROC_WINDOW=1800       # "new in the last 30 min" window, in seconds
RETENTION=2400         # keep 40 min of snapshots on disk
# Our own tooling shows up in ps while we sample — never report it as "new".
PROC_NOISE='^((ps|sort|comm|sed|awk|sleep|tput|who|last|grep|cat|ss|date|head|tail|clear|wc|diff|find|sha256sum|getent|stat)|apollo-master[^ ]*) '
SCRIPT_PATH="$(readlink -f "$0")"
SERVICE_NAME="apollo-monitor.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
MODE="${1:-}"
# Timezone for every timestamp Apollo prints or logs. The VM/box clock is UTC; Eastern matches
# the operator's wall clock. Override per run:  sudo APOLLO_TZ=UTC bash apollo-master.sh monitor
# (use `sudo -E` or put VAR=... after sudo as shown). Set APOLLO_TZ="" to use the system timezone.
APOLLO_TZ="${APOLLO_TZ-America/New_York}"
[ -n "$APOLLO_TZ" ] && export TZ="$APOLLO_TZ"

# ---------------------------------------------------------------------------
# LOOK & FEEL — colors only when talking to a real terminal (never in logs/systemd)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RST=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_CYN=$'\e[36m'
else
  C_RST=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""
fi

ok()   { printf '  %s✔%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '  %s▲%s %s\n' "$C_YEL" "$C_RST" "$*"; }
bad()  { printf '  %s✘%s %s\n' "$C_RED" "$C_RST" "$*"; }
info() { printf '  %s•%s %s\n' "$C_CYN" "$C_RST" "$*"; }
step() { printf '\n%s%s%s\n' "$C_BOLD$C_CYN" "$*" "$C_RST"; }

# ---- time formatting: one clean style everywhere -------------------------
#   fmt_ts <epoch>   -> "Sep 19, 9:12 AM"        (dashboards, tables)
#   now_stamp        -> "Sep 19 9:12:44 AM"      (log lines — seconds matter for the IR)
#   who_pretty       -> `who -u` with times in the same style
fmt_ts()    { date -d "@$1" '+%b %-d, %-I:%M %p' 2>/dev/null || echo "?"; }
now_stamp() { date '+%b %-d %-I:%M:%S %p'; }
who_pretty() {
  local u tty d t idle pid host
  who -u 2>/dev/null | while read -r u tty d t idle pid host; do
    printf '%-16s %-8s %-16s idle %-6s %s\n' "$u" "$tty" "$(date -d "$d $t" '+%b %-d, %-I:%M %p' 2>/dev/null || echo "$d $t")" "$idle" "${host:-local}"
  done
}

utf8_ok() {
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *UTF-8*|*utf8*|*UTF8*) return 0 ;; *) return 1 ;; esac
}

banner() {
  local i=0 line grad=(27 33 39 45 51 87)
  echo
  if utf8_ok; then
    while IFS= read -r line; do
      if [ -n "$C_RST" ]; then printf '\e[38;5;%sm%s\e[0m\n' "${grad[$i]}" "$line"
      else printf '%s\n' "$line"; fi
      i=$((i + 1))
    done <<'ART'
 █████╗ ██████╗  ██████╗ ██╗     ██╗      ██████╗
██╔══██╗██╔══██╗██╔═══██╗██║     ██║     ██╔═══██╗
███████║██████╔╝██║   ██║██║     ██║     ██║   ██║
██╔══██║██╔═══╝ ██║   ██║██║     ██║     ██║   ██║
██║  ██║██║     ╚██████╔╝███████╗███████╗╚██████╔╝
╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
ART
  else
    printf '%s\n' "${C_CYN}${C_BOLD}=== A P O L L O ===${C_RST}"
  fi
  printf '  %sharden · baseline · monitor   v%s   PSUCCSO Red v. Blue 2026 · Debian 12%s\n\n' \
    "$C_DIM" "$APOLLO_VERSION" "$C_RST"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    bad "Run as root (sudo bash $0 $MODE)." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# HARDEN
# ---------------------------------------------------------------------------
harden() {
  # No 'set -e': one missing service (no BIND, no ufw...) must not abort the remaining steps.
  set +e
  local ts f key line entry ans keys_found bak
  ts=$(date +%s)
  step "Apollo master hardening pass"

  # ---- 1. SSH -----------------------------------------------------------
  step "[1/7] SSH"
  cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$ts"
  keys_found=0
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -s "$f" ] && keys_found=$((keys_found + 1))
  done
  info "authorized_keys files with keys in them: $keys_found"

  local settings=("PubkeyAuthentication yes" "MaxAuthTries 3" "ClientAliveInterval 120" "ClientAliveCountMax 2")

  warn "Blocking root SSH login fails the scored SSH check if the scorer logs in as root."
  read -r -p "  Block root SSH login? [Y/n] " ans || true
  case "${ans:-Y}" in [Nn]*) info "PermitRootLogin left as-is." ;; *) settings+=("PermitRootLogin no") ;; esac

  warn "Disabling password login locks you out unless keys are installed, and fails the scored"
  warn "SSH check if the scorer logs in with a password."
  read -r -p "  Disable SSH PASSWORD login? Only 'y' if keys work AND scorer uses keys [y/N] " ans || true
  case "${ans:-N}" in [Yy]*) settings+=("PasswordAuthentication no") ;; *) info "Password login left enabled." ;; esac

  # Debian 12 loads sshd_config.d/*.conf via Include and the FIRST value wins, so drop-ins
  # can silently override edits to the main file. Neutralise conflicts there, then put our
  # value at the very top of the main file (above any Include, outside any Match block).
  for line in "${settings[@]}"; do
    key=${line%% *}
    for f in /etc/ssh/sshd_config.d/*.conf; do
      [ -f "$f" ] || continue
      [ -f "$f.bak.$ts" ] || cp "$f" "$f.bak.$ts"
      sed -i -E "s/^([[:space:]]*${key}[[:space:]])/#\1/I" "$f"
    done
    sed -i -E "/^${key}[[:space:]]/d" /etc/ssh/sshd_config
    sed -i "1i ${line}" /etc/ssh/sshd_config
  done

  if sshd -t; then
    systemctl restart ssh
    ok "SSH hardened. Effective settings:"
    sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries) ' | sed 's/^/      /'
    warn "Open a NEW ssh connection in a second terminal to verify BEFORE closing this one."
  else
    bad "sshd config test failed — restoring backups, SSH left untouched."
    cp "/etc/ssh/sshd_config.bak.$ts" /etc/ssh/sshd_config
    for f in /etc/ssh/sshd_config.d/*.conf; do
      [ -f "$f.bak.$ts" ] && cp "$f.bak.$ts" "$f"
    done
  fi

  # ---- 2. BIND9 ---------------------------------------------------------
  step "[2/7] DNS (BIND9)"
  f=/etc/bind/named.conf.options
  bak="$f.bak.$ts"
  if [ ! -f "$f" ] || ! command -v named-checkconf >/dev/null 2>&1; then
    warn "BIND not installed on this box ($f or named-checkconf missing) — DNS step SKIPPED."
  else
  cp "$f" "$bak"
  for entry in 'recursion|recursion no;' 'allow-transfer|allow-transfer { none; };' 'version|version "unknown";'; do
    key=${entry%%|*}; line=${entry#*|}
    if grep -Eq "^[[:space:]]*${key}[[:space:]]" "$f"; then
      # replace an existing single-line directive instead of adding a duplicate
      sed -i -E "s|^[[:space:]]*${key}[[:space:]].*;[[:space:]]*\$|    ${line}|" "$f"
    else
      sed -i "/^options {/a\\    ${line}" "$f"
    fi
    grep -qF "$line" "$f" || warn "Couldn't set '$line' automatically (multi-line?) — edit $f by hand."
  done
  if named-checkconf; then
    if systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null; then
      ok "DNS hardened (no recursion, no zone transfers, version hidden)."
    else
      bad "Config edited but bind9/named service failed to restart — check: systemctl status named"
    fi
  else
    bad "named-checkconf failed — restoring backup, BIND left untouched."
    cp "$bak" "$f"
  fi
  fi

  # ---- 3. distcc --------------------------------------------------------
  step "[3/7] distcc"
  warn "Anything NOT in this list is refused — include the SCORING ENGINE's IP or the check fails."
  while true; do
    read -r -p "  Allowed client IP/CIDR(s), space-separated (blank = skip): " DISTCC_HOST || { DISTCC_HOST=""; break; }
    # /etc/default/distcc is SOURCED AS ROOT SHELL by /etc/init.d/distcc — never write anything
    # here that isn't strictly IPv4/IPv6/CIDR characters, or a bad paste becomes root code exec.
    case "$DISTCC_HOST" in
      "") break ;;
      *[!0-9a-fA-F:./,\ ]*) bad "Only digits, letters a-f, ':', '.', '/', ',' and spaces allowed (IP/CIDR list) — try again." ;;
      *) break ;;
    esac
  done
  if [ -n "${DISTCC_HOST:-}" ] && [ ! -f /etc/default/distcc ]; then
    warn "/etc/default/distcc not found — distcc not installed here. SKIPPED."
  elif [ -n "${DISTCC_HOST:-}" ]; then
    cp /etc/default/distcc "/etc/default/distcc.bak.$ts"
    if grep -q '^ALLOWEDNETS=' /etc/default/distcc; then
      sed -i "s|^ALLOWEDNETS=.*|ALLOWEDNETS=\"${DISTCC_HOST}\"|" /etc/default/distcc
    else
      echo "ALLOWEDNETS=\"${DISTCC_HOST}\"" >> /etc/default/distcc
    fi
    if systemctl restart distcc; then
      ok "distcc restricted to: ${DISTCC_HOST} — CONFIRM with a real compile test before moving on."
    else
      bad "distcc failed to restart — check: systemctl status distcc"
    fi
  else
    info "distcc left as-is."
  fi
  local distcc_user
  distcc_user=$(ps -eo user,comm | awk '$2=="distccd"{print $1; exit}')
  if [ "$distcc_user" = "root" ]; then
    warn "distccd is running as root. Find a way to drop it to an unprivileged user (systemd unit /"
    warn "/etc/default/distcc) — biggest single risk reduction on this box (CVE-2004-2687)."
  fi

  # ---- 4. HTTP-DNSGui ---------------------------------------------------
  step "[4/7] HTTP-DNSGui credential (practice-box assumption — confirm real box matches)"
  if [ -f /etc/nginx/.htpasswd ]; then
    cp /etc/nginx/.htpasswd "/etc/nginx/.htpasswd.bak.$ts"
    local panel_pw panel_pw2
    while true; do
      read -r -s -p "  New panel password for 'admin': " panel_pw; echo
      if [ -z "$panel_pw" ]; then bad "Password can't be blank — try again."; continue; fi
      read -r -s -p "  Retype to confirm: " panel_pw2; echo
      [ "$panel_pw" = "$panel_pw2" ] && break
      bad "Didn't match — try again."
    done
    if htpasswd -b /etc/nginx/.htpasswd admin "$panel_pw"; then
      systemctl reload nginx && ok "HTTP-DNSGui credential rotated." || bad "Password changed but nginx reload failed."
    else
      bad "htpasswd failed (apache2-utils missing?) — credential NOT rotated."
    fi
    unset panel_pw panel_pw2
  else
    warn "/etc/nginx/.htpasswd not found — real box's panel is likely built differently."
    warn "SKIPPED. Rotate its credentials manually once you know how it's implemented."
  fi

  # ---- 5. UFW -----------------------------------------------------------
  step "[5/7] Firewall (UFW) + close unneeded ports"
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw not installed — firewall step SKIPPED. (apt install ufw, then rerun harden)"
  else
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 53          # udp AND tcp — large DNS answers fall back to TCP
    ufw allow 8053/tcp
    ufw allow 3632/tcp    # keep in sync with NEEDED_PORTS
    ufw --force enable
    fw_prune_rules
    ufw status numbered
  fi
  closeports

  # ---- 6. Report --------------------------------------------------------
  step "[6/7] Account / persistence report (READ-ONLY — nothing here is auto-changed)"
  echo "  --- Accounts with UID >= 1000 ---"
  awk -F: '$3 >= 1000 {print "   ", $1, "uid="$3, $7}' /etc/passwd
  echo "  --- UID 0 accounts (should be ONLY root) ---"
  awk -F: '$3 == 0 {print "   ", $1}' /etc/passwd
  echo "  --- sudo group members ---"
  getent group sudo | cut -d: -f4 | tr ',' '\n' | sed 's/^/    /'
  echo "  --- Accounts with NO password set (real finding) ---"
  awk -F: '($2 == "") {print "   ", $1}' /etc/shadow
  echo "  --- Cron (root + all users + /etc/cron.d) ---"
  for f in /var/spool/cron/crontabs/*; do
    [ -f "$f" ] && { echo "   == $f =="; sed 's/^/    /' "$f"; }
  done
  ls -la /etc/cron.d/ 2>/dev/null
  warn "Review the above now for anything you don't recognize — this script won't remove it for you."

  # ---- 7. SUID ----------------------------------------------------------
  step "[7/7] SUID/SGID binary count (baseline reference — compare after any incident)"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l

  echo
  ok "Hardening done. Now run: sudo bash $0 baseline"
}

# ---------------------------------------------------------------------------
# CLOSE UNNEEDED PORTS — prune stale firewall allows, stop non-scored listeners
# ---------------------------------------------------------------------------
NEEDED_PORTS="22 53 8053 3632"   # SSH, DNS, HTTP-DNSGui, distcc — the only scored ports
PORT_KEEP_UNITS='^(ssh|sshd|dbus|networking|NetworkManager|systemd-[a-z-]+|wazuh-[a-z-]+|apollo-monitor|user@[0-9]+|cloudbase-init[a-z-]*)\.service$'

port_needed() { case " $NEEDED_PORTS " in *" $1 "*) return 0 ;; esac; return 1; }
pid_unit()    { grep -oE '[^/]+\.service' "/proc/$1/cgroup" 2>/dev/null | tail -n 1; }

# Remove old UFW ALLOW rules for ports that aren't scored. `ufw allow` only adds, so a rule
# left over from before (VNC, SMTP, 80...) would otherwise stay open. Our own IP blocks (DENY)
# and broad allow-from-one-IP rules are never touched.
fw_prune_rules() {
  local line n to p drop=""
  while IFS= read -r line; do
    grep -q 'ALLOW' <<< "$line" || continue
    grep -qF "$FW_TAG" <<< "$line" && continue
    n=$(grep -oE '^\[[[:space:]]*[0-9]+' <<< "$line" | tr -dc 0-9)
    [ -n "$n" ] || continue
    to=$(sed -E 's/^\[[[:space:]]*[0-9]+\][[:space:]]+//; s/[[:space:]]+ALLOW.*$//; s/[[:space:]]+\(v6\)$//' <<< "$line")
    case "$to" in
      Anywhere) warn "Rule [$n] allows ALL ports from one source — left alone, review it: $(tr -s ' ' <<< "$line")"; continue ;;
      OpenSSH)  continue ;;
    esac
    p=${to%%/*}
    if [[ "$p" =~ ^[0-9]+$ ]] && port_needed "$p"; then continue; fi
    info "Stale allow rule [$n] '$to' — removing"
    drop="$drop $n"
  done < <(ufw status numbered 2>/dev/null)
  for n in $(printf '%s\n' $drop | sort -rn); do
    ufw --force delete "$n" >/dev/null 2>&1
    log_action "closeports: deleted ufw rule #$n"
  done
  [ -z "$drop" ] && ok "No stale firewall allow rules."
}

# Stop whatever is LISTENING on a non-loopback port that isn't scored. The firewall already
# blocks these from outside, but a running listener is still attack surface (and the firewall
# is one rule away from being changed). Never touches a service that also owns a scored port.
close_listener() {   # pid unit name where
  local pid=$1 unit=$2 name=$3 where=$4
  case "$name" in *cloudbase*) warn "$where ($name): cloudbase-init is required by the competition — left running."; return ;; esac
  if [ -n "$unit" ] && [[ "$unit" =~ $PORT_KEEP_UNITS ]]; then
    warn "$where ($name): $unit is core/monitoring — left running."; return
  fi
  if [ -n "$unit" ] && [[ "$SCORED_UNITS" == *" $unit "* ]]; then
    warn "$where ($name): $unit also serves a scored port — remove that listener in its config instead."; return
  fi
  if [ -n "$unit" ]; then
    systemctl disable --now "$unit" >/dev/null 2>&1
    systemctl disable --now "${unit%.service}.socket" >/dev/null 2>&1
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null
    ok "$where ($name): stopped + disabled $unit"
  elif [ -n "$pid" ] && [ "$pid" != "$$" ]; then
    kill "$pid" 2>/dev/null; sleep 1
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    ok "$where ($name): killed pid $pid (no systemd unit — it may be respawned, check cron/persistence)"
  else
    warn "$where ($name): no owning process visible — investigate by hand."; return
  fi
  log_action "closeports: closed $where ($name pid=${pid:-?} unit=${unit:-none})"
}

closeports() {
  set +e
  local netid state rq sq local_addr peer rest addr port pid name unit re key ans i entry
  local -a cand=()
  local seen=" "
  SCORED_UNITS=" "
  re='\("([^"]+)",pid=([0-9]+)'
  step "Listening ports NOT needed by a scored service (scored: $NEEDED_PORTS)"
  while read -r netid state rq sq local_addr peer rest; do
    port=${local_addr##*:}
    port_needed "$port" || continue
    [[ "$rest" =~ $re ]] || continue
    unit=$(pid_unit "${BASH_REMATCH[2]}"); [ -n "$unit" ] && SCORED_UNITS="$SCORED_UNITS$unit "
  done < <(ss -H -tulnp 2>/dev/null)
  while read -r netid state rq sq local_addr peer rest; do
    addr=${local_addr%:*}; port=${local_addr##*:}
    case "$addr" in 127.*|"[::1]"|::1) continue ;; esac
    port_needed "$port" && continue
    [ "$netid" = udp ] && [ "$port" = 68 ] && continue   # DHCP client — killing it drops the lease
    pid=""; name="?"
    if [[ "$rest" =~ $re ]]; then name=${BASH_REMATCH[1]}; pid=${BASH_REMATCH[2]}; fi
    key="$netid/$port/$pid"
    case "$seen" in *" $key "*) continue ;; esac
    seen="$seen$key "
    unit=""; [ -n "$pid" ] && unit=$(pid_unit "$pid")
    cand+=("$netid|$local_addr|$name|$pid|$unit")
  done < <(ss -H -tulnp 2>/dev/null)

  if [ ${#cand[@]} -eq 0 ]; then
    ok "Nothing else is listening beyond loopback."
    return
  fi
  for i in "${!cand[@]}"; do
    IFS='|' read -r netid local_addr name pid unit <<< "${cand[$i]}"
    printf '   %2d) %-3s %-24s %s (pid %s, %s)\n' "$((i+1))" "$netid" "$local_addr" "$name" "${pid:-?}" "${unit:-no unit}"
  done
  warn "Scored ports ($NEEDED_PORTS) are never touched. Closing a service here CAN break something you need."
  read -r -p "  Close these? [y = all / e = one by one / N = none] " ans || ans=""
  case "$ans" in
    y|Y|e|E) ;;
    *) info "Left as-is. Rerun any time: sudo bash $0 closeports"; return ;;
  esac
  for entry in "${cand[@]}"; do
    IFS='|' read -r netid local_addr name pid unit <<< "$entry"
    case "$ans" in e|E) confirm "Close $netid $local_addr ($name)?" || continue ;; esac
    close_listener "$pid" "$unit" "$name" "$local_addr"
  done
  step "Still listening (non-loopback)"
  ss -H -tuln 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\])/ {print "   ", $1, $5}' | sort -u
}

# ---------------------------------------------------------------------------
# STATE COLLECTION — shared by baseline, watch, the daemon and the dashboard
# ---------------------------------------------------------------------------

# "comm user" per line, kernel threads dropped, our own tooling dropped. Whitespace is
# normalised (ps pads columns, which made identical processes compare as different).
procs_now() {
  ps -eo pid=,ppid=,user=,comm= 2>/dev/null \
    | awk '$1 != 2 && $2 != 2 { c = $4; for (i = 5; i <= NF; i++) c = c " " $i; print c, $3 }' \
    | grep -Ev "$PROC_NOISE" | sort -u
}

# Append the live PID(s) to "comm user" lines from procs_now, e.g. "dd aarmstr+  pid 4821".
# Same ps columns/user truncation as procs_now so the keys match. A process that already exited
# has no PID to show, so it's marked "(exited)".
add_pids() {
  local in; in=$(cat)
  awk '
    NR == FNR { if ($1 != 2 && $2 != 2) { c = $4; for (i = 5; i <= NF; i++) c = c " " $i; k = c " " $3; pids[k] = (k in pids ? pids[k] "," : "") $1 } next }
    { print $0 "  " (($0 in pids) ? "pid " pids[$0] : "(exited)") }
  ' <(ps -eo pid=,ppid=,user=,comm= 2>/dev/null) <(printf '%s\n' "$in")
}

# Remote peer IPs of established connections. IPv6-safe: a naive trailing ":digits" strip
# would eat the last hextet of an IPv6 address.
# NOTE: `state established` makes ss drop the State column, so Peer is $4 (Local is $3).
ips_now() {
  ss -Hntp state established 2>/dev/null | awk '{print $4}' \
    | sed -E 's/^\[([0-9a-fA-F:.]+)\]:[0-9]+$/\1/; t; s/:[0-9]+$//' | sort -u
}

# Account-related state -> $1/<name>.$2. Split out so the dashboard/daemon can re-sample
# it live and diff against the baseline.
snap_accounts() {
  local d="$1" s="$2" f
  mkdir -p "$d"

  awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd | sort > "$d/accounts.$s"
  getent group sudo | sort > "$d/sudoers.$s"

  {
    for f in /root /home/*; do
      [ -f "$f/.ssh/authorized_keys" ] && { echo "== $f/.ssh/authorized_keys =="; cat "$f/.ssh/authorized_keys"; }
    done
  } > "$d/sshkeys.$s" 2>/dev/null

  # A UID-0 account, a changed password hash or a new sudoers drop-in all show up here.
  {
    sha256sum /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d/* 2>/dev/null
    awk -F: '$3 == 0 {print "uid0:" $1}' /etc/passwd
  } | sort > "$d/hashes.$s"
}

snapshot() {
  mkdir -p "$BASE_DIR"

  ss -Hntlup 2>/dev/null | awk '{print $1, $5, $7}' | sort -u > "$BASE_DIR/listeners.$1"
  ss -Hntp state established 2>/dev/null | awk '{print $3, $4, $5}' | sort -u > "$BASE_DIR/established.$1"
  ips_now   > "$BASE_DIR/remote_ips.$1"
  procs_now > "$BASE_DIR/procs.$1"
  snap_accounts "$BASE_DIR" "$1"

  {
    for f in /var/spool/cron/crontabs/*; do
      [ -f "$f" ] && { echo "== $f =="; cat "$f" 2>/dev/null; }
    done
    echo "== /etc/cron.d =="
    ls /etc/cron.d/ 2>/dev/null
  } > "$BASE_DIR/cron.$1"

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$BASE_DIR/suid.$1"
}

# Everything account-related that differs from the baseline, one plain-text line each.
# "+" = appeared, "-" = disappeared. Prints nothing when there is no baseline or no change.
account_changes() {
  local d="$1" f line
  [ -f "$BASE_DIR/accounts.baseline" ] || return 0
  snap_accounts "$d" current
  for f in accounts sudoers sshkeys hashes; do
    [ -f "$BASE_DIR/$f.baseline" ] || continue
    diff "$BASE_DIR/$f.baseline" "$d/$f.current" 2>/dev/null | grep -E '^[<>]' | while IFS= read -r line; do
      case "$f" in
        hashes) printf '%s [critical file] %s\n' "${line:0:1}" "${line:2}" | sed -E 's/[0-9a-f]{64}  //' | cut -c1-90 ;;
        *)      printf '%s [%s] %s\n' "${line:0:1}" "$f" "${line:2}" | sed 's/^>/+/; s/^</-/' | cut -c1-90 ;;
      esac
    done
  done | sed 's/^>/+/; s/^</-/' | sort -u
}

baseline() {
  step "Snapshotting current state as baseline"
  snapshot baseline
  ok "Saved to $BASE_DIR/*.baseline — $(fmt_ts "$(date +%s)")"
  info "Re-run 'sudo bash $0 baseline' any time you want to reset the known-good point"
  info "(e.g. after legitimately adding a service account)."
}

# ---------------------------------------------------------------------------
# WATCH
# ---------------------------------------------------------------------------
diff_section() {
  local label="$1" file="$2" new_lines
  if [ ! -f "$BASE_DIR/${file}.baseline" ]; then
    echo "  (no baseline for $label yet — run 'baseline' mode first)"
    return
  fi
  new_lines=$(diff "$BASE_DIR/${file}.baseline" "$BASE_DIR/${file}.current" 2>/dev/null | grep '^>' | sed 's/^> /   /')
  if [ -n "$new_lines" ]; then
    printf '%s-- NEW %s --%s\n' "$C_YEL" "$label" "$C_RST"
    echo "$new_lines"
  fi
}

watch_once() {
  local new_ips
  snapshot current

  new_ips=$(diff "$BASE_DIR/remote_ips.baseline" "$BASE_DIR/remote_ips.current" 2>/dev/null | grep '^>' | sed 's/^> //')
  printf '%s=== %s ===%s\n' "$C_BOLD" "$(now_stamp)" "$C_RST"
  if [ -n "$new_ips" ]; then
    printf '%s>>> NEW REMOTE IP(S) NOT IN BASELINE — block from: sudo bash %s monitor -> 0) IPs & firewall%s\n' "$C_RED$C_BOLD" "$0" "$C_RST"
    echo "$new_ips" | sed 's/^/    /'
  else
    ok "No new remote IPs since baseline."
  fi

  diff_section "listening ports"         listeners
  diff_section "established connections" established
  diff_section "processes (name,user)"   procs
  diff_section "accounts"                accounts
  diff_section "sudo group members"      sudoers
  diff_section "critical file hashes"    hashes
  diff_section "cron entries"            cron
  diff_section "SSH authorized_keys"     sshkeys
  diff_section "SUID/SGID binaries"      suid

  rm -f "$BASE_DIR"/*.current
  echo
}

watch_mode() {
  if [ ! -f "$BASE_DIR/remote_ips.baseline" ]; then
    bad "No baseline found. Run 'sudo bash $0 baseline' first (right after hardening)." >&2
    exit 1
  fi
  local interval=""
  if [ "${2:-}" = "-n" ] && [ -n "${3:-}" ]; then
    case "$3" in *[!0-9]*|"") bad "-n needs a positive whole number of seconds, got '${3:-}'." >&2; exit 1 ;; esac
    interval="$3"
  fi
  if [ -n "$interval" ]; then
    info "Watching every ${interval}s — Ctrl+C to stop."
    while true; do
      watch_once
      sleep "$interval"
    done
  else
    watch_once
  fi
}

# ---------------------------------------------------------------------------
# BACKGROUND COLLECTOR + LIVE DASHBOARD (start / view / stop / status)
# ---------------------------------------------------------------------------
# Deliberately no 'set -e' below — this runs unattended for hours, and one
# empty `ss` result (e.g. no established connections right now) must not be
# able to kill the whole daemon.

# Snapshot closest to (but not newer than) PROC_WINDOW seconds ago. If the
# daemon hasn't been running that long yet, falls back to the oldest snapshot
# on disk — i.e. "new since monitoring started" until 30 min of history exists.
baseline_30min_snapshot() {
  local now target best best_ts ts f
  now=$(date +%s)
  target=$((now - PROC_WINDOW))
  best=""; best_ts=0
  for f in "$SNAP_DIR"/*."$1"; do
    [ -e "$f" ] || continue
    ts=${f##*/}; ts=${ts%%.*}
    if [ "$ts" -le "$target" ] && [ "$ts" -gt "$best_ts" ]; then
      best="$f"; best_ts="$ts"
    fi
  done
  if [ -z "$best" ]; then
    best=$(ls -1 "$SNAP_DIR"/*."$1" 2>/dev/null | sort | head -1)
  fi
  echo "$best"
}

# New, suspicious lines added to $DISTCC_LOG since we last checked (consumes the position —
# only the daemon and the console call this). Filters out ordinary accepted compiles; only
# whitelist rejections and malformed/bad requests are "new" here.
distcc_new_alerts() {
  local size pos
  [ -f "$DISTCC_LOG" ] || return 0
  size=$(stat -c%s "$DISTCC_LOG" 2>/dev/null) || return 0
  pos=$(cat "$DISTCC_LOG_POS" 2>/dev/null)
  case "$pos" in ''|*[!0-9]*) pos=0 ;; esac
  [ "$pos" -gt "$size" ] && pos=0    # log rotated/truncated since we last looked
  [ "$size" -gt "$pos" ] && tail -c "+$((pos + 1))" "$DISTCC_LOG" 2>/dev/null \
    | grep -E 'CRITICAL!|REJ_BAD_REQ|magic fairy dust'
  echo "$size" > "$DISTCC_LOG_POS.$$" && mv "$DISTCC_LOG_POS.$$" "$DISTCC_LOG_POS"
}

# Wraps distcc_new_alerts and appends each hit to the shared log, timestamped — used by both
# the background daemon and the console (so it still catches up even if the daemon isn't running).
distcc_log_new() {
  local line
  while IFS= read -r line; do
    [ -n "$line" ] && echo "$(now_stamp)  DISTCC ATTACK: $line" >> "$LOGFILE"
  done < <(distcc_new_alerts)
}

# ---- language / keyboard guard (from Logan's locale-guard idea) ----------------------------------
# Red flips the system to Chinese / another keymap. Every collector cycle this checks each layer
# that can carry it and, if it isn't English/US, saves what Red wrote (evidence), puts English
# back and logs "LANG CHANGE". Layers: /etc/default/locale, /etc/locale.conf, /etc/environment,
# /etc/profile.d/*, /etc/default/keyboard, per-user ~/.pam_environment, and the live localectl
# locale / console keymap / X11 layout. Touches config files only -- never kills anything.
LANG_EVID="$MON_DIR/lang-evidence"
LANG_TARGET=""
LANG_TICK=0
LANG_OK_RE='^(en_US|en_GB|en|C|POSIX)([.:@_]|$)'
lang_target() {
  if   locale -a 2>/dev/null | grep -qiE '^en_us\.utf-?8$'; then echo en_US.UTF-8
  elif locale -a 2>/dev/null | grep -qiE '^c\.utf-?8$';     then echo C.UTF-8
  else echo C; fi
}
# does this file set any LANG/LANGUAGE/LC_* to a non-English value?
lang_file_bad() {
  [ -f "$1" ] || return 1
  sed -E 's/^[[:space:]]*(export[[:space:]]+)?//' "$1" 2>/dev/null | grep -E '^(LANG|LANGUAGE|LC_[A-Z_]+)=' \
    | while IFS='=' read -r _ v; do v=${v//\"/}; v=${v//\'/}; [ -z "$v" ] || [[ "$v" =~ $LANG_OK_RE ]] || echo bad; done | grep -q bad
}
lang_evidence() {   # $1 = file  $2 = what happened
  mkdir -p "$LANG_EVID"; chmod 700 "$LANG_EVID" 2>/dev/null
  [ -e "$1" ] && cp -a "$1" "$LANG_EVID/$(echo "$1" | tr '/' '_').$(date +%s)" 2>/dev/null
  echo "$(now_stamp)  LANG CHANGE: $2" >> "$LOGFILE"
}
lang_unlock() { lsattr -d "$1" 2>/dev/null | awk '{print $1}' | grep -q i && chattr -i "$1" 2>/dev/null; }
lang_guard_tick() {
  [ -n "$LANG_TARGET" ] || LANG_TARGET=$(lang_target)
  local f t="$LANG_TARGET" ls km x11 u
  # whole-file layers: rewrite to plain English
  for f in /etc/default/locale /etc/locale.conf; do
    lang_file_bad "$f" || continue
    lang_evidence "$f" "$f was set to non-English — restored to $t"
    lang_unlock "$f"; printf 'LANG=%s\nLC_MESSAGES=%s\n' "$t" "$t" > "$f"
  done
  # shared files: drop only the offending lines, keep everything else
  for f in /etc/environment /etc/profile.d/*.sh /etc/profile /etc/bash.bashrc /root/.profile /root/.bashrc /home/*/.pam_environment /home/*/.profile /home/*/.bashrc /home/*/.bash_profile; do
    lang_file_bad "$f" || continue
    lang_evidence "$f" "non-English locale line(s) in $f — removed"
    lang_unlock "$f"
    sed -i -E '/^[[:space:]]*(export[[:space:]]+)?(LANG|LANGUAGE|LC_[A-Z_]+)=("|'"'"')?(zh|ja|ko|ru|ar|fr|de|es|pt|it|tr|hi|he|fa)/d; /^[[:space:]]*(export[[:space:]]+)?(LANG|LANGUAGE|LC_[A-Z_]+)=("|'"'"')?[a-z][a-z]_[A-Z][A-Z]/{/=("|'"'"')?(en_US|en_GB)/!d}' "$f"
  done
  # keyboard file
  f=/etc/default/keyboard
  if [ -f "$f" ] && grep -E '^XKBLAYOUT=' "$f" | grep -vqE '^XKBLAYOUT=("|'"'"')?us("|'"'"')?$'; then
    lang_evidence "$f" "keyboard layout changed — restored to US"
    lang_unlock "$f"
    sed -i -E 's/^XKBLAYOUT=.*/XKBLAYOUT="us"/; s/^XKBVARIANT=.*/XKBVARIANT=""/; s/^XKBOPTIONS=.*/XKBOPTIONS=""/' "$f"
    command -v setupcon >/dev/null 2>&1 && setupcon --force >/dev/null 2>&1
  fi
  # live state (localectl talks to dbus, so only every 3rd cycle)
  LANG_TICK=$((LANG_TICK+1)); [ $((LANG_TICK % 3)) -eq 1 ] || return 0
  command -v localectl >/dev/null 2>&1 || return 0
  ls=$(localectl status 2>/dev/null)
  echo "$ls" | grep -E 'System Locale:' -A6 | grep -E '(LANG|LC_[A-Z]+|LANGUAGE)=' | sed -E 's/.*=//' \
    | while read -r u; do [[ "$u" =~ $LANG_OK_RE ]] || echo bad; done | grep -q bad && {
      echo "$(now_stamp)  LANG CHANGE: live system locale was non-English — set back to $t" >> "$LOGFILE"
      localectl set-locale "LANG=$t" "LC_MESSAGES=$t" >/dev/null 2>&1; }
  km=$(echo "$ls"  | sed -n 's/^[[:space:]]*VC Keymap:[[:space:]]*//p')
  x11=$(echo "$ls" | sed -n 's/^[[:space:]]*X11 Layout:[[:space:]]*//p')
  if [ -n "$km" ] && [ "$km" != us ] && [ "$km" != "(unset)" ] && [ "$km" != "n/a" ]; then
    echo "$(now_stamp)  LANG CHANGE: console keymap was '$km' — set back to us" >> "$LOGFILE"
    localectl set-keymap us >/dev/null 2>&1 || loadkeys us >/dev/null 2>&1
  fi
  if [ -n "$x11" ] && [ "$x11" != us ] && [ "$x11" != "(unset)" ] && [ "$x11" != "n/a" ]; then
    echo "$(now_stamp)  LANG CHANGE: X11 layout was '$x11' — set back to us" >> "$LOGFILE"
    localectl set-x11-keymap us >/dev/null 2>&1
  fi
}
# sshd will happily accept LANG/LC_* sent by the client -- Red can log in "in Chinese" without
# touching a single file. Report it (and let fixlang turn it off).
lang_ssh_acceptenv() { grep -hE '^[[:space:]]*AcceptEnv[[:space:]].*(LANG|LC_)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; }

collector_loop() {
  local now new_ips base newp acct l ip p
  mkdir -p "$SNAP_DIR" "$LIVE_COL"
  touch "$IP_SEEN" "$PROC_ALERTED" "$ACCT_LOGGED"
  [ -f "$DISTCC_LOG" ] && [ ! -f "$DISTCC_LOG_POS" ] && stat -c%s "$DISTCC_LOG" > "$DISTCC_LOG_POS" 2>/dev/null
  # IPs already in the baseline are known-good — don't shout about them.
  [ -f "$BASE_DIR/remote_ips.baseline" ] && sort -u "$BASE_DIR/remote_ips.baseline" "$IP_SEEN" -o "$IP_SEEN"

  while true; do
    now=$(date +%s)

    pwd_track
    procs_now > "$SNAP_DIR/$now.procs"
    ips_now   > "$SNAP_DIR/$now.ips"

    # -- new remote IPs
    new_ips=$(comm -23 "$SNAP_DIR/$now.ips" "$IP_SEEN" 2>/dev/null)
    if [ -n "$new_ips" ]; then
      while IFS= read -r ip; do
        [ -n "$ip" ] && echo "$(now_stamp)  NEW REMOTE IP: $ip" >> "$LOGFILE"
      done <<< "$new_ips"
      { cat "$IP_SEEN"; echo "$new_ips"; } | sort -u > "$IP_SEEN.tmp" && mv "$IP_SEEN.tmp" "$IP_SEEN"
    fi

    # -- new processes (logged once each, so short-lived ones are still on record)
    base=$(baseline_30min_snapshot procs)
    if [ -n "$base" ] && [ "$base" != "$SNAP_DIR/$now.procs" ]; then
      newp=$(comm -23 "$SNAP_DIR/$now.procs" "$base" 2>/dev/null | comm -23 - "$PROC_ALERTED" 2>/dev/null)
      if [ -n "$newp" ]; then
        while IFS= read -r p; do
          [ -n "$p" ] && echo "$(now_stamp)  NEW PROCESS: $p" >> "$LOGFILE"
        done <<< "$newp"
        { cat "$PROC_ALERTED"; echo "$newp"; } | sort -u > "$PROC_ALERTED.tmp" && mv "$PROC_ALERTED.tmp" "$PROC_ALERTED"
      fi
    fi

    # -- language / keyboard flipped by Red? (evidence saved, English/US restored, logged)
    lang_guard_tick

    # -- distcc attack indicators (compiler-whitelist rejections, malformed protocol)
    distcc_log_new

    # -- account / sudo / ssh-key / passwd changes vs baseline (logged once each)
    acct=$(account_changes "$LIVE_COL")
    if [ -n "$acct" ]; then
      while IFS= read -r l; do
        if ! grep -qxF -- "$l" "$ACCT_LOGGED" 2>/dev/null; then
          echo "$(now_stamp)  ACCOUNT CHANGE: $l" >> "$LOGFILE"
          echo "$l" >> "$ACCT_LOGGED"
        fi
      done <<< "$acct"
    fi

    find "$SNAP_DIR" -type f -mmin +"$((RETENTION / 60))" -delete 2>/dev/null

    sleep "$MON_INTERVAL"
  done
}

service_active() {
  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null
}

service_installed() {
  [ -f "$SERVICE_PATH" ]
}

collector_status_line() {
  if service_active; then
    echo "running via systemd (survives reboot/crash)"
  elif [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    echo "running (PID $(cat "$PIDFILE")) — manual, will NOT survive a reboot (run 'install' to fix that)"
  else
    echo "NOT RUNNING — start it with: sudo bash $SCRIPT_PATH start"
  fi
}

start_collector() {
  if service_active; then
    ok "Already running via the systemd service (survives reboot). Nothing to do."
    return
  fi
  mkdir -p "$MON_DIR" "$SNAP_DIR"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    ok "Already running (PID $(cat "$PIDFILE"))."
    return
  fi
  setsid nohup "$SCRIPT_PATH" __collector__ >>"$LOGFILE" 2>&1 < /dev/null &
  echo $! > "$PIDFILE"
  disown 2>/dev/null || true
  ok "Monitor daemon started — PID $(cat "$PIDFILE")."
  info "Keeps running after you close this terminal or SSH drops. Stop it with: sudo bash $0 stop"
  info "It will NOT survive a reboot this way — run 'sudo bash $0 install' for that."
  info "Open the live dashboard any time with: sudo bash $0 view"
  [ -f "$BASE_DIR/accounts.baseline" ] || warn "No baseline yet — account monitoring needs one. Run: sudo bash $0 baseline"
}

stop_collector() {
  if service_active; then
    systemctl stop "$SERVICE_NAME"
    ok "Stopped for now. It's still enabled — it WILL start again on the next boot."
    info "Run 'sudo bash $0 uninstall' if you want it gone for good."
    return
  fi
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    kill "$(cat "$PIDFILE")"
    rm -f "$PIDFILE"
    ok "Stopped."
  else
    info "Not running."
    rm -f "$PIDFILE"
  fi
}

install_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    bad "systemctl not found — this box doesn't appear to run systemd. Can't install as a boot service." >&2
    exit 1
  fi
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    info "Stopping the manually-started collector first (systemd will take over)..."
    kill "$(cat "$PIDFILE")"
    rm -f "$PIDFILE"
  fi
  mkdir -p "$MON_DIR" "$SNAP_DIR"
  cat > "$SERVICE_PATH" <<UNIT
[Unit]
Description=Apollo live monitor collector (PSUCCSO RvB 2026)
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $SCRIPT_PATH __collector__
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  ok "Installed. Apollo now starts monitoring on every boot; systemd restarts it if it crashes."
  info "Check status: sudo systemctl status $SERVICE_NAME"
  info "Dashboard:    sudo bash $0 view"
  info "Remove:       sudo bash $0 uninstall"
  warn "The unit runs $SCRIPT_PATH — don't move or delete that file."
}

uninstall_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null
  fi
  rm -f "$SERVICE_PATH"
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
  ok "Removed — it will no longer start on boot. Snapshot/log data in $MON_DIR was left in place."
}

baseline_age() {
  local t
  t=$(stat -c %Y "$BASE_DIR/remote_ips.baseline" 2>/dev/null) || { echo "none — run 'baseline'"; return; }
  echo "$(( ($(date +%s) - t) / 60 ))m old (saved $(fmt_ts "$t"))"
}

snapshot_age_label() {
  [ -z "${1:-}" ] && { echo "n/a"; return; }
  local ts now
  ts=${1##*/}; ts=${ts%%.*}
  now=$(date +%s)
  echo "$(( (now - ts) / 60 ))m ago"
}

# Everything is sampled live on each redraw (cheap), so the view is a true 1-second view even
# though the background daemon only snapshots every MON_INTERVAL seconds for history/logging.
render_dashboard() {
  local mode="$1" out="" n_acct=0 n_proc=0 n_ip=0 n_all
  local base acct_txt proc_txt ip_now ip_new rows status

  add() { out+="$*"$'\n'; }
  head_() { add "${C_BOLD}${C_CYN}$*${C_RST}"; }

  # ---- sample
  if [ -f "$BASE_DIR/accounts.baseline" ]; then
    acct_txt=$(account_changes "$LIVE_VIEW")
    [ -n "$acct_txt" ] && n_acct=$(printf '%s\n' "$acct_txt" | grep -c .)
  else
    acct_txt="(no baseline yet — run: sudo bash $SCRIPT_PATH baseline)"
  fi

  base=$(baseline_30min_snapshot procs)
  proc_txt=""
  if [ -n "$base" ]; then
    proc_txt=$(procs_now | comm -23 - "$base" 2>/dev/null)
    [ -n "$proc_txt" ] && n_proc=$(printf '%s\n' "$proc_txt" | grep -c .)
  fi

  ip_now=$(ips_now)
  ip_new=""
  if [ -f "$BASE_DIR/remote_ips.baseline" ] && [ -n "$ip_now" ]; then
    ip_new=$(printf '%s\n' "$ip_now" | comm -23 - "$BASE_DIR/remote_ips.baseline" 2>/dev/null)
    [ -n "$ip_new" ] && n_ip=$(printf '%s\n' "$ip_new" | grep -c .)
  fi

  n_all=$((n_acct + n_proc + n_ip))
  # a "(no baseline...)" hint isn't an alert
  [ -f "$BASE_DIR/accounts.baseline" ] || n_all=$((n_proc + n_ip))
  if [ "$n_all" -eq 0 ]; then status="${C_GRN}${C_BOLD}● ALL CLEAR${C_RST}"
  else status="${C_RED}${C_BOLD}▲ ${n_all} ALERT(S)${C_RST}"; fi

  # ---- header
  add "${C_BOLD}${C_CYN}◢◤ A P O L L O ◥◣${C_RST}  ${C_DIM}live monitor${C_RST}      $(date '+%a %b %-d, %-I:%M:%S %p')      $status"
  add "${C_DIM}daemon:${C_RST} $(collector_status_line)"
  add "${C_DIM}baseline:${C_RST} $(baseline_age)    ${C_DIM}keys:${C_RST} [a]ll [u]sers/accounts [p]rocesses [i]ps [q]uit"
  add "${C_DIM}────────────────────────────────────────────────────────────────────────${C_RST}"

  # ---- users + accounts
  if [ "$mode" = "all" ] || [ "$mode" = "users" ]; then
    head_ "LOGGED IN NOW"
    if [ -n "$(who 2>/dev/null)" ]; then add "$(who_pretty | sed 's/^/  /')"; else add "  (nobody)"; fi
    add ""
    head_ "RECENT LOGINS"
    add "$(last -n 5 -w 2>/dev/null | grep -Ev '^(wtmp|$)' | sed 's/^/  /')"
    add ""
    head_ "ACCOUNT CHANGES vs BASELINE   ${C_DIM}(users · sudo · ssh keys · passwd/shadow/sudoers)${C_RST}"
    if [ -f "$BASE_DIR/accounts.baseline" ]; then
      if [ -n "$acct_txt" ]; then
        add "$(printf '%s\n' "$acct_txt" | sed "s/^/  ${C_RED}/; s/\$/${C_RST}/")"
      else
        add "  ${C_GRN}none${C_RST}"
      fi
    else
      add "  ${C_YEL}${acct_txt}${C_RST}"
    fi
    add ""
  fi

  # ---- processes
  if [ "$mode" = "all" ] || [ "$mode" = "procs" ]; then
    head_ "PROCESSES NEW SINCE ~30 MIN AGO   ${C_DIM}(vs snapshot from $(snapshot_age_label "$base"))${C_RST}"
    if [ -z "$base" ]; then
      add "  (still building history — check back shortly)"
    elif [ -n "$proc_txt" ]; then
      add "$(printf '%s\n' "$proc_txt" | add_pids | sed "s/^/  ${C_RED}NEW${C_RST}  /")"
    else
      add "  ${C_GRN}none${C_RST}"
    fi
    add ""
  fi

  # ---- ips + alert log
  if [ "$mode" = "all" ] || [ "$mode" = "ips" ]; then
    head_ "REMOTE IPs CONNECTED NOW"
    if [ -n "$ip_now" ]; then
      add "$(printf '%s\n' "$ip_now" | while IFS= read -r ip; do
        if printf '%s\n' "$ip_new" | grep -qxF -- "$ip"; then printf '  %sNEW%s  %s\n' "$C_RED" "$C_RST" "$ip"
        else printf '       %s\n' "$ip"; fi
      done)"
    else
      add "  (none)"
    fi
    add ""
    head_ "RECENT ALERTS   ${C_DIM}(from the daemon log)${C_RST}"
    add "$(tail -n 300 "$LOGFILE" 2>/dev/null | grep -E 'NEW (REMOTE IP|PROCESS)|ACCOUNT CHANGE|LANG CHANGE|PASSWORD (CHANGE|SET)|DISTCC ATTACK' | tail -n 8 | sed 's/^/  /')"
  fi

  rows=$(tput lines 2>/dev/null || echo 40)
  printf '\e[H'
  printf '%s\n' "$out" | head -n "$((rows - 1))" | sed $'s/$/\e[K/'
  printf '\e[J'
}

view_cleanup() { printf '\e[?25h\e[?1049l'; }

view_dashboard() {
  local mode="all" key
  if [ ! -d "$SNAP_DIR" ]; then
    bad "No monitor data yet. Start the daemon first: sudo bash $0 start" >&2
    exit 1
  fi
  mkdir -p "$LIVE_VIEW"
  banner; sleep 1
  printf '\e[?1049h\e[?25l'              # alternate screen, hide cursor
  trap 'view_cleanup; exit 0' INT TERM
  while true; do
    render_dashboard "$mode"
    if read -t "$VIEW_INTERVAL" -n 1 -s key; then
      case "$key" in
        u) mode="users" ;;
        p) mode="procs" ;;
        i) mode="ips" ;;
        a) mode="all" ;;
        q) break ;;
      esac
    fi
  done
  view_cleanup
}

# ---------------------------------------------------------------------------
# MONITOR — interactive master console: accounts, passwords, privileges, cron,
# processes/sessions, and removal. Every destructive action shows what it will do,
# asks first, and is written to $ACTION_LOG. Nothing runs unless you pick it.
# ---------------------------------------------------------------------------
ACTION_LOG="$MON_DIR/actions.log"
REMOVED_DIR="$MON_DIR/removed"          # backups of anything the console deletes
PROTECTED_PROCS='^(sshd|named|distccd|nginx|systemd|init|cron|apollo-master.*)$'
CALLER="${SUDO_USER:-root}"
if [ -z "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
  warn "\$SUDO_USER isn't set (you got to root some other way — su, an existing root shell, systemd…)."
  warn "The self-lockout protections below only recognize the account named \"root\" as safe, NOT you."
  warn "If that's wrong, quit and re-run via a fresh: sudo bash $0 monitor"
fi

# distccd's own log records every rejected job — a compiler-whitelist rejection or a malformed
# request is a red-team probe/exploit attempt (e.g. CVE-2004-2687), not a real build. Debian's
# distcc build already blocks the classic exploit via this whitelist; Apollo just surfaces it.
DISTCC_LOG="/var/log/distccd.log"
DISTCC_LOG_POS="$MON_DIR/distccd.log.pos"

log_action() { mkdir -p "$MON_DIR"; printf '%s [%s] %s\n' "$(now_stamp)" "$CALLER" "$*" >> "$ACTION_LOG"; }
confirm() { local a; read -r -p "  $1 [y/N] " a || return 1; case "$a" in [Yy]*) return 0 ;; *) return 1 ;; esac; }
pause()   { local _; read -r -p "  Enter to continue..." _ || true; }
user_exists() { [ -n "$1" ] && id "$1" >/dev/null 2>&1; }
is_sudoer()   { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; }

# ---- password-change times ------------------------------------------------
# Linux stores only the DATE of a password change (days since 1970), never the time. So Apollo
# records it itself: pwd.track holds "user  fingerprint-of-hash  epoch". Whenever a hash differs
# from last time, the epoch becomes "now". The daemon and the console both keep it updated.
# epoch 0 = the password was already like that when tracking began (time unknown -> shown as --:--).
PWD_TRACK="$MON_DIR/pwd.track"
pwd_track() {
  local now init u h fp old ofp ots ts
  mkdir -p "$MON_DIR"
  now=$(date +%s); init=0; [ -s "$PWD_TRACK" ] && init=1
  local pwd_tmp="$PWD_TRACK.tmp.$$"
  : > "$pwd_tmp"
  while IFS=: read -r u h; do
    [ -n "$u" ] || continue
    fp=$(printf '%s:%s' "$u" "$h" | sha256sum | cut -d' ' -f1)
    old=$(awk -v u="$u" '$1==u {print $2, $3}' "$PWD_TRACK" 2>/dev/null)
    if [ -z "$old" ]; then
      if [ "$init" = 1 ]; then ts=$now; echo "$(now_stamp)  PASSWORD SET (new account): $u" >> "$LOGFILE"; else ts=0; fi
    else
      read -r ofp ots <<< "$old"
      if [ "$ofp" = "$fp" ]; then ts=$ots; else ts=$now; echo "$(now_stamp)  PASSWORD CHANGE: $u" >> "$LOGFILE"; fi
    fi
    echo "$u $fp $ts" >> "$pwd_tmp"
  done < <(awk -F: '{print $1":"$2}' /etc/shadow 2>/dev/null)
  mv "$pwd_tmp" "$PWD_TRACK"
}

# "<sortkey>|<display>" for one user. lc = date from passwd -S (YYYY-MM-DD).
pwd_when() {
  local u="$1" lc="$2" ts
  ts=$(awk -v u="$u" '$1==u {print $3}' "$PWD_TRACK" 2>/dev/null)
  if [ "${ts:-0}" -gt 0 ] 2>/dev/null; then
    echo "$ts|$(fmt_ts "$ts")"
  else
    echo "$(date -d "$lc" +%s 2>/dev/null || echo 0)|$(date -d "$lc" '+%b %-d' 2>/dev/null || echo "$lc"), --:--"
  fi
}

# ---- accounts -------------------------------------------------------------
# ---- block / unblock IPs ---------------------------------------------------
# Works with ufw if it's present (harden() sets it up), falls back to raw iptables otherwise.
# Every block is inserted at the TOP of the chain (rule 1) so it wins over the allow rules
# harden() already added, and every block/unblock is confirmed, tagged with a comment so you
# can tell later what Apollo blocked vs. what was already there, and written to the action log.
FW_TAG="apollo-blocked"
fw_backend() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then echo ufw
  elif command -v iptables >/dev/null 2>&1; then echo iptables
  else echo none; fi
}
# the IP the CALLER themself is connected from, if this console is running over SSH — never
# let them block that one by accident and cut off their own session. sudo normally wipes
# SSH_CONNECTION (env_reset), so fall back to matching this process's tty against `who -u`,
# and as a last resort, CALLER's only current remote login.
own_ssh_ip() {
  local mytty ip
  if [ -n "${SSH_CONNECTION:-}" ]; then awk '{print $1}' <<< "$SSH_CONNECTION"; return; fi
  mytty=$(ps -o tty= -p $$ 2>/dev/null | tr -d ' ')
  if [ -n "$mytty" ] && [ "$mytty" != '?' ]; then
    ip=$(who -u 2>/dev/null | awk -v t="$mytty" '$2==t{print $NF}' | tr -d '()')
    [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\. ]] && { echo "$ip"; return; }
  fi
  ip=$(who -u 2>/dev/null | awk -v u="$CALLER" '$1==u{print $NF}' | tr -d '()' | sort -u)
  [ "$(printf '%s\n' "$ip" | grep -c .)" = 1 ] && [[ "$ip" =~ ^[0-9]+\. ]] && echo "$ip"
}

fw_block()   { local ip="$1"
  case "$(fw_backend)" in
    ufw)      ufw insert 1 deny from "$ip" to any comment "$FW_TAG $(date +%s)" >/dev/null 2>&1 ;;
    iptables) iptables -I INPUT 1 -s "$ip" -j DROP -m comment --comment "$FW_TAG" 2>/dev/null ;;
    *) return 1 ;;
  esac
}
fw_list_blocked() {   # "<rule-id>|<ip>" one per line, our tagged blocks only
  case "$(fw_backend)" in
    ufw)      ufw status numbered 2>/dev/null | grep -F "$FW_TAG" | while IFS= read -r line; do
                printf '%s|%s\n' "$(grep -oE '^\[[[:space:]]*[0-9]+' <<< "$line" | tr -dc 0-9)" \
                                   "$(grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' <<< "$line" | head -1)"
              done ;;
    iptables) iptables -L INPUT -n --line-numbers 2>/dev/null | grep -F "$FW_TAG" | awk '{print $1"|"$5}' ;;
  esac
}
fw_unblock() {   # $1 = rule id from fw_list_blocked
  case "$(fw_backend)" in
    ufw)      yes | ufw delete "$1" >/dev/null 2>&1 ;;
    iptables) iptables -D INPUT "$1" 2>/dev/null ;;
  esac
}

mon_ips() {
  local c sel ip me now_ips new_ips i rid target
  local -a conn=() blocked_ids=() blocked_ips=()
  me=$(own_ssh_ip)
  while true; do
    step "IPs & firewall   ${C_DIM}backend: $(fw_backend)$([ -n "$me" ] && echo "   your session: $me")${C_RST}"
    [ -z "$me" ] && warn "Couldn't work out which IP THIS session is on — double-check before blocking anything you might be connected from."
    now_ips=$(ips_now)
    new_ips=""
    [ -f "$BASE_DIR/remote_ips.baseline" ] && new_ips=$(printf '%s
' "$now_ips" | comm -23 - "$BASE_DIR/remote_ips.baseline" 2>/dev/null)
    conn=(); [ -n "$now_ips" ] && mapfile -t conn <<< "$now_ips"
    echo "  --- Remote IPs connected right now ---"
    if [ "${#conn[@]}" -eq 0 ]; then echo "    (none)"
    else
      for i in "${!conn[@]}"; do
        ip="${conn[$i]}"
        printf '   %s%2d)%s %s' "$C_BOLD" $((i+1)) "$C_RST" "$ip"
        [ -n "$new_ips" ] && printf '%s
' "$new_ips" | grep -qxF -- "$ip" && printf '  %sNEW (not in baseline)%s' "$C_RED" "$C_RST"
        [ "$ip" = "$me" ] && printf '  %s(you)%s' "$C_DIM" "$C_RST"
        echo
      done
    fi
    echo "  --- Currently blocked by Apollo ---"
    blocked_ids=(); blocked_ips=()
    while IFS='|' read -r rid ip; do [ -n "$rid" ] || continue; blocked_ids+=("$rid"); blocked_ips+=("$ip"); done < <(fw_list_blocked)
    if [ "${#blocked_ips[@]}" -eq 0 ]; then echo "    (none)"
    else for i in "${!blocked_ips[@]}"; do printf '   %s%2d)%s %s
' "$C_BOLD" $((i+1)) "$C_RST" "${blocked_ips[$i]}"; done
    fi
    echo
    echo "  [b] block an IP   [u] unblock   [r] refresh   [q]/back"
    read -r -p "  > " c || return 0
    case "$c" in
      b)
        read -r -p "  Number from the CONNECTED list above, or type an IP directly: " sel || return 0
        [ -n "$sel" ] || { info "Cancelled."; continue; }
        if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#conn[@]}" ]; then target="${conn[$((sel-1))]}"; else target="$sel"; fi
        if ! [[ "$target" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then bad "Not a valid IPv4 address: $target"; pause; continue; fi
        [ "$(fw_backend)" = none ] && { bad "Neither ufw nor iptables found — install one first (apt install ufw)."; pause; continue; }
        if [ -n "$me" ] && [ "$target" = "$me" ]; then bad "Refusing — that's the IP THIS session is connected from. Blocking it locks you out."; pause; continue; fi
        if [ -f "$BASE_DIR/remote_ips.baseline" ] && grep -qxF -- "$target" "$BASE_DIR/remote_ips.baseline"; then
          warn "$target is in your saved baseline — that's often the scorer or a legitimate service. Blocking it can fail scored checks."
        fi
        confirm "Block $target now (all traffic, inserted ahead of existing allow rules)?" || { info "Cancelled."; pause; continue; }
        if fw_block "$target"; then
          ok "$target blocked."; echo "$(now_stamp)  IP BLOCKED: $target" >> "$LOGFILE"; log_action "blocked IP $target"
        else bad "Block failed — check firewall status by hand."; fi
        pause ;;
      u)
        [ "${#blocked_ips[@]}" -gt 0 ] || { info "Nothing blocked."; pause; continue; }
        read -r -p "  Number to unblock: " sel || return 0
        [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#blocked_ips[@]}" ] || { bad "Bad number."; pause; continue; }
        target="${blocked_ips[$((sel-1))]}"; rid="${blocked_ids[$((sel-1))]}"
        confirm "Unblock $target?" && { fw_unblock "$rid" && ok "Unblocked." && { echo "$(now_stamp)  IP UNBLOCKED: $target" >> "$LOGFILE"; log_action "unblocked IP $target"; }; }
        pause ;;
      r|"") ;;
      b|q) : ;;
    esac
    [ "$c" = q ] && return 0
  done
}

mon_accounts() {
  step "Accounts (root + UID >= 1000)"
  printf '  %s%-18s %-6s %-5s %-17s %-5s %s%s\n' "$C_BOLD" USER UID PWD "PW CHANGED" SUDO "SHELL  GROUPS" "$C_RST"
  pwd_track
  local u uid st lc sd sh grp
  while IFS=: read -r u uid sh; do
    read -r _ st lc _ < <(passwd -S "$u" 2>/dev/null) || true
    sd="no"; is_sudoer "$u" && sd="yes"
    grp=$(id -nG "$u" 2>/dev/null | sed "s/\b$u\b//; s/^ *//; s/ /,/g")
    local col=""
    if [ "$uid" = 0 ] && [ "$u" != root ]; then col="$C_RED"; fi
    if [ "${st:-}" = "L" ]; then col="$C_DIM"; fi
    printf '  %s%-18s %-6s %-5s %-17s %-5s %s  %s%s\n' "$col" "$u" "$uid" "${st:-?}" "$(pwd_when "$u" "${lc:-1970-01-01}" | cut -d'|' -f2)" "$sd" "${sh##*/}" "$grp" "$C_RST"
  done < <(getent passwd | awk -F: '$3==0 || ($3>=1000 && $3<65000) {print $1":"$3":"$7}')
  echo
  info "PWD: P=has password, L=locked, NP=no password (a finding). UID 0 accounts other than root print in red."
  info "PW CHANGED: Linux stores only the date; Apollo records the time when it sees a change. '--:--' = changed before Apollo was watching."
  echo "  --- Logged in now ---"
  who_pretty | sed 's/^/    /'
}

# ---- mass password change -------------------------------------------------
# Numbered list of login accounts -> pick by number (e.g. "1 3 5-7", or "all") -> one password
# mode for everyone picked. Random = unique per user, saved to a root-only file (Apollo never sees
# old passwords, only hashes). Shared = one password you type. You can't pick the account you're
# working from, so you don't cut off your own session's password.
mon_mass_passwords() {
  local u sh i sel tok lo hi mode shared="" ts out pw n=0 failed=0
  local -a cands=() targets=() seen=()
  step "Mass password change"
  warn "If the scorer logs in with a password, do NOT pick its account or you will fail the SSH check."
  while IFS=: read -r u sh; do
    case "$sh" in */nologin|*/false|"") continue ;; esac
    cands+=("$u")
  done < <(getent passwd | awk -F: '$3==0 || ($3>=1000 && $3<65000) {print $1":"$7}')
  [ "${#cands[@]}" -gt 0 ] || { bad "No login accounts found."; return 0; }
  for i in "${!cands[@]}"; do
    u="${cands[$i]}"
    printf '   %s%2d)%s %s%s\n' "$C_BOLD" $((i+1)) "$C_RST" "$u" "$([ "$u" = "$CALLER" ] && echo "  ${C_DIM}(you — can't be picked)${C_RST}")"
  done
  echo "  Pick by number: e.g.  1 3 5   or  2-4   or  all   (blank = cancel)"
  read -r -p "  Accounts > " sel || return 0
  [ -n "$sel" ] || { info "Cancelled."; return 0; }
  for tok in ${sel//,/ }; do
    case "$tok" in
      all|ALL) for i in "${!cands[@]}"; do seen[i]=1; done ;;
      *-*) lo=${tok%-*}; hi=${tok#*-}
           if [[ "$lo" =~ ^[0-9]+$ && "$hi" =~ ^[0-9]+$ && lo -ge 1 && hi -le ${#cands[@]} && lo -le hi ]]; then
             for ((i=lo; i<=hi; i++)); do seen[i-1]=1; done
           else bad "Ignoring bad range: $tok"; fi ;;
      *) if [[ "$tok" =~ ^[0-9]+$ && tok -ge 1 && tok -le ${#cands[@]} ]]; then seen[tok-1]=1
         else bad "Ignoring bad number: $tok"; fi ;;
    esac
  done
  for i in "${!cands[@]}"; do
    [ -n "${seen[$i]:-}" ] || continue
    u="${cands[$i]}"
    if [ "$u" = "$CALLER" ]; then warn "Skipping $u — that's you."; continue; fi
    targets+=("$u")
  done
  [ "${#targets[@]}" -gt 0 ] || { bad "Nothing selected."; return 0; }
  info "Will change ${#targets[@]} account(s): ${targets[*]}"
  echo "  Password for all picked:  [r] unique random per user (recommended)   [s] one shared password you type   [c] cancel"
  read -r -p "  > " mode || return 0
  case "$mode" in
    r) ;;
    s) read -r -s -p "  Shared password: " shared; echo
       [ -n "$shared" ] || { bad "Password can't be blank."; return 0; }
       read -r -s -p "  Confirm: " pw; echo
       [ "$pw" = "$shared" ] || { bad "Passwords don't match."; return 0; } ;;
    *) info "Cancelled."; return 0 ;;
  esac
  confirm "Change ${#targets[@]} password(s) now? Existing sessions stay open; new logins need the new password." || { info "Cancelled."; return 0; }

  ts=$(date +%Y%m%d-%H%M%S)
  mkdir -p "$MON_DIR"
  out="$MON_DIR/new-passwords.$ts.txt"
  ( umask 077; : > "$out" )
  for u in "${targets[@]}"; do
    if [ "$mode" = r ]; then pw=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16); else pw="$shared"; fi
    if printf '%s:%s\n' "$u" "$pw" | chpasswd; then
      printf '%s:%s\n' "$u" "$pw" >> "$out"
      ok "$u"; n=$((n+1))
    else
      bad "$u — chpasswd failed"; failed=$((failed+1))
    fi
  done
  unset pw shared
  pwd_track
  log_action "MASS PASSWORD CHANGE: $n changed, $failed failed ($([ "$mode" = r ] && echo random || echo shared)) users: ${targets[*]}"
  echo
  ok "$n password(s) changed, $failed failed."
  if [ "$mode" = r ]; then
    info "New credentials saved (root-only, mode 600): $out"
    info "View them with:  cat $out"
  else
    rm -f "$out"; info "Shared password not written to disk."
  fi
}

# ---- passwords ------------------------------------------------------------
mon_passwords() {
  local c u tmp w st lc
  while true; do
    pwd_track
    step "Password status — most recently changed first"
    printf '  %s%-18s %-5s %s%s\n' "$C_BOLD" USER PWD "CHANGED" "$C_RST"
    getent passwd | awk -F: '$3==0 || ($3>=1000 && $3<65000) {print $1}' | while read -r u; do
      read -r _ st lc _ < <(passwd -S "$u" 2>/dev/null) || true
      w=$(pwd_when "$u" "${lc:-1970-01-01}")
      printf '%s|  %-18s %-5s %s\n' "${w%%|*}" "$u" "${st:-?}" "${w#*|}"
    done | sort -t'|' -k1,1nr | cut -d'|' -f2-
    echo "  (time = when Apollo saw the change; '--:--' = already that way before tracking began)"
    echo
    echo "  --- Account / password / privilege changes vs baseline ---"
    if [ -f "$BASE_DIR/accounts.baseline" ]; then
      tmp=$(mktemp -d); account_changes "$tmp" | sed 's/^/    /'; rm -rf "$tmp"
    else
      echo "    (no baseline yet — run: sudo bash $0 baseline)"
    fi
    echo
    echo "  [s] set password  [m] MASS change  [l] lock  [u] unlock  [e] force change at next login  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      m) mon_mass_passwords; pause ;;
      s|l|u|e)
        read -r -p "  Username: " u || return 0
        user_exists "$u" || { bad "No such user: $u"; pause; continue; }
        case "$c" in
          s) passwd "$u" && { pwd_track; log_action "password set for $u"; } ;;
          l) if [ "$u" = "$CALLER" ]; then bad "Refusing to lock yourself ($CALLER)."
             elif confirm "Lock $u (blocks password logins)?"; then passwd -l "$u" && log_action "locked $u"; fi ;;
          u) passwd -u "$u" && log_action "unlocked $u" ;;
          e) chage -d 0 "$u" && ok "$u must change password at next login." && log_action "forced password change for $u" ;;
        esac
        pause ;;
      b|"") return 0 ;;
    esac
  done
}

# ---- privileges -----------------------------------------------------------
mon_privileges() {
  local c u
  while true; do
    step "Privileges"
    echo "  --- UID 0 accounts (should be ONLY root) ---"
    awk -F: '$3==0 {print "    "$1}' /etc/passwd
    echo "  --- sudo / wheel / admin group members ---"
    getent group sudo wheel admin 2>/dev/null | while IFS=: read -r g _ _ m; do
      echo "    [$g]"; echo "$m" | tr ',' '\n' | sed '/^$/d; s/^/      /'
    done
    echo "  --- sudoers rules (non-comment) ---"
    grep -hEv '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/    /'
    echo "  --- NOPASSWD rules (risky) ---"
    grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/    /'
    if [ -f "$BASE_DIR/suid.baseline" ]; then
      echo "  --- SUID/SGID binaries not in baseline ---"
      find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort \
        | comm -13 "$BASE_DIR/suid.baseline" - | sed 's/^/    /'
    fi
    echo
    echo "  [a] add user to sudo  [r] remove user from sudo  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      a) read -r -p "  Username: " u || return 0
         user_exists "$u" || { bad "No such user."; pause; continue; }
         confirm "Give $u full sudo?" && usermod -aG sudo "$u" && ok "$u added to sudo." && log_action "added $u to sudo" ;;
      r) read -r -p "  Username: " u || return 0
         user_exists "$u" || { bad "No such user."; pause; continue; }
         if [ "$u" = "$CALLER" ]; then bad "Refusing to remove your own sudo ($CALLER) — you'd lock yourself out."
         elif confirm "Remove $u from sudo?"; then gpasswd -d "$u" sudo && log_action "removed $u from sudo"; fi ;;
      b|"") return 0 ;;
    esac
    pause
  done
}

# ---- cron -----------------------------------------------------------------
mon_cron() {
  local c t f
  while true; do
    step "Scheduled jobs"
    echo "  --- /etc/crontab ---"
    grep -Ev '^\s*(#|$)' /etc/crontab 2>/dev/null | sed 's/^/    /'
    echo "  --- /etc/cron.d ---"
    for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "    == $f"; grep -Ev '^\s*(#|$)' "$f" | sed 's/^/      /'; }; done
    echo "  --- per-user crontabs ---"
    for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && { echo "    == $(basename "$f")"; grep -Ev '^\s*(#|$)' "$f" | sed 's/^/      /'; }; done
    echo "  --- cron.hourly/daily/weekly/monthly ---"
    ls /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null | sed 's/^/    /'
    echo "  --- systemd timers ---"
    systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/    /' | head -20
    command -v atq >/dev/null 2>&1 && { echo "  --- at jobs ---"; atq | sed 's/^/    /'; }
    if [ -f "$BASE_DIR/cron.baseline" ]; then
      echo "  --- cron changes vs baseline ---"
      { for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && { echo "== $f =="; cat "$f" 2>/dev/null; }; done
        echo "== /etc/cron.d =="; ls /etc/cron.d/ 2>/dev/null; } | diff "$BASE_DIR/cron.baseline" - | grep -E '^[<>]' | sed 's/^/    /'
    fi
    echo
    echo "  [d] delete a user's crontab or a /etc/cron.d file (backed up first)  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      d) read -r -p "  Username (crontab) or file name in /etc/cron.d: " t || return 0
         case "$t" in ""|*/*|.*) bad "Invalid name."; pause; continue ;; esac
         mkdir -p "$REMOVED_DIR"
         if [ -f "/etc/cron.d/$t" ]; then
           confirm "Move /etc/cron.d/$t to $REMOVED_DIR ?" && mv "/etc/cron.d/$t" "$REMOVED_DIR/cron.d-$t.$(date +%s)" && ok "Removed." && log_action "removed /etc/cron.d/$t"
         elif [ -f "/var/spool/cron/crontabs/$t" ]; then
           confirm "Delete $t's crontab (backup kept in $REMOVED_DIR)?" \
             && cp "/var/spool/cron/crontabs/$t" "$REMOVED_DIR/crontab-$t.$(date +%s)" \
             && crontab -r -u "$t" && ok "Removed." && log_action "removed crontab of $t"
         else
           bad "Nothing found for '$t'."
         fi
         pause ;;
      b|"") return 0 ;;
    esac
  done
}

# ---- processes & sessions --------------------------------------------------
# ---- suspicious-stuff viewers (ps auxf / ss -antp / ss -tulnp) -------------------
# Same output as the raw commands, but lines matching classic attacker tells are printed in red
# with a leading "!". Nothing is hidden or changed; it just makes the odd lines jump out.
SUS_PROC='(/tmp/|/dev/shm/|/var/tmp/|\(deleted\)|(^|[ /])(nc|ncat|netcat|socat)( |$)|bash -i|sh -i|/dev/(tcp|udp)/|(python[0-9.]*|perl|ruby|php) +-[cer] |mkfifo|base64 +-d|(curl|wget) .*\|.*(sh|bash)|xmrig|minerd|meterpreter|chisel|ligolo)'
SUS_PORTS=' (4444|4445|1337|31337|5555|6666|7777|8888|9001|9999|1234|12345) '
hl_sus() {   # $1 = extended regex; stdin -> stdout
  HL_RE="$1" HL_R="$C_RED" HL_N="$C_RST" awk 'BEGIN{re=ENVIRON["HL_RE"]; R=ENVIRON["HL_R"]; N=ENVIRON["HL_N"]} NR==1{print "  " $0; next} { if ($0 ~ re) printf "%s! %s%s\n", R, $0, N; else print "  " $0 }'
}
view_ps_tree() {
  step "ps auxf  —  full process tree (red ! = suspicious: runs from /tmp,/dev/shm, deleted binary, nc/socat, shell one-liners, reverse-shell tells)"
  ps auxf 2>/dev/null | cut -c1-200 | hl_sus "$SUS_PROC"
}
view_ss_conns() {
  step "ss -antp  —  every TCP connection + owning process (red ! = suspicious port/process)"
  ss -antp 2>/dev/null | cut -c1-200 | hl_sus "($SUS_PROC|$SUS_PORTS)"
}
view_ss_listen() {
  step "ss -tulnp  —  everything LISTENING (TCP+UDP) + owning process"
  ss -tulnp 2>/dev/null | cut -c1-200 | hl_sus "($SUS_PROC|$SUS_PORTS)"
  info "Same as 'ss -tuln' plus the process column. Anything listening that isn't ssh/named/distccd/nginx is worth a look."
  if [ -f "$BASE_DIR/listeners.baseline" ]; then
    local now new
    now=$(ss -Hntlup 2>/dev/null | awk '{print $1, $5, $7}' | sort -u)
    new=$(comm -13 "$BASE_DIR/listeners.baseline" <(printf '%s\n' "$now"))
    if [ -n "$new" ]; then warn "Listeners that were NOT there at baseline:"; printf '%s\n' "$new" | sed 's/^/    /'
    else ok "No new listeners vs baseline."; fi
  fi
}

mon_procs() {
  local c p sig name u tty
  while true; do
    step "Processes & sessions"
    printf '  %s%-7s %-14s %-10s %-6s %s%s\n' "$C_BOLD" PID USER ELAPSED CPU COMMAND "$C_RST"
    ps -eo pid=,ppid=,user=,etime=,pcpu=,args= --sort=-pcpu 2>/dev/null \
      | awk '$1 != 2 && $2 != 2 {c=$6; for(i=7;i<=NF;i++) c=c" "$i; printf "  %-7s %-14s %-10s %-6s %s\n",$1,$3,$4,$5,substr(c,1,70)}' \
      | head -40
    echo
    echo "  --- Logged-in sessions ---"
    who_pretty | sed 's/^/    /'
    echo
    echo "  [t] process tree (ps auxf)  [c] connections (ss -antp)  [l] listeners (ss -tulnp)"
    echo "  [k] kill PID  [n] kill by name  [u] kill ALL of a user's processes  [s] kick a session (tty)  [r] refresh  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      t) view_ps_tree; pause ;;
      c) view_ss_conns; pause ;;
      l) view_ss_listen; pause ;;
      k) read -r -p "  PID: " p || return 0
         case "$p" in ""|*[!0-9]*) bad "PID must be a number."; pause; continue ;; esac
         if [ "$p" -le 1 ] || [ "$p" = "$$" ]; then bad "Refusing (PID $p is init or this console)."; pause; continue; fi
         ps -p "$p" -o pid,user,etime,args 2>/dev/null | sed 's/^/    /' || true
         ps -p "$p" >/dev/null 2>&1 || { bad "No such process."; pause; continue; }
         name=$(ps -p "$p" -o comm= 2>/dev/null)
         [[ "$name" =~ $PROTECTED_PROCS ]] && warn "'$name' is a protected/scored service — killing it can fail a scored check."
         read -r -p "  Signal [15=polite, 9=force] (default 15): " sig || return 0
         sig="${sig:-15}"; case "$sig" in 9|15) ;; *) bad "Use 9 or 15."; pause; continue ;; esac
         confirm "Kill PID $p with signal $sig?" && kill -"$sig" "$p" && ok "Sent." && log_action "kill -$sig $p ($name)"
         pause ;;
      n) read -r -p "  Process name (exact): " name || return 0
         [ -n "$name" ] || continue
         [[ "$name" =~ $PROTECTED_PROCS ]] && warn "'$name' is a protected/scored service — killing it can fail a scored check."
         pgrep -a -x "$name" | sed 's/^/    /' || { bad "No process named $name."; pause; continue; }
         confirm "Kill ALL of the above (SIGKILL)?" && pkill -9 -x "$name" && ok "Killed." && log_action "pkill -9 -x $name"
         pause ;;
      u) read -r -p "  Username: " u || return 0
         user_exists "$u" || { bad "No such user."; pause; continue; }
         if [ "$u" = "$CALLER" ] || [ "$u" = root ]; then bad "Refusing to kill all of $u's processes."; pause; continue; fi
         pgrep -a -u "$u" | sed 's/^/    /'
         confirm "SIGKILL everything owned by $u (also ends their SSH sessions)?" && pkill -9 -u "$u" && ok "Done." && log_action "pkill -9 -u $u"
         pause ;;
      s) read -r -p "  TTY to kick (e.g. pts/1): " tty || return 0
         case "$tty" in pts/[0-9]*|tty[0-9]*) ;; *) bad "Enter a tty like pts/1."; pause; continue ;; esac
         who -u | grep -w "$tty" | sed 's/^/    /' || { bad "No session on $tty."; pause; continue; }
         confirm "Kill every process on $tty?" && pkill -9 -t "$tty" && ok "Session killed." && log_action "kicked session $tty"
         pause ;;
      r|"") ;;
      b) return 0 ;;
    esac
  done
}

# ---- delete a user ---------------------------------------------------------
mon_delete_user() {
  local u uid home ts
  read -r -p "  Username to DELETE: " u || return 0
  user_exists "$u" || { bad "No such user: $u"; pause; return 0; }
  uid=$(id -u "$u"); home=$(getent passwd "$u" | cut -d: -f6)
  local shell extra0=0
  shell=$(getent passwd "$u" | cut -d: -f7)
  if [ "$u" = root ]; then bad "Refusing: that's the real root account."; pause; return 0; fi
  if [ "$uid" -eq 0 ]; then
    extra0=1; warn "$u has UID 0 — a hidden ROOT-equivalent account (classic backdoor). Deleting it is what you want."
  elif [ "$uid" -lt 1000 ]; then
    case "$shell" in
      */nologin|*/false|"") bad "Refusing: $u is a system service account (UID $uid, shell ${shell:-none})."; pause; return 0 ;;
      *) warn "$u has UID $uid (<1000) but a real login shell ($shell) — unusual, likely planted." ;;
    esac
  fi
  if [ "$u" = "$CALLER" ]; then bad "Refusing: that's you ($CALLER)."; pause; return 0; fi
  step "About to delete $u"
  info "UID $uid · home $home · groups: $(id -nG "$u")"
  info "Processes: $(pgrep -c -u "$u" 2>/dev/null || echo 0) · sessions: $(who | awk -v u="$u" '$1==u' | wc -l)"
  info "Their crontab and home directory are backed up to $REMOVED_DIR first (useful as incident-report evidence)."
  local typed
  read -r -p "  Type the username again to confirm: " typed || return 0
  [ "$typed" = "$u" ] || { warn "Names didn't match — cancelled."; pause; return 0; }
  ts=$(date +%s); mkdir -p "$REMOVED_DIR"
  # UID 0: pkill -u would kill every root process (sshd, this script). Kill only its login sessions.
  if [ "$extra0" = 1 ]; then
    who | awk -v u="$u" '$1==u{print $2}' | while read -r t; do pkill -9 -t "$t" 2>/dev/null; done
  else
    pkill -9 -u "$u" 2>/dev/null || true
  fi
  [ -f "/var/spool/cron/crontabs/$u" ] && cp "/var/spool/cron/crontabs/$u" "$REMOVED_DIR/crontab-$u.$ts"
  local safe_home=1
  case "$home" in /|/root|/root/|"") safe_home=0 ;; esac
  [ "$safe_home" = 1 ] && [ -d "$home" ] && tar -czf "$REMOVED_DIR/home-$u.$ts.tgz" -C "$(dirname "$home")" "$(basename "$home")" 2>/dev/null
  [ "$safe_home" = 0 ] && warn "Home is '${home:-none}' (shared/root's) — home directory left in place, not deleted."
  local del_ok=1
  if [ "$extra0" = 1 ]; then
    if userdel -f "$u" 2>/dev/null; then del_ok=0
    else
      # userdel refuses a UID-0 name because root's PID 1 "uses" that UID — edit the files directly.
      lsattr -d /etc/passwd /etc/shadow 2>/dev/null | awk '{print $1}' | grep -q i && chattr -i /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null
      cp /etc/passwd "$REMOVED_DIR/passwd.$ts"; cp /etc/shadow "$REMOVED_DIR/shadow.$ts"
      sed -i "/^${u}:/d" /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null
      user_exists "$u" || del_ok=0
    fi
  elif [ "$safe_home" = 1 ]; then { userdel -r "$u" 2>/dev/null || userdel "$u"; } && del_ok=0
  else userdel "$u" && del_ok=0; fi
  if [ "$del_ok" = 0 ]; then
    ok "Deleted $u."
    log_action "deleted user $u (uid $uid), backups in $REMOVED_DIR (*.$ts*)"
  else
    bad "userdel failed for $u."
  fi
  pause
}

# ---------------------------------------------------------------------------
# FIXLANG — revert locale/keyboard to English/US, hunt down whatever keeps changing it
# ---------------------------------------------------------------------------
fixlang() {
  local ts; ts=$(date +%s)
  step "Language & keyboard revert"

  # ---- 1. current state, before touching anything ----------------------
  step "[1/4] Current state"
  echo "  locale:"; locale 2>/dev/null | sed 's/^/    /'
  [ -f /etc/default/keyboard ] && { echo "  /etc/default/keyboard:"; cat /etc/default/keyboard | sed 's/^/    /'; }     || info "/etc/default/keyboard doesn't exist — no console-keymap package installed, nothing set at this layer."

  # ---- 2. revert locale ---------------------------------------------------
  step "[2/4] Reverting locale to English"
  local target="en_US.UTF-8"
  if ! locale -a 2>/dev/null | grep -qiE '^en_us\.utf-?8$'; then
    if command -v locale-gen >/dev/null 2>&1; then
      [ -f /etc/locale.gen ] && cp -f /etc/locale.gen "/etc/locale.gen.bak.$ts"
      sed -i -E 's/^#[[:space:]]*(en_US\.UTF-8[[:space:]]+UTF-8)/\1/' /etc/locale.gen 2>/dev/null
      grep -qE '^en_US\.UTF-8[[:space:]]+UTF-8' /etc/locale.gen 2>/dev/null || echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen
      locale-gen >/dev/null 2>&1
    fi
  fi
  if ! locale -a 2>/dev/null | grep -qiE '^en_us\.utf-?8$'; then
    target="C.UTF-8"    # always present on glibc, no generation needed — guaranteed English/ASCII fallback
    warn "Couldn't generate en_US.UTF-8 (no locales data / offline) — using C.UTF-8 instead."
  fi
  [ -f /etc/default/locale ] && cp -f /etc/default/locale "/etc/default/locale.bak.$ts"
  command -v update-locale >/dev/null 2>&1 && update-locale LANG="$target" LANGUAGE="" LC_ALL="$target" 2>/dev/null
  command -v localectl     >/dev/null 2>&1 && localectl set-locale "LANG=$target" 2>/dev/null
  ok "System locale set to $target. (Open a new session, or run 'exec bash', to see it in this shell.)"

  # ---- 3. revert console keyboard layout, if that layer is even present -
  step "[3/4] Reverting console keyboard layout to US"
  if [ -f /etc/default/keyboard ]; then
    cp -f /etc/default/keyboard "/etc/default/keyboard.bak.$ts"
    sed -i -E 's/^XKBLAYOUT=.*/XKBLAYOUT="us"/; s/^XKBVARIANT=.*/XKBVARIANT=""/; s/^XKBOPTIONS=.*/XKBOPTIONS=""/' /etc/default/keyboard
    grep -q '^XKBLAYOUT=' /etc/default/keyboard || echo 'XKBLAYOUT="us"' >> /etc/default/keyboard
    command -v setupcon  >/dev/null 2>&1 && setupcon --force 2>/dev/null
    command -v loadkeys  >/dev/null 2>&1 && loadkeys us >/dev/null 2>&1
    command -v localectl >/dev/null 2>&1 && localectl set-keymap us 2>/dev/null
    ok "Console keymap set to 'us'."
  else
    info "No console-setup/kbd package on this box — there's no keymap layer to revert. If Red installs"
    info "one later, re-run this and it'll pick up /etc/default/keyboard then."
  fi

  # ---- 4. hunt down whatever keeps re-applying a different language/keymap -
  step "[4/4] Looking for what's causing it"
  local found=0 procline cronhit unithit envhit f

  procline=$(ps -eo pid=,user=,args= 2>/dev/null     | grep -Ei 'loadkeys|setxkbmap|localectl +set-(locale|keymap)|update-locale|locale-gen' | grep -v grep)
  if [ -n "$procline" ]; then found=$((found+1)); echo "  running process:"; echo "$procline" | sed 's/^/    /'; fi

  cronhit=$(
    { for f in /var/spool/cron/crontabs/* /etc/cron.d/*; do [ -f "$f" ] && { echo "== $f =="; cat "$f"; }; done
      grep -Ev '^[[:space:]]*(#|$)' /etc/crontab 2>/dev/null
    } 2>/dev/null | grep -Ei 'loadkeys|setxkbmap|localectl|update-locale|locale-gen'
  )
  if [ -n "$cronhit" ]; then found=$((found+1)); echo "  cron entry:"; echo "$cronhit" | sed 's/^/    /'; fi

  # Exclude systemd's own locale plumbing (systemd-localed, its D-Bus alias, console-setup) —
  # those units legitimately MENTION locale/keymap tools; only flag a unit whose ExecStart*
  # actually RUNS one, which a stock unit never does.
  unithit=$(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --no-legend --type=service 2>/dev/null | awk '{print $1}' | grep -viE '^(console-setup|keyboard-setup|systemd-vconsole-setup|systemd-localed|dbus-org\.freedesktop\.locale1)\.service$' | while read -r u; do systemctl cat "$u" 2>/dev/null | grep -E '^Exec(Start|StartPre|StartPost)=' | grep -qEi 'loadkeys|setxkbmap|localectl +set-(locale|keymap)|update-locale|locale-gen' && echo "$u"; done)
  if [ -n "$unithit" ]; then found=$((found+1)); echo "  suspicious systemd unit(s):"; echo "$unithit" | sed 's/^/    /'; fi

  # sshd AcceptEnv: lets a client push LANG/LC_* into its own session without editing anything
  local acc; acc=$(lang_ssh_acceptenv)
  if [ -n "$acc" ]; then
    found=$((found+1)); echo "  sshd accepts client-sent LANG/LC_*  (Red can log in with any language):"; echo "$acc" | sed 's/^/    /'
    if confirm "Comment out those AcceptEnv lines and reload sshd (config backed up first)?"; then
      for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] && grep -qE '^[[:space:]]*AcceptEnv[[:space:]].*(LANG|LC_)' "$f" || continue
        cp -f "$f" "$f.bak.$ts"; sed -i -E 's/^([[:space:]]*AcceptEnv[[:space:]].*(LANG|LC_).*)$/# [apollo disabled] \1/' "$f"
      done
      sshd -t 2>/dev/null && { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; ok "AcceptEnv LANG/LC_* disabled, sshd reloaded."; log_action "fixlang: disabled sshd AcceptEnv LANG/LC_*"; } || bad "sshd -t failed — restore the .bak.$ts file."
    fi
  fi

  # immutable files: Red can chattr +i a locale file so nothing can repair it
  for f in /etc/default/locale /etc/locale.conf /etc/default/keyboard /etc/environment; do
    lsattr -d "$f" 2>/dev/null | awk '{print $1}' | grep -q i && { found=$((found+1)); warn "$f is IMMUTABLE (chattr +i) — clearing it."; chattr -i "$f" 2>/dev/null; log_action "fixlang: cleared immutable flag on $f"; }
  done

  # one full guard pass over every layer (locale.conf, /etc/environment, pam_environment, live localectl, X11)
  LANG_TICK=0; lang_guard_tick

  envhit=""
  for f in /etc/environment /etc/profile /etc/profile.d/*.sh /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile; do
    [ -f "$f" ] || continue
    grep -qE '^[^#]*(export[[:space:]]+)?(LANG|LANGUAGE|LC_ALL|LC_[A-Z]+|XKBLAYOUT)=' "$f" 2>/dev/null && envhit="$envhit$f"$'
'
  done
  if [ -n "$envhit" ]; then
    found=$((found+1)); echo "  locale/keyboard override(s) in shell profiles:"; printf '%s' "$envhit" | sed 's/^/    /'
    if confirm "Disable those override lines (each file backed up first)?"; then
      while IFS= read -r f; do
        [ -n "$f" ] || continue
        cp -f "$f" "$f.bak.$ts"
        sed -i -E 's/^([^#]*(export[[:space:]]+)?(LANG|LANGUAGE|LC_ALL|LC_[A-Z]+|XKBLAYOUT)=.*)$/# [apollo disabled] \1/' "$f"
      done <<< "$envhit"
      ok "Disabled. (Originals backed up as <file>.bak.$ts next to each.)"
      log_action "fixlang: disabled locale/keyboard overrides in: $(printf '%s' "$envhit" | tr '
' ' ')"
    fi
  fi

  if [ "$found" -eq 0 ]; then
    ok "Nothing found actively re-applying a different language/keyboard."
  else
    if [ -n "$procline" ] || [ -n "$unithit" ]; then
      if confirm "Kill the matching process(es) and disable the matching systemd unit(s) above?"; then
        pkill -9 -f 'loadkeys' 2>/dev/null; pkill -9 -f 'setxkbmap' 2>/dev/null
        pkill -9 -f 'localectl set-locale' 2>/dev/null; pkill -9 -f 'localectl set-keymap' 2>/dev/null
        if [ -n "$unithit" ]; then
          while read -r u; do [ -n "$u" ] && { systemctl disable --now "$u" 2>/dev/null && warn "Disabled unit: $u"; }; done <<< "$unithit"
        fi
        ok "Done."
        log_action "fixlang: killed loadkeys/setxkbmap/localectl processes, disabled unit(s): ${unithit:-none}"
      fi
    fi
    if [ -n "$cronhit" ]; then
      warn "A cron entry above still needs removing by hand — use: sudo bash $0 monitor -> 4) Cron & timers"
    fi
  fi
  echo
  ok "Re-run this any time — it's safe, and it's exactly what to reach for if Red flips the language/keyboard again."
}

monitor_menu() {
  local c
  mkdir -p "$MON_DIR"
  while true; do
    pwd_track        # catch up on any password changes since the last look
    distcc_log_new   # catch up on any distcc attack indicators since the last look
    printf '\e[2J\e[H' 2>/dev/null
    banner
    printf '  %sMASTER MONITOR%s   caller: %s   baseline: %s\n' "$C_BOLD" "$C_RST" "$CALLER" \
      "$([ -f "$BASE_DIR/accounts.baseline" ] && echo "saved $(date -r "$BASE_DIR/accounts.baseline" '+%b %-d, %-I:%M %p')" || echo 'NONE (run baseline)')"
    printf '  %sdaemon:%s %s\n\n' "$C_DIM" "$C_RST" "$(collector_status_line)"
    echo "   f) FIX LANGUAGE/KEYBOARD NOW  -- same key on every layout, works even if the rest of this menu is unreadable"
    echo "   0) IPs & firewall  see connections, block/unblock an IP"
    echo "   1) Accounts        who exists, sudo, locked, logged in"
    echo "   2) Passwords       last-change dates, lock / unlock / set / expire"
    echo "   3) Privileges      UID 0, sudo group, sudoers, SUID changes, add/remove sudo"
    echo "   4) Cron & timers   every scheduled job, delete a crontab"
    echo "   5) Processes       list, ps auxf tree, ss connections/listeners, kill, kick a session"
    echo "   6) Delete a user   kills their processes, backs up, removes"
    echo "   7) Changes vs baseline   everything new since 'baseline'"
    echo "   8) Activity log    console actions + every change Apollo detected"
    echo "   9) Language/keyboard   revert to English/US + hunt down what's changing it (same as 'f')"
    echo "   q) Quit"
    echo
    read -r -p "  > " c || break
    case "$c" in
      f|F) fixlang; pause ;;
      0) mon_ips ;;
      1) mon_accounts; pause ;;
      2) mon_passwords ;;
      3) mon_privileges ;;
      4) mon_cron ;;
      5) mon_procs ;;
      6) mon_delete_user ;;
      7) if [ -f "$BASE_DIR/accounts.baseline" ]; then watch_once; else bad "No baseline yet: sudo bash $0 baseline"; fi; pause ;;
      9) fixlang; pause ;;
      8) step "Console actions (what you did here)"
         if [ -s "$ACTION_LOG" ]; then tail -n 25 "$ACTION_LOG" | sed 's/^/  /'; else info "Nothing logged yet."; fi
         step "Detected changes (new IPs, processes, accounts, password changes — last 30)"
         if grep -qE 'NEW (REMOTE IP|PROCESS)|ACCOUNT CHANGE|LANG CHANGE|PASSWORD|DISTCC ATTACK' "$LOGFILE" 2>/dev/null; then
           grep -E 'NEW (REMOTE IP|PROCESS)|ACCOUNT CHANGE|LANG CHANGE|PASSWORD|DISTCC ATTACK' "$LOGFILE" | tail -n 30 | sed 's/^/  /'
         else info "Nothing detected yet."; fi
         service_active || [ -f "$PIDFILE" ] || warn "Daemon is NOT running — changes are only caught while this console is open. Run: sudo bash $0 start"
         pause ;;
      q|Q) break ;;
    esac
  done
}

# ---------------------------------------------------------------------------
case "$MODE" in
  harden)        banner; require_root; harden ;;
  baseline)      banner; require_root; baseline ;;
  watch)         require_root; watch_mode "$@" ;;
  start)         banner; require_root; start_collector ;;
  stop)          require_root; stop_collector ;;
  status)        require_root; info "Daemon: $(collector_status_line)" ;;
  view)          require_root; view_dashboard ;;
  monitor)       require_root; monitor_menu ;;
  fixlang)       banner; require_root; fixlang ;;
  closeports)    banner; require_root; ufw status 2>/dev/null | grep -qi '^status: active' && fw_prune_rules; closeports ;;
  install)      banner; require_root; install_service ;;
  uninstall)     require_root; uninstall_service ;;
  __collector__) collector_loop ;;  # internal — used by start_collector/systemd, don't run directly
  *)
    banner
    echo "  Usage: sudo bash $0 {harden|baseline|monitor|watch [-n seconds]|start|view|stop|status|install|uninstall|fixlang|closeports}"
    echo
    echo "  ${C_BOLD}Typical order:${C_RST}  harden → baseline → start → view   (then 'install' to survive a reboot)"
    exit 1
    ;;
esac
