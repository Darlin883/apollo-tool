# 02: Mode Reference

Every mode of `apollo-master.sh`. Usage: `sudo bash apollo-master.sh <mode>`. All modes require root.

| Mode                               | One-liner                                                                         |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| [`harden`](#harden)                | Harden SSH / BIND9 / distcc / HTTP-DNSGui / UFW, then report accounts, cron, SUID |
| [`baseline`](#baseline)            | Freeze the current state as "known good"                                          |
| [`watch`](#watch)                  | Diff live state vs. baseline; print only what's new                               |
| [`start`](#start--stop--status)    | Launch the background monitor daemon                                              |
| [`view`](#view)                    | Live 1-second dashboard                                                           |
| [`stop`](#start--stop--status)     | Stop the daemon                                                                   |
| [`status`](#start--stop--status)   | Is the daemon running, and how?                                                   |
| [`install`](#install--uninstall)   | Register as a systemd service (boot + auto-restart)                               |
| [`uninstall`](#install--uninstall) | Remove the systemd service                                                        |
| [`monitor`](#monitor)              | Interactive master console (see [03-monitor-console](03-monitor-console.md))                           |
| [`fixlang`](#fixlang)              | Revert locale/keyboard to English/US and find what keeps changing it              |
| [`closeports`](#closeports)        | Close every listener and firewall allow that isn't a scored service               |

Running with no/unknown mode prints the banner and usage.

---

## harden

One-shot, seven steps. Uses `set -e` so an unexpected failure stops the run instead of half-applying changes; the read-only report at the end runs with `set +e`.

### Prompts (answer carefully)

| Prompt | Recommended | Why |
|---|---|---|
| Block root SSH login? `[Y/n]` | **Y** unless the scorer logs in as root | Blocks the most-attacked account. Fails the SSH check if the scorer uses root |
| Disable SSH **password** login? `[y/N]` | **N** unless the scorer uses keys | `y` locks out every password user and fails a password-based scorer |
| Allowed client IP/CIDR(s) for distcc | Scorer's IP, or the subnet containing it (`<SUBNET_CIDR>`); space-separated OK; blank = skip | Anything not listed is **refused**, so a wrong value fails the distcc check. Never `127.0.0.1` alone |
| `htpasswd` New password (x2) | A strong password you record | Rotates the HTTP-DNSGui `admin` credential. Type it and don't pipe input (an empty stdin can set an empty password) |

### Steps

| # | Area | Actions |
|---|---|---|
| 1 | **SSH** | Back up `sshd_config`; set `PubkeyAuthentication yes`, `MaxAuthTries 3`, `ClientAliveInterval 120`, `ClientAliveCountMax 2`, optional `PermitRootLogin no` / `PasswordAuthentication no`. Neutralises conflicting lines in `sshd_config.d/*.conf` (first value wins on Debian 12), inserts the setting at the very top of the main file, validates with `sshd -t`, restarts, prints the **effective** values via `sshd -T`. Restores backups on failure |
| 2 | **BIND9** | `recursion no;` `allow-transfer { none; };` `version "unknown";`. Replaces an existing directive rather than duplicating it, inserts into `options {` otherwise. `named-checkconf` gate + backup restore |
| 3 | **distcc** | Sets `ALLOWEDNETS` (CIDR-safe edit). Warns if `distccd` runs as root (CVE-2004-2687 risk) |
| 4 | **HTTP-DNSGui** | If `/etc/nginx/.htpasswd` exists: back up, `htpasswd … admin` (interactive), reload nginx. Otherwise warns and skips (real box may not be nginx + Basic Auth) |
| 5 | **UFW** | default deny in / allow out; allow `22/tcp`, `53` (**udp and tcp**), `8053/tcp`, `3632/tcp`; enable; then prune stale allow rules and run [`closeports`](#closeports) |
| 6 | **Report** (read-only) | UID ≥ 1000 accounts, UID-0 accounts, sudo members (one per line), accounts with no password, all cron |
| 7 | **SUID** | Count of SUID/SGID binaries (reference number) |

### After it runs
- **Open a second SSH session** and confirm you can still log in *before* closing the first.
- Verify all four scored services from **another machine**.
- Then run `baseline`.

### Side effects
Timestamped backups: `/etc/ssh/sshd_config.bak.<ts>`, `/etc/bind/named.conf.options.bak.<ts>`, `/etc/default/distcc.bak.<ts>`, `/etc/nginx/.htpasswd.bak.<ts>`, plus `.bak.<ts>` for any edited `sshd_config.d` file.

---

## baseline

Freezes current state into `/root/apollo-baseline/*.baseline` (files listed in [01-architecture](01-architecture.md)). Prints the timestamp. **Re-run** any time you want to accept the present state as the new normal (e.g. after adding a legitimate service account). It is a reference copy: it **does not restore or reset** anything.

Run it **only after** hardening is verified good; otherwise you bake a broken or already-compromised state in as "normal".

---

## watch

```
sudo bash apollo-master.sh watch            # one-shot
sudo bash apollo-master.sh watch -n 10      # repeat every 10 s until Ctrl+C
```

Takes a fresh snapshot, diffs it against the baseline, prints only new items. **New remote IPs are printed first** (red banner). That's the list to feed into an IP block (`monitor`, then `0`). Then sections for new listening ports, established connections, processes, accounts, sudo members, critical-file hashes, cron entries, SSH keys, SUID/SGID binaries. Requires a baseline.

---

## start · stop · status

- **`start`**: launches `__collector__` detached (`setsid nohup … &`), writes `collector.pid`. Survives closing the terminal / SSH drop. Does **not** survive a reboot. No-op if already running (manually or via systemd). Warns if no baseline exists.
- **`stop`**: stops the manual daemon; if running under systemd it stops the unit but leaves it *enabled* (it returns on next boot, so use `uninstall` for good).
- **`status`**: one line: running via systemd / running manually (PID) / not running.

What the daemon logs to `/root/apollo-monitor/collector.log` (once per event): `NEW REMOTE IP`, `NEW PROCESS`, `ACCOUNT CHANGE`, `PASSWORD CHANGE: <user>`, `PASSWORD SET (new account): <user>`, `DISTCC ATTACK: <rejected/malformed distccd log line>`, `LANG CHANGE: <what was reverted>`. **Nothing is logged while the daemon is stopped**, so start it right after `baseline`.

Every cycle the daemon also runs the **language/keyboard guard** (see [`fixlang`](#fixlang)), so a locale or keymap flip is fixed on its own within seconds, whether or not anyone has the console open.

---

## view

Live dashboard, read-only, redraws every second on the terminal alternate screen.

| Panel | Content |
|---|---|
| Header | Timestamp, `● ALL CLEAR` / `▲ N ALERT(S)`, daemon state, baseline age, key help |
| Logged in now | `who` |
| Recent logins | `last -n 5` |
| Account changes vs baseline | New/removed users, sudo changes, SSH keys, `passwd`/`shadow`/`group`/`sudoers` hash changes |
| Processes new since ~30 min ago | vs. the snapshot closest to 30 min back |
| Remote IPs connected now | `NEW` flag on anything not in the baseline |
| Recent alerts | Last 8 lines from the daemon log |

Keys: `a` all · `u` accounts · `p` processes · `i` IPs · `q` quit. Needs the daemon started (`start`) so history exists. Quitting does not stop the daemon.

---

## install · uninstall

- **`install`**: writes `/etc/systemd/system/apollo-monitor.service` (`Restart=always`, `RestartSec=5`, `User=root`, `ExecStart=/bin/bash <script> __collector__`), `daemon-reload`, `enable --now`. Stops any manually started collector first. **Don't move or delete the script file**, because the unit points at its path.
- **`uninstall`**: disables and removes the unit. Snapshot/log data stays.

---

## monitor

Interactive master console: IPs and firewall, accounts, passwords (including mass change), privileges, cron, processes and sessions, delete-user, activity log, plus `f` to fix language/keyboard from any screen. Full detail in [03-monitor-console](03-monitor-console.md).

---

## fixlang

```
sudo bash apollo-master.sh fixlang
```

Red can flip the box's language or keyboard layout to make the console unreadable. `fixlang` puts it back and then goes looking for whatever is re-applying the change. Four steps:

| Step | What it does |
|---|---|
| 1. Current state | Prints the live `locale` and `/etc/default/keyboard` before touching anything |
| 2. Locale | Generates `en_US.UTF-8` if missing (falls back to `C.UTF-8`), sets it via `update-locale` / `localectl` |
| 3. Keyboard | Sets `XKBLAYOUT="us"` in `/etc/default/keyboard`, reloads with `setupcon` / `loadkeys` / `localectl` (skipped if no keymap package exists) |
| 4. Hunt | Looks for a running `loadkeys`/`setxkbmap`/`localectl` process, cron entries, systemd units whose `ExecStart` runs those tools, sshd `AcceptEnv LANG/LC_*` (lets a client push a language into its own session), `chattr +i` immutable locale files, and overrides in shell profiles |

Anything that changes a file is backed up as `<file>.bak.<epoch>` first, and each removal (AcceptEnv, profile overrides, kill processes/disable units) asks for confirmation. It is safe to re-run. The same guard runs inside the daemon, and evidence of each fix is saved to `/root/apollo-monitor/lang-evidence/`.

Inside `monitor` it is also on `f` and `9`. `f` is deliberate: it is the same key on every keyboard layout, so it still works if the rest of the menu is unreadable.

---

## closeports

```
sudo bash apollo-master.sh closeports
```

Shrinks the attack surface to the four scored ports (22, 53, 8053, 3632). `harden` runs it as part of step 5, and it is safe to re-run any time.

1. **Stale firewall rules.** If UFW is active, deletes old `ALLOW` rules for unscored ports (a leftover VNC or SMTP rule, say). Apollo's own IP blocks, `OpenSSH` rules and any broad "allow from one source" rule are left alone; the last is reported for review.
2. **Listeners.** Lists every non-loopback listener that isn't a scored port, then asks: `y` close all, `e` one by one, `N` none. Closing means `systemctl disable --now` on the owning unit, or a kill if there is no unit.

What it will not touch: scored ports, a service that also owns a scored port (it tells you to fix that in the service's own config), core and monitoring units (`ssh`, `dbus`, `networking`, `systemd-*`, `wazuh-*`, `apollo-monitor`), `cloudbase-init` (required by the competition), and the DHCP client on UDP 68. Each closure is written to the action log.

---

## Internal mode

`__collector__`: used by `start` and the systemd unit. Not meant to be run by hand.

## Tunables (top of the script)

| Variable | Default | Meaning |
|---|---|---|
| `MON_INTERVAL` | 5 | Seconds between daemon snapshots |
| `VIEW_INTERVAL` | 1 | Seconds between dashboard redraws |
| `PROC_WINDOW` | 1800 | "New process" comparison window (30 min) |
| `RETENTION` | 2400 | Snapshot retention (40 min) |
| `PROC_NOISE` | regex | Commands never reported as "new" (the tool's own helpers) |
| `PROTECTED_PROCS` | regex | Services the console warns before killing |
| `DISTCC_LOG` | `/var/log/distccd.log` | Where distccd logs rejected/malformed jobs; Apollo watches this for attack attempts |
| `APOLLO_TZ` | `America/New_York` | Timezone for every printed/logged time. Override: `sudo APOLLO_TZ=UTC bash apollo-master.sh <mode>`; empty string = system timezone |
