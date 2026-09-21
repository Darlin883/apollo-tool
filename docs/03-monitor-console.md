# 03: The Master Monitor Console

`sudo bash apollo-master.sh monitor`

An interactive, menu-driven console for **inspecting and responding**: IPs and firewall, accounts, passwords, privileges, cron, processes/sessions, user deletion, and language/keyboard repair. It exists because during a Red vs. Blue event you need to go from "I see something odd" to "it's contained and I have evidence" in seconds, without recalling ten different commands.

```
  MASTER MONITOR   caller: <user>   daemon: running (PID 1024) — manual, will NOT survive a reboot
  baseline: saved Sep 19, 12:09 PM

   f) FIX LANGUAGE/KEYBOARD NOW
   0) IPs & firewall  see connections, block/unblock an IP
   1) Accounts        who exists, sudo, locked, logged in
   2) Passwords       last-change dates, lock / unlock / set / expire / MASS change
   3) Privileges      UID 0, sudo group, sudoers, SUID changes, add/remove sudo
   4) Cron & timers   every scheduled job, delete a crontab
   5) Processes       list, ps auxf tree, ss connections/listeners, kill, kick a session
   6) Delete a user   kills their processes, backs up, removes
   7) Changes vs baseline   everything new since 'baseline'
   8) Activity log    console actions + every change Apollo detected
   9) Language/keyboard   same as 'f'
   q) Quit
```

`caller` is `$SUDO_USER`, the human who invoked sudo. Several safeguards key off it.

---

## Safeguards (apply to the whole console)

| Rule | Behaviour |
|---|---|
| **Confirm before change** | Every destructive action prints what it will touch and asks `[y/N]` (default No) |
| **Don't lock yourself out** | Refuses to lock, delete, or strip sudo from `$SUDO_USER`; refuses to kill all of your own processes |
| **Don't nuke the system** | Refuses to delete `root` or any UID < 1000; refuses to kill PID ≤ 1 or the console itself |
| **Warn on scored services** | Killing `sshd`, `named`, `distccd`, `nginx`, `systemd`, `init`, `cron` prints a warning that it can fail a scored check |
| **Typed confirmation for deletion** | User deletion requires typing the username again |
| **Back up before remove** | Deleted crontabs, `cron.d` files and home directories are archived first |
| **Path-safe input** | Cron target names containing `/` or starting with `.` are rejected |
| **Signal whitelist** | Kill-by-PID accepts only `15` (polite) or `9` (force) |
| **Don't block yourself** | The IP blocker refuses the address your own SSH session comes from, and warns before blocking any IP that is in the baseline (often the scorer) |
| **Individual IPs only** | Blocking takes a single IPv4 address; anything else is rejected, so a whole subnet can't be blocked by accident |
| **Audit trail** | Every change is appended to `/root/apollo-monitor/actions.log` with time and caller |

---

## 0) IPs & firewall

Shows every remote IP connected right now (numbered, `NEW` flag on anything not in the baseline, `(you)` on your own session) and the blocks Apollo has already placed.

| Key | Action |
|---|---|
| `b` | Block an IP: pick a number from the connected list or type an address, then confirm |
| `u` | Unblock: pick from the list of Apollo's own blocks |
| `r` | Refresh |

- **Backend:** `ufw` if it is active, raw `iptables` otherwise. The rule is inserted at position 1 so it wins over the allow rules `harden` added, and it carries an `apollo-blocked` comment so Apollo lists only its own blocks.
- **Logged:** `IP BLOCKED` / `IP UNBLOCKED` go to both the daemon log and the action log.
- **Why individual IPs only:** the event rules allow blocking single addresses, never subnets.

## 1) Accounts

One table: **USER · UID · PWD · LASTCHANGE · SUDO · SHELL · GROUPS** for `root` plus every UID 1000–64999 account, then who is logged in now.

- `PW CHANGED`: when the password last changed, as `Sep 19, 9:12 AM`. See [Password-change times](#password-change-times) below.
- `PWD`: `P` has a password, `L` locked, `NP` no password (a finding).
- UID-0 accounts other than `root` print **red** (a hidden root-equivalent is a classic backdoor).
- Locked accounts print dim.

## 2) Passwords

List sorted by most-recently-changed first, plus the **account/password/privilege changes vs baseline** (uses the same `account_changes` diff as the dashboard, so a changed `/etc/shadow` hash shows up here).

| Key | Action | Command used |
|---|---|---|
| `s` | Set a password | `passwd <user>` (typed interactively) |
| `l` | Lock | `passwd -l <user>` (refuses for yourself) |
| `u` | Unlock | `passwd -u <user>` |
| `e` | Force change at next login | `chage -d 0 <user>` |
| `m` | **Mass change** | `chpasswd` (see below) |

### Mass password change (`m`)

Rotates many passwords at once, which is the fast answer to "Red knows the packet passwords".

1. A numbered list of login accounts appears (root plus UID ≥ 1000 with a real shell). Pick by number: `1 3 5`, a range like `2-4`, or `all`.
2. Your own account is skipped so you can't cut off your own session.
3. Choose **`r`** unique random 16-character password per user (recommended) or **`s`** one shared password you type twice.
4. Confirm. Existing sessions stay open; new logins need the new password.

Random passwords are saved to `/root/apollo-monitor/new-passwords.<timestamp>.txt` (mode 600, root only). A shared password is never written to disk. The action log records who was changed and in which mode, never the passwords themselves.

> **Scorer warning:** if the scorer logs in with a password, do not pick its account or you will fail the SSH check. The console prints this warning before the picker.

### Password-change times
Linux records only the **date** of a password change (days since 1970) — never the time. Apollo fills the gap itself: `pwd.track` stores a fingerprint of each account's hash, and whenever it differs from last time the current time is recorded. The collector daemon and the console both keep it updated.

| Shown | Meaning |
|---|---|
| `Sep 19, 4:46 PM` | Apollo saw the change happen (or the account appear) at that time |
| `Sep 19, --:--` | Already that way when tracking began (date only) |

Times use `APOLLO_TZ` (default `America/New_York`, set at the top of the script) so they match your wall clock even though the VM runs on UTC. Override per run with `sudo APOLLO_TZ=UTC bash apollo-master.sh monitor`, or set it to an empty string to use the system timezone. Locking/unlocking also changes the hash, so it stamps a new time.

## 3) Privileges

Shows, in one screen: UID-0 accounts · members of `sudo`/`wheel`/`admin` (one per line) · active sudoers rules (comments stripped) · **`NOPASSWD` rules** called out separately · **SUID/SGID binaries not in the baseline**.

| Key | Action |
|---|---|
| `a` | Add a user to `sudo` (confirm) |
| `r` | Remove a user from `sudo` with `gpasswd -d` (confirm; refuses for yourself) |

## 4) Cron & timers

Everything that can run a job on a schedule, in one view: `/etc/crontab`, `/etc/cron.d/*`, per-user crontabs, `cron.hourly/daily/weekly/monthly`, `systemd` timers, `at` jobs, and **cron changes vs baseline**.

| Key | Action |
|---|---|
| `d` | Delete a user's crontab (`crontab -r -u`) **or** move a `/etc/cron.d/<file>` away. A copy goes to `removed/` first |

## 5) Processes & sessions

Top 40 processes by CPU (kernel threads hidden) and current login sessions, plus three viewers that show the raw command output with suspicious lines flagged.

| Key | Action |
|---|---|
| `t` | Process tree (`ps auxf`) |
| `c` | Every TCP connection with its process (`ss -antp`) |
| `l` | Everything listening, TCP and UDP (`ss -tulnp`), plus listeners that weren't there at baseline |
| `k` | Kill by PID: shows the process, warns if protected, asks signal (15/9) and confirmation |
| `n` | Kill by exact name (`pkill -9 -x`); lists matches first |
| `u` | Kill **everything** a user owns (`pkill -9 -u`); also ends their SSH sessions |
| `s` | Kick a session by tty (`pts/N`, `ttyN`) with `pkill -9 -t` |
| `r` | Refresh |

**Suspicious-line flagging.** The viewers print the same output as the raw commands. Lines matching classic attacker tells get a red `!`: processes running from `/tmp`, `/dev/shm` or `/var/tmp`, deleted binaries, `nc`/`ncat`/`socat`, shell one-liners (`bash -i`, `/dev/tcp/`, `python -c`, `curl | sh`), `mkfifo`, `base64 -d`, and known tooling names (`xmrig`, `chisel`, `ligolo`, `meterpreter`). Connection views also flag common backdoor ports (4444, 1337, 31337, 9999 and similar). Nothing is hidden or changed, and a flag is a lead, not proof.

## 6) Delete a user

Sequence:
1. Validate: exists, not `root`, not the caller. A **UID-0 account other than root** is allowed and flagged as a likely backdoor. A UID below 1000 is refused if it is a service account (`nologin`/`false` shell) and only warned about if it has a real login shell.
2. Show UID, home, groups, process count, active sessions.
3. Require typing the username again.
4. End their processes: `pkill -9 -u` normally. For a UID-0 account this would kill every root process (including `sshd` and the console), so only that account's login sessions are killed.
5. Archive: crontab copy + `tar -czf home-<user>.<ts>.tgz` into `/root/apollo-monitor/removed/`.
6. `userdel -r` (falls back to `userdel` if the mail spool/home removal errors). For a UID-0 account `userdel` often refuses because root's PID 1 uses that UID, so the console backs up `passwd` and `shadow` to `removed/` and edits the account files directly, clearing an immutable flag if Red set one.
7. Log the action.

**Why archive first:** the event's Incident Report is worth points only with **proof** (processes run, attacker IPs, accounts used, sessions hijacked). A planted account's home directory and crontab *are* that proof — deleting them without a copy destroys your evidence.

## 7) Changes vs baseline

Runs `watch_once`, the full diff (new IPs first, then ports, connections, processes, accounts, sudo, hashes, cron, SSH keys, SUID).

## 8) Activity log

Two sections:
1. **Console actions**: the last 25 lines of `/root/apollo-monitor/actions.log` (what *you* did here).
2. **Detected changes**: the last 30 `NEW REMOTE IP` / `NEW PROCESS` / `ACCOUNT CHANGE` / `LANG CHANGE` / `PASSWORD CHANGE` / `PASSWORD SET` / `DISTCC ATTACK` lines from `collector.log` (what *anyone* did to the box, including outside the console).

It warns if the daemon isn't running, because then changes are only noticed while the console is open. The console header also shows `daemon: running…` / `NOT RUNNING`.

## f) and 9) Language & keyboard

Runs `fixlang` (full description in [02-mode-reference](02-mode-reference.md)). `f` sits above the numbered menu on purpose: if Red switches the system to another language or keymap, the menu text and the digit keys may not be readable or typeable, but a plain `f` is the same key on every layout.

Example of the console-actions file:

```
Sep 19 12:23:40 PM [<user>] removed /etc/cron.d/zzevil
Sep 19 12:23:40 PM [<user>] deleted user zztest (uid 1021), backups in /root/apollo-monitor/removed (*.1789835020*)
Sep 19 12:24:08 PM [<user>] kill -9 2130 (sleep)
```

---

## Suggested response playbook

| You see… | Do this in the console |
|---|---|
| Dashboard alert `+ [accounts] <name>` | `1` confirm it's not yours → `2` `l` lock it (keep as evidence) → later `6` delete |
| Unknown session in `who` | `5` → note the tty and IP → `s` kick it → `2`/`6` deal with the account |
| New process you don't recognise | `5` → `k` (`15` first, `9` if it ignores it); screenshot for the IR first |
| `DISTCC ATTACK` in the activity log | Note the source IP and block it with `0`. The whitelist already stopped the RCE, so this is visibility, not an emergency |
| `NEW REMOTE IP` in the log or dashboard | `0`, check it isn't the scorer or a teammate, then `b` |
| Red knows the packet passwords | `2` then `m`, pick the accounts (not the scorer's), choose random, and read the new list from the saved file |
| Menu or shell suddenly in another language, or keys typing wrong characters | `f` |
| Process is flagged red `!` in the tree | `5` then `k` on the PID; screenshot the tree first for the IR |
| `NOPASSWD` or unknown sudo member | `3` → `r` remove from sudo |
| New file in `/etc/cron.d` or a user crontab | `4` → `d` (backed up automatically) |
| New SUID binary | `3` shows it; investigate, then remove by hand (`chmod -s`) |

## Limitations

- Doesn't touch SSH `authorized_keys`. A planted key is shown by the dashboard/`watch` but must be removed by editing the file (see [apollo-tool-quick-reference](apollo-tool-quick-reference.md)).
- IP blocking is IPv4 only and one address at a time (deliberate, see above). It may not cut connections that are already established, so kick the session or kill the process as well.
- The process list shows the top 40 by CPU; use `pgrep -a <name>` for anything quiet.
- Deleting an account leaves files it owned elsewhere on disk (only the home directory is removed and archived).
