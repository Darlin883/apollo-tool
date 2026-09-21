# 05: Testing Log

What was tested, how, and what is still untested. Written honestly so any claim made about the tool stays defensible.

**Test bed:** `apollo-practice`, a Debian 12 VM on a Proxmox host, on an isolated lab network (`<TARGET_IP>`). Reached through the Proxmox host as a jump host (`ssh -J root@<PROXMOX_IP>`).

## Repeatable environment (snapshots)

| Snapshot | Contents |
|---|---|
| `vulnerable-baseline` | Original vulnerable state: SSH, BIND9, distcc, nginx-DNSGui (`admin:admin`) all live |
| `vulnerable-baseline-sshkey` | + operator SSH key in `authorized_keys` (so a rollback doesn't lock the tester out) |
| `vulnerable-baseline-users` | + the 20 competition-packet accounts (default passwords, the 8 "Admin" ones in `sudo`) |

Rollback between drills: `qm stop <VMID> && qm rollback <VMID> <snapshot> && qm start <VMID>`. The script itself must be re-copied after a rollback (it lives in `~`).

Deployment integrity check used every time: `sha256sum` local vs remote + `bash -n` syntax check.

## Test matrix

| Area | Test | Result |
|---|---|---|
| distcc attack log | Reset tracking, triggered a probe from Kali, checked daemon (~5s) and console (catch-up on open) both logged `DISTCC ATTACK:` | ✔ |
| Transfer | `scp -J` copy; hash match; `bash -n` | ✔ |
| Rollback | Roll back to snapshot, boot, verify key login, UFW inactive, no baseline/backups, services active | ✔ |
| Accounts | Created 20 packet users; verified UIDs, groups, sudo (8 admins), password hashes | ✔ |
| `harden` | SSH: `permitrootlogin no`, `maxauthtries 3`, `pubkeyauthentication yes` | ✔ (effective via `sshd -T`) |
| `harden` | BIND: `recursion no`, `allow-transfer { none; }`, `version "unknown"`; `dig` still answers | ✔ |
| `harden` | distcc: `ALLOWEDNETS="<SUBNET_CIDR>"` written | ✔ (config only, **no compile test yet**) |
| `harden` | UFW: active; 22/tcp, 53, 8053/tcp, 3632/tcp | ✔ |
| `harden` | HTTP-DNSGui rotation | ✔ after fixing an empty-password mistake (bug 9) |
| `harden` | Backups `.bak.<ts>` created for sshd, BIND, distcc | ✔ |
| `harden` | Services `ssh bind9 distcc nginx` still active | ✔ |
| `baseline` | 10 `.baseline` files written to `/root/apollo-baseline/` | ✔ |
| Monitor 1 Accounts | Table incl. all 21 users, sudo flags, logged-in sessions | ✔ |
| Monitor 2 Passwords | Sorted list; baseline diff showed a new test user and hash changes | ✔ |
| Monitor 3 Privileges | UID 0, sudo list, sudoers rules, `NOPASSWD` callout, SUID diff | ✔ (found real `NOPASSWD` for `<user>`) |
| Monitor 4 Cron | Listed planted `/etc/cron.d/zzevil`; showed it under "changes vs baseline"; deleted it; backup written | ✔ |
| Monitor 5 Processes | Kill by PID (`-9`), kill by name; refusals for PID 1 and "kill all of my own processes" | ✔ |
| Monitor 6 Delete user | Deleted throwaway `zztest`: processes killed, home tarball + logged | ✔ |
| Monitor 8 Action log | Entries for cron removal, user deletion, kills | ✔ |
| Safeguards | Refused PID 1; refused killing own processes | ✔ |
| Sudo report formatting | One member per line | ✔ (unit-checked with sample data) |

## Full practice run, 2026-09-19 (clean rollback → harden → baseline → daemon)

Rolled back to `vulnerable-baseline-users`, re-copied the script (hash-verified), operator ran `harden` with: root SSH `Y`, password login `N`, distcc `<SUBNET_CIDR>`, typed an `htpasswd` password. Independent read-only verification afterwards:

| Check | Result |
|---|---|
| `ssh` `bind9` `distcc` `nginx` | all `active` |
| `sshd -T` | `permitrootlogin no` · `maxauthtries 3` · `pubkeyauthentication yes` · `clientaliveinterval 120` · `clientalivecountmax 2` |
| BIND | `recursion no` · `allow-transfer { none; }` · `version "unknown"` · `named-checkconf` OK |
| DNS answers | UDP **and** TCP (`dig` and `dig +tcp`) both return |
| distcc | `ALLOWEDNETS="<SUBNET_CIDR>"`, listening on 3632, runs as user `distccd` (**not** root) |
| UFW | active; 22/tcp, 53, 8053/tcp, 3632/tcp (+ v6) |
| HTTP-DNSGui | new password → **200**; `admin:admin` → **401** |
| Backups | `.bak.<ts>` for sshd_config, named.conf.options, distcc, .htpasswd |
| Baseline | 10 `.baseline` files present |
| Daemon | running (manual PID), not yet installed as a service |
| Users | 21 accounts, none with an empty password |
| Root SSH from laptop | `Permission denied (publickey)` ✔ (expected) |
| Password SSH as a packet user | `Permission denied (publickey)`; password auth is **not offered** (see finding below) |

## Detection tests: changes made *outside* the console

| Action | Daemon off, console opened after | Daemon on |
|---|---|---|
| `chpasswd` on a user | `PASSWORD CHANGE: <user>` logged when the console opened (time = when noticed) | Logged within ~5 s with the real time |
| Create a user | `ACCOUNT CHANGE: + [accounts] <user>` (diff) | `ACCOUNT CHANGE` + `PASSWORD SET (new account): <user>` within ~5 s |

This test exposed gap #12 in [04-design-decisions-and-bugs](04-design-decisions-and-bugs.md) (changes weren't attributed to a user and weren't in any log the console showed). Fixed and re-tested.

## Findings from testing (real issues on the practice box)

| Finding | Detail |
|---|---|
| Password SSH already off in the snapshot | `PasswordAuthentication no` was in the original `sshd_config`; answering **N** to the prompt leaves it off, so the packet accounts cannot log in over SSH by password |
| `<user>` has `NOPASSWD:ALL` | From `/etc/sudoers.d/90-cloud-init-users` (listed twice): passwordless root for that account |
| ~~distccd runs as root~~ | On the clean snapshot it runs as user `distccd`; `harden` only warns if it is root |
| Root has no usable password | `su root` fails; expected (locked) |

## Red-team drill from Kali (same-subnet attacker), 2026-09-19

Started `kali-attacker` (also on the isolated lab network, IP `<ATTACKER_IP>`) and attacked the hardened `apollo-practice` directly, with no jump host needed, since Kali sits on the scored subnet like a real red team host would.

| Attack | Tool | Result |
|---|---|---|
| Port/service scan | `nmap -sV` on 22/53/3632/8053 | All 4 open; BIND version hidden, distcc unidentified |
| Default panel creds | `curl -u admin:admin` | `401` |
| Root SSH | `ssh root@` | `Permission denied (publickey)` |
| Password SSH as a packet user | `ssh -o PreferredAuthentications=password` | Server offers **only `publickey`**, which confirms the earlier finding from the attacker's own view |
| DNS zone transfer | `dig axfr` | `Transfer failed` |
| DNS recursion | `dig google.com @apollo` | `REFUSED` |
| BIND version | `dig CH TXT version.bind` | Returns `"unknown"` |
| **distcc RCE (CVE-2004-2687)** | Metasploit `exploit/unix/misc/distcc_exec` | **Failed**: distccd's compiler whitelist rejected the payload (`sh not in … whitelist`); `check` couldn't even confirm the target as vulnerable |

**Real finding:** `ALLOWEDNETS="<SUBNET_CIDR>"` lets *any* host on the subnet reach distcc, including Kali. The specific RCE is blocked by the whitelist in this distcc build, but the exposure (anyone on the subnet can talk to distcc) is still there. Narrow this to the scorer's actual address once known.

**Detection gap found and fixed:** none of the distcc probe traffic showed up anywhere in Apollo except a generic `NEW REMOTE IP`. distccd's own log had the full story (`CRITICAL!` whitelist rejections, `REJ_BAD_REQ` malformed requests) and Apollo wasn't reading it. Added and verified; see bug #14 in [04-design-decisions-and-bugs](04-design-decisions-and-bugs.md). Re-triggered a probe after the fix: daemon logged `DISTCC ATTACK: …` within ~5 s; repeated with the daemon stopped and the console caught it on open instead.

## v2.1 additions (IP block, mass passwords, viewers, language guard)

Written after the practice-VM runs above. No test results are recorded for them yet, so treat them as **implemented, not yet verified**. Fill in this table as each is exercised.

| Feature | Test to run | Result |
|---|---|---|
| IP block/unblock | Block the Kali IP from `monitor` → `0`; confirm Kali can no longer reach the scored ports; unblock and confirm it can | |
| IP block guard | Try to block your own SSH source IP; expect a refusal | |
| Mass password change | Pick 2-3 accounts, random mode; confirm the saved file is mode 600 and the new passwords work | |
| `ps`/`ss` viewers | Start `nc -lp 4444` from `/tmp` and confirm it gets a red `!` in `t`, `c` and `l` | |
| Language guard | Set `LANG=zh_CN.UTF-8` in `/etc/default/locale`; expect `LANG CHANGE` in the log and the file restored within ~5 s | |
| `fixlang` hunt | Plant a cron entry, an `AcceptEnv LANG` line and a `chattr +i` locale file; confirm each is reported | |

## Not yet tested

- `install` → reboot → daemon returns (systemd path): **next thing to test**.
- Console actions: tty kick (`s`), lock/unlock/set/expire, sudo add/remove, `cron.d`/crontab delete for a *user* crontab (file-in-`cron.d` path was tested).
- Real-terminal 1-second dashboard behaviour over a long session (only the monitoring functions were sandbox-tested earlier).
- distcc compile from the scorer's address; scored-service checks from a separate machine after hardening.
- Password-based SSH login as a packet user: **confirmed failing** (password auth not offered); decide whether the scorer needs it.

## How to re-run a full drill

```bash
ssh root@<PROXMOX_IP> 'qm stop <VMID> && qm rollback <VMID> vulnerable-baseline-users && qm start <VMID>'
scp -J root@<PROXMOX_IP> apollo-master.sh <user>@<TARGET_IP>:~/
ssh -J root@<PROXMOX_IP> <user>@<TARGET_IP>
sudo bash ~/apollo-master.sh harden      # Y / N / <SUBNET_CIDR> / type a password
sudo bash ~/apollo-master.sh baseline
sudo bash ~/apollo-master.sh start && sudo bash ~/apollo-master.sh view
# in another terminal: sudo useradd testuser   → dashboard flips to ▲ ALERT
sudo bash ~/apollo-master.sh monitor
```
