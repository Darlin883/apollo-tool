# Apollo Tool Quick Reference: Event Day Fallback

Pure command dump, no explanations; for the "why" behind any of these, see [README](../README.md) and [02-mode-reference](02-mode-reference.md). This file is for glancing at mid-event, not reading.

All commands: `sudo bash ~/apollo-master.sh <mode>` (shortened to `A` below).

---

## Get it on the box
```
scp -J root@<PROXMOX_IP> apollo-master.sh <user>@<TARGET_IP>:~/       # practice VM via Proxmox jump host
sha256sum apollo-master.sh                                         # compare local vs remote
bash -n apollo-master.sh                                           # syntax check
```

## Standard order
```
A harden        # 1) prompts: root SSH = Y · SSH password off = N · distcc IPs = scorer/subnet · type an admin password
# → open a 2nd SSH session, verify all 4 scored services from ANOTHER machine
A baseline      # 2) freeze known-good (only after verifying)
A start         # 3) background monitor
A view          # 4) live dashboard  (a/u/p/i/q)
A install       # 5) survive reboot (optional)
A monitor       # response console
```

## Modes at a glance
```
A harden            # harden SSH/BIND/distcc/HTTP-DNSGui/UFW + report
A baseline          # save known-good (re-run to accept a new normal)
A watch             # one-shot diff vs baseline (new IPs first)
A watch -n 10       # repeat every 10 s
A start | stop | status
A view              # live dashboard, q to quit (daemon keeps running)
A install | uninstall
A monitor           # interactive master console
A fixlang           # revert language/keyboard to English/US, hunt what changes it
A closeports        # close every listener and firewall allow that isn't 22/53/8053/3632
```

## Harden prompt answers
```
Block root SSH login?            Y   (N if the scorer logs in as root)
Disable SSH PASSWORD login?      N   (Y only if scorer uses keys)
Allowed distcc IP/CIDR           <scorer IP> or <SUBNET_CIDR>   (space-separated ok, NEVER 127.0.0.1 alone)
htpasswd New password            type it yourself, twice, write it down
```

## Master monitor menu
```
f FIX LANGUAGE/KEYBOARD (works on any layout)   0 IPs & firewall
1 Accounts     2 Passwords    3 Privileges   4 Cron & timers
5 Processes    6 Delete user  7 Changes vs baseline   8 Activity log (yours + detected)   9 Language/keyboard   q Quit
```
```
0:  b block IP (pick # or type it) · u unblock · r refresh     (single IPs only, refuses your own session)
2:  s set pw · m MASS change (pick #s, random or shared) · l lock · u unlock · e force change
3:  a add to sudo · r remove from sudo
4:  d delete crontab / cron.d file (backed up)
5:  t ps auxf tree · c ss -antp · l ss -tulnp (red ! = suspicious) · k kill PID (15/9) · n kill by name · u kill all of a user · s kick tty · r refresh
6:  type username twice → kills procs, archives home+cron, userdel -r
```

## Where things live
```
/root/apollo-baseline/*.baseline        known-good state
/root/apollo-monitor/collector.log      daemon alerts (NEW IP / NEW PROCESS / ACCOUNT CHANGE / PASSWORD CHANGE / DISTCC ATTACK / LANG CHANGE)
/root/apollo-monitor/actions.log        what the console changed
/root/apollo-monitor/removed/           backups of anything deleted (evidence for the IR)
/root/apollo-monitor/new-passwords.*.txt  random passwords from a mass change (root only)
/root/apollo-monitor/lang-evidence/     locale/keyboard files as Red left them
/etc/*.bak.<epoch>                      pre-hardening config backups
```
```
sudo tail -f /root/apollo-monitor/collector.log
sudo cat /root/apollo-monitor/actions.log
sudo ls -la /root/apollo-monitor/removed/
```

## Verify hardening actually applied
```
sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|maxauthtries|pubkeyauthentication) '
sudo grep -E 'recursion|allow-transfer|version' /etc/bind/named.conf.options
grep ^ALLOWEDNETS /etc/default/distcc
sudo ufw status numbered
systemctl is-active ssh bind9 distcc nginx
curl -s -o /dev/null -w '%{http_code}\n' -u admin:<pw> localhost:8053     # expect 200
curl -s -o /dev/null -w '%{http_code}\n' -u admin:admin localhost:8053    # expect 401
ls /root/apollo-baseline /root/apollo-monitor                             # (sudo) expect files
```

## Users & passwords, no-bloat
```
getent passwd | awk -F: '$3>=1000 && $3<65000 {print $1}'                 # real users
getent passwd | awk -F: '$3>=1000 && $3<65000 {print $1}' | xargs -n1 id -nG   # + groups
sudo passwd -Sa | grep -v ' L '                                           # P = has password, L = locked
sudo awk -F: '$3>=1000' /etc/passwd | cut -d: -f1 | xargs -I{} sudo getent shadow {} | cut -d: -f1,2   # hashes
```

## Planted SSH key (the console doesn't manage these)
```
sudo find /root /home -name authorized_keys -exec echo == {} == \; -exec cat {} \;
sudo nano /home/<user>/.ssh/authorized_keys        # delete the line you don't recognise
```

## Block a Red IP: individual only, NEVER a subnet
```
A monitor  →  0  →  b            # easiest: guarded, tagged, logged
sudo ufw insert 1 deny from <ip> to any    # manual fallback
```

## Practice VM reset (Proxmox host)
```
ssh root@<PROXMOX_IP> 'qm stop <VMID> && qm rollback <VMID> vulnerable-baseline-users && qm start <VMID>'
ssh root@<PROXMOX_IP> 'qm listsnapshot <VMID>'
ssh root@<PROXMOX_IP> "qm snapshot <VMID> <name> --description '<text>'"
# after a rollback: re-scp the script (it lives in ~)
```
Snapshots: `vulnerable-baseline` (original) · `vulnerable-baseline-sshkey` (+key) · `vulnerable-baseline-users` (+20 packet accounts)

## Login debugging
```
ssh -v -J root@<PROXMOX_IP> <user>@<TARGET_IP> 2>&1 | grep -E 'Offering|Authentications that can continue|Permission denied'
sudo -i          # root shell (NOT `sudo cd`, since cd is a builtin)
```

## Times
```
sudo APOLLO_TZ=UTC bash ~/apollo-master.sh monitor    # default is America/New_York; "" = system tz
```
`--:--` next to a password date = it changed before Apollo started tracking (Linux stores only the date).

## distcc attack evidence
```
sudo grep -E 'CRITICAL!|REJ_BAD_REQ|magic fairy dust' /var/log/distccd.log   # raw distccd rejections
sudo grep 'DISTCC ATTACK' /root/apollo-monitor/collector.log               # what Apollo flagged
```

## Known traps
- **Nothing is logged unless the daemon is running**: `start` right after `baseline`, then `status`.
- Panel check: `curl ... -u 'admin:PW' localhost:8053` → 200; `-u admin:admin` → 401. Use `curl` (not `url`) and a real password, not `<pw>`.
- `PasswordAuthentication no` may already be set → packet users can't SSH by password. Check with `sshd -T`.
- Never pipe answers into `harden`: an empty stdin sets an **empty** `htpasswd` password.
- `baseline` bakes in the current state, so don't run it on a box you haven't checked.
- Killing `sshd`/`named`/`distccd`/`nginx` can fail a scored check.
- After any rollback, the script and the baseline are gone: re-copy, re-harden, re-baseline.

---

Full docs: [README](../README.md) · [01-architecture](01-architecture.md) · [02-mode-reference](02-mode-reference.md) · [03-monitor-console](03-monitor-console.md) · [04-design-decisions-and-bugs](04-design-decisions-and-bugs.md) · [05-testing-log](05-testing-log.md)
Event-day fallback for services: apollo-quick-reference
