# Helper Scripts

Four small standalone scripts live next to `apollo-master.sh`. They exist for the moments when the full toolkit is more than you need: get the scored services back up, remove Red's known persistence, hunt flags.

All except `flagscan.py` need root. None of them depend on `apollo-master.sh`.

| Script | Use it when | Run |
|---|---|---|
| `apollo-up.sh` | A scored service is down and you want it back fast | `sudo bash apollo-up.sh` |
| `apollo-guard.sh` | Red keeps planting the same persistence and you want it removed automatically | `sudo bash apollo-guard.sh [once\|bg\|install]` |
| `apollo-fix-all.sh` | Start of a shift: purge, lock down and restart everything in one command | `sudo bash apollo-fix-all.sh` |
| `flagscan.py` | You need to find `ARTEMIS{...}` flags on a box (read-only) | `python3 flagscan.py [dir ...]` |

## apollo-up.sh

Restarts SSH, DNS (BIND9), distcc and the HTTP-DNSGui panel (unmasking and enabling each unit first), opens their ports in `iptables` and UFW, and prints `UP`/`DOWN` for each port. If the panel service doesn't open 8053, it starts the panel app directly, detached. It finishes with a DNS check that the event zones answer. Firewall changes only ever **add** rules. Safe to re-run.

## apollo-guard.sh

Every 5 seconds it removes Red's known persistence patterns:

- any non-root **UID-0 account** and a known backdoor account name, including its `passwd`/`shadow`/`group` lines and `sudoers` entries (sudoers edits are validated with `visudo` before they replace the file);
- rogue `python -m http.server` processes (the scored panel on 8053 is left alone);
- reverse and bind shells: python `socket`+`dup2`/`execv` one-liners, `/dev/tcp/`, `nc -e`, `bash -i`;
- cron lines that re-add users, touch `passwd`/`shadow`/`sudoers`, or start `http.server`.

Modes: `once` (single pass), `bg` (background), `install` (systemd unit, restarts if killed), or no argument for the foreground loop. Everything is logged to `/root/apollo-guard.log`, and copies of what it removed go to `/root/evidence/` for the incident report.

> Unlike the console, the guard **acts without asking**. It exists because a wrong automatic action on these specific patterns costs less than Red keeping them. Read the patterns in the script before you rely on it, and edit `BAD_NAMES` and `CRON_BAD` to match what you actually see.

## apollo-fix-all.sh

Runs four steps in order:

1. Purge Red persistence and start the guard (uses a sibling `apollo-guard.sh`, or downloads it from this repo if missing).
2. **distcc:** set `ALLOWEDNETS` to localhost plus the box's own /24. Override with `sudo ALLOWED="127.0.0.1 <team-subnet> <scorer-ip>" bash apollo-fix-all.sh`. If no IPv4 address is found, the step is skipped instead of guessing.
3. **DNS:** listen on all interfaces, no zone transfers, no recursion. `named-checkconf` gates the change and the original is restored if it fails.
4. Restart the services, open ports and print status (uses `apollo-up.sh`).

## flagscan.py

Read-only. Walks the usual hiding places (`/etc`, `/var/www`, `/opt`, `/home`, `/root`, `/tmp`, `/var/tmp`, `/usr/local`, `/srv`) or the directories you pass, and prints any `ARTEMIS{...}` match, including flags hidden under up to three layers of base64. Skips files over 10 MB and never follows symlinks.
