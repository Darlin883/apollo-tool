# Apollo: Hardening, Baseline & Live Monitoring Toolkit

**`apollo-master.sh`**: a single-file Bash tool (~1,800 lines, 75 functions) that hardens a Debian 12 server, records a known-good state, watches for deviations in real time, and gives the defender an interactive console to respond: lock or delete accounts, mass-rotate passwords, block attacker IPs, kill processes and sessions, remove cron persistence, close unscored ports, and undo language/keyboard tampering. Four small companion scripts (`apollo-up.sh`, `apollo-guard.sh`, `apollo-fix-all.sh`, `flagscan.py`) cover fast recovery and auto-removal of known Red persistence.

Built for **PSUCCSO Red vs. Blue 2026** ("Space RVB" / Artemis theme) to defend the **Apollo** box, tested on a Proxmox practice VM (`apollo-practice`, `<TARGET_IP>`).

> Scored services on Apollo: **SSH (22) · DNS/BIND9 (53) · HTTP-DNSGui (8053) · distcc (3632)**. Uptime is ~50% of the score, so every action the tool takes is built around *not breaking a scored service*.

**Author:** Darlin Diaz Muñoz · [GitHub](https://github.com/Darlin883)

---

## What it does (one paragraph)

`harden` closes the obvious holes in the four scored services, prompting before anything that could lock the defender out or fail a scoring check. `baseline` freezes the resulting state (accounts, sudoers, SSH keys, cron, listeners, processes, connections, SUID files, hashes of critical files). From then on, `start`/`view`/`watch` diff live state against that baseline and surface only what is **new**. `monitor` is the response side: an interactive console for IPs and firewall, accounts, passwords, privileges, cron and processes, where every destructive action is confirmed, backed up and logged. A separate `fixlang` pass (also run automatically by the daemon) reverts the locale and keyboard layout if Red flips them.

## The workflow

```
harden  →  baseline  →  start  →  view            (detect)
                                    └→  monitor    (respond)
                       install  →  survives reboot
```

| Phase | Mode | Purpose |
|---|---|---|
| Prevent | `harden` · `closeports` | One-shot hardening of SSH, BIND9, distcc, HTTP-DNSGui, UFW (including closing every unscored port) + account/cron/SUID report |
| Record | `baseline` | Snapshot "known good" to diff against |
| Detect | `watch` · `start` · `view` · `status` · `stop` · `install` · `uninstall` | One-shot diff, background daemon, live 1-second dashboard, systemd boot service |
| Respond | `monitor` · `fixlang` | Interactive master console (inspect, lock, delete, kill, block IPs, mass password change) with backups and an audit log; language/keyboard revert |

## Quick start

```bash
# copy to the box (practice VM is behind the Proxmox host, so jump through it)
scp -J root@<PROXMOX_IP> apollo-master.sh <user>@<TARGET_IP>:~/

sudo bash apollo-master.sh harden      # answer the prompts (see 02-mode-reference.md)
sudo bash apollo-master.sh baseline    # only after you verify the 4 scored services still work
sudo bash apollo-master.sh start       # background monitor daemon
sudo bash apollo-master.sh view        # live dashboard (a/u/p/i/q keys)
sudo bash apollo-master.sh monitor     # master console (f = fix language/keyboard, 0 = block IPs)
sudo bash apollo-master.sh fixlang     # revert locale/keyboard to English/US on demand
sudo bash apollo-master.sh closeports  # close every listener that isn't a scored service
sudo bash apollo-master.sh install     # optional: start on every boot
```

## Screenshots

<!-- Save images into screenshots/ and uncomment each line. -->

<!-- ![apollo-banner](screenshots/apollo-banner.png) -->
<!-- ![apollo-dashboard](screenshots/apollo-dashboard.png) -->
<!-- ![apollo-monitor-menu](screenshots/apollo-monitor-menu.png) -->
<!-- ![apollo-ip-block](screenshots/apollo-ip-block.png) -->
<!-- ![apollo-mass-password](screenshots/apollo-mass-password.png) -->
<!-- ![apollo-ps-tree-flagged](screenshots/apollo-ps-tree-flagged.png) -->

## Documentation map

| File | What's in it |
|---|---|
| [01-architecture](docs/01-architecture.md) | Components, data flow, what lives where on disk, the baseline/diff model |
| [02-mode-reference](docs/02-mode-reference.md) | Every mode: what it does, prompts, output, side effects |
| [03-monitor-console](docs/03-monitor-console.md) | The interactive master console, menu by menu, safeguards, audit trail |
| [04-design-decisions-and-bugs](docs/04-design-decisions-and-bugs.md) | Why it's built this way + real bugs found and fixed |
| [05-testing-log](docs/05-testing-log.md) | What was tested, how, results, and what is still untested |
| [apollo-tool-quick-reference](docs/apollo-tool-quick-reference.md) | One-page command cheat sheet for use mid-event |
| [helper-scripts](docs/helper-scripts.md) | `apollo-up.sh`, `apollo-guard.sh`, `apollo-fix-all.sh`, `flagscan.py`: what each does and when to run it |

## Design principles

1. **Never break a scored service.** Anything that can lock you out or fail a check asks first, explains the risk, and has a safe default.
2. **Roll back on failure.** Config edits are validated (`sshd -t`, `named-checkconf`) and the original is restored if validation fails. Timestamped `.bak` files are kept.
3. **Surface, don't decide.** Monitoring reports *what changed*; it never auto-blocks or auto-kills. The human decides. The one exception is the language/keyboard guard, which only rewrites config files (never a process) and logs every fix.
4. **Evidence first.** Deleted users' home directories and crontabs are archived before removal, because the incident-report (IR) scoring needs proof.
5. **Idempotent and re-runnable.** Running `harden` twice does not duplicate directives.
6. **Zero dependencies.** Pure Bash + coreutils + tools already on Debian 12 (`ss`, `ps`, `ufw`, `systemd`). Nothing to install on a locked-down competition box.

## Environment

| | |
|---|---|
| Target OS | Debian 12 |
| Shell | Bash (`set -u`; `set -e` only inside `harden`) |
| Privileges | Root required for every mode (`sudo bash …`) |
| Practice box | `apollo-practice` VM on Proxmox, `<TARGET_IP>`, on an isolated lab network |
| Snapshots | `vulnerable-baseline`, `vulnerable-baseline-sshkey`, `vulnerable-baseline-users` (rollback targets for repeat drills) |

## Status

- **v2.2**: `harden`, `baseline`, `watch`, `start`/`stop`/`status`, `view`, `monitor`, `fixlang` and `closeports` implemented, plus the helper scripts. v2.1 added IP block/unblock, numbered-picker mass password change, `ps`/`ss` viewers with suspicious-line flagging, and the always-on language/keyboard guard. v2.2 added `closeports` (also run by `harden`), removal of extra UID-0 accounts from the console, and the helper scripts. Core modes were exercised on the practice VM (see [05-testing-log](docs/05-testing-log.md)).
- **Full clean practice run passed (2026-09-19):** rollback → `harden` → verify → `baseline` → daemon; all four scored services stayed up; see [05-testing-log](docs/05-testing-log.md).
- Not yet exercised on the practice VM: `install` (systemd boot service + reboot), long-session dashboard redraw, distcc compile from the scorer's address. The v2.1 and v2.2 additions have no recorded practice-VM test results yet (see [05-testing-log](docs/05-testing-log.md)).
- Open finding: SSH password auth is off on the snapshot, so packet accounts can't log in by password. Confirm what the scorer uses.

