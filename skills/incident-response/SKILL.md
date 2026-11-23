---
name: incident-response
description: Use when (and only when) the user explicitly wants to CONTAIN or REMOVE a confirmed threat on their own PC — network isolation, quarantining a file, killing a process, disabling a task/service, removing a Run value or WMI binding — through time-boxed IR opt-in, evidence-first, dry-run-by-default actions; also for ransomware/infostealer first-response advice.
---

# Incident response (OPT-IN)

> **Scope:** the user's own, authorised machine only; every action is opt-in, time-boxed and dry-run by default.

> **This is the only ARGUS skill that changes the system.** It never runs on its own initiative.
> The user must (1) confirm the finding, (2) grant a time-boxed opt-in, (3) approve each action.

## Preconditions (all required)
1. Finding is **dispositioned `true_positive`** in the case (`argus case dispose`).
2. Evidence captured (evidence-discipline): file hash/copy, memory if relevant.
3. User grants opt-in: `python -I engine/argus_cli.py case optin --case <dir> --minutes 60 --reason "<why>"`.
4. The PreToolUse guard will still **ask** before each destructive command.

## Actions (`scripts/Invoke-ArgusResponse.ps1`, dry run unless `-Execute`)
| Action | Evidence kept | Reversible |
|---|---|---|
| `Isolate` / `Unisolate` | firewall state before | yes |
| `Quarantine -Path` | SHA-256 copy in `evidence\`, metadata JSON | yes (move back) |
| `KillProcess -ProcessId` | path, cmdline, hash, parent | n/a |
| `DisableTask -TaskPath -TaskName` | task XML | yes (Enable-ScheduledTask) |
| `DisableService -ServiceName` | `sc qc` config | yes |
| `RemoveRunValue -RegistryKey -ValueName` | `.reg` export | yes (import) |
| `RemoveWmiBinding -ConsumerName` | binding + consumer dump | partially |

Refuses: protected OS paths, critical processes, non-Run registry keys, expired opt-in.
Every action → `<case>\response-log.jsonl`. Revoke when done: `argus case revoke --case <dir>`.

## Playbooks
- [containment-order.md](references/containment-order.md) — the order that avoids losing evidence or tipping off the attacker
- [ransomware-first-response.md](references/ransomware-first-response.md)
- Infostealer: `browser-forensics/references/infostealer-response.md`
- When to rebuild instead of clean: [rebuild-vs-clean.md](references/rebuild-vs-clean.md)
