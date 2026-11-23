---
name: scope-discipline
description: Use when about to collect from, scan, dump memory of, capture traffic on or analyse ANY machine, file share, account or network, confirms the target is the user's own (or explicitly authorised) machine and keeps every ARGUS action inside that boundary.
---

# Scope discipline

**Iron law: only the user's own, authorised machine.** ARGUS is a personal-PC defence toolkit, not a
scanner for other people's systems.

## Before the first action
1. Ask (if not already clear): *Is this your own computer, or do you have written permission from its owner?*
2. Open a case with the attestation: `argus case init --name <pc-date> --i-own-this-machine`.
3. Check: `python -I skills/scope-discipline/scripts/scope_check.py --case <dir> [--telemetry t.json]`
verifies attestation, that telemetry came from the local host (or a host named in the case),
   and flags UNC/network paths and remote targets.

## In scope
Local processes, registry, logs, files, memory, browser profiles of consenting users, traffic *of this host*.

## Out of scope (refuse, explain, offer alternatives)
- Other computers on the LAN, NAS devices, routers, company devices without IT authorisation
- Other people's accounts, mailboxes, cloud storage, browser data without consent
- Active probing of attacker infrastructure (no scanning, no "hack back"); passive intel lookups only (opt-in)
- Capturing traffic of shared networks (cafés, dorms, employer networks)

## Rationalizations to reject
| Excuse | Answer |
|---|---|
| "It's just a quick look at my roommate's laptop" | not authorised → no |
| "The attacker's IP is right there, let's scan it" | active probing is out of scope; record the IOC |
| "My work laptop is mine" | company-managed device → IT/security team decides |
