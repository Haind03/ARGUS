---
name: hunt-methodology
description: Use when planning or running a threat hunt on the user's own PC — hypothesis-driven, tactic-by-tactic (ATT&CK) sequencing, choosing data sources, deciding when a hypothesis is supported/refuted, when to go deeper (memory/disk/network), and when to stop.
---

# Hunt methodology (hypothesis-driven)

> Scope: the user's own, authorised machine (scope-discipline). Detect-only.

## Loop (per phase of `workflows/full-hunt.yml`)
1. **Hypothesis** — falsifiable: "*Malware persists via a Run key or task pointing to a user-writable path.*"
2. **Data** — which telemetry sections/logs answer it? Missing data = **gap**, not "clean".
3. **Query** — run the tactic skill (`hunt_<tactic>.py` or `argus case run`).
4. **Analyse** — validate top findings (false-positive-discipline); pivot on artefacts (hash, path, parent, time).
5. **Verdict** — supported / weak / not supported **given available data**. Record it.
6. **Expand or move on** — supported → deep-dive skills; then next tactic. Lateral pivots across tactics are expected
   (a persistence hit implies an execution and an initial-access question).

## Sequencing
Default: kill-chain order (TA0001 → TA0040). Exceptions:
- Ransomware indicators → **impact first** (ransomware-response workflow), isolate early.
- Active C2 suspected → capture volatile data (memory, connections) before anything else.
- Scheduled scans → quick preset + baseline diff; full hunt weekly/monthly.

## Depth triggers
| Trigger | Go to |
|---|---|
| score ≥ 60 on a binary | malware-triage |
| injection / LSASS / fileless / rootkit lead | memory-acquisition → memory-forensics |
| "what ran when" / deleted files | disk-forensics, eventlog-forensics |
| beacon / unknown destinations | network-forensics |
| browser vector / stealer | browser-forensics |

## Stop criteria
All phases have a verdict; every high/critical finding dispositioned; collection gaps documented;
remaining risk stated. A hunt never "proves clean" — it reports coverage and confidence.

References: [hypothesis-library.md](references/hypothesis-library.md) · [coverage-and-gaps.md](references/coverage-and-gaps.md)
