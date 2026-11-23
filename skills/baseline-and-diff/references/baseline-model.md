# Baseline model

`argus.baseline/1` stores:

- `inventory.<category>` — normalised keys (lower-case paths, GUIDs and long numbers replaced by `<guid>`/`<n>`
  so updates of versioned folders do not churn).
- `finding_keys` — keys of every finding (min_score 0) at baseline time. A later finding with the same key
  is marked `baseline_known` and its score is multiplied by 0.3.
- `shadow_copies` — count; going from >0 to 0 triggers `all_shadow_copies_gone_since_baseline` (T1490).

## Diff → review items (`ARG-BL-NEW`)
| Category | ATT&CK | Base score |
|---|---|---|
| wmi_subscriptions | T1546.003 | 45 |
| defender_exclusions | T1562.001 | 40 |
| local_admins | T1098 | 40 |
| autoruns / scheduled_tasks / services | T1547.001 / T1053.005 / T1543.003 | 30 |
| drivers | T1068 | 30 |
| browser_extensions | T1176 | 20 |
| listening_ports | T1571 | 15 |

## Hygiene
- Re-baseline after major software installs **only after a clean hunt**.
- Keep old baselines (dated file names) — they are evidence of when something first appeared.
- A baseline is host-specific; never reuse across machines.
