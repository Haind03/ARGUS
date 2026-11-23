# Cross-tactic detection patterns

## Scoring model
`score = clamp(Σ signal weights, 0, 100)` — negative weights mitigate (valid Microsoft signature −20,
third-party signature −10, vendor download domain −20, JIT-heavy process −25).
Severity: ≥80 critical · ≥60 high · ≥40 medium · ≥20 low · <20 info (dropped by default).
Baseline-known finding: score × 0.3 (kept visible, never silently dropped).
Local IOC match: +35/+40. Opt-in VT ≥5 engines or MalwareBazaar hit: +30.

## Path classes (`engine/argus/indicators.py`)
| Class | Paths | Weight |
|---|---|---|
| high-risk user-writable | `%TEMP%`, `C:\Windows\Temp`, `C:\Users\Public`, `$Recycle.Bin`, `PerfLogs`, INetCache | 25 |
| user-writable | `AppData\Roaming`, `AppData\Local`, `ProgramData`, Downloads, Desktop, Documents | 15 |
| drive-root binary | `C:\x.exe` | 15 |
| allow-hinted | Teams, OneDrive, `AppData\Local\Programs`, Discord, Slack, Zoom, Chrome/Edge user installs | 0 |

## Parent → child
| Parent | Suspicious child | Weight |
|---|---|---|
| Office / PDF / mail | shells, LOLBins | 45 |
| Browser | script hosts, LOLBins (not cmd) | 35 |
| wmiprvse.exe | shells | 40 |
| wsmprovhost.exe | anything | 35 |
| auto-elevating binary (fodhelper, eventvwr, sdclt...) | shells | 55 |
| services.exe | (svchost expected) — svchost with other parent | 40 |

## Command-line patterns
Encoded PowerShell (decoded and rescanned), IEX, download cradles, FromBase64String, hidden window,
execution-policy bypass, AMSI strings, reflective load, `[char]` / backtick obfuscation, Win32 injection APIs,
Defender cmdlets, compressed payloads, URLs, >1000-char command lines.

## Trust model for allow-lists
Allow-listing by **name** is only honoured when the image lives in a protected system/program directory
(`_trusted_system_image`): a renamed `svchost.exe` in `%TEMP%` never inherits trust.
