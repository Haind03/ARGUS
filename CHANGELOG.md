# Changelog

ARGUS by HaiND from the Post and Telecommunication Institute of Technology.

## v0.1.1 (2026-11-23)
### Fixed
- Windows checkouts corrupted the vendored YARA bundle (git treated it as text and rewrote line endings);
  `.gitattributes` now marks it binary. A CI step compiles the bundle on Windows.
- CI matrix: Python 3.10 and 3.13 (3.9 is no longer available on current runners); minimum Python is now 3.10.
- PowerShell syntax check runs on every push, not only on release.

## v0.1.0 (2026-11-23)
First public release.

### Engine
- Heuristic detection engine: ~60 rules over 82 MITRE ATT&CK techniques, all 12 host-observable tactics.
- Scoring 0 to 100 with mitigating signals, severity bands, baseline down-weighting, short finding IDs.
- Outputs per hunt: JSON, Markdown report, ATT&CK Navigator layer, HTML assessment report.
- Offline-first threat intelligence; VirusTotal v3 and MalwareBazaar lookups are opt-in and send SHA-256 only.
- Static PE triage (sections, entropy, imports, overlay, strings) and YARA.

### Harness
- Cases with scope attestation, 14-phase hypothesis-driven `full-hunt` workflow with gates,
  `incident-investigation` and `ransomware-response` workflows.
- Analyst dispositions, FINAL-report gate, SHA-256 hash-chained audit log.
- PreToolUse action guard: destructive commands denied unless a time-boxed IR opt-in exists.

### Skills (33)
Data layer, 12 tactic hunting skills, memory acquisition and Volatility 3 forensics, process memory,
disk, event log, network and browser forensics, triage, intel, YARA/Sigma authoring, opt-in incident
response, 7 discipline skills.

### Detection content
- 1993 YARA rule files vendored from Haind03/Exhume and Haind03/Unveil (masked, in-memory bundle).
- Starter YARA and 10 Sigma rules.

### Platforms
- Claude Code plugin and manual install (Windows, macOS, Linux), OpenAI Codex CLI, Claude Code on GLM.
- Windows Task Scheduler scheduled scan.

### Packages
- `argus-defense` wheel and sdist (`pip install argus-defense-0.1.0-py3-none-any.whl`, command `argus`).
- Container image `ghcr.io/haind03/argus` for offline analysis of collected telemetry.
- `argus-0.1.0-toolkit.zip` full toolkit.
