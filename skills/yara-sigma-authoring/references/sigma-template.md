# Sigma template

```yaml
title: <Short behaviour description>
id: <uuid4>
status: experimental
description: <what, why suspicious, ATT&CK technique>
author: ARGUS
date: 2026-11-23
tags:
    - attack.<tactic_name>
    - attack.t1xxx.xxx
logsource:
    category: process_creation      # or: product: windows / service: security|system|windefend|wmi|powershell
    product: windows
detection:
    selection_img:
        Image|endswith: '\binary.exe'
    selection_cmd:
        CommandLine|contains|all:
            - 'fragment1'
            - 'fragment2'
    filter_legit:
        ParentImage|startswith: 'C:\Program Files\Vendor\'
    condition: selection_img and selection_cmd and not filter_legit
falsepositives:
    - <benign software>
level: medium
```
Use `contains|all` with separate fragments rather than one full command string (more robust to
argument reordering and AV-safe). Convert for a SIEM with `sigma convert -t <backend>` (pySigma).
ARGUS itself evaluates its Python heuristics, which mirror these rules.
