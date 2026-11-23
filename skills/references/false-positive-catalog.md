# False-positive catalog (personal Windows PCs)

| Trigger | Typical benign cause | How to tell |
|---|---|---|
| Binary in `AppData\Local\...` running | Teams, Discord, Slack, Spotify, Zoom, VS Code user install, Chrome/Edge per-user | signed by vendor, path under `Programs\` or vendor folder, long-lived |
| Scheduled task runs from AppData | OneDrive, Google/Edge updaters, Discord updater | signed updater, vendor name in task path |
| Encoded PowerShell | Intune/SCCM, Chocolatey, some OEM tools | parent is a signed agent, consistent daily |
| Defender exclusion | developer build folders, games, VMs | user remembers adding it; path is a project/game dir |
| Real-time protection off | third-party AV installed (Defender passive) | `antivirus_enabled` false + another AV in Security Center |
| Remote access tool | user's own AnyDesk/TeamViewer for family support | installed in Program Files, user confirms |
| Tunnel tool (ngrok/cloudflared) | web developers | started from a terminal by the user |
| Vulnerable driver (RTCore64, WinRing0) | MSI Afterburner, hardware monitors, RGB software | matching app installed |
| Discovery command burst | user troubleshooting network | parent explorer/terminal, daytime |
| Unsigned DLL beside signed EXE | portable apps, games | vendor folder, unchanged since install |
| DGA-like domain | CDN / telemetry hashes | queried by browser or signed vendor process |
| Large upload | OneDrive/Dropbox/Google Drive/Backblaze, game uploads, video calls | process is a sync client |
| malfind hit | browsers, Electron apps, .NET JIT, AV | process is JIT-heavy, no MZ header |
| WMI subscription | Dell/HP/Lenovo OEM utilities, `SCM Event Log Consumer` (default) | consumer is NTEventLog type / OEM name |

Rule of thumb: **benign = explainable + consistent with baseline + signed by the expected vendor**.
One unexplained element (wrong path, wrong parent, odd time) is enough to keep investigating.
