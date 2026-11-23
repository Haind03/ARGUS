# Acquisition tools

| Tool | Type | Format | Notes |
|---|---|---|---|
| WinPmem (Velocidex) | OSS, kernel driver | raw / aff4 | `winpmem_mini_x64.exe out.raw`; best Volatility 3 compatibility |
| DumpIt (Magnet/Comae) | free | crash dump (.dmp) | one-click; Vol3 reads crash dumps |
| Magnet RAM Capture | free GUI | raw | signed; easy for non-experts |
| Belkasoft RAM Capturer | free | raw | — |
| ProcDump (Sysinternals) | signed | minidump | used by ARGUS `-Mode Process` (`-ma`) |
| Task Manager → Create dump file | built-in | minidump | user-friendly; writes to %TEMP% (move it to case folder) |

## Pitfalls
- AV may quarantine a dump of a malicious process — that is expected and is itself evidence. Record it, keep the
  quarantine entry, and analyse a fresh dump on a separate analysis machine/VM. ARGUS never adds Defender exclusions.
- Memory integrity / HVCI can block unsigned acquisition drivers — use a signed tool.
- ARGUS never dumps LSASS by process; credential exposure is assessed from a full RAM image offline.
- Do not capture over the network share of a possibly compromised NAS.
- Always hash immediately; verify the hash again before analysis.
