# Memory acquisition

| Tool | Command | Notes |
|---|---|---|
| WinPmem (Velocidex, OSS) | `winpmem_mini_x64.exe E:\mem.raw` | raw format, works with Vol3 |
| Magnet RAM Capture | GUI | free, signed |
| DumpIt (Magnet/Comae) | `DumpIt.exe /OUTPUT E:\mem.dmp` | crash-dump format |

Order of volatility: memory → network state → processes → disk. Capture memory **before** killing anything.
Image size ≈ installed RAM; write to external media, not the system disk (overwrites deleted-file evidence).
Hash: `Get-FileHash E:\mem.raw -Algorithm SHA256` → record in chain-of-custody (evidence-discipline).
Hibernation file (`hiberfil.sys`) and `pagefile.sys` are alternative sources when live capture is impossible.
