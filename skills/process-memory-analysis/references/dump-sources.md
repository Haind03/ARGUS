# Dump sources & limits

| Source | Contains | Limit |
|---|---|---|
| Full minidump (ProcDump `-ma`, ARGUS Process mode) | all committed memory, handles, threads, modules | large (process size) |
| Mini dump (`-mm`) | stacks + module list only | not enough for strings |
| Volatility `memmap --dump` | full address space from RAM image | paged-out pages missing |
| Volatility `malfind --dump` | only suspicious VADs | small, focused |
| WER crash dumps | crash-time state | often minimal |

Paged-out memory is absent from RAM-based dumps; `pagefile.sys` strings can fill gaps.
Protected processes (PPL: LSASS with RunAsPPL, AV) cannot be dumped from user mode — that is a protection working, not a failure.
