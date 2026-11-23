# Rootkits & kernel tampering

| Indicator | Plugin | Notes |
|---|---|---|
| DKOM-hidden process | psscan vs pslist | Unlinked EPROCESS; psscan carves pool tags |
| SSDT hook | windows.ssdt | Entry owner not ntoskrnl/win32k — on x64 PatchGuard makes this rare; high confidence |
| Unknown kernel callback | windows.callbacks | PsSetCreateProcessNotifyRoutine/LoadImage/Registry callbacks from UNKNOWN module |
| Driver object without module | driverscan vs modules | unloaded/hidden driver |
| Vulnerable signed driver | modules, driverscan | BYOVD (RTCore64, dbutil_2_3, gdrv, procexp152, ...) — used to kill AV/EDR |
| IRP hooks | windows.driverirp | IRP handlers outside the driver's own module |

## Response posture
A confirmed kernel rootkit means the OS can no longer be trusted to report on itself:
recommend **offline analysis + rebuild** (reinstall from trusted media) after evidence capture, then
password resets from a clean device. Do not attempt in-place "cleaning".

## FPs
AV/EDR, anti-cheat (Vanguard, EAC, BattlEye), virtualization tools and hardware monitors register callbacks
and load signed drivers. Identify vendor before concluding.
