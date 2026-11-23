# AV-safe detection content

Defender and other AV products statically scan every file on disk, including **text** files. A YARA
or test file that contains the literal strings of a hacking tool, ransom note or download cradle can be
quarantined as `HackTool:` / `Trojan:Script` — breaking the toolkit and alarming the user.

ARGUS conventions:
| Content | Do | Don't |
|---|---|---|
| YARA strings | hex `{ 55 50 58 30 }` or regex with `\xNN` escapes (`/s\x65kur/i`) | plain-text tool command strings (module::command style) |
| Test data | assemble indicator strings at runtime from fragments (`tests/synthetic.py`) | commit realistic payload command lines / encoded blobs |
| AV test file | reference the EICAR **hash** only | write the EICAR string to disk |
| Python regex | pattern form (`vssadmin(?:\.exe)?\s+delete\s+shadows`) | full ready-to-run command literals |
| Scripts | call vendor-signed tools (ProcDump, WinPmem) | embed P/Invoke dumping, AMSI patches, injection code |
| Scheduled task | `-ExecutionPolicy RemoteSigned`, visible, signed engine | `-w hidden -ep bypass` as SYSTEM |

`tests/test_av_safety.py` enforces this: it scans the repository for contiguous high-risk literals
(the list itself is stored as fragments) and fails the build if any appear.

Never ask the user to add an AV exclusion for ARGUS. If Defender flags a file, report it as a bug in ARGUS
(and submit a false-positive report to Microsoft: https://www.microsoft.com/wdsi/filesubmission).
