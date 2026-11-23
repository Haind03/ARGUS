# Ransomware first response (personal PC)

| Do | Don't |
|---|---|
| Disconnect network (cable/Wi-Fi) immediately | Don't reboot or shut down (keys may be in RAM; some strains finish encryption at boot) |
| Capture memory if possible | Don't pay before checking for a free decryptor (nomoreransom.org) |
| Photograph the ransom note; keep one encrypted sample + its original if any | Don't delete encrypted files or notes |
| Disconnect external drives / NAS / cloud sync clients | Don't plug backup drives in until clean |
| Check if shadow copies survived (`vssadmin list shadows`, read-only) | Don't run "cleaner" tools before evidence capture |
| Identify the strain (note + extension → ID Ransomware) | Don't trust the attacker's "proof" of deletion |
| Report to local CERT/police for crime records | |

Afterwards: rebuild from trusted media (rebuild-vs-clean.md), restore from offline backups, reset all passwords from a clean device.
