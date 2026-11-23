# Authorisation model

| Situation | OK? | Note |
|---|---|---|
| Your own personal PC/laptop | yes | attest with `--i-own-this-machine` |
| Family member's PC, they asked you | yes, with their consent | note who consented in the case owner field |
| Employer-managed laptop | only with IT/security approval | corporate EDR/IR process takes precedence |
| Lab VM / CTF box you control | yes | label the case "lab" |
| Second-hand device before wiping | yes (you own it) | consider privacy of previous owner's data |
| Anything reached over the network | no | ARGUS is local-only by design |

Consent covers the *machine*; browser history, mailboxes and chat data of other users on that machine
need their own consent. Keep personal data out of reports (reporting-discipline).
