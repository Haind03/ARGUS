# Chain of custody (lightweight, personal-PC grade)

Each evidence item records: SHA-256 (+MD5/SHA-1 for intel compatibility), original path, size,
MAC times, host, collector, UTC time, reason (finding ID). Stored in `evidence/custody.jsonl`;
memory dumps in `chain-of-custody.json` next to the image (memory-acquisition).

Integrity: `argus case verify` checks the hash-chained `audit.jsonl`; re-hash evidence before analysis
and before handing it to anyone (police, insurer, CERT).

If the case might become legal (fraud, extortion): stop at evidence capture, do not remediate further,
and contact the authorities, they may want the device as-is.
