# Timeline method

1. **Anchor**: pick the highest-confidence event (e.g. first execution of the malicious binary from Prefetch/Amcache,
   or the Run key creation time from Sysmon 13).
2. **Window**: ±2 h around the anchor, expand as needed.
3. **Merge sources** into one timeline (UTC): `execution-timeline.json` (artefacts) + hunt findings
   (`events[].time`, `processes[].start_time`) + memory findings + browser downloads.
   Optional super-timeline: plaso `log2timeline.py` on a disk image (offline).
4. **Walk backwards** to initial access (download? attachment? USB?) and **forwards** to persistence, C2, impact.
5. **Record** every pivot in the case notes with source + timestamp (evidence-discipline).

Pitfalls: time zones (store UTC), clock skew, Prefetch timestamps are last-8-runs not first run, ShimCache
time is file modification time (not execution), timestomped $SI times — prefer $FN and USN.
