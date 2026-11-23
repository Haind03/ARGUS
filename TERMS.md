# Terms of use

ARGUS is a **defensive** toolkit. By using it you agree to:

1. **Authorised scope only.** Run ARGUS only on computers you own, or for which you hold the owner's explicit
   permission. Do not use it to access, monitor or collect data from other people's devices, accounts or networks.
2. **Detect-only default.** ARGUS collects and scores artefacts; it does not remediate unless you explicitly
   opt in (incident-response). You are responsible for any action you approve.
3. **Privacy.** Telemetry, memory images, packet captures and browser data contain personal and sensitive
   information. Keep them local and encrypted; share reports only after redaction. Online threat-intel lookups
   are off by default; when you enable them, SHA-256 hashes are sent to the provider you configure and are
   subject to that provider's terms.
4. **No warranty.** Heuristic results can be wrong in both directions. ARGUS does not replace antivirus/EDR or
   professional incident response. See LICENSE (MIT).
5. **No offensive use.** Detection content and knowledge in this repository must not be used to build or
   improve malware or to evade security controls.
6. **Third-party tools** (Sysmon, osquery, Volatility, YARA, WinPmem, ProcDump, tshark, Eric Zimmerman tools,
   VirusTotal, abuse.ch) are governed by their own licences and terms; download them from their vendors.

ARGUS by HaiND from the Post and Telecommunication Institute of Technology.
