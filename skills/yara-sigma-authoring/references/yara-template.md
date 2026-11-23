# YARA template

```yara
rule ARGUS_<Family>_<Artifact>
{
    meta:
        author = "ARGUS"
        description = "<what it detects and why it is suspicious>"
        attack = "T1xxx.xxx"
        reference = "<case id / report>"
        fp = "<known benign software that may match>"
    strings:
        $mutex = /G\x6cob\x61l\\\x61rg\x75s_test/ ascii wide      // escaped regex
        $pdb   = { 3A 5C 62 75 69 6C 64 5C }                        // hex
        $cfg   = /"c2"\s*:\s*"https?:\/\//                           // structural regex, no literal URL
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of them
}
```
Guidelines: anchor with file type (`uint16(0)==0x5A4D`, `uint32(0)==0x0000004C` for LNK), cap `filesize`,
require ≥2 independent strings, avoid strings present in Windows binaries, document FPs in `meta`.
Memory scanning (`windows.vadyarascan`) drops the file-type anchor, create a `_mem` variant without it.
