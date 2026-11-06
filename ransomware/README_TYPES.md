# Ransomware types: what Dual-Shield names, stops and recovers

The guard now says WHICH kind of attack it sees (`RANSOM_TYPE ...` in its log, `evidence/ransom_class.json`, the dashboard tile
"Attack type"). The type comes from behaviour, so it also works for tools nobody has named yet. Family names (WannaCry-like,
LockBit-like ...) are only hints from file/note names; affiliates rename them, so never rely on them.

| Type | How it is recognised | Detect | Block / kill | Recover | Limits |
|---|---|---|---|---|---|
| **Crypto** (WannaCry, LockBit, Ryuk) | files fail the header check (A) or look uniform-random now (B), also encrypted copies + deleted originals; same new extension on many files; ransom note | yes, also header-preserving, partial, intermittent | process killed after 3 files; gate stops bad copies reaching the vault; egress cut | verified restore from the vault (bit for bit in the tests) | slow, header-kept encryption of files that were never structured; Windows-native; boot/disk-level |
| **Wiper** (NotPetya, Shamoon style) | files zeroed / truncated / filled with one byte, or mass deletion (>=10 and >=25% of the folder); "ransom note + destruction" is called out as a wiper posing as ransomware | yes (file level) | zero/truncate: process killed after 3 files; mass delete: gate + freeze + containment, process NOT killed (Linux does not say who deleted; needs auditd/fanotify) | from the vault; **stop the deleting process before restoring** | boot record / partition tables not seen; deletions below the threshold count as normal edits |
| **Double extortion** (Maze, REvil, Conti) | encryption, wiping or a note PLUS data-theft signs: archives created in the protected folders and/or an outbound-transfer spike | yes when `exfil` is on and/or archives are staged | egress blocked when archives were staged, files are damaged, or `exfil_contain` is set | files restored; **the stolen copy cannot be recalled**: the verdict says to treat the data as leaked and rotate credentials | outbound spike is host-wide, not per process; a thief who uploads slowly under the threshold is missed |
| **Exfiltration only** (doxware's first phase) | theft signs without file damage | yes, same signals | egress blocked if archives staged or `exfil_contain` | nothing to restore | same |
| **Locker / scareware / doxware** (note only) | a note appears (several demand words, or a fake-infection / "device locked" / "we will publish" message) and no file is damaged | note content only | alert; no freeze because nothing is damaged | nothing to restore | a screen locker that writes no file is invisible to a file-based guard; mobile ransomware is out of scope |
| **RaaS** | not a technique: affiliates differ, so there is no separate detector; behaviour rules above apply, family name is a hint | via the behaviour types | same | same | |
| **Fileless loaders** (PowerShell, in memory) | irrelevant to the file rules: the damage to the files looks the same | yes (the damage) | process is found through its open files | same | the loader itself is not inspected |

Turn on theft detection in `protect.json`: `"exfil": true, "exfil_min_mbps": 2.0` (and `"exfil_contain": true` for a hard stop).
`"delete_threshold": 10` sets the mass-delete limit (0 = off).

Test: `python3 ransomware/test_types.py` (46 checks: each type named, gate/vault protection, verified recovery, benign files stay quiet,
live guard + live wiper process).
