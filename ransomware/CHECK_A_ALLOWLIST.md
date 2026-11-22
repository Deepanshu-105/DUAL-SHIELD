# Check-A allow-list: decision memo for the team

**Status: implemented, OFF by default.** `RESULTS_FROZEN.md` (Day 8) stays true as long as nobody sets `DS_CHECK_A_ALLOW=1`.
Enable (per run): `DS_CHECK_A_ALLOW=1 python3 ransomware/guard.py ...` or `export DS_CHECK_A_ALLOW=1` before the demo/start script.

## The problem it fixes
Check A flags any file whose first 16 bytes changed. From `evidence/fp_by_type.csv`: every benign operation that rewrites the file start
(adding a title line to a text file, re-saving a zip/jar/docx, re-compressing a gz) is flagged: 243 of 243 in the frozen run.
One flag does not kill anything (kill rule = 3 distinct files in 2 s), but it is the main known weakness and it makes the gate/containment noisy.

## What the allow-list does (only for check A; check B and the wiper test are untouched)
- zip family (.zip .docx .xlsx .pptx .jar .odt .ods) and .gz: not flagged if the first bytes are still the same magic number (PK\x03\x04 / 1f 8b 08).
- text files: not flagged if the first 16 bytes were printable text before AND are printable text now AND the first 4096-byte block still has text-like entropy (<= 5.75 bits/byte).
  Random/encrypted bytes are not printable; base64-armoured ciphertext is printable but too random.

## Measured (python3 ransomware/check_a_allow_eval.py data/benign ; corpus = 300 files from this machine, mock "ciphertext" = random bytes, copies only)
| Operation | Files | Flagged, OFF | Flagged, ON |
|---|---|---|---|
| BENIGN edit_top (text) | 210 | 210 (100%) | 5 (2%) |
| BENIGN resave zip/jar | 10 | 10 (100%) | 0 |
| BENIGN recompress gz | 13 | 13 (100%) | 0 |
| ATTACK overwrite all bytes | 300 | 300 (100%) | 300 (100%) |
| ATTACK keep first 16 bytes, encrypt the rest | 300 | 149 (49%) | 149 (49%) (same: check B covers the uncompressed ones) |
| ATTACK keep only the magic number, encrypt the rest | 300 | 300 (100%) | **287 (95%)** |
| ATTACK base64-armoured ciphertext | 300 | 300 (100%) | 300 (100%) |

Mock-ransomware runs (`test_m3.py`, 10 runs): 10/10 killed, 10/10 rollback verified, same with the allow-list ON and OFF. `test_guard.py`, `test_types.py`: ALL PASS both ways.
The first version of the text rule (printable only) let base64-armoured ciphertext through (30% detected); the entropy condition fixed that. That is why the eval has the base64 row.

## The honest trade-off (say this in the report)
An attacker who READS this rule can keep the magic number of a zip/gz and encrypt the rest: with the allow-list ON, check A no longer flags those
(13 of 300 files here). Check B was already blind to them (compressed data is random before and after), so what is lost is only the case "header
bytes 4-16 changed, magic kept" on compressed files. Hex-armoured ciphertext (4 bits/byte, printable) is a second theoretical hole in the text rule.
The corpus is files from one Linux machine, not Govdocs1; numbers on another corpus will differ a little.

## Recommendation
Turn it ON for the demo and the report if the team agrees that "243/243 benign flagged" is a worse headline than "13/300 adaptive-attacker files unflagged".
If the team prefers the frozen numbers, leave it OFF and cite this memo as "improvement tested, not adopted". Either way, write the decision and the date here:

Decision: ______   Date: ______   Who: ______
