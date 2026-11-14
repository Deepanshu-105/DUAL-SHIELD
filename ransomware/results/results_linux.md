| attack | expected | named | correct | gate_tripped | vault_clean | detect_s | kill | recovered | recover_s |
|---|---|---|---|---|---|---|---|---|---|
| Crypto ransomware (LockBit-like, rename + note) | crypto | crypto | yes | yes | yes | 0.01 | n/a | yes, bit-for-bit | 0.21 |
| Crypto, header kept (evasive) | crypto | crypto | yes | yes | yes | 0.09 | n/a | yes, bit-for-bit | 0.28 |
| Crypto, encrypted copy + delete original | crypto | crypto | yes | yes | yes | 0.02 | n/a | yes, bit-for-bit | 0.25 |
| Wiper, zero-fill | wiper | wiper | yes | yes | yes | 0.0 | n/a | yes, bit-for-bit | 0.14 |
| Wiper, truncate to 0 | wiper | wiper | yes | yes | yes | 0.0 | n/a | yes, bit-for-bit | 0.14 |
| Wiper, mass delete | wiper | wiper | yes | yes | yes | 0.0 | n/a | yes, bit-for-bit | 0.11 |
| Double extortion (encrypt + stage archive + note) | double_extortion | double_extortion | yes | yes | yes | 0.02 | n/a | yes, bit-for-bit | 0.1 |
| Data theft only (archive staged) | exfiltration | exfiltration | yes | no | yes | 0.05 | n/a | n/a |  |
| Locker / note only | note_only | note_only | yes | no | yes | 0.05 | n/a | n/a |  |
| Benign edits (false-positive check) | no alarm | no alarm | yes | no | yes | 0.07 | n/a | n/a |  |
| LIVE crypto process (handle held open) | killed | (not logged) | yes | yes | yes | 0.91 | yes | yes, bit-for-bit | 0.16 |
| LIVE wiper process (zero-fill) | killed | (not logged) | yes | yes | yes | 0.71 | yes | yes, bit-for-bit | 0.15 |

12 scenarios, 0 problems. detect_s = time from end of attack to verdict (live rows: time to kill). Run on: linux
