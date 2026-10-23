# M3 ransomware detection and recovery: frozen results (Day 7)

Every number comes from a file in ransomware/evidence/ and can be re-run.

## Detection, kill and rollback (10 runs of the mock ransomware)
Source: ransomware/evidence/m3_results.csv (made by ransomware/test_m3.py)

| Measure | Result |
|---|---|
| Runs where the process was killed | 10 of 10 |
| Kill latency: kill rule fires (KILL_TRIGGER in the watcher log) to attacker process dead | 2.23 ms average, max 3.12 ms |
| Files damaged before the kill | 3 of 10 on average (kill rule: 3 distinct files in 2 s) |
| Rollback restored a verified copy | 10 of 10 runs (file hashes match the pre-attack snapshot) |
| Rollback time (restore + hash verification of 10 files) | 4.09 ms average |
| Rollback refused on a tampered snapshot | yes, by comparing the Merkle root with the chain (blockchain/day6_rollback_anchor.txt) |

The 3 damaged files are damaged before the kill rule fires (it needs 3 distinct files in 2 s).
Time from the first encrypted file to the kill is therefore longer than the kill latency above and is not measured separately.

## False positives on benign file operations
Source: ransomware/evidence/fp_by_type.csv (made by ransomware/fp_test.py), 752 benign operations on 300 system files.

| Kind of operation | Tested | Flagged |
|---|---|---|
| Operations that keep the file header (append) | 509 | 0 |
| Operations that change the header (edit_top, recompress_gz, resave_zip / jar) | 243 | 243 (100%) |

How to read this:
- Check A compares the first bytes of a file. Any benign operation that rewrites the start of a file changes them, so it is always flagged. This is the main known weakness.
- One flag does not kill anything. The kill rule needs 3 distinct files flagged within 2 s, so a single benign edit does not stop a process.
- Check B (chi-square on start, middle and end blocks) did not flag any appended file.

## Known limits (state them in the report)
- New files that have no baseline are not checked.
- Files that were already random or compressed at baseline are invisible to check B (their entropy was already high).
- The baseline covers one protected folder (data/sample_copy), not a whole disk.
- The attack is a mock (mock_crypto.py) run on copies, in an isolated lab.
- Possible improvement: a header-aware allow-list for known benign rewrites (zip, gz), so check A flags fewer legitimate edits.
