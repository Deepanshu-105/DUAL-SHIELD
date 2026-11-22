# v13.8 - Layer 2 false-positive hardening (step 1 of "ready for real ransomware")
- ransomware/results_table.py now also runs 10 ordinary heavy workloads that must NOT raise an alarm: backup copy of every file, zip a folder, extract an
  archive, build output (many new files), photo import (random-looking jpgs), sort files into folders, editor re-saves all files unchanged, log rotate
  (gzip + delete), large installer download, delete 3 old files.  First run found 1 real false positive (sorting/moving files = "mass delete = wiper").
- Fix (classify.py + detect.py): a file that is gone but whose size, header and byte statistics match a NEW file is a move/rename, not a deletion.
  Encrypted copies do not match, so ransomware (rename+encrypt, encrypt copy + delete original) and wipers are still caught.
- Result: 20 scenarios, 0 problems (10 attacks all detected + recovered bit-for-bit, 10 benign no alarm); test_types, test_guard, test_m3 all pass.
Not done (still needed before real malware): Windows kernel hook (kill takes 3-4 s), vault on a separate account/machine, tests on public simulators
(e.g. Atomic Red Team) and real samples ONLY in an isolated VM with written supervisor approval.
