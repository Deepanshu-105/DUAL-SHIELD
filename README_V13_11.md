# v13.11 - the "kya baaki hai" items of the dashboard table, done as far as software can
1. Phone lost: python3 multi/make_backup_codes.py -> 8 one-time codes (only SHA-256 hashes in config.env); type one in the "code" field. Each works once; audited as LOGIN_OK_BACKUP_CODE.
2. Finer permissions: DASH_PATH_ROLES="/api/rollback=admin,/api/recovery=operator" (lowest role per POST path; viewer < operator < admin). Default as before.
3. Passphrase lost: python3 multi/secrets_vault.py recovery-key -> RK-... key (print it, keep it away); at any passphrase prompt type the RK-... key. Run again after re-sealing.
4. Watcher forgotten: python3 multi/watch_dashboard.py --url ... --print-autostart prints the cron / schtasks lines that start it at boot (run on ANOTHER laptop).
5. TLS tunnel clients look identical: DASH_TRUST_PROXY=1 (already present) gives real client addresses behind a reverse proxy.
Tests: multi/test_v13_11.py (18 checks: backup codes once-only, role overrides, recovery key) + dashboard test_security / 2 / 3 all pass.
Install: unzip -o at repo root, restart the dashboard (multi/start_D.sh). Then run make_backup_codes.py and recovery-key once.
NOT fixable in software (honest limits): style="" attributes (cannot run code; removing them means rewriting all inline styles), root reading the running dashboard's memory (needs HSM/secret manager),
remote browsers need TLS=1 (an operating choice: TLS=1 multi/start_D.sh), root attacker stopping the dashboard (the external watcher alarms instead), volumetric DDoS (upstream).
