# v13.5 Dashboard: the remaining gaps

| Gap from v13.4 | Fix | Where |
|---|---|---|
| Secrets are a plain file | Sealed store `multi/secrets.enc` (AES-256-GCM, key from a passphrase via scrypt). `config.env` keeps empty lines; the start scripts open the secrets into memory only. Wrong passphrase or a changed file is refused. | `multi/secrets_vault.py seal / status / set KEY [--random] / unseal`, `common.sh` |
| `'unsafe-inline'` for styles | `<style>` elements need the per-response nonce; only `style=""` attributes stay open (no code can run from them) | `lib/security.js` |
| Root attacker on D can stop the dashboard | Cannot be prevented on D itself; it can no longer go unnoticed: a watcher on ANOTHER laptop alarms (screen, log, webhook) when D stops answering or answers wrongly | `multi/watch_dashboard.py --url https://D_IP:3443/login --cafile multi/tls/node/ca.crt` |
| Flood against the console | Requests without a valid session share a small per-minute budget (default 120, `DASH_RATE_ANON`), signed-in sessions have their own (1500, `DASH_RATE_SESSION`); 429 + Retry-After; one audit line per flood | `proxy.js` |

Seal the secrets (once, on every laptop that has a config.env with secrets):
```
pip install cryptography            # D only if missing
python3 multi/secrets_vault.py seal      # passphrase, min 12 characters; do not forget it
multi/start_D.sh                         # asks for the passphrase; for unattended starts: DS_PASSPHRASE_FILE=/path/to/file (chmod 600, USB stick or tmpfs)
```
Watcher on P (or any other laptop): `python3 multi/watch_dashboard.py --url http://D_IP:3000/login` (lab) or the https form above.

Limits that remain (honest): a root attacker on D can still read process memory while the dashboard runs and can stop it (you are now alerted); behind the TLS tunnel all clients share one address, so a flood of anonymous requests can also slow a NEW sign-in (signed-in operators are not affected); volumetric DDoS must be filtered upstream (router, ISP, CDN); style attributes remain allowed.

Tests: `cd dashboard && npm run build && python3 test_security.py && python3 test_security2.py && python3 test_security3.py` (19 + 17 + 5 checks); Playwright browser check: login and all 8 tabs with 0 CSP violations under the strict policy.
