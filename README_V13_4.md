# v13.4 Dashboard security fixes

| Gap | Fix | Where |
|---|---|---|
| Password only (no 2FA) | 2-step sign-in (authenticator app, TOTP) for administrator and operator; a code works once (replay refused) | `multi/make_totp.py`, `lib/security.js`, login form |
| Password over plain HTTP | Sign-in from another machine over HTTP is refused (426). Allowed: this machine, or TLS=1 (https://D_IP:3443) | `plainHttpRefused` |
| Inline scripts allowed (CSP) | Per-response nonce: `script-src 'self' 'nonce-...' 'strict-dynamic'`, no `'unsafe-inline'` for scripts (pages are now rendered per request) | `proxy.js`, `next.config.mjs` |
| Only two roles | New **operator** role: Layer 2 actions and the demo; no governance, no audit log | `DASH_OPERATOR_PASS` |
| Audit log deletable | Every line is mirrored to a second file or POSTed to a collector; `multi/verify_audit.py` checks the chain and compares the mirror | `DASH_AUDIT_MIRROR`, `DASH_AUDIT_WEBHOOK` |
| Secrets in plain file | `start_D.sh` forces `config.env` to mode 600 and warns about 2FA/TLS/mirror; `multi/rotate_secrets.py` rotates session key, passwords, agent secrets without printing them | |

Still open (honest): secrets are still a plain file (no vault/HSM), styles keep `'unsafe-inline'`, a root attacker on D can still stop the dashboard, DDoS must be filtered upstream.

Turn on:
```
python3 multi/make_totp.py                 # 2-step sign-in; type the setup key into an authenticator app (do not screenshot it)
# in multi/config.env: DASH_OPERATOR_PASS=..., DASH_AUDIT_MIRROR=/some/other/path.jsonl, TLS=1 for other machines
multi/start_D.sh
```
Tests: `cd dashboard && npm run build && python3 test_security.py && python3 test_security2.py` (19 + 17 checks). A real browser check (Playwright) confirmed the nonce policy: login, hydration and all tabs work with 0 CSP violations.
