# Dual-Shield v13 — secure Admin Console

## What changed
| Area | v12 | v13 |
|---|---|---|
| Login | HTTP Basic prompt, one password | Login page, signed session cookie (HttpOnly, SameSite=Strict, Secure under TLS), 30 min idle / 8 h hard limit, logout revokes the session |
| Roles | one | **admin** (`DASH_PASS`) and read-only **viewer** (`DASH_VIEW_PASS`, ideal for the evaluator) |
| Brute force | none | lockout 5 tries → 30 s doubling to 15 min, global counter, constant-time compare, fixed delay |
| CSRF / cross-site | custom header on two routes | every state change: admin role + same-origin + `x-ds-confirm`, enforced in the proxy AND again in each route |
| Browser hardening | none | CSP (no framing, no foreign scripts/forms, `base-uri none`), nosniff, no-referrer, COOP/CORP, HSTS under TLS, `no-store` on API |
| Audit | none | hash-chained log `multi/logs/dashboard_audit.jsonl` (login, fail, lock, refusal, rollback, recovery, governance, demo); tamper check in the UI |
| Input | — | IP / node id / numbers validated on the server before they reach the chain |
| Offline | Google web fonts fetched at build | system fonts only; nothing fetched from the internet |
| Dev server | `npm run dev` (source maps, eval) | production build + `next start` (`DASH_DEV=1` for the old way); live API data can never be cached |
| UI | one page | Admin Console: Overview, Layer 1, Consensus & Chain, Governance (propose/sign), Layer 2 (start mock ransomware, roll back, recover, unfreeze), Security posture, Audit log |

Slashed vs not-yet-registered nodes are now shown differently (the old page compared a number with `0n`, so slashing never showed).

## Use
1. `multi/gen_secrets.sh` → put `DASH_PASS`, `DASH_VIEW_PASS`, `DASH_SESSION_KEY` in `multi/config.env`.
2. `multi/start_D.sh` (builds the dashboard first, takes a minute) → open the page, sign in.
3. Give the evaluator `DASH_VIEW_PASS`; you keep the administrator password.
4. `DEMO_MODE=0` hides the demo-ransomware button for a real deployment.
Test: `cd dashboard && npm run build && python3 test_security.py` (19 checks).

## Honest limits
- Over plain HTTP the password and cookie cross the network in clear text: use `TLS=1` (https://D:3443) for anything beyond a closed lab. Cookie is `Secure` only under TLS.
- CSP still allows inline scripts (`'unsafe-inline'`), required by this Next.js setup without a nonce rework; it blocks foreign scripts, framing and form hijack, not injected inline script. React escapes all data, so no HTML is built from server data.
- Behind the built-in TLS proxy all clients look like one address, so lockout is global: someone who guesses wrong repeatedly can lock the login screen for others (an already signed-in session keeps working). Put a real reverse proxy with `DASH_TRUST_PROXY=1` for per-client lockout.
- Passwords live in `multi/config.env`; anyone with root on D can read them or the audit log. The audit chain detects edits, it cannot stop root deleting the whole file.
- Two roles share one process: this is not multi-user accounts with individual identities.
