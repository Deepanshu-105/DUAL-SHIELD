# Dual-Shield v7 — encrypted, mutually authenticated traffic between the laptops (TLS)

Off by default (`TLS=0`). With `TLS=1` nothing readable crosses the network between D, T and P.

## What was open before
v2 signed every agent request (HMAC) but the traffic itself was plain HTTP: the chain RPC (8545), the dashboard (3000, password
in HTTP Basic), the agents (8800) and the registry (8801) could be read by anyone on the LAN. The signatures stopped forgery and
replay, not eavesdropping.

## What TLS=1 does
| Link | Before | With TLS=1 |
|---|---|---|
| Dashboard → agents on T and P (8800) | HMAC over plain HTTP | **mutual TLS** (private CA, only the dashboard certificate may call an agent) + the same HMAC |
| T and P → registry on D (8801) | HMAC over plain HTTP | **mutual TLS** (only target or peer certificates) + HMAC |
| T and P → chain RPC | plain 8545 | local door 127.0.0.1:8545 → **mutual TLS tunnel** → D:8546 → chain (bound to 127.0.0.1 on D) |
| Operators → dashboard | http://D:3000 | **https://D:3443** (password only over TLS); plain 3000 is bound to 127.0.0.1 |
| T and P fetch the contract file | http://D:3000 | https://D:3443 with the CA pinned (`curl --cacert`) |

Certificates carry the role in the CN (`dualshield-dashboard`, `-target`, `-peer`). The client checks that role instead of a
hostname, so discovery with changing addresses keeps working and a stolen peer certificate cannot pose as the dashboard.
Minimum TLS 1.2 (`TLS_MIN=1.3` to require 1.3). RSA 3072 keys, certificates valid 365 days.

## Set up (once)
```bash
# on D
cp multi/config.env.example multi/config.env    # set D_IP (and T_IP / P_IP, or DISCOVERY=1), TLS=1
multi/make_tls.sh                               # creates multi/tls/{ca.crt, ca.key, dashboard/, target/, peer/}
scp -r multi/tls/target  user@T:DUAL-SHIELD/multi/tls/node       # T gets ONLY its own folder
scp -r multi/tls/peer    user@P:DUAL-SHIELD/multi/tls/node       # P gets ONLY its own folder
# set TLS=1 in multi/config.env on T and P as well, then start D, T, P as before
sudo multi/start_D.sh
```
Open `https://D_IP:3443` and trust `multi/tls/dashboard/ca.crt` in the browser once (or accept the warning in the lab).
Re-run `make_tls.sh` after the addresses are known if you want the dashboard certificate's address list to include them
(delete the old `multi/tls` first). Renew before the 365 days are over.

## Limits
* **ca.key is the crown jewel.** Whoever has it can mint a certificate for any role. Keep it off T and P (and offline after issuing).
* No automatic certificate renewal or revocation list: to revoke a laptop, issue a new CA and new certificates (deliberately simple).
* The Hardhat chain itself still listens on plain HTTP, on 127.0.0.1 of D only; the tunnel is the way in.
* The tunnel hides the caller's address from the chain node (it sees 127.0.0.1); per-node identity on the chain remains the account/contract rule.
* The attacker laptop A has no certificate, so with TLS=1 it cannot even connect to the agents, the registry or the chain.
* This protects the transport. It does not make a compromised laptop trustworthy.

## Test
`python3 multi/test_tls.py` — real certificates, 15 checks: wrong role, rogue CA, no client certificate, plain HTTP, registry join over TLS, tunnel.
