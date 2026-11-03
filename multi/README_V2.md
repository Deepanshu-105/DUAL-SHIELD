# Dual-Shield v2: securing the dashboard laptop (D) and its links

v2 lives in its own folder (`DUAL-SHIELD-v2`). The original `DUAL-SHIELD` folder is not touched.

## What changed

| # | Change | Where | What it stops |
|---|---|---|---|
| 1 | Operator login on the dashboard (HTTP Basic, user `operator`, password `DASH_PASS`); rollback needs a confirm dialog and a custom header | `dashboard/proxy.js`, `app/api/rollback/route.js`, `ShieldLive.jsx` | Anyone on the Wi-Fi opening the page or calling `/api/rollback` and `/api/*`. The dashboard refuses to serve at all if `DASH_PASS` is missing |
| 2 | Signed agent requests: HMAC-SHA256 over method, path, time, nonce and body hash, one secret per laptop (`AGENT_SECRET_T`, `AGENT_SECRET_P`); answers are signed back | `multi/agent.py`, `dashboard/lib/agent.js`, `multi/agent_call.py` | A sniffer copying a token (the secret never crosses the network), replayed requests (nonce and 60 s window), forged answers such as a fake `ANCHOR_MATCH` |
| 3a | Owner-approved nodes: `registerNode` needs `addNode(address)` from the deployer first; `revokeNode` removes a node and forfeits its stake | `blockchain/contracts/CityShield.sol`, `scripts/deploy.js`, tests | A rogue laptop registering and casting fake votes to block a legitimate address |
| 3b | Port allowlist: chain `8545` and dashboard file `3000` only from T and P; agents `8800` only from D | `multi/lockdown.sh` | A (or any other laptop) talking to the chain or the agents directly |

## Set up (once)

```bash
# on D, inside DUAL-SHIELD-v2
cp multi/config.env.example multi/config.env      # then put the four IPs in
multi/gen_secrets.sh                              # prints three lines; paste them into multi/config.env
```

* D keeps all three lines. T keeps only `AGENT_SECRET_T`. P keeps only `AGENT_SECRET_P`. A needs none.
  Give T and P their line by hand (read it out or type it); do not send it in a chat.
* Everything else (install scripts, start order) is the same as `multi/README_MULTI.md`.

## Run order

1. D: `multi/start_D.sh` (deploys the contract and approves the three node accounts), then `sudo multi/lockdown.sh D`
2. T: `sudo multi/start_T.sh`, then `sudo multi/lockdown.sh T`
3. P: `sudo multi/start_P.sh`, then `sudo multi/lockdown.sh P`
4. A: `multi/attack_A.sh` (after lockdown, `check_net.sh` on A shows the chain and agents as unreachable: that is correct)
5. D: `multi/ransomware_trigger.sh`, then open `http://localhost:3000` (login `operator` / `DASH_PASS`) and click rollback

`sudo multi/lockdown.sh off` removes the rules on that laptop.

## Demo to show the evaluator (each takes about 20 seconds)

| Show | Command | Expect |
|---|---|---|
| No login | `curl -i http://D_IP:3000/api/blocked` from any laptop | `401` (from A or an unlisted laptop it will not even connect after lockdown) |
| Old token no longer works | `curl -i -H 'X-Token: dualshield' http://T_IP:8800/health` | `401 bad signature` |
| Replay refused | capture a signed request and send it twice (see `agent.py` test below) | second one `401 replayed request` |
| Rogue node refused | `npx hardhat test` | the four "v2: owner-approved registration" tests pass |
| Port closed | from A: `curl -m3 http://D_IP:8545` | times out |
| Normal flow still works | full four-laptop run | same results as v1 |

## Tests run for this version

* `npx hardhat test`: 10 passing (6 original contract tests kept, 4 new for owner approval, revocation and fake reports).
* Agent and dashboard client: valid request accepted; old `X-Token`, wrong secret, replayed nonce, request 10 minutes old and a signature reused on another path were all refused with 401.
* Dashboard: no password `401`, wrong password `401`, right password `200`, `/localhost.json` open for T and P, rollback without the confirm header `403`.
* Gas, re-measured: registerNode 68,065 (was 65,800), first report 164,438, second report 113,466, slash 79,680, anchor 94,883. `addNode` is a one-off owner call.

## What v2 does not cover (say this honestly)

* The dashboard login and the agent traffic are not encrypted (plain HTTP). Signing protects the commands and answers, but a sniffer can still read the log lines and the operator password. Full TLS or mTLS is the next step.
* The chain is still one Hardhat node on D, and Hardhat's well-known test keys are unlocked on it. The port allowlist limits who can reach it, but a compromised D can still rewrite the chain. A multi-validator chain is future work.
* Source-address rules (`lockdown.sh`) can be spoofed on a LAN by a determined attacker; they narrow the door, they are not the only defence.
* `lockdown.sh` and the end-to-end four-laptop run were not tested on real laptops by the author of this patch; the contract, agent, signing and login logic were tested in a sandbox.
* The one-laptop Docker lab dashboard now also asks for `DASH_PASS`. For that lab only, start it with `DASH_AUTH=off`.
