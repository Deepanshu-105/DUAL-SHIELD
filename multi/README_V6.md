# Dual-Shield v6 — join by knowing only the dashboard's address

Off by default (`DISCOVERY=0`): nothing changes for the existing four-IP setup.

## Use it
1. On every laptop's `multi/config.env`: set `DISCOVERY=1` and `D_IP` (the dashboard laptop). T_IP and P_IP may stay empty.
   T keeps `AGENT_SECRET_T`, P keeps `AGENT_SECRET_P`, D has both (as before). `A_IP` stays typed in on purpose:
   the lab attacker must never register itself as a trusted node.
2. `sudo multi/start_D.sh` (also starts the registry on :8801), then `sudo multi/start_T.sh` and `sudo multi/start_P.sh`
   in any order. Each registers with D, waits up to 60 s (`DISCOVERY_WAIT`) for the other, and then keeps a 30 s heartbeat.
3. The dashboard follows the registered addresses live and shows "Node Target / Node Peer: online, heartbeat Ns ago".
4. After the nodes have joined, run `sudo multi/lockdown.sh D` again so the firewall rules use the discovered addresses.

## How it is protected
* Every registration and every table request is signed (HMAC-SHA256, time, nonce) with the role's own secret; answers are
  signed back, so an impostor registry is detected by the client.
* The stored address is the TCP source address of the request, not a value the sender claims.
* A role that is still online cannot be taken over from another address (HTTP 409, `REGISTRY_CONFLICT` in the log), so a stolen
  key cannot hijack a live node. After the heartbeat expires (120 s) the role may move (normal DHCP change).
* Replay, stale timestamps, unknown roles and a per-source rate limit are refused. The table file is mode 600 and is shown
  only to authenticated peers.
* Registering does not make a laptop a chain node: trust still comes from the contract (`addNode` / approved nodes).

## Limits
* If D is down, new nodes cannot find each other; nodes that already know each other keep working.
* Detectors on T read the never-block list (D and P addresses) when they start. If P's address changes later, restart
  `start_T.sh`.
* One target and one peer per role for now (the dashboard shows one of each).
* The shared secret per role is symmetric: keep it off the machine being attacked. Per-node certificates (as in Fabric's MSP) would be the product-level next step.
* Traffic is not encrypted (HTTP), only authenticated; use a trusted LAN or add TLS for production.

## Test
`python3 multi/test_registry.py` (20 checks, includes a live server/client round trip and an impostor registry).
