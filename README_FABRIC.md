# Dual-Shield on Hyperledger Fabric (v9)

The whole project now uses **Hyperledger Fabric** as its ledger. No Hardhat, no Solidity, no web3, no gas, no ETH.
`blockchain/contracts`, `blockchain/test` and the Hardhat config remain in the repository **only as the legacy reference** the chaincode was ported from; nothing starts them.

## What replaced what
| Before (Hardhat) | Now (Fabric) |
|---|---|
| `CityShield.sol` | `fabric/chaincode/cityshield` (Node chaincode, 22 unit tests) |
| `npx hardhat node` + deploy | `fabric/deploy/network.sh up` (orderer, Org1 peer, Org2 peer, channel `cityshield`, no Docker) |
| web3 + JSON-RPC 8545 | `network/chainlib.py` -> Fabric gateway on D (`fabric/gateway/server.js`, port 8600) |
| gas / ETH stake | no gas. Both organisations must endorse each transaction (policy `AND(Org1MSP.peer, Org2MSP.peer)`); stake is a counter in the chaincode |
| accounts 0..3 | Fabric identities: 0 Org1 Admin (owner), 1 target node (Org1 User1), 2 peer node (Org2 User1) |
| contract events | one chaincode event per transaction carrying a JSON list; the gateway keeps an event log, `listener.py` polls it |
| dashboard ethers in browser | dashboard server route `/api/chain` |
| `localhost.json` fetched by T and P | gone: T and P only need `D_IP` and the gateway port |
| TLS tunnel for 8545 | the gateway itself speaks mutual TLS (`TLS=1`); certificate role decides which identity may be used |

## Run on four laptops (D, T, P, A) - same steps as before
```bash
# every laptop, once: apply v4..v9 patches, then multi/config.env (D_IP, secrets; GATEWAY_PORT=8600, GATEWAY_LAB=1)
# D (no sudo for Fabric; apt may need it):
multi/install_D.sh            # Node 22, Fabric 2.5 binaries (fabric/deploy/install_fabric.sh), npm packages
multi/start_D.sh              # Fabric network + chaincode + gateway + approves node identities + dashboard
# T:  sudo multi/install_T.sh && sudo multi/start_T.sh      # registers identity 1 (stake 1) on the chain
# P:  sudo multi/install_P.sh && sudo multi/start_P.sh      # registers identity 2, listens to chain events, blocks
```
Single machine with Docker containers: `./start_lab.sh` (Fabric runs natively, containers call the gateway at host.docker.internal:8600).
Check: `multi/check_net.sh` (prints the Fabric gateway status).

## Tests
```bash
(cd fabric/chaincode/cityshield && npm install && npm test)                 # 22 chaincode tests
fabric/deploy/network.sh up; node fabric/gateway/server.js &                  # then:
GATEWAY_URL=http://127.0.0.1:8600 python3 fabric/test_fabric.py              # real network: K=2, slashing, governance, listener
# strict TLS: multi/make_tls.sh; TLS=1 GATEWAY_LAB=0 node fabric/gateway/server.js; python3 fabric/test_gateway_tls.py
```

## Honest limits
- In the lab all Fabric nodes (orderer, both peers) run on D. That shows the logic (two organisations endorse, K=2 consensus) but **not** distributed trust. A product runs each organisation's peer on its own server and several orderers (Raft with 3+).
- One Raft consenter: if D dies the chain stops (the defenders keep their local blocks).
- `GATEWAY_LAB=1` (default) lets the demo target report as the peer to reach K=2 from one process; the lab holds all keys. `GATEWAY_LAB=0` enforces one identity per certificate, but then a second real reporter on P is needed (not in the demo yet).
- Fabric tools need Linux (WSL2 is fine), Node 18+, about 1.5 GB RAM. Tested in a Linux sandbox; **not yet on your four laptops or WSL**. The Docker single-machine lab (`start_lab.sh`) could not be run in the sandbox (no Docker).
- Slashing/stake are counters, not money; they only matter inside the policy of the consortium.
