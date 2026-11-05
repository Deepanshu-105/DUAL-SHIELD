# v3: network attacks, block expiry, hardened contract, multi-signature

Everything here is OFF or neutral by default. With no changes to multi/config.env the system behaves exactly as before.

## 1. DDoS / port-scan detector (Layer 1)  `detector/flood_detector.py`
Same pipeline as the SSH parser: detect, block locally (ipset), report to the chain, K nodes agree, every peer blocks.
Turn it on for the demo: add `FLOOD=1` to multi/config.env on T, then start T as usual.
Detects: syn-flood, udp-flood, port-scan, and botnet floods (many quiet sources that are loud together; the top
talkers are reported and a hashlimit "under attack mode" rule is printed, applied only with --apply-mitigation).
Try it without risk:  `sudo python3 detector/flood_detector.py --iface eth0 --dry`
Attack it from A:  `sudo hping3 -S --flood -p 22 T_IP`  (or `nmap -p 1-1000 T_IP` for the port-scan rule).
Tests: `python3 detector/test_flood.py`
Limits: a flood that fills the network link cannot be stopped on the target; spoofed sources defeat IP blocking.

## 2. Block expiry  `detector/expire_blocks.py`
`BLOCK_TTL=3600` in multi/config.env (T and P) lifts a block after that many seconds, so a false positive is not
permanent. Known limit: the SSH parser remembers what it blocked until it restarts, so restart it to re-arm.

## 3. Contract hardening (CityShield, all defaults unchanged)
- protected IPs: the city's own addresses can never be reported or blocked
- per-node report limit per hour (0 = off)
- quorum percent: required reports grow with the network (0 = off, K=2 as before)
- overrule: a confirmed block can be cancelled and its reporters slashed; every peer's listener lifts the block

## 4. Multi-signature governance  `network/governance.py`
Starts as one governor (account 0), threshold 1: same as before. Demo of 2-of-3:
  python3 network/governance.py propose add-governor --node 4
  python3 network/governance.py propose add-governor --node 5
  python3 network/governance.py propose threshold --value 2
  python3 network/governance.py propose overrule --ip 203.0.113.50 --as 0   # 1 of 2: nothing happens
  python3 network/governance.py approve 3 --as 4                            # 2 of 2: executes
  python3 network/governance.py status
Once the threshold is above 1, the owner's direct addNode / revokeNode stop working and need M-of-N too.
Set CHAIN_HTTP=http://D_IP:8545 when running it from another laptop. In the lab one machine holds all keys;
in a real deployment every governor signs with their own key.
Limit to state: governors are still a trusted group (a city authority), so this removes the single point of
failure, not the need for trust.
