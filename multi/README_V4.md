# v4: more attacks handled

All new detectors are opt-in (off in multi/config.env.example) and run as their own process, so the SSH parser,
the vault and the chain keep working exactly as before. Every detector feeds the same pipeline: block or flag
locally, report to the chain, K nodes agree, peers act.

| Gap | New piece | Turn on | Test |
|---|---|---|---|
| Slow brute force, password spraying, distributed guessing, stolen-credential logins (login after failures, from Tor, outside an allow-list or working hours) | detector/login_watch.py | LOGIN_WATCH=1 | detector/test_more_attacks.py |
| Man-in-the-middle by ARP spoofing (gateway MAC change, one MAC claiming two IPs, MAC flapping), optional static-ARP repair | detector/arp_watch.py | ARP_WATCH=1 | same |
| Spoofed-source and SYN floods (host side) | multi/harden_host.sh (SYN cookies, reverse-path filter, no source routing; --apply / --undo) | run by hand | prints a dry run |
| Slow or header-preserving ransomware | canary decoy files + burst rule in ransomware/guard.py | "canary": true, "burst_files": N in protect.json | same |
| Fake sensor data in the smart city (forged, replayed, out-of-range, impossible jump, frozen, drifting away from neighbours) | network/sensor_guard.py, reports "sensor:<id>" to the chain; peers log SENSOR_QUARANTINE | run by hand: --demo, --stdin, --udp PORT | same |

Dashboard: an "Other alerts" tile counts login, ARP and sensor alerts.

## Try it
  python3 network/sensor_guard.py --demo --dry                 # a simulated district with four injected attacks
  sudo python3 detector/login_watch.py --dry                   # then guess passwords slowly from another machine
  sudo python3 detector/arp_watch.py --dry
  sudo multi/harden_host.sh                                    # dry run, then --apply
  # ransomware decoys: in ransomware/protect.json add   "canary": true, "burst_files": 20

## Still NOT handled (needs more than software on these laptops)
- A flood that fills the network link, or spoofed sources at scale: needs upstream filtering at the ISP or a scrubbing service.
- Ransomware that runs below the OS (boot-level) or encrypts a whole disk: the off-machine vault on P is the way back.
- Phishing, insider abuse and data theft: policy, training and access control, not packet or file detection.
- SCADA/industrial protocols, GPS spoofing, radio jamming and physical tampering: need protocol-aware or hardware defences.
- DNS spoofing and TLS interception: only ARP-level man-in-the-middle is covered.
- A stolen password used from an allowed address at a normal hour looks exactly like the real user.
