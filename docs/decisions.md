# Design decisions

## M1: fingerprinting method (Day 1)
Decision: use HASSH (SSH client fingerprinting), not JA3.
Reason: the lab's attack is SSH brute-forcing (Hydra against sshd). HASSH
fingerprints the SSH client handshake; JA3 only applies to TLS clients and
would matter only if an HTTPS target is added later.
