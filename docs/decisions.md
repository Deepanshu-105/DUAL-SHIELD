# Design decisions

## M1: fingerprinting method (Day 1)
Decision: use HASSH (SSH client fingerprinting), not JA3.
Reason: the lab's attack is SSH brute-forcing (Hydra against sshd). HASSH
fingerprints the SSH client handshake; JA3 only applies to TLS clients and
would matter only if an HTTPS target is added later.

## M1 Day 2: HASSH observed in the lab
Hydra (libssh): 015322ee8471fa8338c558a918183b11
OpenSSH client: PASTE_THE_HASH_HERE
