# v13.12 - laptop D: every gap that software can close
## One switch
PRODUCTION=1 in multi/config.env  ->  TLS on, gateway strict (each laptop only its own Fabric identity, no lab co-reporting), certificates made automatically,
and start_D.sh REFUSES to start while python3 multi/check_D.py shows a FAIL (2-step off, secrets not sealed, no audit mirror, ...). With PRODUCTION=1 the peer P must report for itself (a real second laptop).
## Check at any time
python3 multi/check_D.py      -> PASS / WARN / FAIL / INFO per item, with the fix command. INFO = cannot be fixed in software (see the end).
## Ledger backup and restore (fabric/deploy/)
backup_ledger.sh [--stop] [--to user@host:/path]   encrypted (AES-256, passphrase or DS_BACKUP_PASSFILE mode 600), SHA-256 file next to it, optional copy to another machine; put it in cron (daily).
restore_ledger.sh FILE.enc                         network must be stopped; the old folder is moved aside, never deleted; checks the checksum; wrong passphrase / changed file refused.
Tested: backup -> restore -> identical tree; wrong passphrase refused; a changed backup file refused.
## Certificates
multi/make_tls.sh               re-running it ROTATES the dashboard/target/peer certificates (CA kept). check_D.py warns 30 days before expiry. TLS_DAYS=365 default.
multi/make_tls.sh --node NAME   certificate for an added node (CN dualshield-node-NAME). Tested on a real Fabric network with the strict gateway:
                                the Mumbai certificate may use identity 6 only; identity 1 is refused; the target certificate may not use identity 6.
## Node onboarding / offboarding policy (write it into the project report)
1 Request: the owner of the laptop gives NAME and ORG to the administrator of D.   2 On D: python3 network/add_node.py NAME ORG ; multi/make_tls.sh --node NAME ; send multi/tls/node-NAME to that laptop (scp) as multi/tls/node.
3 If the governor threshold is above 1, the governors approve the proposal in the dashboard (Governance).   4 On the node: NODE_ID=<number printed by add_node.py>.
Offboarding: governors revoke the node (Governance, kind revoke); delete its certificate folder; if its laptop was stolen or compromised also re-create the CA (delete multi/tls/ca.key and re-run make_tls.sh; every laptop gets new certificates).
Keep multi/tls/ca.key offline after issuing certificates.
## Still not software (honest)
Orderers and peers on separate machines (a Fabric infrastructure job: ORDERERS=3 on one host exists, real multi-host needs machines), root attacker on D (the external watcher and the audit mirror warn), HSM / secret manager, volumetric DDoS (upstream).
