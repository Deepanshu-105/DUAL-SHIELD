# v13.9 - vault protection (step 2)
  sudo python3 ransomware/protect_vault.py lock        # Linux: vault + vault.key owned by root, 700, sticky parent folder
  python  ransomware\protect_vault.py lock             # Windows, Administrator PowerShell: icacls, only SYSTEM + Administrators   (NOT tested on Windows yet)
  python3 ransomware/protect_vault.py status | selfcheck | unlock
Run the guard as that privileged account (root / a service). Ransomware running as the ordinary user can then not read, change, delete or move the vault.
The guard now prints VAULT_PROTECTED or VAULT_EXPOSED at start. selfcheck = git fsck + "does the append-only remote hold the latest snapshot".
Tested on Linux as root against an ordinary account (nobody): ransomware/test_protect_vault.py (9 checks pass); test_guard still passes.
Does NOT help if the malware gets root/Administrator: keep the append-only remote (multi/make_vault_remote.sh) as the second line.
# Step 1 (Windows kernel-level kill) - not done: a file-system minifilter driver needs the Windows Driver Kit, a Windows test machine and a signed driver; it cannot be built or tested here.
