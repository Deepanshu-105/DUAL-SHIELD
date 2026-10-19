# Literature Notes — Dual-Shield

Status key: ✅ verified (opened and confirmed) | ⚠️ partly verified | ❌ not found

Checked on 2026-10-19 against the five sources cited in the Novelty Review (section 1.3, "Sources I looked at").

| # | Short name | Full citation | Link | Type | Verified | Date checked |
|---|------------|---------------|------|------|----------|--------------|
| 1 | Kent | Pont, J., Arief, B., Hernandez-Castro, J. (2020). *Why Current Statistical Approaches to Ransomware Detection Fail.* In: Information Security (ISC 2020, Bali), Springer. doi:10.1007/978-3-030-62974-8_12 | https://kar.kent.ac.uk/82960/ | Conference paper | ⚠️ exists; one detail unconfirmed (see notes) | 2026-10-19 |
| 2 | Hamburg thesis | Hipke, D. (2025). *Möglichkeiten zur Erkennung von Crypto-Ransomware durch File-Integrity-Monitoring* ("Possibilities for detecting crypto ransomware through file integrity monitoring"). Bachelor thesis, B.Sc. Angewandte Informatik, HAW Hamburg. Submitted 16 July 2025. | https://reposit.haw-hamburg.de/bitstream/20.500.12738/19400/1/BA_M%c3%b6glichkeiten%20zur%20Erkennung%20von%20Crypto-Ransomware%20durch%20File-Integrity-Monitoring_geschw%c3%a4rzt.pdf | Bachelor thesis (German) | ✅ | 2026-10-19 |
| 3 | BLOCIS | Gong, S., Lee, C. (2020). *BLOCIS: Blockchain-Based Cyber Threat Intelligence Sharing Framework for Sybil-Resistance.* Electronics 9(3), article 521. Published 21 March 2020. | https://www.mdpi.com/2079-9292/9/3/521 | Journal article | ✅ | 2026-10-19 |
| 4 | 2023 undergraduate paper | Hasan, M., Alam, M., Akash, A. N. (2023, January). *Blockchain-Based Intrusion Detection Systems (IDS) using Decentralized Threat Intelligence Sharing.* IUB Academic Repository (listed under Undergraduate Thesis). | http://ar.iub.edu.bd/handle/11348/988 | Undergraduate thesis | ✅ | 2026-10-19 |
| 5 | Ransomware patent | US patent 12,361,122, *Systems and methods for ransomware detection.* Claims priority to US provisional 63/203,505, filed 26 July 2021. | https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12361122 | Patent | ⚠️ content confirmed; assignee and grant date not seen | 2026-10-19 |

## Verification checklist (per source)

- [x] 1 Kent: link opens; authors, title, year, venue match
- [ ] 1 Kent: the claim "false positives above 50% on images and compressed data" is stated in the source (the abstract says "often above 50%, even above 90%" but does not name images or compressed data; check the full text)
- [x] 2 Hamburg: link opens; university, degree level, year confirmed
- [x] 2 Hamburg: claim (Windows monitor, chi-square + file-type change, stored baseline) is stated in the thesis
- [x] 3 BLOCIS: link opens; authors, title, year, journal match; Sybil-resistance is the stated focus
- [x] 4 Undergraduate paper: link opens; authors, year match; it is described as a theoretical analysis
- [x] 5 Patent: number and title open on USPTO; chi-square, extension/magic mismatch and header modification all appear in the claims
- [ ] 5 Patent: assignee and grant date (open the patent on patents.google.com and copy them in)

## Notes per source

### 1. Kent (Pont et al., 2020)
- Key idea: simple statistical randomness tests (entropy, chi-square) used by anti-ransomware tools give far too many false positives; the authors tested thresholds taken from earlier papers and suggest skewness and kurtosis instead.
- Relevance to Dual-Shield: directly motivates the baseline gate and magic-byte check, because a lone chi-square threshold will misfire on compressed files.
- Gap it leaves (our novelty): it measures the problem but does not build a full detect, kill, share and roll-back system. We still must report our own measured false-positive rate.
- Fix in Novelty Review: say "often above 50%, and above 90% in several cases" and drop "on images and compressed data" unless the full text confirms it.

### 2. Hamburg thesis (Hipke, 2025)
- Key idea: host-based file integrity monitor for Windows using chi-square and file-type change against a stored baseline, plus hidden decoy files and a scoring model. Tested on 15 ransomware samples; 14 were detected. The author reports weak resistance to tampering by ransomware.
- Relevance to Dual-Shield: the closest prior work for Layer 2. Its chi-square threshold is 350 on the whole file; ours is 310.46 on a 4 KB block, so the parameters differ but the technique is known.
- Gap it leaves (our novelty): the thesis scopes out automatic process stopping, runs on Windows only, and has no network layer or rollback. Our Linux plus kill plus rollback chain is the difference.
- Note: the thesis is written in German; cite the English title given in its abstract.

### 3. BLOCIS (Gong and Lee, 2020)
- Key idea: blockchain framework for sharing cyber threat intelligence where smart contracts validate contributions and the design resists Sybil attacks; evaluated by simulation.
- Relevance to Dual-Shield: base work for the sharing and anti-poisoning part of the contract.
- Gap it leaves (our novelty): it is a sharing framework, not tied to firewall action on a host or to a ransomware layer.

### 4. 2023 undergraduate paper (Hasan, Alam, Akash)
- Key idea: theoretical analysis of a blockchain IDS that uses Isolation Forest for anomaly detection and smart contracts for actions such as node quarantine and malicious-IP blocking.
- Relevance to Dual-Shield: closest prior idea for "smart contract triggers IP block".
- Gap it leaves (our novelty): it is theoretical; we have a working prototype on real Linux ipset with measured latency. Keep the wording soft, as the Novelty Review already says.
- Note: it is an undergraduate thesis in an institutional repository, not a peer-reviewed paper. Label it that way in the report.

### 5. Ransomware patent (US 12,361,122)
- Key idea: ransomware detection by comparing "before" and "after" statistical snapshots of files. Features include chi-square, entropy, extension change, extension/magic mismatch and header modification. A process is flagged when it encrypts enough files within a time window. Remediation includes terminating the process.
- Relevance to Dual-Shield: supports the Novelty Review point that chi-square and header checks are known techniques. It also skips comparison for valid archives to avoid false positives, which matches our baseline-gate idea.
- Gap it leaves (our novelty): endpoint-only; no blockchain sharing, no on-chain anchoring of Tattack, no snapshot rollback in the claims I read.
- Caution: its claims also cover counting flagged files in a time window and terminating the process, which resembles our "3 files in 2 s then kill" rule. Do not describe that rule as new. This is a novelty-wording point, not legal advice.
- To do: copy the assignee and grant date from Google Patents.

## Other sources found (not yet in Novelty Review)

- Davies and Macfarlane (2022), cited in the Novelty Review for chi-square as a known ransomware indicator. A Napier University repository entry on comparing entropy methods for encrypted file identification exists, but the exact title, year and venue of the paper the review means are not yet confirmed. Open it and fill in a full citation. The Hamburg thesis also cites Davies et al. (2022) on chi-square performing best among 53 methods.

## Wording fixes to carry into the Novelty Review

1. Kent: replace "often above 50% on images and compressed data" with "often above 50% and above 90% in several cases".
2. Source 4: call it an "undergraduate thesis", not a paper.
3. Source 5: add the patent's own coverage of process termination and time-window counting before claiming the 3-in-2-seconds kill rule as new.
