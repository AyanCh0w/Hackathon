# Research ideas grounded in the local AIT-ADS logs

Reviewed on October 12, 2026. This is supporting evidence for the chat analysis, not a measured detection system.

## Recommendation

Build a system that groups related alerts into incidents, retrieves supporting records across AMiner and Wazuh, and records which evidence supports each conclusion. Require more evidence to dismiss an incident than to escalate one. Add an explicit **insufficient telemetry** result. Introduce specialist DNS detection after obtaining the underlying DNS logs. This recommendation is a synthesis of the papers below and the local findings; its effectiveness has not been measured here and its novelty is not established.

## What was inspected

All 16 newline-delimited JSON files were streamed, not just sampled. There are 2,655,821 alerts: 2,600,263 in the Wazuh files (including Suricata) and 55,558 AMiner alerts. Events span January 14–February 8, 2022 UTC. The labels contain 79 phase intervals across eight scenarios and ten phase types; Wheeler has no cracking interval. No malformed JSON or missing event timestamps were found; Wazuh event IDs were unique within each file. These checks do not establish complete collection or correctness of attack attribution.

The file names and counts match the [AIT-ADS publisher description](https://zenodo.org/records/8263181). The local labels file's MD5, `60ff33796c77fd2136c4d1a4bc841bd9`, matches the publisher's checksum. The alert files have not been individually checksum-verified against the archive.

### Observed problems and implications

| Finding | Local evidence | Implication |
|---|---|---|
| Repeated alerts overwhelm the distribution | 1,571,313 Wazuh-file alerts, 60.4%, have description `Web server 400 error code.` | Preserve request/path evidence and aggregate repeated activity into summaries. Do not delete HTTP-error alerts wholesale: they expose reconnaissance. |
| Serious phases have very little alert evidence | Across all eight scenarios, labeled webshell intervals contain 12 AMiner and 109 Wazuh-file alerts; reverse-shell intervals contain 10 and 72 respectively. | Rank related sparse evidence alongside preceding scans; alert count alone can hide compromise. Counts describe temporal overlap, not verified attack detections. |
| Sources complement one another | Russellmitchell's reverse-shell interval contains 3 AMiner alerts and 0 Wazuh-file alerts. | Cross-source retrieval is justified. Zero returned records from one detector does not establish benign activity. |
| DNS visibility is insufficient for a complete exfiltration experiment | The eight DNSteal intervals contain only 27 AMiner alerts, 6 of them training-mode; Russellmitchell and Shaw have none. Some DNS query excerpts occur elsewhere, but these are selected alerts. | Obtain original DNS request/response logs and event labels; do not train an all-traffic DNS detector on this alert-only subset. |
| Training mode overlaps phase intervals | 4,739 AMiner alerts, 8.53%, have `TrainingMode=true`; 13 occur inside phase intervals, including all 6 Wardbeck DNSteal-overlapping alerts. | Track training status explicitly. A training-mode alert is neither a clean normal example nor proof of an operational detection. |
| Source schemas require explicit normalization | 306,635 Wazuh-file records lack `full_log` and preserve Suricata data under `data`; sensor identity differs from traffic endpoints. | Preserve nested flow, HTTP and signature fields. Never treat `agent.ip` or AMiner `ID` as the attacker's address. Normalize IP:port fields without destroying the originals. |
| Repeated evidence is distinct from duplicate IDs | 186,933 Wazuh records repeat the same nonempty raw string, event time and sensor; AMiner has 1,855 such repetitions. | Retain detector-specific metadata and audit links while grouping common evidence; these are not necessarily duplicate alert records. Empty `full_log` values were excluded from this calculation. |
| Time-window labels are weak supervision | Background Dovecot logins and ClamAV updates appear in labeled intervals; Russellmitchell's network-scan interval contains 8 Wazuh alerts, all ClamAV updates, and no AMiner alerts. | A temporal match is not event-level maliciousness. Random alert splits and window-based F1 can give misleading results. |

A descriptive grouping by source, minute, sensor, category, source/destination endpoint and resource produces 401,318 groups, 84.9% fewer than the original rows. This measures potential display compression only. It has not tested information retention, incident purity, attack recall, or analyst workload. Generic categories can merge distinct signatures, so production grouping must retain signature IDs, paths, detector identities and member references.

### A concrete attack trace

Russellmitchell, January 24, 2022 UTC:

1. At 03:56:47, AMiner records SSH identification failure during service scanning (line 426).
2. Around 03:57, directory enumeration and WPScan produce thousands of web-error alerts.
3. At 03:59:14, AMiner records a request to a PHP file under WordPress uploads with an encoded command parameter (line 3876).
4. At 04:37:25, three AMiner detectors point to the same request carrying an encoded shell/callback command (lines 3881–3883); Wazuh has no records in the labeled 04:36:56–04:37:39 interval.
5. At 04:37:40, AMiner auth and audit evidence records `su` from `www-data` to a user account (lines 3884 and 3887), followed by Wazuh sudo/root-related records (lines 33188–33193).

These observations support investigating a connected compromise sequence. HTTP success alone does not prove execution, and alert excerpts do not provide a complete causal process tree. Exfiltration/service-stop intervals form a separate branch and precede the web attack in several scenarios; do not force all ten phase types into one fixed chronological chain. Raw encoded payloads are retained only in the local evidence file and are not reproduced here.

## Screening the supplied arXiv page

The [supplied cs.CR recent page](https://arxiv.org/list/cs.CR/recent?skip=0&show=2000) contained 315 entries covering October 6–12 announcements at capture, including new submissions, revisions and cross-lists. All 315 titles were screened. Relevant candidate abstracts were examined, and methods/results/limitations were read for the main recommendations. This is not a claim to have read 315 full papers. The page is a moving recent-announcement list, not a historical or exhaustive search. A snapshot and title inventory are saved beside this note.

### Best matches from that page

**1. [AIDA / From Investigation Failures to Reliable SOC Agents](https://arxiv.org/abs/2610.10608)** — submitted October 7, 2026. Uses an investigation ledger, committed verdict, independent challenge and separate adjudication. Its primary evaluation uses Russellmitchell and its additional evaluation uses Wardbeck from AIT-LDSv2. Reported main F1 is 0.958, with 3.1% false negatives, on 1,247 sampled alerts. This is the closest match. Adopt the evidence and review protocol after aggregation. It starts from existing detector alerts, uses underlying telemetry and event-level labeling, and does not validate discovery of undetected attacks or generalization to independent enterprise data. Source: full-text methods, evaluation and limitations.

**2. [SERA-IDS](https://arxiv.org/abs/2610.03999)** — submitted October 2, revised October 7, 2026. Replaces free-form retrieved experience with structured rules containing feature conditions, provenance and confusion information; freezes the library during testing. Adapt the library idea to reviewed incident examples and actual log fields. Its experiments use numerical NetFlow records from NF-BoT-IoT and NF-ToN-IoT, not this alert schema. Reported gains against other LLM approaches do not establish superiority over strong conventional classifiers. Source: full-text architecture, results and runtime discussion.

**3. [Sigma-Hunter](https://arxiv.org/abs/2610.09007)** — submitted October 6, 2026. Uses LoRA adaptation for local Sigma-rule generation and emphasizes semantic rule quality beyond valid YAML. Apply to drafting rules for PHP execution from upload paths and unusual privilege changes, using only supported Linux/web/audit fields. Generated rules require replay testing and analyst review. Its semantic scores use an LLM judge and are not measured production attack recall. Source: full-text evaluation and conclusion.

**4. [Correct Answers, Unsupported Findings](https://arxiv.org/abs/2610.09581)** — submitted October 7, 2026. Shows why a correct answer can still lack a preserved link from its citation to the supporting record. Adopt explicit evidence bindings: incident claim → record identifier → file/line/hash → original sensor and timestamp. Use deterministic verification for locators. Its experiment is a bounded audit of AgentDojo Banking agent logs, not SOC incident detection. Source: full-text abstract, introduction and corpus description.

**5. [Constrained-Action AI Remediation for SIEM/XDR](https://arxiv.org/abs/2610.09906)** — submitted October 7, 2026. Separates model-selected action intents from validated command templates and evaluates guardrails against adversarial alert content. Relevant if response automation is added, because HTTP/query strings in these logs are untrusted inputs. Begin with read-only recommendations; future execution should validate target identity, arguments and authorization outside the model. Its injection-defense result does not measure whether every selected remediation is correct. Source: full-text architecture and stated execution boundary.

**6. [Organizational Context for the Enterprise Security Brain](https://arxiv.org/abs/2610.12540)** — submitted October 9, 2026; announced October 12. Links source-backed organizational claims to asset identities and checks conflicts with live state. Useful later for distinguishing approved scans, maintenance and legitimate privileged administration from incidents. The local files do not contain authoritative ownership, change approvals or policies, so that layer cannot currently be populated reliably. The experiments concern a production cloud/SaaS context, not AIT attack recognition. Source: full-text abstract and context model.

**7. [NetAgent](https://arxiv.org/abs/2610.07386)** — submitted October 5, 2026. Orchestrates specialist traffic-analysis tools using a planner, execution environment and decision layer. Borrow the separation of reasoning from feature extraction. Full reproduction needs network traffic/features beyond this alert export; use after obtaining packet or flow data. Source: full-text introduction and architecture plus abstract evaluation claims.

**8. [Case-Level Verification in Scanner-LLM Cascades](https://arxiv.org/abs/2610.08406)** — submitted October 6, 2026. Demonstrates that an aggregated alert can mix true and false cases, making group-level suppression discard legitimate detections. Preserve per-request evidence and allow member-level decisions after grouping. Its evaluated setting is DAST on DVWA/WebGoat with request replay, not passive SOC logs. Source: abstract; adaptation is an inference.

### Other candidates screened

- [SwarmReconGuard](https://arxiv.org/abs/2610.09138): useful for future distributed/slow reconnaissance experiments; current labels do not establish such a population attack.
- [ToFu](https://arxiv.org/abs/2610.13651): useful for testing future investigation-tool input semantics; does not directly detect the local attacks.
- [Host Attack Graph for Botnet Propagation](https://arxiv.org/abs/2610.11640): models propagation strategies and topology; lower fit than evidence correlation for these alerts.
- [POLAR](https://arxiv.org/abs/2610.07298): vulnerability/threat-intelligence prioritization; an enrichment layer after evidence extraction, not a direct alert classifier.
- [AI-Augmented SIEM / CRA practitioner case study](https://arxiv.org/abs/2610.07873): operational governance rather than the detection problem under investigation.

Cryptography, watermarking, model extraction, automotive/IoT-specific detection and code repair work have lower immediate fit to this Linux alert export. Title relevance is a screening decision, not an assessment of those papers' scientific quality.

### DNS-specific research outside the supplied recent list

[Improving DNS Exfiltration Detection via Transformer Pretraining](https://arxiv.org/abs/2604.09849), posted April 9, 2026, studies character-level, in-domain BERT pretraining and thresholds frozen on validation before test. Use its low-false-positive evaluation approach and compare against length/entropy/unique-subdomain/rate features plus a simple tree classifier. Requires complete query logs and labeled exfiltration examples. Its 12-layer model and A100 training setup are a substantial experiment, and its results do not establish performance on DNSteal or this dataset. Source: full-text methods and results. This paper was found in the earlier broader search and is not one of the 315 entries.

## Proposed experiment

1. Normalize Wazuh, Suricata and AMiner into event time, sensor, observed host, source/destination endpoints, user, URL/file/process information, rule/signature/detector identity, resource, training flag and immutable evidence references. Preserve originals; mark inferred entities and absent fields.
2. Aggregate repeated evidence without discarding member records, requests or transitions. Compare several windows rather than assuming one minute is optimal.
3. Correlate through shared entities and explicit temporal/contextual links. Keep an observed relation separate from inferred causation. Begin with inspectable rules; do not assume eight scenarios justify a trained GNN.
4. Retrieve facts around an incident and compare malicious and benign explanations. Output `escalate`, `dismiss with supporting evidence`, or `insufficient evidence`. Keep the independent challenge separate from the initial model context. Missing telemetry should remain a visible limitation.
5. Test incremental variants: existing rule/severity baseline; grouping plus correlation; structured retrieval; independent challenge; evidence verification. Include runtime, token cost and unsupported-claim rate.
6. Acquire event/flow-level ground truth using the [authors' labeling workflow](https://github.com/ait-aecid/alert-data-set), which requires AIT-LDSv2/AIT-NDS. Until then, report only phase-window overlap and manually reviewed evidence, not precision/recall claims.
7. Hold out entire scenarios, use time-respecting validation, freeze libraries/thresholds, keep grouped copies together, and avoid absolute timestamps, scenario names or memorized IPs as predictive shortcuts. Use only information available by the decision cutoff. Test delayed or missing logs and changed addresses/paths.
8. Measure per-phase/event and incident recall, false dismissals, false escalations per host-day, time to first supported alert, group purity, evidence correctness and cost. Include sparse webshell/reverse-shell/exfiltration phases; a high score dominated by scans is insufficient.

For a hackathon, the most useful demonstration is the Russellmitchell web attack: reduce the scan flood into a timeline, preserve the AMiner webshell/shell evidence, link the privilege changes, and explain every step with record references. Display the DNS visibility gap as unresolved instead of inventing an exfiltration verdict.

## Reproduce

Run `python3 analysis/investigate_security_logs.py` from the workspace. Inspect `security-log-evidence.json` for counts, windows, schemas and representative record locators. `security-log-investigation.ipynb` contains the rerun entry point. Original data was not changed. No LLM detector was trained or evaluated and no remediation was executed.
