# Trace: Security Replay and Investigation Lab

Trace is a local cybersecurity prototype that turns large collections of security alerts and logs into an inspectable stream of findings. It replays events in chronological order, classifies observed behavior, groups related evidence, and connects those groups into incident candidates that an analyst can investigate.

The goal is to help analysts answer: **What happened, which evidence supports it, what might be related, and what should we check next?** The browser interface shows the replay, evidence graph, review priorities, source records, and decision ledger. Detection uses deterministic rules and bounded behavioral windows; optional AI analysis explains a selected node using its observed evidence.

## The data

The project uses eight AIT security scenarios: `russellmitchell`, `fox`, `harrison`, `santos`, `shaw`, `wardbeck`, `wheeler`, and `wilson`.

| Input | Location | Purpose |
| --- | --- | --- |
| Wazuh and AMiner alert exports | `ait_ads/` | Sixteen JSON files containing **2,655,821 records** across the eight scenarios. |
| Optional native telemetry | `telemetry-inputs/` | Scenario JSONL files add selected DNS, authentication, audit, firewall, and Suricata observations. Manifests record acquisition details. |
| Attack-window labels | `labels.csv` | **79 labeled time windows**, used only for evaluation after replay completes. |
| Saved analyses and evaluations | `tests/` | Reproducible evaluation evidence and saved summaries. |

The labeled behaviors include network and service scans, web directory and WordPress probing, webshell activity, password cracking, reverse shells, privilege escalation, service stops, and DNS exfiltration. Labels describe attack intervals rather than identifying every malicious record.

The original alert exports derive from AIT-LDS v2.0. Optional native inputs are acquired from AIT-LDS v2.1, so augmented evaluations change the available evidence as well as the detection rules. Collection remains incomplete: a missing signal can reflect missing telemetry or unsupported detection.

## The pipeline

```text
Alert exports + optional native logs
                 |
       Normalize and cache in SQLite
                 |
       Replay in chronological order
                 |
       Classify each arriving event
                 |
       Group evidence into episodes
                 |
       Connect related episodes
                 |
       Rank and review findings
                 |
       Freeze completed outcomes
                 |
       Verify against labeled windows
```

1. **Prepare the data.** Normalize timestamps, hosts, source and destination addresses, sensor identity, and available evidence fields. Store normalized events in fingerprinted SQLite caches for repeatable replay. Preparation does not classify command content or consult attack labels.
2. **Replay events.** Read records in timestamp order. Event-paced playback compresses quiet gaps; time-scaled playback advances the original timeline evenly. Pause, step, and resume support close inspection.
3. **Classify observed behavior.** Apply rules for scans, suspicious web requests, command and callback content, credential tools, privilege transitions, service stops, DNS behavior, and sensor anomalies. Bounded windows detect patterns such as connection fan-out, repeated authentication failures, password spraying, and high-entropy DNS sequences. Only the current event and earlier observations influence a decision. Encoded command content is inspected as data and never executed.
4. **Group evidence.** Build episodes by scenario, behavior family, observed source, and host identity. A gap of more than 30 minutes starts a new episode. Count repeated detector outputs separately from distinct evidence. A web episode can escalate when it contains at least 25 distinct requests across 12 paths within three minutes.
5. **Connect episodes.** Link operational findings on the same scenario and host, with the same observed source, within 15 minutes. Privilege and service findings can also receive weaker host-and-time links when source continuity is unproven. Training-only evidence cannot create operational links, and separate scenarios cannot connect through reused addresses.
6. **Prioritize and review.** Assign High priority, Investigate, Context, or Routine/training tiers. Connected components spanning at least two behavior families become incident candidates. Evidence review makes up to three host/time queries within the ingested data, records a supported claim, considers benign explanations, and identifies missing corroboration. Optional AI node analysis provides a separate advisory explanation and does not change classifications.
7. **Verify after completion.** Freeze findings before reading labels. Compare operational, technique-specific signals with each labeled window. Verification cannot alter the replay results.

A graph connection represents an evidence relationship. It does not establish causality, successful execution, compromise, or attacker attribution. Review priority is also separate from classification confidence.

## How it works in pseudocode

The following summarizes the implementation; it omits UI updates and storage details.

```text
function prepare(selected_scenarios):
    for scenario in selected_scenarios:
        inputs = alert_files(scenario) + optional_native_logs(scenario)
        if cached_input_fingerprint_changed(inputs):
            for raw_record in inputs:
                event = normalize_structure(raw_record)
                preserve_source_reference_and_evidence_hash(event)
                store_in_scenario_cache(event)
    return merge_caches_in_timestamp_order(selected_scenarios)

function replay(ordered_events):
    state = empty_online_state()

    for event in ordered_events:
        wait_for_replay_scheduler_or_manual_step()

        decision = classify_with_deterministic_rules(event)
        behavior = update_bounded_behavior_windows(state, event)
        decision = apply_behavior_result_when_eligible(decision, behavior)
        mark_training_evidence_and_adjust_confidence(decision, event)

        key = (event.scenario, decision.family, event.source_ip,
               resolved_or_scoped_host_identity(event))
        episode = find_episode(key)
        if episode_is_missing_or_inactive_for_more_than_30_minutes:
            episode = create_episode(key)

        add_event_and_update_distinct_evidence_counts(episode, event)
        check_distinct_operational_web_burst(episode)

        if event_is_eligible_for_operational_linking:
            for eligible_recent_episode_on_same_scenario_and_host:
                if within_15_minutes_and_source_matches:
                    connect_with_medium_confidence()
                else if within_15_minutes_and_current_family_is_privilege_or_service:
                    connect_with_low_confidence()

        update_review_priorities(state)
        record_decision_and_source_references(state, event, decision)
        publish_live_snapshot(state)

    return freeze(state)

function review_episode(episode, ingested_prefix):
    evidence = representative_episode_records(episode)
    evidence += retrieve_context(ingested_prefix, max_queries=3)
    return evidence_ledger_with_claim_challenge_gaps_and_qualified_verdict(evidence)

function verify(completed_results):
    require_replay_complete()
    labels = read("labels.csv")
    return compare_technique_specific_operational_signals_to_windows(
        completed_results, labels
    )
```

## Results and benefits

The saved paired evaluations use the same technique-specific verifier for the baseline and current rules. Coverage means the fraction of the 79 labeled windows containing an operational signal for the expected technique.

| Evaluation inputs | Records processed | Baseline coverage | Current coverage | Gain |
| --- | ---: | ---: | ---: | ---: |
| Alerts only | 2,655,821 | 54/79 (68.4%) | 62/79 (78.5%) | 8 windows; 10.1 percentage points |
| Alerts + selected native telemetry | 10,596,150 | 55/79 (69.6%) | 72/79 (91.1%) | 17 windows; 21.5 percentage points |

Source: [alert-only evaluation](tests/alert-only-improvement-results.json) and [augmented evaluation](tests/improvement-results.json). These are recorded regression results, rather than a new evaluation performed when writing this README.

On unchanged alert inputs, password-cracking coverage improves from **0/7 to 7/7** windows, and network-scan coverage improves from **0/8 to 1/8**. With native telemetry, current network-scan coverage reaches **8/8**, while DNS-exfiltration coverage reaches **2/8**. DNS remains a substantial visibility and detection gap.

The [saved full alert replay](tests/all-dataset-run-results.json) processed all 2,655,821 records, formed 52,707 episodes and 51 evidence relationships, and produced 41 incident candidates. Its checks recorded record conservation, priority accounting, and no label reads during inference. Candidate counts describe the tool's output; they are not counts of confirmed attacks.

The practical benefits are:

- **More manageable investigation:** episodes and priorities organize millions of records into findings an analyst can inspect.
- **Traceable decisions:** rule explanations, source file and line references, evidence hashes, and a decision ledger make conclusions reviewable.
- **Better context:** native telemetry and temporal relationships expose patterns that isolated alert exports can miss.
- **Honest uncertainty:** training evidence, weak links, unsupported behavior, and missing telemetry remain visible.
- **Repeatable experiments:** chronological replay, cached inputs, frozen outcomes, and isolated evaluation support comparisons between rule versions.

These results do **not** establish record-level accuracy, precision, recall, F1, false-positive rate, or attack success. All eight scenarios were previously inspected, there is no untouched test split, and behavioral thresholds remain experimental. The two input modes should not be treated as a rules-only comparison because their evidence differs.

## Research foundations: what was included

The design combines ideas from security research with the concrete limitations found in the AIT exports. These are adaptations, rather than reproductions of the papers' architectures or performance.

| Research | Relevant idea | Included in Trace | Boundary / future work |
| --- | --- | --- | --- |
| [AIDA: From Investigation Failures to Reliable SOC Agents](https://arxiv.org/abs/2610.10608) | Preserve investigation history, challenge a proposed decision independently, and require stronger evidence before dismissing an alert. | A deterministic evidence ledger records retrieval outcomes, a supported thesis, benign challenges, missing corroboration, and a qualified verdict. Empty retrieval does not justify a benign dismissal. | Trace does not implement AIDA's independent investigator, challenger, and judge agents. Its deterministic challenge is not independent model reasoning. |
| [SERA-IDS](https://arxiv.org/abs/2610.03999) | Represent decision knowledge as structured conditions with confidence and provenance; freeze the experience library during testing. | Versioned rules expose conditions, benign counterexamples, provenance, and experimental status in `detection.py`. Saved evaluations compare fixed classifier versions. | No learned experience library, retrieval-augmented small-language-model classifier, or NetFlow training experiment is implemented. |
| [Correct Answers, Unsupported Findings](https://arxiv.org/abs/2610.09581) | A plausible finding needs an explicit binding to the preserved record that supports it. | Record IDs, file/line references, and evidence hashes bind findings to observations. AI response validation rejects citation IDs outside the supplied evidence. | A valid locator establishes which record was cited; it does not establish that every interpretation of that record is correct. |
| [Case-Level Verification in Scanner-LLM Cascades](https://arxiv.org/abs/2610.08406) | An aggregated alert can contain mixed cases; suppressing the entire group can hide a true detection. | Grouping preserves member references and separates repeated detector outputs from distinct evidence. Analysts can inspect individual records. | No DAST request-replay verifier or automated member-level benign suppression is implemented. |
| [Constrained-Action AI Remediation for SIEM/XDR](https://arxiv.org/abs/2610.09906) | Separate model recommendations from validated execution. | The current review boundary is read-only; command content is inspected as data, and AI advice cannot change classifications or act on hosts. | The paper's guardrails proxy, validated remediation templates, and response executor are not implemented. |
| [Improving DNS Exfiltration Detection via Transformer Pretraining](https://arxiv.org/abs/2604.09849) | Evaluate DNS classifiers at low false-positive operating points, with thresholds selected on validation and frozen for testing. | Current DNS rules inspect lexical properties and bounded query sequences. The paper informs the proposed calibration and learned-detector experiment. | No pretrained DNS Transformer exists in Trace. Independent benign data, event labels, and fixed operating-point validation remain necessary. |

Additional research was considered for extensions: [Sigma-Hunter](https://arxiv.org/abs/2610.09007) for model-assisted Sigma rule generation, [NetAgent](https://arxiv.org/abs/2610.07386) for specialist network-analysis orchestration, and [Organizational Context for the Enterprise Security Brain](https://arxiv.org/abs/2610.12540) for authoritative asset, ownership, and maintenance context. These capabilities are not currently implemented.

AIDA reports an F1 of 0.958 on its evaluated alerts. Trace's 91.1% augmented attack-window coverage measures a different task with different labels and cannot be compared with that F1. Research results belong to their respective experimental settings, not to this implementation. [AIDA paper](https://arxiv.org/abs/2610.10608)

## What is different from a basic version, and why it helps

Here, a **basic version** means an alert viewer that classifies each record independently, sorts by sensor severity or volume, and provides little structured investigation support. This is a reference design for explaining the project, not a claim that all SIEM products work this way. The actual measured comparator is the frozen earlier classifier in [baseline.py](baseline.py), which already recognizes several web, callback, privilege, service, and scan signals.

| Basic reference design | Trace's addition | Practical reason |
| --- | --- | --- |
| Independent per-record checks | Bounded behavioral windows for scans, authentication attacks, and DNS sequences | Detect patterns spread across individually weak observations. |
| Repeated alerts dominate the queue | Distinct-evidence counting, episodes, and evidence-based priority tiers | Keep sparse command/callback evidence visible alongside large scanning bursts. |
| Separate detector queues | Shared normalization and scenario-scoped host/source/time relationships | Investigate complementary Wazuh, AMiner, and native-log evidence together. |
| Alert severity becomes incident importance | Separate review urgency from confidence; generic severity alone does not promote an anomaly to Investigate | Make priority explainable using the observed behavior and corroboration. |
| Narrative summary with loosely attached citations | File/line/hash references, bounded retrieval, and validated citation IDs | Make supporting observations inspectable and expose unsupported conclusions. |
| Empty search treated as reassuring | Explicit missing-evidence and insufficient-telemetry outcomes | Avoid treating collection gaps as proof of benign behavior. |
| Offline evaluation can accidentally use future evidence or labels | Prefix-only decisions, training separation, and post-completion label access | Preserve the information boundary of an online detector. |
| A single final report | Pause/step replay, live graph, decision ledger, and optional node explanation | Support teaching, debugging, and analyst review of how findings develop. |

The project contribution is the integration of these mechanisms into a small, inspectable replay system: **observe → classify → group → connect → challenge → verify**. Grouping, correlation, provenance, and AI assistance are established ideas; this repository does not establish a new scientific algorithm.

The evidence for improvement is specific: on unchanged alerts, the current evaluated rules cover **62 rather than 54 of 79 windows**. With augmented inputs, the paired comparison covers **72 rather than 55 windows**. These evaluations support improved technique-window coverage over the earlier local classifier. They do not isolate the benefit of each feature, prove reduced analyst workload or false positives, or establish superiority over commercial systems. Ablations and independent validation are needed for those claims.

The saved paired evaluations identify rule version `2026-10-12.4`; the current rule catalog identifies `2026-10-12.5`. Consequently, the reported numbers describe the saved version and should be regenerated before attributing them to the latest checkout.

## Limiting false positives through tracked evidence and sequences

Trace aims to limit unsupported escalation by grounding findings in **tracked records, observed event sequences, and explicit evidence requirements**. A suspicious string or high-severity alert is a starting observation. Stronger conclusions require evidence appropriate to that conclusion.

### Track what supports each finding

Each finding preserves record identifiers, timestamps, source file and line references, and evidence hashes. The decision ledger records the rule that fired and why. An analyst can trace a summary back to supporting observations rather than accepting an unexplained score or AI narrative. Citation validation checks that AI references belong to the supplied evidence; it does not prove that the interpretation is correct.

Repeated detector reports are counted separately from distinct evidence. Copies of the same observation cannot satisfy distinct-event thresholds or increase urgency merely through repetition. Training-mode observations remain separate and cannot supply operational evidence for behavioral thresholds, burst promotion, or relationships.

### Require patterns before promoting weak signals

An isolated incomplete SSH identification exchange can result from a disconnected client or health check. It remains Context unless a supported scan signature is present or at least **10 distinct operational exchanges from the same observed source and resolved host occur within five minutes**. A web episode needs **25 distinct requests across at least 12 paths within three minutes** for burst promotion. These requirements reduce the chance that one ordinary error becomes an escalated finding.

Behavioral detectors use bounded event-time windows and entity-scoped observations. Relationships require the same scenario and resolved host, usually the same observed source, and activity within 15 minutes. Privilege and service links without source continuity are explicitly weaker. This constrains unrelated events from being combined into a convincing-looking attack story. Decisions use only the ingested prefix, so later evidence cannot silently justify an earlier classification.

Sequence and repetition still do not establish malicious intent. An approved scanner can meet scan thresholds, and legitimate telemetry can resemble unusual DNS activity. Rules retain benign counterexamples, and review identifies the authoritative context needed to resolve them.

### Match the conclusion to what the evidence proves

| Observed evidence | Supported conclusion | Evidence needed for a stronger outcome claim |
| --- | --- | --- |
| PHP request contains a recognized command | A command-bearing request was observed and merits review. | Linked process execution and endpoint ownership to establish execution on the target. |
| Request contains a callback construct | A callback construct appears in observed command content. | Process-to-socket linkage and connection confirmation to establish a successful callback. |
| Successful identity transition appears in auth/audit records | The recorded transition occurred. | Initiating process, authorized user context, and change approval to establish malicious privilege escalation. |
| Explicit service-stop record | A service stop was recorded. | Initiating identity/process and maintenance context to distinguish disruption from an approved restart. |
| Long or high-entropy DNS sequence | An unusual DNS pattern was observed. | Fuller request/response traffic and domain purpose to substantiate exfiltration. |

The review ledger states the evidence-backed claim, challenges it with possible benign explanations, and lists missing corroboration. Its qualified verdict can recommend investigation without declaring a confirmed attack. Missing records cannot justify a benign dismissal, and proximity on the graph cannot substitute for execution evidence. The current review does not automatically prove compromise or resolve authorized-maintenance context.

This design targets **false-positive escalation and unsupported attack claims**, while keeping uncertain signals available for investigation. It does not eliminate false positives. Thresholds remain experimental, and no reduction in false-positive rate has been measured. Demonstrating that reduction would require independent benign traffic, fixed thresholds, analyst-adjudicated outcomes, and measurements such as false escalations per host-day alongside missed attacks.

## How this relates to CrowdStrike

Comparison based on public CrowdStrike documentation checked October 12, 2026. The closest counterparts are **Falcon Next-Gen SIEM** for ingestion, queries, correlation, and investigation; **Threat Graph** for telemetry relationships; and **Charlotte AI** for AI-assisted triage. The similarities below are architectural comparisons, not evidence that Trace uses CrowdStrike internals or integrates with Falcon.

| Area | Trace | Documented CrowdStrike capability |
| --- | --- | --- |
| Data and detection | Local historical alert exports and selected native logs; transparent rules and experimental windows. | Falcon investigation APIs expose detections, incidents, and raw-telemetry searches, including custom correlation rules. [Developer documentation](https://developer.crowdstrike.com/accomplish/investigate-threats/) |
| Relationship graph | Episode links use explicit scenario, host, observed source, and time conditions, with weaker links marked. | Threat Graph ingests and enriches endpoint telemetry. Trace's temporal episode graph has substantially less telemetry context. [Threat Graph overview](https://www.crowdstrike.com/resources/wp-content/brochures/datasheets/threat-graph.pdf) |
| Investigation interface | Live evidence map, record inspector, deterministic review ledger, and incident candidates. | Next-Gen SIEM case management presents attack activity, asset relationships, and threat context in a visual investigation graph. [Incident management](https://www.crowdstrike.com/en-us/platform/next-gen-siem/incident-management/) |
| AI | Optional OpenAI explanation of a frozen, redacted node snapshot; core classifications stay deterministic. | Charlotte AI offers detection triage and agent workflows with configurable automatic actions and human review. [Charlotte AI](https://www.crowdstrike.com/en-us/platform/charlotte-ai//) |
| Response | Read-only investigation and recommendations. | Fusion SOAR and Charlotte Agentic SOAR connect investigation to automated workflows and response. [Incident management](https://www.crowdstrike.com/en-us/platform/next-gen-siem/incident-management/) |
| Evaluation | Public local regression artifacts and explicit attack-window coverage limits. | CrowdStrike describes Charlotte AI triage accuracy as agreement with Falcon Complete MDR expert decisions. This is a different metric and population. [Metric definition](https://www.crowdstrike.com/en-us/platform/charlotte-ai//) |

Trace follows the same broad direction of turning scattered observations into contextual investigations. Its useful distinction for a hackathon or research setting is that the implemented rules, link conditions, source evidence, and evaluation process can be inspected and changed locally. It can run its core demonstration without a commercial account, endpoint deployment, or hosted model inference.

CrowdStrike's documented scope includes telemetry-backed investigation and operational response capabilities that this prototype does not provide. A local graph and an AI explanation are therefore insufficient grounds to claim parity with Falcon. There has been no head-to-head test: Trace's coverage figures cannot show that it detects more attacks, responds faster, or produces fewer false positives than CrowdStrike.

A possible future use is as an experimental replay and evidence-review companion: prototype rules on historical logs, validate their evidence requirements, then translate suitable conditions into production correlation rules. That is a proposed workflow; this repository currently contains no CrowdStrike connector, CQL rule exporter, or Falcon response integration.

## Real-world applications

Trace can serve as a prototype for several security workflows:

- **Security operations triage:** group related SIEM alerts, highlight evidence worth reviewing, and guide analysts toward corroborating logs.
- **Incident reconstruction:** inspect a chronological sequence of suspicious requests, identity transitions, and service activity while preserving uncertainty about their relationships.
- **Detection engineering:** replay historical data to evaluate rule changes and identify telemetry gaps before deployment.
- **Analyst training:** pause and step through scenarios to practice separating observed behavior from assumptions about intent or success.
- **Collection planning:** use uncovered attack windows to identify where DNS, process, authentication, or network visibility needs improvement.

The current implementation is a local replay lab. Production use would require live ingestion, independent validation and threshold calibration, reliable host identity, access controls, durable storage, and integration with incident-response workflows.

## Run the project

Requires Python 3.10+ and a modern browser. The core application needs no additional Python packages or API key.

Download or clone this project, then open a terminal in its root folder (the folder containing this README). Datasets, native telemetry, local credentials, and generated caches are excluded from Git; code, tests, documentation, and saved evaluation summaries are included.

### Download the data separately

Download `ait_ads.zip` and `labels.csv` from the [AIT-ADS publisher on Zenodo](https://zenodo.org/records/8263181). The archive is approximately 96 MB compressed and expands to about 2.7 GB. These commands download both files from the publisher:

```sh
curl -fL --retry 3 -o ait_ads.zip https://zenodo.org/records/8263181/files/ait_ads.zip
curl -fL --retry 3 -o labels.csv https://zenodo.org/records/8263181/files/labels.csv
```

Extract the sixteen alert files into `ait_ads/`. This command handles either flat or nested archive paths and checks the publisher's archive checksum before extraction:

```sh
python3 - <<'PY'
import hashlib
import shutil
import zipfile
from pathlib import Path

archive = Path('ait_ads.zip')
assert hashlib.md5(archive.read_bytes()).hexdigest() == '43db6b1f0996e0024befd617706c50e9', 'Archive checksum mismatch'
assert hashlib.md5(Path('labels.csv').read_bytes()).hexdigest() == '60ff33796c77fd2136c4d1a4bc841bd9', 'Labels checksum mismatch'
scenarios = 'russellmitchell fox harrison santos shaw wardbeck wheeler wilson'.split()
destination = Path('ait_ads')
destination.mkdir(exist_ok=True)
with zipfile.ZipFile(archive) as bundle:
    for scenario in scenarios:
        for sensor in ('aminer', 'wazuh'):
            name = f'{scenario}_{sensor}.json'
            matches = [item for item in bundle.infolist() if Path(item.filename).name == name]
            assert len(matches) == 1, f'Expected one archive member for {name}'
            with bundle.open(matches[0]) as source, (destination / name).open('wb') as target:
                shutil.copyfileobj(source, target)
print('Ready: sixteen alert files in ait_ads/ and labels.csv at project root.')
PY
```

You may delete `ait_ads.zip` after extraction. Keep `labels.csv` at the project root for **Verify at end**; replay itself uses the alert files. Expected layout:

```text
README.md
labels.csv
ait_ads/
  russellmitchell_aminer.json
  russellmitchell_wazuh.json
  ... remaining fourteen scenario files
server.py
```

### Start the application

```sh
python3 server.py
```

Open <http://127.0.0.1:8787>, select datasets, and start replay. After completion, choose **Verify at end** to inspect labeled-window coverage.

The first preparation builds local SQLite caches under `.cache/`. Start with the default Russellmitchell scenario to keep initial preparation small. All eight scenarios and optional native telemetry can consume tens of GB in inputs and caches. Stop the server before deleting caches; they are rebuilt on the next preparation.

### Optional native telemetry

In **Replay settings**, enable **Ignore raw telemetry** to prepare and replay only Wazuh and AMiner alerts. The selection is saved in this browser and cannot change during an active replay. Alerts-only preparation uses a separate cache, updates record totals and time bounds, and excludes native records from investigation retrieval. Disable the toggle to include native telemetry again.

The alert files are sufficient to run the application. To reproduce the augmented evaluations, download the selected native logs separately using the included acquisition script:

```sh
python3 fetch_ait_telemetry.py --scenarios russellmitchell fox harrison santos shaw wardbeck wheeler wilson
```

This creates raw logs, normalized JSONL files, and manifests in the ignored `telemetry-inputs/` directory. Restart the server afterward. The current full selection uses about 11 GB before replay caches. See the [native telemetry details](#native-telemetry-and-reproducibility) for provenance and limitations.

### Checks and evaluations

Run the implementation tests:

```sh
python3 -m unittest discover -s tests -v
```

Reproduce the paired evaluations:

```sh
python3 tests/evaluate_improvements.py --alert-only
python3 tests/evaluate_improvements.py
```

The second command includes native inputs when available. See the sections below for telemetry acquisition, optional OpenAI setup, replay controls, and implementation limits. AI node analysis sends a redacted evidence snapshot to OpenAI when requested and requires an API key; the core replay operates locally.

## Project layout

```text
README.md                   Project overview and setup
.gitignore                  Excludes downloaded data, caches, and secrets
server.py                   Local server and replay scheduling
telemetry.py                Input normalization
detection.py                Behavioral detectors
engine.py                   Classification, groups, and relationships
investigation.py            Evidence review
verification.py             Completed-run label verification
ai_analysis.py              Optional AI explanation
fetch_ait_telemetry.py       Optional native data downloader
static/                     Browser interface and vendored assets
tests/                      Tests and saved evaluation summaries
ait_ads/                    Separately downloaded alert exports (ignored)
labels.csv                  Separately downloaded labels (ignored)
telemetry-inputs/           Optional downloaded native telemetry (ignored)
.cache/                     Generated SQLite caches (ignored)
```

## Replay controls

1. Open **Datasets**, choose scenarios, then click **Start replay**. Preparation builds chronological caches; later runs reuse them.
2. Use **Pause**, **Step +1**, and **Resume** to inspect events. **Inspect dataset** filters the displayed findings while all selected scenarios continue processing.
3. Select a log, graph node, group card, or ledger reference for evidence. **Reset** cancels the replay and clears the view.
4. Once complete, click **Verify at end** to compare findings with attack-window labels. Coverage measures labeled windows with a technique-specific signal, not record-level accuracy.

## Optional AI node analysis

Copy `.env.example` to `.env` and set `OPENAI_API_KEY`, or export it in the shell that starts the server. Exported variables take precedence. Restart the server after changing settings. `OPENAI_MODEL` is optional (default `gpt-6-astra`) and must support the Responses API with structured outputs. No additional Python packages are needed. `.env` is ignored by Git and cannot be served by the static-file endpoint.

Click a graph node or evidence group, then **Analyze node with AI**. The result explains the evidence, confidence and possible benign explanations, gives prioritized next checks and escalation criteria, and links citations to source records. Missing-key, provider, quota and timeout errors appear in the inspector with a retry button.

The server freezes the node's details, full episode statistics, direct connections, up to 20 connected-node summaries, up to 100 retained decision entries, representative evidence, up to 120 evenly spaced member traces plus representatives, and the existing bounded investigation results. Large trace samples may be reduced to bound request size; the response displays included and total counts. It uses only the ingested prefix and never labels or future records. Credentials and embedded commands remain redacted. Clicking the button sends this data to OpenAI; API usage is billed to your project. Requests use `store: false`. The API key stays on the server. Reports are advisory and do not alter classifications, verification or hosts. Repeated requests for the same replay prefix reuse a bounded in-memory cache; new observations produce a fresh analysis. Only one analysis runs per replay at a time.

## Label isolation

`telemetry.py`, `engine.py`, and preparation/replay in `server.py` never read `labels.csv`. No scenario-specific attack times or labels enter the rules or scheduler. The only label reader is `verification.py`, imported lazily by `/api/verify` after the entire selected run is complete; earlier calls return HTTP 409. Verification receives a frozen copy of the completed outcomes and does not alter classifications, groups, edges, or candidates. The static server cannot serve labels or source telemetry files.

Preparation extracts structural fields and stores an opaque command parameter where present. Encoded parameter inspection occurs only when that record reaches the online classifier. It is parsed as bounded data, never executed. No future record participates in a current inference. The scheduler knows the total count and time bounds solely to pace playback.

## Analysis shown live

- **Read record:** decode a structurally normalized cached record; ingestion preparation has its own progress indicator. Pipeline time is cumulative measured processing time, not wall-clock delay.
- **Classify:** deterministic rules for reconnaissance, unsuccessful/scanner-like HTTP activity, command-bearing PHP requests, callback-bearing requests, privilege transitions, explicit service stops, credential tools, DNS names across all query types, sensor anomalies, and routine observations. Bounded windows detect distinct connection fan-out, repeated authentication failures, password spraying, and high-entropy DNS sequences. Thresholds are experimental and do not imply a measured false-positive rate. Classification remains deterministic; optional AI analysis is a separate, read-only node review.
- **Group:** same dataset, rule family, observed source, and host; a 30-minute inactive gap starts a new episode. Repeated detector outputs count as records, while identical raw evidence at the same timestamp/host counts once within an episode. A web episode with 25 distinct requests to 12 paths within three minutes is promoted to a burst-probing candidate.
- **Connect:** same dataset, observed source, and host within 15 minutes. Privilege and service changes can also connect by host and time alone, with low-confidence dashed edges. Unresolved hosts cannot create edges. Entities in independent datasets never connect just because they reuse an IP or hostname. Sensor IP is never treated as an actor. Host names inferred from a log path remain marked as inferred.
- **Review:** connected components containing at least two rule families become incident candidates. Each group also supports an evidence review with at most three dataset-scoped host/time queries, limited to the ingested prefix. The ledger records each query outcome, an evidence-backed thesis, a benign challenge, and a qualified verdict. Missing corroboration cannot dismiss a signal as benign. Every member remains addressable through paginated references, with redacted source lines and SHA-256 evidence identifiers. Neither a graph edge nor an HTTP command parameter proves causality, execution, compromise, or attribution.

Training-mode records remain marked. They cannot create operational connections or supply the operational count for burst escalation. The map shows Investigate groups active within the latest 15 replay minutes in their dataset, plus every High group and all nodes reached recursively through its incoming relationships. Investigation nodes linked to each other remain visible regardless of age. Unrelated endpoints and stale isolated investigations are excluded; High traces have no node cap. Dataset filters and explicit cluster collapse still apply. Group cards show up to eight representatives per priority tier; priority totals count every episode. The live log buffer holds 220 records. The ledger retains 240 recent decisions plus 240 signal decisions, supplemented by 80 recent and 120 signal decisions per dataset so earlier datasets remain inspectable. Use the ledger's **Signals** toggle to inspect signal decisions after later anomalies arrive. Total counters cover the full replay. Every ledger group, including those outside the visible shortlist, can be inspected through `/api/group`.

### Importance and the evidence map

Node and decision inspectors show an analyst summary of what happened, the dataset and observed host, full first/last UTC timestamps, source and destination IP counts, collection sensors, and log locations. These counts cover all received episode members, rather than only the supporting-record samples; lists show the top 12 values and report when more exist. Frequency separates distinct evidence, repeated detector records, training records, and operational distinct evidence. Average rates use elapsed event time from first to last observation and are unavailable for a single timestamp. Suggested next checks point to corroborating telemetry for each signal family. Decision inspection preserves the original decision reason, event time, and a link to the triggering record alongside the episode snapshot.

Growing groups are categorized and sorted by review urgency, recalculated only from evidence already received:

- **High priority:** command-bearing or callback-bearing requests, or a high-confidence web-account identity transition. These merit prompt review; they do not prove execution or compromise.
- **Investigate:** supported scan, credential-attack, web or DNS signals corroborated by a different supported behavior family on the same observed actor and host within the existing 15-minute window. Standalone signatures and bursts remain Context. Service stops and ordinary privilege changes require a supported attack signal: the same observed actor and host, or command / callback evidence on the host within the existing 15-minute relationship window. Two administrative changes do not corroborate each other.
- **Context:** generic sensor anomalies (including high-severity alerts), isolated SSH identification failures, or unsuccessful requests with insufficient evidence to escalate.
- **Routine / training:** routine background activity or training-only episodes.

Links to other rule families increase a group's rank within its tier. Detector repeat volume does not affect urgency. Classification confidence is shown separately. Cards explain their priority, and promotion decisions appear in the live ledger. High priority and Investigate summary counts cover consolidated review items in the selected dataset view. Cards report underlying episode totals and inspectors link every actionable episode in the item. Consolidation uses observed actor/host/time relationships; weaker host-only relationships consolidate only when command or callback evidence is present. Context and Routine counts still cover episodes, while the map preserves all significant findings and connected groups, and group cards remain representative shortlists.

The default horizontal map organizes evidence clusters into connection levels with readable priority cards, counts, and latest UTC activity. Drag the background to pan, scroll or use **+ / −** to zoom, and use **Fit** to see the displayed nodes. Drag cards to arrange them; connection endpoints follow, and custom positions survive live updates and view switches. Select a card to inspect; hover or focus highlights direct neighbors. Each connected cluster has a **Collapse / Expand related** control, with **Collapse all** and **Expand all** in the toolbar. Collapsing hides related cards and their lines without changing evidence. Focus a card and use arrow keys to move it. Levels indicate graph distance from each cluster’s highest-ranked starting node, not chronology or causality. **Show original map** reveals the preserved circular map, and **Show horizontal map** returns to the default view. The view preference is remembered across refreshes. Both views share dataset filters and show all high-priority and investigation nodes, plus at most one directly connected supporting node per investigation, ranked by priority score and latest activity. Supporting nodes do not expand recursively. Full connection lists remain available in the inspector.

The circular map uses [D3's force simulation](https://d3js.org/d3-force) with repulsion, collisions, and springs along actual evidence links. Drag a circle to move its neighbors; lines follow the circle endpoints. Drag the background to pan, scroll to zoom, and use **Fit** to restore the full view. **Freeze** pauses layout motion while ingestion continues. Hover or keyboard-focus a circle to highlight direct neighbors; click or press Enter to inspect evidence. Arrow keys move a focused circle. Node size reflects a capped count of distinct evidence, and color reflects priority. Dashed links remain weak host-and-time matches. Circle positions survive streaming updates and dataset filters. Reduced-motion preference uses an immediately settled layout with dragging still available.

D3 7.9.0 is vendored under `static/vendor/` with its ISC license and loaded locally; telemetry stays local unless you explicitly click **Analyze node with AI**, which sends the redacted evidence snapshot to OpenAI. The physics is a visual layout, not another detection rule, and it creates no evidence relationships.

The alert exports alone do not contain full packet, DNS, process, or file telemetry. Selected native logs improve visibility while leaving collection incomplete. Many attack windows contain background records or no related sensor evidence. Labels describe intervals, not malicious membership of individual records; the verification table deliberately does not present precision, recall, or F1.

## Research connection

The inspectable evidence groups and uncertainty-marked relationships provide a foundation for a bounded, evidence-grounded analyst, as discussed in [AIDA](https://arxiv.org/abs/2610.10608). The implementation adds a deterministic evidence protocol and bounded native-telemetry retrieval. It adapts [SERA](https://arxiv.org/abs/2610.03999) by recording rule conditions, counterexamples, provenance, and a frozen version. Optional OpenAI node review is available; a trained DNS classifier remains a future extension; research accuracy is not claimed for these adaptations.


## Native telemetry and reproducibility

`telemetry-inputs/<scenario>.jsonl` is optional and joins that dataset's chronological stream. Restart the server after adding or replacing inputs so preparation checks the new fingerprint. Each line needs an explicit epoch or ISO timestamp and can include a host, `src_ip`, `dest_ip`, transport ports, `proto`, EVE `dns`/`flow`/`alert`, or a Linux audit/authentication `raw` record. For example:

```json
{"timestamp":"2022-01-24T04:00:00Z","host":"intranet-server","event_type":"flow","src_ip":"192.0.2.5","dest_ip":"192.0.2.8","dest_port":443,"proto":"TCP","flow_id":"example-1"}
```

The public source acquisition uses [AIT-LDS v2.1](https://zenodo.org/records/19483937). It downloads only selected ZIP ranges, verifies each selected member's CRC, and preserves raw files and a manifest. Selection includes DNS, authentication, audit, firewall syslog/kernel records, and firewall/intranet Suricata flows, DNS and alerts. It excludes attacker logs and labels and never filters by attack times. Repeated acquisition reuses files only when size and CRC match. No packet capture is imported.

```sh
python3 fetch_ait_telemetry.py --scenarios russellmitchell fox harrison santos shaw wardbeck wheeler wilson
python3 tests/evaluate_improvements.py
```

The latest raw source is v2.1, whereas the original AIT-ADS exports derive from v2.0: augmented results therefore measure a change of available evidence as well as rules. Syslog without a year is explicitly interpreted as 2022 UTC, and manifests record that assumption. File-derived host identity is marked. The publisher reports Shaw's DNS exfiltration is absent from its DNS logs; an empty result there cannot establish benign behavior.

`tests/alert-only-improvement-results.json` records the paired rule comparison on unchanged alert inputs. `tests/improvement-results.json` records the current paired comparison including native inputs and per-scenario source counts. Both versions use the same corrected technique-specific verifier. These datasets were already inspected: this is regression evaluation, with no untouched test split and no event-level false-positive labels. A later calibration experiment needs independent benign data and fixed thresholds; the methodology in [DNS pretraining research](https://arxiv.org/abs/2604.09849) motivates that requirement.

## Verify the implementation

```sh
python3 -m unittest discover -s tests -v
```

Tests cover priority ordering without alert-volume inflation, training-to-operational promotion, distinct web-burst escalation, priority and dataset shortlist coverage, event timestamps, nested EVE records without `full_log`, redaction, command inspection happening after preparation, causal prefix preservation, weak relationship marking, repeat counting, training separation, cross-dataset entity isolation, label-file denial throughout a complete replay, pause/step behavior, record conservation, and verification leaving inference unchanged. With the server running, `python3 tests/check_live.py` prepares all eight datasets and checks the completion gate, static-file isolation, a mixed replay, and frozen verification.

Caches are ignored in `.gitignore`; prepared scenario SQLite files live under `.cache/`. Stop the server with Ctrl+C. Runs are in memory, with at most four retained sessions; completed runs put their ID in the local page URL, so refresh restores their frozen results while that server session remains available. A server restart or expiry of the four-run history starts a fresh view. Dataset checkboxes are remembered. The measured full-dataset check, including priority totals and ranking, is recorded in `tests/all-dataset-run-results.json`; the mixed-run completion-gate and verification checks are in `tests/live-check-results.json`. Browser checks for dragging, attached line endpoints, spring motion, freeze, pan, zoom, keyboard inspection, and priority filters are recorded in `tests/graph-interaction-results.json`. The final 79-window label verification left the completed inference unchanged.

Priority calibration: generic sensor severity alone never promotes an anomaly to Investigate. An incomplete SSH identification exchange stays in Context until 10 distinct operational exchanges from the same observed source and resolved host occur within five minutes. Repeated copies and training records cannot meet this threshold. Explicit scan signatures remain Context until corroborated by another supported behavior family. Thresholds remain experimental. Restart the server and replay to apply changed rules; existing runs retain their original classifications.

## False positive reviews

In the evidence inspector, choose **Flag possible false positive** to add a group to the False positive tracker. Record a suspected, confirmed false positive, valid detection, or inconclusive outcome with supporting evidence and follow-up notes. Confirmed false positives require notes. Reviews are stored in the current browser, keyed by replay run and group, and survive replay resets; use **Export reviews** to save a JSON copy. Reviews do not modify the detector or read attack labels.

## Incident chains, suppression and verifiable investigations

Open an evidence group and select **Show incident timeline** to inspect its connected component in event order. The existing map displays the same relationships. Prefix-only correlation now also joins source/destination addresses and same-host accounts within 15 minutes, scoped to one scenario; entity histories retain at most 100 episodes per entity. Each connection includes its witness alert IDs. **Confirmed evidence** means the cited records contain matching entity fields. The relationship between episodes remains **inferred**: shared hosts, accounts or addresses do not prove causality or compromise. Timelines include representative alert IDs, and full episode membership remains available in the inspector. Missing telemetry and the bounded joins prevent a guarantee of a complete attack chain.

The **View timeline** control loads the real connected incident episodes in chronological order, with clickable alert references and evidence relationship details. Only the suppression controls are marked **For demo only**: approval, expiry and unsuppress controls are disabled and have no action handlers. Suppression endpoints reject requests, and saved suppression rules do not affect live review queues. Detection, correlation and the separate AI investigation feature remain available.

The AI inspector accepts an analyst question and returns cited answers to **Why was this escalated?** and **What evidence would disprove this hypothesis?**. It marks answers as supported, hypothesis or abstain. Findings and supported answers require nonempty alert citations, and all citations must belong to the frozen supplied snapshot. Summary citations are also displayed. Hypotheses, proposed checks and missing evidence are conditional. Citation validation confirms record membership, not semantic entailment; analysts must inspect the cited records before accepting conclusions. AI cannot approve suppression or change detection.

## Paired triage benchmark

Run the benchmark on prepared, unchanged normalized caches:

```sh
python3 replay-lab/benchmark.py --scenarios russellmitchell fox harrison santos shaw wardbeck wheeler wilson --cache-dir replay-lab/.cache/alerts-only --labels labels.csv --output replay-lab/tests/triage-benchmark.json
```

Add `--reviews exported-reviews.json` to include explicitly **Confirmed false positive** cases with notes and evidence IDs. With no such cases, benign rates remain null. Activity outside labeled attack windows is never assumed benign.

The benchmark compares raw severity ranking (fixed severity threshold 10), a host/scenario correlation baseline with a 15-minute inactivity gap using the same selected alerts, and online pipeline review priorities. Labels are opened only after all detection decisions. All methods report attack-window **review coverage**, review-item reduction, latency from window start, review-unit burden, and missed windows separately. Review coverage means any selected signal overlaps the window, rather than proving that the expected technique was detected. The pipeline's technique-specific verifier is reported separately. Review units are a workload proxy; measured analyst minutes are unavailable. Benign case-selection rates use sampled reviewed alert references and are not population false-positive rates. Suppression is disabled for repeatability. The output includes parameters, evidence digest and raw severity ranking preview.

The saved full-alert comparison is [triage-benchmark.json](tests/triage-benchmark.json). Its results expose the tradeoff between a smaller review queue and missed review windows; do not infer better detection merely from alert reduction.

The latest unchanged-alert run processed **2,655,821 records** (2,651,082 operational).

| Method | Review items | Windows with review signals | Missed review windows | Median latency in covered windows |
| --- | ---: | ---: | ---: | ---: |
| raw severity | 132,939 | 45/79 | 34 | 15.5 s |
| time correlation | 3,411 | 45/79 | 34 | 15.5 s |
| pipeline | 16 | 30/79 | 49 | 8.0 s |

Pipeline technique-specific coverage is **62/79**; review escalation coverage is **30/79**. The reduced queue trades away review coverage under the current priority policy. Latency medians include different covered windows and should not be treated as a paired speed improvement. No reviewed benign cases were supplied, so false-positive rates and measured human review time remain unavailable.
