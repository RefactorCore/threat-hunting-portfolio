# LockBit 3.0 ("LockBit Black") — Threat Hunt & Detection Engineering

A proactive threat hunt against LockBit 3.0 ransomware TTPs, translated into a
reusable Sigma rule set, multi-SIEM query library, and MITRE ATT&CK-mapped
detection engineering package.

## Overview

**Threat Actor / Malware Family:** LockBit 3.0, also known as LockBit Black,
is a Ransomware-as-a-Service (RaaS) operation active since mid-2022. Its
affiliate model allows a broad range of operators to deploy the payload
against organizations across many sectors and geographies, which makes its
TTP set one of the more consistently reused ransomware playbooks to hunt
against.

**Hunt Objective:** Proactively search endpoint telemetry for evidence that a
LockBit 3.0 affiliate had gained a foothold and was progressing through
reconnaissance, credential access, lateral movement, or pre-encryption
staging — rather than waiting for the encryption event itself to trigger an
alert.

## Threat Summary

LockBit 3.0 affiliates typically gain initial access through exploitation of
internet-facing applications or phishing, then use native Windows tooling
("living off the land") alongside a small set of well-known offensive
security utilities to escalate privileges, harvest credentials, move
laterally, and disable security and backup infrastructure before executing
the encryptor. The payload itself deletes shadow copies, disables recovery
options, and encrypts files, leaving the victim organization with degraded
recovery options unless backups are isolated from the affected environment.

## MITRE ATT&CK Coverage

| Technique | Technique ID | Description |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Exploiting vulnerabilities in internet-facing applications (e.g. Citrix NetScaler) for initial access |
| Phishing | T1566 | Malicious email attachments or links used to gain initial entry |
| Command and Scripting Interpreter | T1059 | PowerShell, Batch, or script-based payload execution |
| Exploitation for Privilege Escalation | T1068 | Exploiting system vulnerabilities or token impersonation to gain admin-level access |
| Obfuscated Files or Information | T1027 | Code packing, Base64 encoding, and function obfuscation to evade detection |
| Disable or Modify Security Tools | T1562.001 | Disabling Defender, AV, or EDR components to prevent detection |
| OS Credential Dumping | T1003 | Extracting credentials from memory or registry hives via Mimikatz-style tooling |
| Network Service Scanning | T1046 | Scanning the internal network for reachable systems and services |
| Remote Services | T1021 | Using RDP, SMB, WMI, or PowerShell remoting for lateral movement |
| Data Encrypted for Impact | T1486 | Encrypting files to render them inaccessible |
| Inhibit System Recovery | T1490 | Deleting shadow copies and disabling recovery options |
| Service Stop | T1489 | Disabling security tools and backup-related services |

Full mapping with detection coverage and confidence ratings is in
[`attack/mitre-mapping.md`](attack/mitre-mapping.md).

## Hunt Hypothesis

A LockBit 3.0 operator may have gained initial access and be conducting
reconnaissance or lateral movement within the environment. Malicious activity
such as privilege escalation, credential dumping (e.g. Mimikatz), disabling
of security tooling, and execution of suspicious binaries or LOLBins may be
present in process-creation telemetry. By analyzing process creation logs,
script executions, and network-related command activity, the hunt aims to
surface ransomware deployment or pre-encryption staging activity before it
reaches the impact stage.

## Data Sources

- **Endpoint Detection and Response (EDR) process-creation telemetry** —
  primary data source for this hunt, captured via SentinelOne Deep Visibility
  (`tgt.process.*`, `src.process.*` fields). Equivalent coverage is achievable
  with Sysmon Event ID 1 or any EDR platform exposing process lineage and
  full command-line arguments.
- **Process command-line arguments** — required for every rule in this
  package; several detections (T1059, T1027, T1003) rely entirely on
  command-line content rather than image path.
- **Process parent/child lineage** — used both for detection logic (T1021,
  T1003) and for tuning out known-benign automation and management agents.

## Detection Logic

Each Sigma rule in [`sigma/`](sigma/) targets a specific ATT&CK technique and
follows the same general design pattern: match on a small set of
security-relevant binaries (`Image|endswith`) **and** a set of command-line
substrings associated with malicious usage (`CommandLine|contains`), rather
than matching on either condition alone. This two-part condition is
deliberate — matching only on binary path (e.g. `powershell.exe`) would be
far too noisy for any production environment, while matching only on
command-line content risks missing legitimate binaries invoked with unusual
arguments.

Two techniques — **T1486 (Data Encrypted for Impact)** and **T1490 (Inhibit
System Recovery)** — are rated at `level: critical` rather than `high`,
because their command-line combinations (shadow-copy deletion + boot-recovery
tampering, or the LockBit encryptor's `/encrypt /path:` flag) have very low
legitimate-use overlap. Every other rule is rated `high` and is expected to
require environment-specific tuning before it is suitable for direct,
unattended alerting — see [`detections/detection-notes.md`](detections/detection-notes.md)
for the reasoning behind each individual rule, how an attacker could evade
it, and what additional logging would close the gap.

## Hunt Queries

Every query below was originally written and executed in SentinelOne Deep
Visibility. Microsoft Sentinel, Splunk, and Elastic equivalents were derived
from the same underlying logic (matching binary + command-line substrings)
so the same hunt can be reproduced on any of the four platforms.

### SentinelOne
Full query set (with exclusion logic and grouping used during the live hunt):
[`queries/sentinelone.md`](queries/sentinelone.md)

### Microsoft Sentinel (KQL)
Converted against the `DeviceProcessEvents` table (Microsoft Defender for
Endpoint via Sentinel): [`queries/sentinel.kql`](queries/sentinel.kql)

### Splunk (SPL)
Converted against Sysmon Event ID 1 process-creation events:
[`queries/splunk.spl`](queries/splunk.spl)

### Elastic (KQL / EQL)
Converted against ECS `process.*` fields, with both KQL (Discover/Lens) and
EQL (sequence-capable detection rule) syntax provided:
[`queries/elastic.kql`](queries/elastic.kql)

## Results

- **Hits:** No confirmed malicious activity was identified across any of the
  ten process-creation-based hunt queries. Several queries (T1486, T1490)
  returned zero results at all, which is the expected/desired outcome for
  ransomware-specific impact indicators.
- **False positives:** The majority of raw query hits were attributable to
  identified legitimate software: IT management and discovery agents, a PAM
  session-recording agent, vulnerability-management tooling, hypervisor
  management software, enterprise installers (including a productivity
  suite's scheduled task and a packet-capture driver installer), and a
  contact-center/telephony business application that uses `cmd.exe` for
  internal connectivity checks and network share access. Full breakdown in
  [`false-positives/tuning.md`](false-positives/tuning.md).
- **Interesting observations:**
  - A `powershell.exe` process spawning `cmd.exe /c script.cmd` could not be
    conclusively attributed to benign automation and was flagged for file
    acquisition and follow-up analysis.
  - `OpenConsole.exe`, a documented [LOLBAS](https://lolbas-project.github.io/lolbas/OtherMSBinaries/OpenConsole/)
    binary, was observed spawning `reg.exe` — worth tracking as a standing
    detection opportunity since it can be abused when not launched by
    Windows Terminal as expected.

## Detection Tuning

- **What was filtered:** Command-line substrings and process-lineage
  identifiers belonging to known IT management, security, and infrastructure
  automation tooling were excluded from each query (generalized in this
  repository as placeholders such as `<IT_MANAGEMENT_AGENT_1>` — see
  [`false-positives/tuning.md`](false-positives/tuning.md) for the full
  per-technique breakdown).
- **Why:** These platforms legitimately invoke the same binaries
  (`powershell.exe`, `msiexec.exe`, `sc.exe`, etc.) with command-line flags
  that superficially resemble ransomware staging behavior, and without
  exclusion they dominated the result set and obscured genuinely anomalous
  activity.
- **Remaining blind spots:** No email-gateway or web-proxy telemetry was in
  scope, so initial-access techniques (T1190, T1566) have no detection
  coverage in this rule set. Fileless execution, renamed binaries, and
  API-level (COM/WMI) equivalents of the flagged command-line actions would
  evade the current, command-line-centric detection logic. Full detail per
  technique is in [`detections/detection-notes.md`](detections/detection-notes.md).

## Detection Opportunities

- Add Sysmon Event ID 10 (ProcessAccess) coverage for direct LSASS memory
  access, independent of command-line content, to close the T1003 blind spot
  around renamed or custom credential dumpers.
- Add file-system telemetry (mass file rename/creation of ransom notes) to
  strengthen T1486 beyond process-creation-only detection.
- Add authentication-log correlation (Event ID 4624, logon type 10) to
  T1021 to catch interactive RDP lateral movement that doesn't rely on a
  visible command line.
- Tighten the T1489 rule with an explicit exclusion for the infrastructure
  management agent identified as the dominant false-positive source, since
  this rule currently has the weakest signal-to-noise ratio in the set.

## Lessons Learned

- **Hostnames are not a reliable standalone indicator.** Client feedback
  during this engagement correctly noted that non-domain-joined machines,
  temporary/testing systems, legacy or third-party vendor equipment, and
  newly provisioned hosts can all have inconsistent naming that has nothing
  to do with compromise. Detection and triage decisions should be anchored
  to behavioral and log-based evidence, not naming conventions.
- **Findings and recommendations should be actionable, not bundled.**
  Recommendations arising from a hunt (e.g. "acquire this script for
  analysis," "tune this exclusion," "prioritize this patch") should be
  tracked as individual, assignable tickets rather than folded into a single
  summary report, so that follow-up work doesn't get lost.
- **Vague remediation guidance isn't useful.** Where a hunt surfaces a
  security gap (e.g. a high-risk vulnerability needing patching), the
  specific vulnerability or system should be named explicitly rather than
  referenced generically, so the receiving team can act on it directly.

## References

- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1566 Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK — T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK — T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK — T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK — T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK — T1046 Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK — T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK — T1489 Service Stop](https://attack.mitre.org/techniques/T1489/)
- [LOLBAS Project — OpenConsole](https://lolbas-project.github.io/lolbas/OtherMSBinaries/OpenConsole/)

## Repository Structure

```
LockBit-3.0-Threat-Hunt/
├── README.md
├── LICENSE
├── sigma/
│   ├── T1059.yml
│   ├── T1068.yml
│   ├── T1027.yml
│   ├── T1562.001.yml
│   ├── T1003.yml
│   ├── T1046.yml
│   ├── T1021.yml
│   ├── T1486.yml
│   ├── T1490.yml
│   └── T1489.yml
├── queries/
│   ├── sentinelone.md
│   ├── sentinel.kql
│   ├── splunk.spl
│   └── elastic.kql
├── detections/
│   └── detection-notes.md
├── attack/
│   └── mitre-mapping.md
├── false-positives/
│   └── tuning.md
└── images/
```
