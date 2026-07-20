# MITRE ATT&CK Mapping — LockBit 3.0 ("LockBit Black")

This mapping covers the techniques associated with LockBit 3.0 that were in
scope for this hunt. Confidence and coverage ratings reflect the outcome of
this specific hunt (query fidelity + validated results), not a general
statement about the technique's overall detectability.

| Technique | ID | Detection | Coverage | Confidence |
|---|---|---|---|---|
| Exploit Public-Facing Application | T1190 | Not covered by an endpoint-based Sigma rule in this hunt; requires WAF/edge and vulnerability-scanning telemetry (out of scope for this hunt's data sources) | None | N/A |
| Phishing | T1566 | Not covered by an endpoint-based Sigma rule in this hunt; requires email-gateway telemetry (out of scope for this hunt's data sources) | None | N/A |
| Command and Scripting Interpreter | T1059 | [`sigma/T1059.yml`](../sigma/T1059.yml) | Partial | Medium |
| Exploitation for Privilege Escalation | T1068 | [`sigma/T1068.yml`](../sigma/T1068.yml) | Partial | Medium |
| Obfuscated Files or Information | T1027 | [`sigma/T1027.yml`](../sigma/T1027.yml) | Partial | Medium |
| Disable or Modify Security Tools (Impair Defenses) | T1562.001 | [`sigma/T1562.001.yml`](../sigma/T1562.001.yml) | Partial | Medium |
| OS Credential Dumping | T1003 | [`sigma/T1003.yml`](../sigma/T1003.yml) | Partial | Medium |
| Network Service Scanning | T1046 | [`sigma/T1046.yml`](../sigma/T1046.yml) | Partial | Low-Medium |
| Remote Services | T1021 | [`sigma/T1021.yml`](../sigma/T1021.yml) | Partial | Low-Medium |
| Data Encrypted for Impact | T1486 | [`sigma/T1486.yml`](../sigma/T1486.yml) | Full | High |
| Inhibit System Recovery | T1490 | [`sigma/T1490.yml`](../sigma/T1490.yml) | Full | High |
| Service Stop | T1489 | [`sigma/T1489.yml`](../sigma/T1489.yml) | Partial | Medium |

## Coverage Legend

- **Full** — Command-line pattern is highly specific to malicious/ransomware
  behavior; benign matches are rare and the rule can operate at high
  confidence with minimal tuning.
- **Partial** — Detection logic relies on process/command-line patterns that
  are also produced by legitimate administrative tools, IT management agents,
  or business applications. The rule requires environment-specific tuning
  (see [`false-positives/tuning.md`](../false-positives/tuning.md)) and
  correlation with other signals before it is actionable at scale.
- **None** — No detection logic exists for this technique in the current rule
  set; a different telemetry source (network/email) would be required.

## Confidence Legend

- **High** — Validated during this hunt as producing no false positives, or
  matching only on a narrow, high-specificity command combination.
- **Medium** — Validated during this hunt as producing a manageable but
  non-trivial false-positive rate, all attributable to identified legitimate
  software.
- **Low-Medium** — Validated during this hunt as matching almost exclusively
  on a single legitimate business application; the rule's current selectivity
  is low and would benefit from tighter scoping (see Detection Opportunities
  in the main README).

## ATT&CK Navigator Reference

For a visual heat-map of this coverage, the technique IDs above can be pasted
into the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
to generate a layer file for this hunt.
