# False Positive Analysis and Detection Tuning

This document records every false-positive source identified while validating
the LockBit 3.0 Sigma rules against live process-creation telemetry, why each
one triggered, the filter that was applied, and the residual risk left after
tuning. Specific hostnames, usernames, and internal ticket references from the
original hunt have been generalized to protect client confidentiality.

| Technique | Observed False Positive | Reason | Filter Applied | Residual Risk |
|---|---|---|---|---|
| T1059 | Scripting-interpreter invocations from an IT-management/orchestration agent, a PAM session-recording agent, a vulnerability-management agent, an IT discovery agent, and hypervisor management tooling | These platforms legitimately spawn PowerShell/cmd with automation-style flags (`-NoProfile`, `-ExecutionPolicy Bypass`) as part of normal agent check-ins and orchestration jobs | Excluded by matching `src.process.cmdline` / `src.process.parent.cmdline` against the known agent identifiers | Low — an attacker could attempt to masquerade a malicious command line to match one of the excluded strings; exclusions should be scoped as tightly as possible (exact match, not substring) and reviewed periodically |
| T1068 | `msiexec.exe`, `schtasks.exe`, and print-subsystem processes triggered by legitimate software installers, patch management, vulnerability scanning, and a productivity-suite background task registration | Enterprise software installers and productivity suites routinely use silent MSI installs and register scheduled tasks (e.g. a creative-software daily update check) | Excluded known installer/updater command-line substrings; verified odd results traced to legitimate installer GUIDs, Npcap driver install, Windows print isolation host, and a productivity-suite scheduled task | Medium — path-only matching on `msiexec.exe`/`schtasks.exe` is inherently noisy; true privilege-escalation abuse (token impersonation tools) is better isolated by tightening the command-line selection rather than the image path |
| T1027 | A single `powershell.exe` process spawning `cmd.exe /c script.cmd` | Superficially matches obfuscated-execution patterns for a locally staged script, but no Base64/encoded content was present | Not filtered — flagged for manual follow-up and file acquisition rather than suppressed, since this pattern is also consistent with legitimate custom automation *and* with staged payload execution | Medium-High — this is the one result from the hunt that could not be conclusively resolved as benign; recommend acquiring the referenced script for static/dynamic analysis before closing |
| T1562.001 | Core OS service-control activity (`sc.exe`, `net.exe`) tied to normal system operation, plus a patch-management agent restarting services | Windows service start/stop is extremely common in routine operations and updates | Excluded the patch-management agent's command-line identifier; remaining matches manually reviewed and attributed to standard OS behavior | Low — the rule's specificity (targeting security-relevant service names like `WinDefend`) keeps true-positive risk reasonably contained even without heavy exclusion |
| T1003 | `reg.exe` invoked for benign registry queries (driver info lookup), Windows Terminal's `OpenConsole.exe` spawning `reg.exe`, a batch-file replacement utility, and a generic `command.cmd` invocation, after excluding a Java runtime updater, patch agent, discovery agent, and an internal error-handling script | `reg.exe` is a dual-use LOLBIN; most invocations are unrelated to SAM/SECURITY hive extraction | Excluded known benign automation sources; command-line-based selection (`sekurlsa::`, `reg save HKLM\SAM`, etc.) returned zero matches, confirming no actual dumping occurred | Medium — `OpenConsole.exe` is a documented LOLBAS binary that can be abused when not spawned by Windows Terminal; this specific pattern should be tracked as a standing detection opportunity rather than dismissed |
| T1046 | `cmd.exe`-driven connectivity checks from a contact-center/telephony business application | The application performs internal connectivity validation using native Windows networking commands at startup | Not filtered (low occurrence); documented as an accepted, recurring benign source tied to a known business application | Low — volume is low and consistently attributable to one identified application; recommend a named exclusion if it continues to generate noise |
| T1021 | Same contact-center/telephony application establishing internal connections via `cmd.exe` | Same root cause as T1046 — legitimate application-layer connectivity, not attacker-driven lateral movement | Not filtered (low occurrence); documented as accepted benign source | Low — same rationale as above |
| T1486 | No matches returned | N/A | N/A | Low — absence of results is expected in an environment without active encryption; this rule should be treated as a critical/high-priority alert if it ever fires |
| T1490 | No matches returned | N/A | N/A | Low — same rationale as T1486; combination of shadow-copy deletion and boot-recovery tampering is rarely benign |
| T1489 | High-volume matches tied to hyperconverged infrastructure management tooling (e.g. snapshot/orchestration agents that stop and restart VSS/SQL-related services as part of normal operations) | Infrastructure management platforms routinely cycle backup- and database-related services during snapshot and maintenance windows | Not fully suppressed in the original hunt; recommended as the top tuning priority for the next iteration of this rule | Medium — this was the single largest false-positive source in the entire hunt; an explicit exclusion for the known infrastructure management agent's process lineage is recommended before this rule is used for high-confidence alerting |

## Client Feedback Incorporated Into Tuning Philosophy

During stakeholder review, the client raised a valid concern that had not been
sufficiently addressed in the original hunt output: **hostname-based
identification of "suspicious" assets is not a reliable standalone signal.**
Non-domain-joined devices, temporary/testing systems, legacy or third-party
vendor equipment, and newly provisioned machines can all have inconsistent or
non-standard hostnames that do not reflect malicious intent.

This is reflected in the tuning approach above: every exclusion and every
retained detection is anchored to **process lineage, command-line content, and
behavioral context** rather than to device or hostname naming patterns. Where
a hunt needs to prioritize follow-up across many endpoints, the recommended
validation order is:

1. Correlate the process-level match with authentication and network logs for
   the same host/time window.
2. Check for lateral-movement or credential-access indicators occurring near
   the same timestamp.
3. Confirm (or rule out) the presence of known-benign software via installed
   application inventory before treating a hostname pattern as significant.

## Remaining Blind Spots

- No email-gateway or web-proxy telemetry was in scope, so T1566 (Phishing)
  and T1190 (Exploit Public-Facing Application) have no detection coverage in
  this rule set.
- Rules are based on command-line substring matching; a LockBit affiliate
  using renamed binaries, indirect command execution (e.g. `.lnk` files,
  compiled scripts, or in-memory execution without a visible command line)
  would evade the current selection logic.
- No file-integrity or file-creation telemetry was used to detect the LockBit
  3.0 encryptor dropping ransom notes or renaming files with the ransomware
  extension — this would meaningfully strengthen T1486 coverage.
