# Detection Notes

Detailed engineering rationale for each detection: why it exists, how an
attacker could evade it, the logging prerequisites required for it to fire
reliably, known blind spots, and possible improvements.

---

## T1059 — Command and Scripting Interpreter

**Why it exists:** LockBit 3.0 affiliates rely heavily on PowerShell, cmd,
and Windows Script Host to download and stage payloads, disable protections,
and orchestrate the pre-encryption phase. Flagging combinations of
interpreter + high-risk flags catches this staging activity earlier than
waiting for the encryptor itself.

**Evasion:** Attackers can avoid flagged flags entirely (e.g. omit
`-ExecutionPolicy Bypass` by targeting a host with an already-permissive
policy), use `-EncodedCommand` with a short alias (`-enc` vs `-Enc` casing,
handled by Sigma's case-insensitive `contains` matching), or invoke
PowerShell via `.NET` reflection / `System.Management.Automation.dll` to
avoid spawning `powershell.exe` entirely.

**Logging requirements:** Sysmon Event ID 1 (or EDR-equivalent process
creation telemetry) with full command-line capture enabled. Command-line
auditing must not be truncated — several EDR/SIEM ingestion pipelines
truncate long command lines by default.

**Blind spots:** Fileless execution (reflective PowerShell loading) and
renamed binaries bypass image-path matching.

**Improvements:** Add parent-process-lineage logic (e.g. Office application
spawning PowerShell) and script-block logging (Event ID 4104) for encoded
command deobfuscation.

---

## T1068 — Exploitation for Privilege Escalation

**Why it exists:** Token-impersonation tooling (JuicyPotato/PrintSpoofer-style
exploits) and scheduled-task creation are common LockBit affiliate techniques
for escalating from an initial foothold to SYSTEM or admin-equivalent access.

**Evasion:** Renaming the exploit binary defeats image-path matching (already
partially mitigated by also matching on command-line privilege strings).
Using a custom-compiled impersonation tool with different exported function
names would not reference `SeImpersonatePrivilege` in the command line at
all, and would evade this rule.

**Logging requirements:** Process creation telemetry with command-line
arguments; ideally paired with Windows Security Event ID 4672 (special
privileges assigned to new logon).

**Blind spots:** In-memory/reflective loading of exploit code that never
touches disk or produces a visible command line matching the selection.

**Improvements:** Correlate with Event ID 4688/4672 privilege-assignment
events, and add detection for named-pipe impersonation techniques that don't
rely on scheduled tasks.

---

## T1027 — Obfuscated Files or Information

**Why it exists:** Base64-encoded PowerShell, `Invoke-Expression`, and
`WebClient` download cradles are near-ubiquitous in ransomware staging
because they evade simple string-based AV signatures and complicate manual
log review.

**Evasion:** Splitting encoded strings across variables, using alternative
encoding (Gzip + Base64, XOR), or leveraging `rundll32`/`regsvr32` with
custom exports not covered by the selection would evade this rule.

**Logging requirements:** Full command-line logging plus PowerShell
Script Block Logging (Event ID 4104) to decode Base64 payloads for analysis.

**Blind spots:** The hunt surfaced one case of `powershell.exe` spawning
`cmd.exe /c script.cmd` with no encoding present — this pattern is not
inherently obfuscation but was flagged because encoded/obfuscated stagers
frequently invoke a secondary interpreter this way. This is a known gap:
the rule cannot currently distinguish benign local automation from
staged-payload execution using this pattern alone.

**Improvements:** Acquire and sandbox any script referenced by ambiguous
`cmd.exe /c *.cmd` invocations; add a companion rule on `EncodedCommand`
length/entropy thresholds.

---

## T1562.001 — Disable or Modify Security Tools

**Why it exists:** LockBit 3.0 affiliates frequently disable Windows Defender
real-time protection, stop AV/EDR-related services, or clear event logs
immediately prior to encryption to reduce the chance of detection and
forensic reconstruction.

**Evasion:** Using direct registry writes to disable Defender (bypassing the
`Set-MpPreference` cmdlet entirely), or using a kernel-level BYOVD (Bring
Your Own Vulnerable Driver) technique to terminate AV/EDR processes, would
not match this rule's command-line selection.

**Logging requirements:** Process creation telemetry; Windows Defender
operational log (Event ID 5001, real-time protection disabled) as a
corroborating source.

**Blind spots:** Registry-based tampering with Defender policy keys directly
(not via PowerShell cmdlets) is not currently covered.

**Improvements:** Add a registry-modification-based Sigma rule targeting the
`DisableRealtimeMonitoring` and `DisableAntiSpyware` registry values directly,
independent of the command used to set them.

---

## T1003 — OS Credential Dumping

**Why it exists:** Credential theft (via Mimikatz, ProcDump against LSASS, or
direct SAM/NTDS extraction) enables lateral movement and domain-wide
encryption, which is central to LockBit 3.0's operating model.

**Evasion:** Renaming `mimikatz.exe`, using a custom/compiled credential
dumper with different function names, or dumping LSASS memory via a
built-in tool (e.g. Task Manager "Create dump file") would evade command-line
based matching entirely.

**Logging requirements:** Process creation telemetry; Sysmon Event ID 10
(ProcessAccess) targeting `lsass.exe` provides stronger, more evasion-resistant
coverage than command-line matching alone.

**Blind spots:** The hunt identified that `OpenConsole.exe` (a documented
LOLBAS entry) can spawn `reg.exe` and other utilities when not launched by
Windows Terminal as expected — this is a standing detection gap that command-
line matching alone will not close, since the abuse signal is in the process
lineage, not the command line.

**Improvements:** Add a Sysmon Event ID 10 rule for LSASS memory access from
non-standard processes, and a parent-process-lineage rule for
`OpenConsole.exe` spawning child processes without `WindowsTerminal.exe` as
the direct parent.

---

## T1046 — Network Service Scanning

**Why it exists:** Internal reconnaissance (identifying reachable hosts and
services) typically precedes lateral movement in a LockBit 3.0 intrusion.

**Evasion:** Using a renamed or custom scanning utility, or built-in
PowerShell socket-based scanning that doesn't call `Test-NetConnection`,
would evade this selection.

**Logging requirements:** Process creation telemetry; ideally paired with
network connection telemetry (Sysmon Event ID 3) to detect scan-like
connection fan-out independent of the tool used.

**Blind spots:** The rule currently has low selectivity — a legitimate
business application generated the majority of matches in this hunt, which
indicates the rule alone is not suitable for high-confidence alerting without
network-based corroboration.

**Improvements:** Add a network-telemetry-based detection for high-fan-out
connection attempts from a single host in a short time window, independent of
the initiating process.

---

## T1021 — Remote Services

**Why it exists:** RDP, SMB-based admin shares, WMI, and PowerShell remoting
are the primary lateral movement channels observed in LockBit 3.0 intrusions
once credentials have been obtained.

**Evasion:** Using stolen credentials over RDP without any of the flagged
command-line indicators (e.g. logging in interactively via the GUI rather
than `mstsc /v:`) would not be captured by this process-creation-based rule.

**Logging requirements:** Process creation telemetry; Windows Security Event
ID 4624 (logon type 3/10) provides authentication-based corroboration that is
harder to evade.

**Blind spots:** Interactive RDP sessions established without a scripted
command line are invisible to this rule.

**Improvements:** Correlate with authentication logs for logon type 10
(RemoteInteractive) from source IPs not previously seen for a given account,
and add a rule for anomalous SMB admin-share (`C$`/`ADMIN$`) access.

---

## T1486 — Data Encrypted for Impact

**Why it exists:** This is the terminal, business-impacting stage of a
LockBit 3.0 intrusion — detecting it is a last line of defense, but the
supporting shadow-copy-deletion and boot-tampering commands are a
high-fidelity leading indicator that encryption is imminent or underway.

**Evasion:** A renamed encryptor binary with no recognizable command-line
flags, or an encryptor that skips shadow-copy deletion (relying on other
persistence-denial techniques), would reduce this rule's fidelity.

**Logging requirements:** Process creation telemetry; file-system telemetry
(mass file rename/modification events, e.g. Sysmon Event ID 11 for file
creation of ransom notes) would substantially strengthen this detection.

**Blind spots:** No file-content or file-extension-based detection is
included in this rule set; encryption activity that doesn't touch
`vssadmin`/`bcdedit` at all would not be flagged.

**Improvements:** Add a file-monitoring-based rule for mass file renames to a
known or unknown ransomware extension within a short time window, and for
ransom note file creation across many directories in rapid succession.

---

## T1490 — Inhibit System Recovery

**Why it exists:** Deleting shadow copies and disabling Windows recovery
options removes the victim's ability to restore data without paying the
ransom — a core LockBit 3.0 impact technique.

**Evasion:** Using the Volume Shadow Copy Service COM API directly (rather
than `vssadmin.exe`/`wmic.exe`) to delete shadow copies would bypass
process-creation-based detection entirely.

**Logging requirements:** Process creation telemetry.

**Blind spots:** COM-based or PowerShell-native (`Get-CimInstance
Win32_ShadowCopy | Remove-CimInstance`) shadow copy deletion is not currently
covered.

**Improvements:** Add detection for shadow-copy deletion via WMI/CIM
PowerShell cmdlets, and for direct service-stop of the Volume Shadow Copy
service (`VSS`) as a standalone indicator when combined with other impact
techniques.

---

## T1489 — Service Stop

**Why it exists:** Stopping security, backup, and database services reduces
detection capability and removes recovery options prior to encryption.

**Evasion:** Using the Service Control Manager API directly (via a custom
tool) rather than `sc.exe`/`net.exe`/`taskkill.exe` would bypass this rule.

**Logging requirements:** Process creation telemetry; Windows System Event
Log Service Control Manager events (Event ID 7036, service stopped) as a
corroborating, harder-to-evade source.

**Blind spots:** This rule generated the highest false-positive volume of
the entire hunt, driven by legitimate infrastructure management tooling that
routinely cycles backup/database-related services — this must be tuned
before the rule is suitable for direct alerting (see
[`false-positives/tuning.md`](../false-positives/tuning.md)).

**Improvements:** Add an exclusion for the identified infrastructure
management agent's process lineage, and add Event ID 7036 correlation to
reduce reliance on command-line matching alone.
