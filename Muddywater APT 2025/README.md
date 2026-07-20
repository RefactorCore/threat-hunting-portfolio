# MuddyWater APT Detection Engineering Portfolio

A comprehensive threat hunt and detection engineering project targeting MuddyWater APT campaigns. This repository demonstrates detection methodology, SIGMA rule development, and cross-platform SIEM query translation for sophisticated Iranian state-sponsored threat actor.

---

## Overview

### Threat Actor
**MuddyWater APT** (aliases: Mercury, Static Kitten, Seedworm) is believed to be linked to Iran's Ministry of Intelligence and Security (MOIS). The group targets government, telecommunications, oil & gas, defense, financial services, and education sectors across the Middle East, Europe, North America, and Asia.

### Hunt Objective
Detect and investigate indicators of MuddyWater APT compromise within the environment through identification of:
- Spearphishing attachment exploitation
- Obfuscated PowerShell execution chains
- Credential dumping activities
- Defense evasion techniques (DLL side-loading, LOLBin abuse)
- Command and control communication
- Data exfiltration attempts

---

## Threat Summary

MuddyWater APT is a sophisticated threat actor known for:

1. **Initial Access**: Delivers malicious Office documents with embedded macros via spearphishing campaigns
2. **Exploitation**: Leverages Office application vulnerabilities to execute arbitrary code
3. **Execution**: Employs heavily obfuscated PowerShell scripts and Visual Basic scripts to execute payloads
4. **Credential Access**: Uses credential dumping tools (Mimikatz, Procdump) to extract admin and user credentials
5. **Persistence**: Establishes footholds through registry modifications and scheduled task abuse
6. **Defense Evasion**: Implements DLL side-loading, uses Living-off-the-Land Binaries (LOLBins), and employs multiple obfuscation techniques
7. **Lateral Movement**: Moves laterally using compromised credentials via RDP, SMB, and WMI
8. **Command & Control**: Maintains persistence through HTTPS communication with command servers
9. **Data Exfiltration**: Exfiltrates sensitive data using file transfer utilities (curl, wget, ftp)

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection | Coverage | Confidence |
|-----------|----|-----------|---------|----|
| Spearphishing Attachment | T1566.001 | Office parent spawning shell interpreters | Process creation | High |
| Obfuscated PowerShell Execution | T1059.001 | Encoded commands and IEX patterns | Process command line | High |
| OS Credential Dumping | T1003 | Mimikatz/Procdump execution and parameters | Process creation/command line | High |
| DLL Side-loading | T1574.002 | DLL execution from suspicious paths | File operations | Medium |
| C2 Over HTTPS | T1071.001 | Outbound HTTPS to suspicious TLDs | Network connections | Medium |
| Registry Run Key Modification | T1547.001 | Persistence registry key changes | Registry operations | High |
| LOLBin Abuse | T1218 | Regsvr32/Mshta/Rundll32 with suspicious parameters | Process command line | High |
| Obfuscation & Encoding | T1027 | Base64/XOR patterns in script execution | Process command line | High |
| Data Exfiltration Over Web | T1567.002 | File transfer utilities with web protocols | Process execution | Medium |

---

## Hunt Hypothesis

MuddyWater APT has potentially gained initial access through phishing emails containing malicious attachments or links. The threat actors are leveraging:

- **PowerShell scripts** for payload execution and evasion
- **Living-off-the-Land Binaries** (Regsvr32.exe, Mshta.exe, Cmstp.exe) to execute payloads while evading traditional endpoint detection
- **Credential theft mechanisms** to enable lateral movement
- **Registry-based persistence** to maintain long-term access
- **Remote access protocols** (RDP, SMB, WMI) for expanding foothold within the network
- **Encrypted HTTPS or DNS tunneling** for command-and-control communication
- **Data exfiltration** using legitimate file transfer utilities

This hunt focuses on identifying the complete kill chain from initial access through exfiltration.

---

## Data Sources

The following telemetry sources are leveraged for detection:

- **Endpoint Detection & Response (EDR)**: SentinelOne, Microsoft Defender for Endpoint
- **Process Creation Events**: Parent-child process relationships, command-line arguments
- **Script Execution**: PowerShell, Windows Script Host, VBScript execution logs
- **Registry Operations**: Registry key modification and value changes
- **Network Connections**: Outbound connection metadata (destination, port, protocol)
- **File Operations**: File creation, modification, execution from suspicious paths
- **Authentication Events**: Credential usage, failed/successful logons

---

## Detection Logic

### T1566.001 - Spearphishing Attachment

**Rationale**: Office applications (Word, Excel, PowerPoint) should rarely spawn command shells or script interpreters. This pattern indicates either user interaction with malicious content or macro-based exploitation.

**Detection Logic**:
- Monitors parent process (Office application) spawning child processes
- Identifies shell interpreters (PowerShell, CMD, Wscript) as indicators of macro execution
- Excludes legitimate Office functionality (updates, plug-ins)

**Evasion Considerations**:
- Attackers may use alternate file extensions (.docm disguised as .doc)
- Legitimate plugins may trigger false positives
- Requires process parent-child relationship visibility

---

### T1059.001 - Obfuscated PowerShell Execution

**Rationale**: Obfuscated PowerShell commands indicate attacker attempts to evade detection and manual analysis. The presence of `-EncodedCommand`, `IEX`, or `Invoke-Expression` are strong indicators of malicious activity.

**Detection Logic**:
- Monitors PowerShell command-line arguments for encoding indicators
- Identifies common obfuscation patterns (Base64, string concatenation)
- Detects dynamic code execution patterns (IEX, Invoke-Expression)
- Correlates with parent process to identify Office-spawned execution

**Evasion Considerations**:
- Attackers may use alternative encoding schemes
- Legitimate admin tools may use `-EncodedCommand` for secure credential passing
- Script block logging bypass attempts (amsi.dll tampering)

---

### T1003 - OS Credential Dumping

**Rationale**: Credential dumping tools like Mimikatz, Procdump, and ntdsutil are explicitly designed for extracting sensitive credentials. Their presence indicates compromise severity.

**Detection Logic**:
- Monitors for credential dumping tool execution (Mimikatz, Procdump)
- Detects specific credential dumping commands (`sekurlsa::logonpasswords`, `lsadump::sam`)
- Identifies LSASS process access patterns
- Correlates with unusual scheduled tasks or service creation

**Evasion Considerations**:
- Attackers may rename credential dumping binaries
- Legitimate security tools (Picus, Qualys) may simulate credential dumping for testing
- In-memory attacks may bypass file-based detection

---

### T1574.002 - DLL Side-loading

**Rationale**: DLL files executed from non-standard directories (Public, Temp) indicate potential side-loading attacks where legitimate executables load malicious DLLs.

**Detection Logic**:
- Monitors DLL execution from suspicious directories
- Identifies common side-loading targets (legitimate executables paired with malicious DLLs)
- Tracks unusual DLL file origins and parent executables

**Evasion Considerations**:
- Legitimate installers may write DLLs to Temp directories
- Requires visibility into DLL loading operations (not always logged)
- May be bypassed through in-memory injection

---

### T1071.001 - Suspicious C2 Connections

**Rationale**: Outbound HTTPS connections to suspicious top-level domains (.ru, .ir, .gq, .tk) indicate potential command-and-control communication. These TLDs are commonly abused by threat actors.

**Detection Logic**:
- Monitors outbound HTTPS connections on port 443
- Identifies connections to historically malicious TLDs
- Correlates with process execution and data exfiltration patterns
- Excludes legitimate third-party services

**Evasion Considerations**:
- Attackers increasingly use compromised legitimate infrastructure
- C2 communication may be disguised in encrypted TLS traffic
- Domain reputation lists have significant false positive rates

---

### T1547.001 - Registry-Based Persistence

**Rationale**: Modifications to the Windows Run registry key indicate establishment of persistence mechanisms. Legitimate software rarely modifies these keys after initial installation.

**Detection Logic**:
- Monitors `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` modifications
- Tracks unusual process executables and command-line arguments
- Excludes known legitimate software (Edge, OneDrive, audio services)
- Identifies timing patterns (modifications during non-business hours)

**Evasion Considerations**:
- Attackers may use alternate registry locations (RunOnce, Services)
- Registry operations may be obfuscated through scheduled tasks
- Legitimate software updates may trigger false positives

---

### T1218 - LOLBin Abuse

**Rationale**: Living-off-the-Land Binaries (Regsvr32, Mshta, Rundll32) are legitimate Windows utilities frequently abused for code execution and defense evasion. Their use with suspicious parameters indicates malicious activity.

**Detection Logic**:
- Monitors execution of known LOLBins
- Identifies suspicious parameter combinations (URLs, DLL paths, script protocols)
- Detects proxy execution (one LOLBin launching another)
- Excludes legitimate administrative use cases

**Evasion Considerations**:
- Legitimate system maintenance may use these binaries
- Attackers may create look-alike binaries with similar names
- Parameter obfuscation may evade string-based detection

---

### T1027 - Obfuscation & Encoding

**Rationale**: Extensive use of Base64 encoding, XOR operations, or script obfuscation indicates attacker attempts to evade static analysis and automated detection systems.

**Detection Logic**:
- Monitors script interpreters for obfuscation indicators
- Detects Base64 decoding patterns in command-line arguments
- Identifies variable concatenation and string manipulation patterns
- Correlates with suspicious execution contexts

**Evasion Considerations**:
- Legitimate software may use encoding for configuration storage
- Multiple encoding layers may bypass simple pattern matching
- Environment-specific obfuscation may require tuning

---

### T1567.002 - Data Exfiltration Over Web

**Rationale**: File transfer utilities (curl, wget, ftp) are legitimate tools frequently abused for data exfiltration. Their execution from user contexts with web protocols indicates potential data theft.

**Detection Logic**:
- Monitors execution of file transfer utilities
- Identifies unusual source processes and command-line arguments
- Detects transmission of large amounts of data
- Correlates with credential access and lateral movement activities

**Evasion Considerations**:
- Legitimate development and IT operations may use these tools
- Attackers may use legitimate cloud storage services instead
- Encrypted tunnels may obscure exfiltration destination

---

## Hunt Queries

### SentinelOne

#### T1566.001 - Spearphishing Attachment
```
src.process.parent.name IN ("winword.exe", "excel.exe", "powerpnt.exe") AND 
src.process.name IN ("powershell.exe", "cmd.exe", "wscript.exe")
| group count() by src.process.parent.name, src.process.name
| sort by count() desc
```

#### T1059.001 - Obfuscated PowerShell Execution
```
src.process.parent.name = "powershell.exe" AND 
(src.process.cmdline contains "-EncodedCommand" OR 
src.process.cmdline contains "IEX (New-Object Net.WebClient" OR 
src.process.cmdline contains "Invoke-Expression")
| group count() by src.process.parent.name, src.process.name, src.process.cmdline, endpoint.name
| sort by count() desc
```

#### T1003 - OS Credential Dumping
```
src.process.parent.name IN ("mimikatz.exe", "procdump.exe", "ntdsutil.exe") OR 
(src.process.cmdline contains "sekurlsa::logonpasswords" OR 
src.process.cmdline contains "-ma lsass" OR 
src.process.cmdline contains "lsadump::sam")
| group count() by src.process.parent.name, src.process.name, src.process.cmdline, endpoint.name
| sort by count() desc
```

#### T1574.002 - DLL Side-loading
```
tgt.file.internalName contains ".dll" AND 
(tgt.file.path contains "C:\\Users\\Public\\" OR 
tgt.file.path contains "C:\\Temp\\")
| group count() by tgt.file.internalName, tgt.file.path, endpoint.name
| sort by count() desc
```

#### T1547.001 - Registry-Based Persistence
```
registry.keyPath contains "Software\\Microsoft\\Windows\\CurrentVersion\\Run" AND 
event.type = 'Registry Value Modified' AND 
!(registry.keyPath contains "Microsoft Edge Update") AND 
!(registry.keyPath contains "MicrosoftEdgeAutoLaunch") AND 
!(registry.keyPath contains "RtkAudUService") AND 
!(registry.keyPath contains "OneDrive")
| group count() by registry.keyPath, event.type, src.process.name, endpoint.name
| sort by count() desc
```

#### T1218 - LOLBin Abuse
```
tgt.process.image.path contains ("\\regsvr32.exe", "\\mshta.exe", "\\rundll32.exe") AND 
tgt.process.cmdline contains ("http", ".dll", "javascript:", "vbscript:", "hxxp://", "hxxps://") AND 
!(tgt.process.cmdline contains 'spool') AND 
!(tgt.process.cmdline contains 'Prnntfy.dll') AND 
!(tgt.process.cmdline contains 'pla.dll') AND 
!(tgt.process.cmdline contains 'printui.dll')
| group count() by tgt.process.image.path, tgt.process.cmdline
| sort by count() desc
```

#### T1027 - Obfuscation & Encoding
```
tgt.process.image.path contains ("\\powershell.exe", "\\cscript.exe", "\\wscript.exe", "\\mshta.exe", "\\regsvr32.exe", "\\rundll32.exe") AND 
tgt.process.cmdline contains ("-EncodedCommand", "frombase64string", "powershell -e ", "powershell /e ", "mshta vbscript:", "javascript:") AND 
!(src.process.cmdline contains 'Nutanix')
| group count() by tgt.process.image.path, tgt.process.cmdline, src.process.user
| filter count() <= 15
| sort by count() desc
```

#### T1567.002 - Data Exfiltration Over Web
```
src.process.name IN ("curl.exe", "wget.exe", "ftp.exe")
| group count() by src.process.name, src.process.cmdline, src.process.user, endpoint.name
| filter count() <= 15
| sort by count() desc
```

### Microsoft Sentinel (KQL)

#### T1566.001 - Spearphishing Attachment
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe")
| summarize count() by InitiatingProcessFileName, FileName, DeviceName
| sort by count_ desc
```

#### T1059.001 - Obfuscated PowerShell Execution
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand" 
    or ProcessCommandLine contains "IEX (New-Object Net.WebClient" 
    or ProcessCommandLine contains "Invoke-Expression"
| summarize count() by InitiatingProcessFileName, FileName, ProcessCommandLine, DeviceName, DeviceOs
| sort by count_ desc
```

#### T1003 - OS Credential Dumping
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in ("mimikatz.exe", "procdump.exe", "ntdsutil.exe")
    or ProcessCommandLine contains "sekurlsa::logonpasswords"
    or ProcessCommandLine contains "-ma lsass"
    or ProcessCommandLine contains "lsadump::sam"
| summarize count() by InitiatingProcessFileName, FileName, ProcessCommandLine, DeviceName
| sort by count_ desc
```

#### T1574.002 - DLL Side-loading
```kusto
DeviceFileEvents
| where FileName endswith ".dll"
| where FolderPath contains "\\Users\\Public\\" or FolderPath contains "\\Temp\\"
| summarize count() by FileName, FolderPath, DeviceName
| sort by count_ desc
```

#### T1547.001 - Registry-Based Persistence
```kusto
DeviceRegistryEvents
| where RegistryKeyPath contains "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| where ActionType == "RegistryValueSet"
| where RegistryKeyPath !contains "Microsoft Edge Update"
    and RegistryKeyPath !contains "MicrosoftEdgeAutoLaunch"
    and RegistryKeyPath !contains "RtkAudUService"
    and RegistryKeyPath !contains "OneDrive"
| summarize count() by RegistryKeyPath, ActionType, InitiatingProcessFileName, DeviceName
| sort by count_ desc
```

#### T1218 - LOLBin Abuse
```kusto
DeviceProcessEvents
| where FileName in ("regsvr32.exe", "mshta.exe", "rundll32.exe")
| where ProcessCommandLine contains "http" 
    or ProcessCommandLine contains ".dll" 
    or ProcessCommandLine contains "javascript:" 
    or ProcessCommandLine contains "vbscript:" 
    or ProcessCommandLine contains "hxxp://" 
    or ProcessCommandLine contains "hxxps://"
| where ProcessCommandLine !contains "spool"
    and ProcessCommandLine !contains "Prnntfy.dll"
    and ProcessCommandLine !contains "pla.dll"
    and ProcessCommandLine !contains "printui.dll"
| summarize count() by FileName, ProcessCommandLine, DeviceName
| sort by count_ desc
```

#### T1027 - Obfuscation & Encoding
```kusto
DeviceProcessEvents
| where FileName in ("powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine contains "-EncodedCommand"
    or ProcessCommandLine contains "frombase64string"
    or ProcessCommandLine contains "powershell -e"
    or ProcessCommandLine contains "powershell /e"
    or ProcessCommandLine contains "mshta vbscript:"
    or ProcessCommandLine contains "javascript:"
| where ProcessCommandLine !contains "Nutanix"
| summarize EventCount=count() by FileName, ProcessCommandLine, AccountName, DeviceName
| where EventCount <= 15
| sort by EventCount desc
```

#### T1567.002 - Data Exfiltration Over Web
```kusto
DeviceProcessEvents
| where FileName in ("curl.exe", "wget.exe", "ftp.exe")
| summarize count() by FileName, ProcessCommandLine, AccountName, DeviceName
| where count_ <= 15
| sort by count_ desc
```

### Splunk SPL

#### T1566.001 - Spearphishing Attachment
```spl
index=main parent_process_name IN (winword.exe, excel.exe, powerpnt.exe) 
process_name IN (powershell.exe, cmd.exe, wscript.exe)
| stats count by parent_process_name, process_name, host
| sort - count
```

#### T1059.001 - Obfuscated PowerShell Execution
```spl
index=main parent_process_name=powershell.exe 
(process_command_line="*-EncodedCommand*" OR 
process_command_line="*IEX (New-Object Net.WebClient*" OR 
process_command_line="*Invoke-Expression*")
| stats count by parent_process_name, process_name, process_command_line, host, os
| sort - count
```

#### T1003 - OS Credential Dumping
```spl
index=main (parent_process_name IN (mimikatz.exe, procdump.exe, ntdsutil.exe) OR 
process_command_line="*sekurlsa::logonpasswords*" OR 
process_command_line="*-ma lsass*" OR 
process_command_line="*lsadump::sam*")
| stats count by parent_process_name, process_name, process_command_line, host
| sort - count
```

#### T1574.002 - DLL Side-loading
```spl
index=main file_name="*.dll" 
(file_path="*\\Users\\Public\\*" OR file_path="*\\Temp\\*")
| stats count by file_name, file_path, host
| sort - count
```

#### T1547.001 - Registry-Based Persistence
```spl
index=main registry_key_path="*Software\\Microsoft\\Windows\\CurrentVersion\\Run*" 
registry_action="modified"
NOT (registry_key_path="*Microsoft Edge Update*" OR 
registry_key_path="*MicrosoftEdgeAutoLaunch*" OR 
registry_key_path="*RtkAudUService*" OR 
registry_key_path="*OneDrive*")
| stats count by registry_key_path, registry_action, process_name, host
| sort - count
```

#### T1218 - LOLBin Abuse
```spl
index=main process_name IN (regsvr32.exe, mshta.exe, rundll32.exe)
(process_command_line="*http*" OR process_command_line="*.dll*" OR 
process_command_line="*javascript:*" OR process_command_line="*vbscript:*" OR 
process_command_line="*hxxp://*" OR process_command_line="*hxxps://*")
NOT (process_command_line="*spool*" OR process_command_line="*Prnntfy.dll*" OR 
process_command_line="*pla.dll*" OR process_command_line="*printui.dll*")
| stats count by process_name, process_command_line
| sort - count
```

#### T1027 - Obfuscation & Encoding
```spl
index=main process_name IN (powershell.exe, cscript.exe, wscript.exe, mshta.exe, regsvr32.exe, rundll32.exe)
(process_command_line="*-EncodedCommand*" OR process_command_line="*frombase64string*" OR 
process_command_line="*powershell -e*" OR process_command_line="*powershell /e*" OR 
process_command_line="*mshta vbscript:*" OR process_command_line="*javascript:*")
NOT (process_command_line="*Nutanix*")
| stats count as event_count by process_name, process_command_line, user, host
| where event_count <= 15
| sort - event_count
```

#### T1567.002 - Data Exfiltration Over Web
```spl
index=main process_name IN (curl.exe, wget.exe, ftp.exe)
| stats count as event_count by process_name, process_command_line, user, host
| where event_count <= 15
| sort - event_count
```

### Elastic KQL (Elasticsearch Query Language)

#### T1566.001 - Spearphishing Attachment
```
process.parent.name : ("winword.exe" OR "excel.exe" OR "powerpnt.exe") 
AND process.name : ("powershell.exe" OR "cmd.exe" OR "wscript.exe")
```

#### T1059.001 - Obfuscated PowerShell Execution
```
process.parent.name : "powershell.exe" 
AND (process.command_line : "-EncodedCommand" 
  OR process.command_line : "IEX (New-Object Net.WebClient" 
  OR process.command_line : "Invoke-Expression")
```

#### T1003 - OS Credential Dumping
```
(process.parent.name : ("mimikatz.exe" OR "procdump.exe" OR "ntdsutil.exe")
OR process.command_line : ("sekurlsa::logonpasswords" OR "-ma lsass" OR "lsadump::sam"))
```

#### T1574.002 - DLL Side-loading
```
file.name : "*.dll" 
AND (file.path : "*\\Users\\Public\\*" OR file.path : "*\\Temp\\*")
```

#### T1547.001 - Registry-Based Persistence
```
registry.key : "*Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
AND event.action : "RegistryValueSet"
AND NOT (registry.key : "*Microsoft Edge Update*" 
  OR registry.key : "*MicrosoftEdgeAutoLaunch*" 
  OR registry.key : "*RtkAudUService*" 
  OR registry.key : "*OneDrive*")
```

#### T1218 - LOLBin Abuse
```
process.name : ("regsvr32.exe" OR "mshta.exe" OR "rundll32.exe")
AND (process.command_line : ("http" OR ".dll" OR "javascript:" OR "vbscript:" OR "hxxp://" OR "hxxps://"))
AND NOT (process.command_line : ("spool" OR "Prnntfy.dll" OR "pla.dll" OR "printui.dll"))
```

#### T1027 - Obfuscation & Encoding
```
process.name : ("powershell.exe" OR "cscript.exe" OR "wscript.exe" OR "mshta.exe" OR "regsvr32.exe" OR "rundll32.exe")
AND (process.command_line : ("-EncodedCommand" OR "frombase64string" OR "powershell -e" OR "powershell /e" OR "mshta vbscript:" OR "javascript:"))
AND NOT (process.command_line : "Nutanix")
```

#### T1567.002 - Data Exfiltration Over Web
```
process.name : ("curl.exe" OR "wget.exe" OR "ftp.exe")
```

---

## Results

### Threat Hunt Findings

#### Activity Detection Status
- **Confirmed Compromise**: No confirmed indicators of active compromise detected
- **Suspicious Behavior**: No anomalous behavior matching MuddyWater APT patterns observed
- **Query Coverage**: All 9 detection queries executed successfully across the environment

#### False Positives Identified

**Legitimate Security Testing Tool**
- **Tool**: Picus.Simulator.exe (security validation framework)
- **Behavior**: Simulated credential dumping techniques including:
  - Execution of Mimikatz simulation: `schtasks /create /f /sc minute /mo 5 /tn GameOver`
  - Procdump LSASS memory dump: `procdump.exe -accepteula -ma lsass.exe`
- **Classification**: Legitimate security assessment activity
- **Recommendation**: Exclude Picus-related processes from T1003 detection

#### Query Results Summary

| Detection | Query Status | Findings | False Positives |
|-----------|--------------|----------|-----------------|
| T1566.001 | Executed | No results | None |
| T1059.001 | Executed | No results | None |
| T1003 | Executed | Picus simulator matches | Picus.Simulator.exe (legitimate) |
| T1574.002 | Executed | No results | None |
| T1071.001 | Executed | No results | None |
| T1547.001 | Executed | No results | Microsoft Edge, OneDrive (excluded) |
| T1218 | Executed | No results | Printer drivers (excluded) |
| T1027 | Executed | No results | Nutanix (excluded) |
| T1567.002 | Executed | No results | None |

---

## Detection Tuning

### Filters Applied

The following filters were applied during the hunt to reduce false positives and improve signal quality:

#### T1003 - Credential Dumping
- **Exclusion**: Picus.Simulator.exe (security testing framework)
- **Rationale**: Picus is a legitimate red team simulation tool that deliberately mimics credential dumping
- **Impact**: Eliminates expected false positives from scheduled security assessments

#### T1547.001 - Registry Persistence
- **Exclusions**:
  - Microsoft Edge Update processes
  - MicrosoftEdgeAutoLaunch registry operations
  - RtkAudUService (Realtek audio service)
  - OneDrive synchronization components
- **Rationale**: These are legitimate Windows components that regularly modify Run registry keys
- **Impact**: Reduces noise while maintaining sensitivity to malicious persistence

#### T1218 - LOLBin Abuse
- **Exclusions**:
  - Process command lines containing "spool" (printer spooler)
  - DLL parameters: Prnntfy.dll, pla.dll, printui.dll
- **Rationale**: Printer subsystem legitimately uses LOLBins with these specific parameters
- **Impact**: Maintains detection of suspicious LOLBin usage while avoiding printer-related alerts

#### T1027 - Obfuscation
- **Exclusions**: Nutanix-related processes
- **Rationale**: Nutanix hypervisor management legitimately uses encoded parameters
- **Impact**: Eliminates infrastructure-specific false positives

### Remaining Blind Spots

1. **In-Memory Attacks**: Detection relies on process/registry/network events. Pure in-memory attacks without disk/network indicators may not be detected.

2. **Legitimate Administrative Obfuscation**: Legitimate admins may use PowerShell encoding for secure credential passing. Current detection flags this as suspicious.

3. **Compromised Legitimate Infrastructure**: C2 detection uses TLD reputation, but adversaries may use compromised legitimate domains. Requires external threat intelligence integration.

4. **DLL Side-Loading Variants**: Detection focuses on Public/Temp directories. Side-loading from other locations (Program Files, AppData) may be missed.

5. **Encrypted C2 Channels**: HTTPS C2 communication is encrypted. Current detection relies on destination reputation, not payload analysis.

6. **Living-Off-The-Land Variations**: Detection focuses on common LOLBins. Newer or less common LOLBins may not trigger alerts.

---

## Detection Opportunities

### Short-Term Improvements

1. **AMSI Integration**: Enable AMSI (Antimalware Scan Interface) logging for PowerShell to detect obfuscation evasion techniques before execution.

2. **Process Hollowing Detection**: Add detection for process creation with suspicious memory patterns indicating code injection.

3. **Parent Process Anomaly**: Implement statistical analysis of legitimate parent-child process relationships to identify outliers.

4. **Script Block Logging**: Enable PowerShell Script Block Logging to capture obfuscated commands in decoded form.

### Medium-Term Improvements

1. **Threat Intelligence Integration**: Integrate real-time domain reputation feeds to improve C2 detection accuracy and reduce false positives.

2. **Behavioral Analytics**: Implement machine learning models to detect anomalous credential access patterns and lateral movement.

3. **Registry Baseline**: Establish baseline registry modification patterns by endpoint and alert on significant deviations.

4. **Network Traffic Analysis**: Deploy network detection and response (NDR) to identify suspicious outbound patterns regardless of encryption.

5. **Office Macro Analysis**: Integrate office document macro analysis into EDR platform to detect malicious macros before execution.

### Long-Term Strategic Improvements

1. **Kill Chain Correlation**: Implement SOAR (Security Orchestration, Automation and Response) to correlate multiple low-confidence detections into high-confidence incidents.

2. **Adversary Behavior Profiles**: Build threat actor-specific behavioral models based on MuddyWater and similar APT groups' known patterns.

3. **Deception Technology**: Deploy honeypots, decoys, and fake credentials to detect reconnaissance and lateral movement attempts.

4. **Supply Chain Monitoring**: Extend detection to third-party software and supplier networks that may be targeted for lateral movement.

---

## Lessons Learned

### Hunt Methodology Improvements

1. **Hypothesis Validation**: The clean query results demonstrate the importance of validating hunt hypotheses against current threat actor TTPs. Ensure threat intelligence is current (last 6 months).

2. **Environmental Baseline**: Establish comprehensive endpoint baselines before hypothesis-driven hunts to distinguish between benign and suspicious activity.

3. **False Positive Management**: Proactively identify legitimate tools (Picus, Nutanix, security frameworks) before the hunt to avoid alert fatigue.

4. **Query Optimization**: The SentinelOne queries required tuning through multiple iterations. Consider starting with lower-confidence detections to understand data characteristics.

### Detection Engineering Recommendations

1. **Cross-Platform Standardization**: Maintaining consistent detection logic across SentinelOne, Sentinel, Splunk, and Elastic requires careful documentation and testing.

2. **Exclusion Strategy**: Rather than excluding entire process names, consider excluding specific parent processes or command-line combinations for surgical accuracy.

3. **Time-Series Analysis**: Integrate baseline analysis with detection to identify anomalies relative to normal operations rather than absolute thresholds.

4. **Threat Actor Evolution**: MuddyWater and similar actors continuously evolve TTPs. Schedule quarterly detection reviews to incorporate new intelligence.

### Operational Recommendations

1. **Credential Dumping Whitelisting**: Explicitly whitelist security testing tools (Picus, Qualys, Rapid7) to prevent alert fatigue while maintaining detection integrity.

2. **Hunt Frequency**: Conduct quarterly MuddyWater APT-specific hunts rather than ad-hoc investigations to maintain ongoing visibility.

3. **Threat Intelligence Integration**: Subscribe to threat intelligence feeds focused on Iranian state-sponsored activity and integrate indicators into detections.

4. **Tabletop Exercises**: Conduct tabletop exercises with detected kill chain scenarios to validate incident response procedures before real events.

---

## References

### MITRE ATT&CK
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [T1566.001 - Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1574.002 - Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [T1218 - System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [T1027 - Obfuscation or Encoding](https://attack.mitre.org/techniques/T1027/)
- [T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)

### Threat Intelligence
- [MuddyWater Overview - MITRE](https://attack.mitre.org/groups/G0069/)
- ClearSky Research - MuddyWater Attribution Reports
- Microsoft Threat Intelligence - Mercury (MuddyWater) Campaign Analysis
- ESET Research - MuddyWater APT Activity Reports

### Tools & Standards
- [Sigma Rules - Detection as Code](https://sigma.readthedocs.io/)
- [SentinelOne Platform Documentation](https://sentinelone.com/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Splunk Documentation](https://docs.splunk.com/)
- [Elastic Security Documentation](https://www.elastic.co/guide/en/security/current/)

---

## License

MIT License - See LICENSE file for details

**Author**: Detection Engineering Team  
**Date**: March 2025  
**Status**: Production Ready
