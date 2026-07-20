# Detection Engineering Notes

## Overview

This document provides detailed engineering analysis for each detection implemented in the MuddyWater APT threat hunt. Each detection explains:
- **Why** the detection exists
- **How** attackers evade it
- **What** logging is required
- **What** blind spots remain
- **How** to improve it

---

## T1566.001 - Spearphishing Attachment Detection

### Why This Detection Exists

Spearphishing with malicious attachments is the primary initial access vector for sophisticated threat actors. The MuddyWater group has historically used weaponized Office documents containing embedded macros or ActiveX objects to establish initial footholds.

**Attack Flow**:
1. Attacker sends phishing email with office document attachment
2. User opens document, triggering macro execution
3. Macro contains PowerShell/VBScript commands for payload download
4. Macro launches command interpreter to execute scripts
5. Command interpreter downloads and executes remote malware

This detection catches the critical step where Office applications spawn command interpreters - a virtually unambiguous indicator of malicious macro execution or document exploitation.

### How Attackers Evade This Detection

1. **Alternative Execution Methods**
   - Use Office features (OLE, embedded objects) that execute without spawning child processes
   - Leverage DLL injection techniques within Office process memory
   - Use built-in Windows features accessed through Office object models

2. **File Extension Obfuscation**
   - Rename .docm (macro-enabled) to .doc or .pdf
   - Use misleading icons to disguise file type
   - Exploit Office default settings to auto-enable macros for .xls files

3. **Social Engineering**
   - Convince user to enable macros through pretexting
   - Create plausible business justification for macro requests
   - Use lookalike file names from trusted organizations

4. **Legitimate Office Functionality**
   - Use Office add-ins or plugins that legitimately spawn interpreters
   - Abuse Office update mechanisms to execute code
   - Exploit Office cloud integration features

### Logging Requirements

For this detection to function, the following must be logged:

| Log Source | Required Field | Log Type | Event ID |
|-----------|----------------|----------|----------|
| EDR (SentinelOne) | Process Creation | Parent-Child Process | Any |
| Windows Event Log | Process Creation | Sysmon | Event 1 |
| Windows Event Log | Process Creation | Security | Event 4688 |
| Splunk | process_name, parent_process_name | Any Windows process source | N/A |

**Specific Required Fields**:
- Parent Process Name: `InitiatingProcessFileName`, `ParentImage`, `parent_process_name`
- Child Process Name: `FileName`, `Image`, `process_name`
- Process Command Line (for extended analysis): `CommandLine`, `ProcessCommandLine`, `process_command_line`
- Endpoint Identifier: `DeviceName`, `ComputerName`, `host`

### Current Blind Spots

1. **In-Process Code Execution**
   - Macros using Office object models to execute code without child process spawning
   - Example: Using ADODB.Stream and XMLHttpRequest for remote downloads
   - Impact: **HIGH** - Completely bypasses this detection

2. **Alternative File Delivery**
   - Malware delivered via cloud services (SharePoint, OneDrive, Teams)
   - File downloaded and executed after user clicks sharing link
   - Impact: **MEDIUM** - Requires network and file execution detection

3. **Delayed Execution**
   - Macros that schedule tasks or create registry entries for later execution
   - Macro closes without spawning child processes
   - Execution occurs via scheduled task or registry autorun
   - Impact: **HIGH** - Initial macro execution not detected

4. **Office Plugin Abuse**
   - Malicious Excel add-ins (.xlam files)
   - Word template injection
   - Outlook add-in exploitation
   - Impact: **HIGH** - Legitimately spawns child processes

5. **User-Initiated Execution**
   - Attacker convinces user to copy-paste malicious commands from document
   - Attacker directs user to manually open Command Prompt and execute downloaded script
   - Impact: **MEDIUM** - No Office-to-interpreter connection in logs

### Detection Improvement Recommendations

#### Short-Term (1-2 weeks)

1. **Add Registry Monitoring**
   - Monitor Office-related registry keys for suspicious modifications
   - Watch for task scheduler entries created by Office processes
   - Track Office add-in registry entries for malicious additions

2. **Enhanced Filtering**
   - Whitelist legitimate Office plugins in your environment
   - Exclude Office update processes
   - Identify and exclude legitimate IT operations

3. **Command-Line Analysis**
   - Analyze spawned interpreter command lines for suspicious patterns
   - Flag if command includes downloading (IEX, DownloadString, wget)
   - Alert on encoded/obfuscated commands

#### Medium-Term (1-3 months)

1. **AMSI Integration**
   - Enable Antimalware Scan Interface (AMSI) logging
   - Capture obfuscated commands before execution
   - Monitor PowerShell Script Block Logging

2. **Behavioral Analytics**
   - Establish baseline of normal Office-to-PowerShell interactions
   - Detect anomalies based on user role and frequency
   - Implement machine learning models for unknown patterns

3. **Email Gateway Integration**
   - Track emails with attachments to user who triggered detection
   - Correlate email sender reputation with process execution
   - Identify if document was delivered via email or USB

#### Long-Term (3-6 months)

1. **Deception Technology**
   - Deploy decoy Office documents with monitoring
   - Track access to honeypot resources from Office processes
   - Alert immediately on any interaction with decoys

2. **Threat Intelligence Integration**
   - Track Office document hash against malware databases
   - Monitor for known malicious macro code patterns
   - Integrate with sandbox analysis results

3. **Extended Kill Chain Monitoring**
   - Correlate with network outbound connections
   - Track file downloads initiated by Office-spawned processes
   - Monitor memory injection attempts following Office process creation

---

## T1059.001 - Obfuscated PowerShell Execution

### Why This Detection Exists

PowerShell is a powerful scripting language built into Windows that threat actors extensively abuse for:
- Fileless malware execution
- Lateral movement
- Data exfiltration
- Living-off-the-land attacks

MuddyWater group heavily relies on PowerShell for post-exploitation activities. They encode and obfuscate commands to evade:
- Signature-based detection
- Manual analyst review
- Automated sandboxes
- Intrusion detection systems

The presence of `-EncodedCommand`, `IEX`, and Base64 patterns are strong indicators of malicious intent rather than legitimate administration.

### How Attackers Evade This Detection

1. **Alternative Encoding**
   - Use XOR encoding instead of Base64
   - Implement custom obfuscation algorithms
   - Chain multiple encoding layers
   - Use string concatenation without obvious -EncodedCommand

2. **Legitimate Administrative Patterns**
   - System administrators may legitimately use encoding for:
     - Passing credentials securely
     - Transporting scripts between systems
     - Automation frameworks (Puppet, Chef, Ansible)
   - False positives from legitimate operations mask real alerts

3. **AMSI Bypass**
   - Modify AMSI.dll in memory to disable scanning
   - Use alternative PowerShell hosts (pwsh.exe, ISE)
   - Downgrade to PowerShell 2.0 without logging

4. **Script Block Logging Bypass**
   - Disable logging before script execution
   - Use obfuscated disable commands
   - Execute scripts from compressed or encoded containers

5. **In-Memory Code Execution**
   - Load PowerShell assemblies without spawning process
   - Use .NET reflection to execute code
   - Execute PowerShell through COM automation

### Logging Requirements

| Log Source | Required Field | Log Type | Event ID |
|-----------|----------------|----------|----------|
| EDR (SentinelOne) | Process Creation | Parent-Child Process | Any |
| Windows Event Log | Process Creation | Sysmon | Event 1, Event 11 |
| PowerShell | Script Block Logging | PowerShell/Operational | Event 4104 |
| PowerShell | Module Logging | PowerShell/Operational | Event 4103 |
| EDR | Script Execution | Any script execution log | N/A |

**Critical Fields**:
- Process Name: Must be `powershell.exe`
- Command Line: Must contain full command arguments
- Script Block Logging: Required for command decoding
- Parent Process: Required to identify origin

### Current Blind Spots

1. **PowerShell 2.0 Legacy Support**
   - PowerShell 2.0 does not support modern logging
   - Attackers may downgrade to bypass logging
   - Impact: **CRITICAL** - Completely bypasses detection

2. **Legitimate Encoding Use Cases**
   - Many legitimate tools encode PowerShell commands
   - IT operations may use encoded credentials
   - Ansible/Puppet may encode complex commands
   - Impact: **MEDIUM** - High false positive rate

3. **In-Memory PowerShell Execution**
   - PowerShell can be invoked through .NET reflection
   - C++ malware can host PowerShell runtime
   - No process execution logs generated
   - Impact: **HIGH** - Complete bypass

4. **Alternative Command Shells**
   - Pwsh.exe (PowerShell Core) may not be monitored
   - Different logging paths may not be captured
   - Impact: **MEDIUM** - Depends on environment

5. **Compression and Encryption**
   - Attackers may compress payloads to evade pattern matching
   - Encrypted PowerShell scripts won't match signatures
   - Runtime decryption occurs in memory
   - Impact: **HIGH** - Sophisticated evasion

### Detection Improvement Recommendations

#### Short-Term (1-2 weeks)

1. **Enable Script Block Logging**
   ```powershell
   New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
   ```

2. **Implement Transcription Logging**
   ```powershell
   New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Logs\PowerShell"
   ```

3. **Monitor PowerShell Event 4104 (Script Block)**
   ```kusto
   Get-WinEvent -LogName "Windows PowerShell" -FilterXPath "*[System[(EventID=4104)]]" -MaxEvents 100
   ```

#### Medium-Term (1-3 months)

1. **Command-Line Argument Analysis**
   - Parse and decode Base64 encoded commands
   - Alert on specific malicious patterns in decoded content
   - Implement behavioral signatures for known malware families

2. **Process Parent Analysis**
   - Establish baseline of legitimate PowerShell parents
   - Alert on unusual parent processes (Network processes, Office, browsers)
   - Correlate parent process with user context

3. **Registry/File Modification Monitoring**
   - Monitor attempts to disable PS logging
   - Track AMSI.dll tampering
   - Flag PowerShell execution policy changes

#### Long-Term (3-6 months)

1. **Machine Learning Detection**
   - Build models to distinguish legitimate from malicious obfuscation patterns
   - Identify anomalous PowerShell behavior
   - Create user-specific baselines

2. **Constrained Language Mode**
   - Implement AppLocker policies to restrict PowerShell execution
   - Use Device Guard to enforce code integrity
   - Require signed scripts in sensitive environments

---

## T1003 - OS Credential Dumping

### Why This Detection Exists

Credential dumping is the critical step enabling lateral movement and privilege escalation. Once attackers obtain credentials, they can:
- Move laterally through the network
- Access sensitive data repositories
- Escalate privileges to administrative accounts
- Establish persistent access

The presence of credential dumping tools like Mimikatz or Procdump virtually always indicates a serious compromise requiring immediate investigation.

### How Attackers Evade This Detection

1. **Custom Credential Dumping Tools**
   - Write custom dumping utilities to avoid signature detection
   - Leverage legitimate OS features (ntdsutil, vssadmin)
   - Use undocumented APIs for memory access

2. **In-Memory Attacks**
   - Inject credential dumping code into legitimate processes
   - Use direct memory access (DMA) attacks
   - Avoid writing tools to disk entirely

3. **Renamed or Obfuscated Tools**
   - Rename Mimikatz to legitimate executable names
   - Pack executables to change hashes
   - Execute from alternative paths

4. **Windows Native Alternatives**
   - Use vssadmin to access Volume Shadow Copy (contains NTDS.dit)
   - Use ntdsutil for legitimate backup operations
   - Use reg.exe to dump registry hives

5. **Legitimate Security Tools**
   - Abuse Picus Simulator, Rapid7 Nexpose, Qualys for credential testing
   - These tools legitimately dump credentials for assessment
   - Difficult to distinguish from malicious use

### Logging Requirements

| Log Source | Required Field | Log Type | Event ID |
|-----------|----------------|----------|----------|
| EDR (SentinelOne) | Process Execution | Process Creation | Any |
| Windows Event Log | Process Execution | Sysmon | Event 1 |
| Windows Event Log | LSASS Access | Sysmon | Event 10 |
| Windows Event Log | File Create | Sysmon | Event 11 |
| EDR | Command Line Arguments | Process Creation | N/A |

**Critical Fields**:
- Process executable path and name
- Full command-line arguments
- Parent process (to identify lateral movement source)
- LSASS memory access attempts (Process Access event)

### Current Blind Spots

1. **Legitimate Testing Tools**
   - Security scanning platforms legitimately dump credentials
   - Picus Simulator, Qualys, Rapid7, Tenable tools use Mimikatz
   - Current filter excludes these, may miss malicious operators impersonating testing
   - Impact: **MEDIUM** - Filtering reduces effectiveness

2. **Native Windows Alternatives**
   - vssadmin/ntdsutil can dump credentials without triggering this detection
   - Registry dump tools can extract SAM/SECURITY hives
   - No tool name signature to alert on
   - Impact: **HIGH** - Common attack path

3. **Lateral Movement via RDP/SMB**
   - Remote dumping may occur with different process names
   - Domain controllers may handle dumps differently
   - Impact: **MEDIUM** - Requires network-based detection

4. **In-Memory Injection**
   - Credentials dumped within legitimate process memory
   - No obvious process name indicators
   - Requires process memory analysis
   - Impact: **HIGH** - Sophisticated evasion

5. **Offline Attacks**
   - Physical disk access to dump credentials
   - USB-based memory dump tools
   - Virtualization-based credential extraction
   - Impact: **CRITICAL** - Out of scope for logs

### Detection Improvement Recommendations

#### Short-Term (1-2 weeks)

1. **Add LSASS Access Monitoring**
   ```xml
   <Rule name="LsassAccess" groupRelation="or">
     <ProcessAccess condition="is">lsass.exe</ProcessAccess>
   </Rule>
   ```

2. **Monitor vssadmin and ntdsutil Usage**
   ```kusto
   process.name : ("vssadmin.exe" OR "ntdsutil.exe")
   AND (process.command_line : ("diskshadow" OR "delete shadows" OR "ntdsutil"))
   ```

3. **Enhance Exclusions with Context**
   - Exclude security testing tools only during scheduled windows
   - Track user context for legitimate credential access
   - Require approval workflow for testing tools

#### Medium-Term (1-3 months)

1. **Process Access Event Correlation**
   - Correlate LSASS access with credential dumping tools
   - Alert on unexpected LSASS access attempts
   - Track memory dump file creation patterns

2. **Network-Based Detection**
   - Monitor for unusual authentication patterns
   - Alert on impossible travel (credential use from multiple locations)
   - Track unusual credential delegation

3. **Registry Hive Dumping Detection**
   - Monitor SAM, SECURITY, SYSTEM hive access
   - Alert on registry export operations
   - Track suspicious reg.exe commands

#### Long-Term (3-6 months)

1. **Endpoint Hardening**
   - Enable Credential Guard (Windows Defender Credential Guard)
   - Implement Protected Process Light for LSASS
   - Use multi-factor authentication to reduce credential value

2. **Behavioral Detection**
   - Establish baseline of legitimate admin tool usage
   - Alert on anomalous credential access patterns
   - Implement deception technology with fake credentials

---

## T1574.002 - DLL Side-loading

### Why This Detection Exists

DLL side-loading is a sophisticated defense evasion technique where threat actors place malicious DLLs alongside legitimate executables that load them by default. This allows:
- Code execution while appearing legitimate
- Bypassing application whitelisting
- Evading signature-based detection
- Establishing persistence with low suspicion

MuddyWater and other sophisticated actors use this technique with stolen legitimate applications.

### How Attackers Evade This Detection

1. **Alternative DLL Locations**
   - Place DLLs in legitimate program directories
   - Use application-specific directories with proper permissions
   - Exploit DLL search path order to load from unexpected locations

2. **Legitimate Installer Activity**
   - Package malicious DLL with legitimate software installers
   - Place DLL in temp during installation, move to legitimate location later
   - Abuse software packaging tools

3. **Timing Evasion**
   - Create DLL well before execution (not detected in real-time)
   - Execute DLL after significant time delay
   - Load on system startup when monitoring may be lighter

4. **Process Hollowing**
   - Replace DLL content after loading begins
   - Use legitimate DLL initially, modify in memory
   - Requires advanced execution capabilities

### Logging Requirements

| Log Source | Required Field | Log Type | Event ID |
|-----------|----------------|----------|----------|
| EDR (SentinelOne) | File Operations | File Write/Create | N/A |
| Windows Event Log | File Creation | Sysmon | Event 11 |
| Windows Event Log | DLL Load | Sysmon | Event 7 |
| EDR | Module Load | Process injection monitoring | N/A |

### Current Blind Spots

1. **Legitimate Software Updates**
   - Software vendors legitimately write DLLs to temp during updates
   - Windows Update staging DLLs in temporary directories
   - Distinguishing malicious from benign is difficult

2. **Administrative Legitimate Use**
   - IT operations may stage software in temp/public directories
   - Application deployment tools use similar patterns

3. **DLL Execution Timing**
   - DLL may be created days before execution
   - Real-time detection may miss delayed loading
   - Requires correlating file creation with actual loading

### Detection Improvement Recommendations

1. **Add Module Load Monitoring**
   - Monitor Sysmon Event 7 (Image Loaded)
   - Correlate DLL path with creation time
   - Alert on loading from suspicious directories

2. **Parent Process Analysis**
   - Identify legitimate executables known to load DLLs
   - Alert on unusual parent processes
   - Monitor for renamed legitimate executables

---

## T1071.001 - Suspicious C2 Connections

### Why This Detection Exists

Outbound network connections to suspicious domains indicate command-and-control (C2) communication for:
- Receiving attacker commands
- Downloading additional payloads
- Exfiltrating sensitive data
- Maintaining persistent access

Detection of C2 communication is critical for stopping attacks before damage escalates.

### How Attackers Evade This Detection

1. **Compromised Legitimate Infrastructure**
   - Use hacked legitimate servers hosted on trusted TLDs
   - Rent infrastructure from legitimate providers
   - Current detection relies on TLD reputation, not operator reputation

2. **Domain Generation Algorithms (DGA)**
   - Generate hundreds of random domains
   - Only a few need to be active for C2 communication
   - Static lists cannot keep up with DGA-generated domains

3. **DNS Tunneling**
   - Encode C2 commands in DNS queries
   - Uses standard DNS port 53, appears legitimate
   - Detection requires DNS analysis capabilities

4. **Encrypted Traffic**
   - HTTPS encryption prevents payload inspection
   - Current detection only checks TLD reputation
   - Requires threat intelligence integration for improvement

5. **VPN and Proxy Abuse**
   - Route C2 through legitimate VPN services
   - Use legitimate proxy services
   - Difficult to distinguish from normal business traffic

### Logging Requirements

| Log Source | Required Field | Log Type | Event ID |
|-----------|----------------|----------|----------|
| Network Monitoring | Destination Domain/IP | Network Connection | N/A |
| DNS Logs | Query | DNS Query | N/A |
| Proxy Logs | HTTP CONNECT | Proxy Traffic | N/A |
| EDR | Network Connection | Outbound Connection | N/A |
| Firewall | Outbound Connection | Firewall Log | N/A |

### Current Blind Spots

1. **Legitimate Business Use of Suspicious TLDs**
   - Organizations may use .ru or .ir domains legitimately
   - Difficulty distinguishing business from malicious

2. **Compromised Infrastructure**
   - Legitimate companies' infrastructure may host C2
   - TLD alone is poor indicator of maliciousness

3. **Encrypted C2**
   - Cannot inspect HTTPS payload
   - Only destination inspection available
   - Requires threat intelligence for accuracy

### Detection Improvement Recommendations

1. **Threat Intelligence Integration**
   - Integrate with real-time IP reputation feeds
   - Use community threat intelligence (URLhaus, etc.)
   - Monitor for historical C2 server indicators

2. **DNS Monitoring**
   - Monitor for suspicious DNS query patterns
   - Alert on frequent DNS requests to suspicious domains
   - Detect DNS tunneling patterns

3. **Network Behavioral Analysis**
   - Establish baseline of normal outbound traffic
   - Alert on anomalous traffic patterns
   - Monitor for data exfiltration connections

---

## T1547.001 - Registry-Based Persistence

### Why This Detection Exists

Registry Run keys provide automatic persistence, allowing attackers to:
- Re-execute malware automatically on user login
- Maintain access across reboots
- Avoid one-time execution limitations
- Establish long-term presence with minimal overhead

### How Attackers Evade This Detection

1. **Alternative Registry Locations**
   - RunOnce keys (execute once, then delete)
   - Services registry entries
   - Scheduled tasks registry entries
   - Userinit registry modifications

2. **Registry Hive Modifications**
   - Modify registry offline by copying hives
   - Use registry editor to hide entries
   - Modify registry from kernel-mode drivers

3. **Legitimate Software Updates**
   - Microsoft Edge, OneDrive, and other services frequently modify Run keys
   - Security software adds persistence entries
   - Distinguishing malicious from benign is challenging

### Logging Requirements

| Log Source | Required Field | Log Type | Event ID |
|-----------|----------------|----------|----------|
| EDR (SentinelOne) | Registry Modification | Registry Event | N/A |
| Windows Event Log | Registry | Sysmon | Event 13 |
| Windows Event Log | Registry | Audit Policy | Event 4657 |
| Auditbeat | Registry | Auditbeat Registry | N/A |

### Detection Improvement Recommendations

1. **Registry Baseline**
   - Establish baseline of legitimate Run key entries
   - Alert on new entries not in baseline
   - Track modification source process

2. **Alternative Location Monitoring**
   - Monitor RunOnce, RunOnceEx keys
   - Track Services registry modifications
   - Monitor Userinit registry changes

---

## T1218 - LOLBin Abuse

### Why This Detection Exists

Living-off-the-Land Binaries (LOLBins) are legitimate Windows utilities frequently abused for code execution and evasion because:
- They're pre-installed, appearing normal in logs
- Many have remote download capabilities
- Some bypass execution policies or whitelisting
- Attackers avoid writing malicious executables to disk

### How Attackers Evade This Detection

1. **Legitimate Parameter Usage**
   - Many LOLBins have legitimate uses with similar parameters
   - Difficult to distinguish malicious from benign

2. **Parameter Obfuscation**
   - Split parameters across environment variables
   - Use alternate parameter formats
   - Encode or obfuscate URLs and paths

3. **Timing Evasion**
   - Execute during business hours when LOLBin usage is normal
   - Use on workstations where usage is more common

### Detection Improvement Recommendations

1. **Behavioral Analysis**
   - Establish baselines for LOLBin usage by user role
   - Alert on usage from unusual user accounts
   - Monitor for process execution chains

2. **Parent Process Analysis**
   - Identify legitimate parents for each LOLBin
   - Alert on unusual parent processes
   - Correlate with other suspicious activities

---

## T1027 - Obfuscation & Encoding

### Why This Detection Exists

Obfuscation and encoding are universal characteristics of malicious scripts, indicating:
- Attempts to evade signature detection
- Hiding command intent from analysts
- Concealing malware delivery mechanisms
- Avoiding automated sandboxes

### Detection Improvement Recommendations

1. **Decoding and Analysis**
   - Automatically decode Base64 commands
   - Alert on decoded command content (URLs, known malware commands)
   - Implement YARA rules for common malicious patterns

2. **Environmental Context**
   - Establish baseline of legitimate encoding usage
   - Alert on encoding from unusual processes
   - Correlate with user behavior anomalies

---

## T1567.002 - Data Exfiltration Over Web

### Why This Detection Exists

Data exfiltration represents the final stage of the attack, indicating:
- Successful compromise and lateral movement
- Access to valuable data repositories
- Intent to cause maximum damage

### How Attackers Evade This Detection

1. **Legitimate File Transfer Tools**
   - Use built-in cloud sync (OneDrive, Dropbox)
   - Abuse legitimate FTP/SFTP services
   - Legitimate admins also use these tools

2. **Encrypted Exfiltration**
   - Use VPN or encrypted tunnel
   - Compress data to smaller size
   - Hide in legitimate traffic

### Logging Requirements

Requires visibility into:
- Process execution and command-line arguments
- Network outbound connections with destination
- File access and data movement

### Detection Improvement Recommendations

1. **Data Context Awareness**
   - Monitor access to sensitive data repositories
   - Alert when sensitive data is accessed then exfiltrated
   - Correlate file access with network traffic

2. **Volume-Based Detection**
   - Alert on unusually large data transfers
   - Monitor for sustained exfiltration patterns
   - Baseline normal data movement by user/role

3. **Destination Reputation**
   - Integrate with threat intelligence
   - Monitor for connections to known malicious infrastructure
   - Alert on connections to suspicious cloud services

---

## Cross-Detection Correlation

### Kill Chain Analysis

Effective detection requires correlating multiple lower-confidence detections into high-confidence incidents:

1. **Office + PowerShell + C2**
   ```
   T1566.001 (Office spawning shell) → T1059.001 (Obfuscated PowerShell) → T1071.001 (C2 connection)
   = Likely initial compromise → malware execution → C2 callback
   Confidence: HIGH
   ```

2. **Credential Dumping + Lateral Movement**
   ```
   T1003 (Credential dumping) → T1021.* (Lateral movement indicators)
   = Potential privilege escalation and network spread
   Confidence: HIGH
   ```

3. **Registry Persistence + Scheduled Task**
   ```
   T1547.001 (Registry persistence) → T1053.* (Scheduled task indicators)
   = Dual persistence mechanisms indicate serious compromise
   Confidence: MEDIUM-HIGH
   ```

---

## Continuous Improvement Process

1. **Monthly Review**
   - Analyze detection performance
   - Adjust filters based on false positives
   - Update threat intelligence

2. **Quarterly Threat Hunt**
   - Re-run hunt against all detections
   - Validate detection coverage
   - Identify new evasion techniques

3. **Annual Assessment**
   - Review against updated MITRE ATT&CK framework
   - Assess new threat actor techniques
   - Redesign detections as needed
