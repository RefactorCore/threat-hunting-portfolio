# MITRE ATT&CK Framework Mapping

## Executive Summary

The MuddyWater APT threat hunt covers 9 distinct MITRE ATT&CK techniques across 6 tactics in the kill chain. This mapping documents detection coverage, confidence levels, and gaps in the current detection strategy.

---

## Mapping by Tactic

### Initial Access

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Phishing: Spearphishing Attachment | T1566.001 | Office Application Spawning Command Interpreter | PARTIAL | HIGH | Detects macro execution, not initial email delivery |
| Phishing: Spearphishing Link | T1566.002 | None | NONE | N/A | Not included in this hunt - requires browser-level detection |

**Gap Analysis**: Detection only covers email attachment exploitation, not phishing links or user-initiated downloads. No email security integration.

---

### Execution

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Obfuscated PowerShell Command Execution | FULL | HIGH | Covers encoded commands and IEX patterns |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Office Application Spawning Command Interpreter (partial) | PARTIAL | MEDIUM | Detects cmd.exe spawned from Office, not standalone |
| System Binary Proxy Execution | T1218 | Living-off-the-Land Binaries (LOLBin) Abuse Detection | FULL | HIGH | Covers regsvr32, mshta, rundll32, certutil with suspicious params |
| System Binary Proxy Execution: Regsvr32 | T1218.010 | Living-off-the-Land Binaries Detection | FULL | HIGH | Specific coverage via regsvr32 pattern detection |
| System Binary Proxy Execution: Mshta | T1218.005 | Living-off-the-Land Binaries Detection | FULL | HIGH | Specific coverage via mshta pattern detection |
| System Binary Proxy Execution: Rundll32 | T1218.011 | Living-off-the-Land Binaries Detection | FULL | HIGH | Specific coverage via rundll32 pattern detection |

**Gap Analysis**: Limited visibility into command-line execution without Office context. No detection of .NET execution or COM object instantiation.

---

### Persistence

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Registry Run Key Modification for Persistence | FULL | HIGH | Covers HKLM and HKCU Run key modifications |
| Scheduled Task/Job | T1053.005 | None (partial correlation possible) | PARTIAL | MEDIUM | No dedicated detection; correlates with registry detection |
| Windows Service | T1543.003 | None | NONE | N/A | Not included in threat hunt scope |

**Gap Analysis**: Limited persistence detection to Registry Run keys. No monitoring of RunOnce, Services, Scheduled Tasks (beyond correlation).

---

### Privilege Escalation

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Abuse Elevation Control Mechanism: User Access Control Bypass | T1548.002 | None | NONE | N/A | Not included in hunt; requires UAC event monitoring |

**Gap Analysis**: No privilege escalation detection. MuddyWater often targets organizations with limited logging of UAC events.

---

### Defense Evasion

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | Suspicious DLL Execution from Non-Standard Paths | PARTIAL | MEDIUM | Covers Public and Temp directories; may miss other locations |
| Obfuscation or Encoding: Command Obfuscation | T1027.001 | Obfuscation & Encoding Detection | FULL | HIGH | Covers Base64, XOR, and encoding indicators |
| Obfuscation or Encoding | T1027 | Obfuscation & Encoding Detection | FULL | HIGH | Comprehensive coverage of encoding patterns |

**Gap Analysis**: No detection of process injection, AMSI bypassing, or script-level obfuscation evasion techniques.

---

### Credential Access

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| OS Credential Dumping | T1003 | OS Credential Dumping Detection | FULL | CRITICAL | Covers Mimikatz, Procdump, ntdsutil |
| OS Credential Dumping: LSASS Memory | T1003.001 | OS Credential Dumping Detection (partial) | PARTIAL | HIGH | Detects procdump targeting LSASS, not all methods |
| OS Credential Dumping: SAM | T1003.002 | OS Credential Dumping Detection (partial) | PARTIAL | MEDIUM | Covers ntdsutil-based SAM dumping |
| OS Credential Dumping: NTDS | T1003.003 | OS Credential Dumping Detection (partial) | PARTIAL | MEDIUM | Ntdsutil detection covers NTDS.dit extraction |

**Gap Analysis**: No detection of legitimate Windows tools (vssadmin, reg.exe, volume shadow copies) used for credential dumping. High false-positive rate from security testing tools.

---

### Discovery

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| System Network Configuration Discovery | T1016 | None | NONE | N/A | Not included in hunt scope |
| Permission Groups Discovery | T1069 | None | NONE | N/A | Not included in hunt scope |
| Remote System Discovery | T1018 | None | NONE | N/A | Not included in hunt scope |

**Gap Analysis**: Discovery phase completely undetected. MuddyWater extensively reconnaissance networks before lateral movement.

---

### Lateral Movement

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Remote Services: Remote Desktop Protocol | T1021.001 | None | NONE | N/A | Requires network/authentication event detection |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | None | NONE | N/A | Requires network monitoring |
| Remote Services: WMI | T1021.006 | None | NONE | N/A | Requires WMI event logging |

**Gap Analysis**: No lateral movement detection. Critical gap as MuddyWater relies on RDP/SMB for network spread.

---

### Command and Control

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Application Layer Protocol: Web Protocols | T1071.001 | Suspicious C2 Communication Over HTTPS | PARTIAL | MEDIUM | Covers suspicious TLD reputation only; no threat intel integration |

**Gap Analysis**: Limited C2 detection to TLD reputation. No DNS, HTTP header analysis, or behavioral C2 detection.

---

### Exfiltration

| Technique | ID | Detection Name | Coverage | Confidence | Notes |
|-----------|----|----|----------|-----------|-------|
| Exfiltration Over Alternative Protocol: Data Over Web Service | T1567.002 | Data Exfiltration Over Web Detection | PARTIAL | MEDIUM | Covers curl/wget/ftp execution only |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.003 | None | NONE | N/A | Requires cloud integration detection |

**Gap Analysis**: Limited exfiltration detection. Only covers legacy file transfer tools, not modern cloud-based exfiltration methods.

---

## Tactical Coverage Summary

### Coverage by Kill Chain Stage

```
Initial Access:        ██████░░░░ 60%   (Email attachment detected, not delivery)
Execution:             ████████░░ 80%   (PowerShell, LOLBins covered)
Persistence:          ████░░░░░░ 40%   (Registry only, missing tasks/services)
Privilege Escalation:  ░░░░░░░░░░  0%   (Not detected)
Defense Evasion:      ██████░░░░ 60%   (Obfuscation detected, injection/AMSI not covered)
Credential Access:    ████████░░ 80%   (Tools detected, native alternatives missed)
Discovery:            ░░░░░░░░░░  0%   (Not detected)
Lateral Movement:     ░░░░░░░░░░  0%   (Not detected)
Command & Control:    ████░░░░░░ 40%   (Limited to TLD reputation)
Exfiltration:         ████░░░░░░ 40%   (Legacy tools only)
```

### Overall Coverage
- **Total Techniques Covered**: 9 of ~150 MITRE ATT&CK techniques
- **High Confidence Detections**: 6
- **Medium Confidence Detections**: 3
- **Coverage Percentage**: ~30% of common APT techniques

---

## Technique Details

### T1566.001 - Phishing: Spearphishing Attachment

**Description**: Sending emails with malicious attachments (Office documents with macros)

**Detection Capability**:
- ✅ Detects macro execution when Office spawns shell
- ❌ Does not detect email receipt
- ❌ Does not detect initial attachment delivery
- ⚠️ May miss macro evasion techniques

**Confidence**: HIGH (macro execution is nearly unambiguous indicator)

**Improvement Opportunities**:
- Integrate email gateway logs to track attachment reception
- Monitor email-to-process correlation
- Detect macro-less exploitation techniques

---

### T1059.001 - Command and Scripting Interpreter: PowerShell

**Description**: Using PowerShell for execution with obfuscation/encoding

**Detection Capability**:
- ✅ Detects EncodedCommand parameter
- ✅ Detects IEX and Invoke-Expression patterns
- ✅ Detects Base64 encoding patterns
- ❌ Does not detect other encoding methods
- ❌ May miss PowerShell 2.0 or in-memory execution
- ⚠️ Legitimate encoding usage creates false positives

**Confidence**: HIGH (encoding strongly suggests malicious intent)

**Improvement Opportunities**:
- Enable Script Block Logging for command decoding
- Implement AMSI integration
- Build user role baselines for legitimate encoding

---

### T1003 - OS Credential Dumping

**Description**: Extracting credentials from system memory

**Detection Capability**:
- ✅ Detects Mimikatz execution
- ✅ Detects Procdump targeting LSASS
- ✅ Detects specific credential dumping commands
- ❌ Does not detect native Windows alternatives (vssadmin, reg.exe)
- ❌ May miss in-memory attacks
- ⚠️ Security testing tools create legitimate false positives

**Confidence**: CRITICAL (credential dumping is virtually always malicious in operational context)

**Improvement Opportunities**:
- Add LSASS memory access monitoring
- Monitor vssadmin and volume shadow copy activities
- Implement behavioral analysis for admin tool usage

---

### T1574.002 - Hijack Execution Flow: DLL Side-Loading

**Description**: Loading malicious DLLs alongside legitimate executables

**Detection Capability**:
- ✅ Detects DLL execution from Public and Temp directories
- ❌ May miss other non-standard locations
- ❌ Cannot correlate DLL with legitimate executable loading it
- ⚠️ Legitimate software staging creates false positives

**Confidence**: MEDIUM (requires additional context for confirmation)

**Improvement Opportunities**:
- Add module load event monitoring
- Correlate DLL creation with executable loading
- Monitor DLL import anomalies

---

### T1071.001 - Application Layer Protocol: Web Protocols

**Description**: C2 communication over HTTPS using suspicious infrastructure

**Detection Capability**:
- ✅ Identifies HTTPS connections to suspicious TLDs
- ❌ Cannot inspect HTTPS payload
- ❌ No threat intelligence integration
- ⚠️ May false positive on legitimate business use of suspicious TLDs

**Confidence**: MEDIUM (TLD alone insufficient for high confidence)

**Improvement Opportunities**:
- Integrate threat intelligence feeds
- Monitor DNS query patterns
- Implement network behavioral analysis

---

### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

**Description**: Adding registry Run keys for persistence

**Detection Capability**:
- ✅ Detects HKLM and HKCU Run key modifications
- ❌ Does not detect RunOnce or other persistence mechanisms
- ⚠️ Legitimate software frequently modifies Run keys

**Confidence**: HIGH (when unauthorized process modifies)

**Improvement Opportunities**:
- Add baseline of legitimate Run key entries
- Monitor alternative registry persistence locations
- Implement source process analysis

---

### T1218 - System Binary Proxy Execution

**Description**: Abusing LOLBins for code execution and evasion

**Detection Capability**:
- ✅ Detects regsvr32, mshta, rundll32, certutil with suspicious parameters
- ✅ Identifies HTTP/HTTPS/JavaScript/VBScript patterns
- ❌ May miss newer LOLBin abuse techniques
- ⚠️ Legitimate uses of these binaries create false positives

**Confidence**: HIGH (when suspicious parameters present)

**Improvement Opportunities**:
- Add cmdkey, eventvwr, and other emerging LOLBins
- Implement parent process analysis
- Build behavioral baselines for each LOLBin

---

### T1027 - Obfuscation or Encoding

**Description**: Using encoding (Base64, XOR) to hide malicious code

**Detection Capability**:
- ✅ Detects Base64 encoding patterns
- ✅ Identifies common encoding parameters
- ❌ Does not detect custom encoding schemes
- ⚠️ Legitimate administration may use encoding

**Confidence**: HIGH (when combined with suspicious execution context)

**Improvement Opportunities**:
- Add AMSI logging for command decoding
- Implement behavioral detection of decoded payloads
- Build user role baselines

---

### T1567.002 - Exfiltration Over Alternative Protocol

**Description**: Using file transfer utilities (curl, wget, ftp) to exfiltrate data

**Detection Capability**:
- ✅ Detects curl, wget, ftp execution with web protocols
- ❌ Does not detect modern cloud exfiltration
- ❌ May miss renamed or obfuscated tools
- ⚠️ Legitimate IT operations use these tools

**Confidence**: MEDIUM (requires correlation with data access)

**Improvement Opportunities**:
- Monitor sensitive data access before exfiltration
- Implement volume-based exfiltration detection
- Add cloud service integration

---

## Critical Detection Gaps

### Completely Undetected Techniques

1. **Discovery Phase (T1016, T1018, T1069, T1087)**
   - Network reconnaissance completely undetected
   - No logging of `ipconfig`, `whoami`, `net view` commands
   - Risk: **CRITICAL** - Cannot detect reconnaissance before attack

2. **Lateral Movement (T1021.001, T1021.002, T1021.006)**
   - RDP, SMB, WMI lateral movement undetected
   - Requires network or authentication monitoring
   - Risk: **CRITICAL** - Cannot prevent network spread

3. **Privilege Escalation (T1548.002)**
   - UAC bypass and privilege escalation undetected
   - Requires advanced Windows security event monitoring
   - Risk: **HIGH** - Cannot detect escalation attempts

### Partially Detected Techniques

1. **Initial Access (T1566.001)**
   - Only detects post-exploitation macro execution
   - Email delivery phase not monitored
   - Risk: **MEDIUM** - Early warning unavailable

2. **Persistence (T1547.001)**
   - Only monitors Registry Run keys
   - Services, Tasks, and other mechanisms undetected
   - Risk: **MEDIUM** - Limited persistence coverage

3. **Command & Control (T1071.001)**
   - Only reputation-based TLD filtering
   - Encrypted payload analysis unavailable
   - Risk: **MEDIUM** - Compromised infrastructure may bypass detection

---

## Recommended Detection Priorities

### Phase 1 (Weeks 1-4): Quick Wins
1. Add Script Block Logging for PowerShell
2. Enable Credential Guard for LSASS protection
3. Integrate threat intelligence feeds for domain reputation

### Phase 2 (Weeks 5-12): Core Gaps
1. Implement lateral movement detection (RDP/SMB analysis)
2. Add discovery phase detection
3. Expand persistence monitoring to Tasks and Services

### Phase 3 (Weeks 13-24): Advanced Detection
1. Implement behavioral analytics for kill chain correlation
2. Add machine learning models for anomaly detection
3. Deploy deception technology and honeypots

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MuddyWater APT Profile](https://attack.mitre.org/groups/G0069/)
- [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
