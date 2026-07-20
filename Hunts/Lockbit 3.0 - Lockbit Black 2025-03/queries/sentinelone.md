# SentinelOne Deep Visibility Queries — LockBit 3.0

All queries below were executed against SentinelOne Deep Visibility (process
creation telemetry). Field names follow the SentinelOne Deep Visibility Query
Language: `tgt.process.image.path`, `tgt.process.cmdline`,
`src.process.cmdline`, `src.process.parent.cmdline`, `endpoint.name`.

Exclusions for known-benign IT management, security, and virtualization
tooling have been generalized from the original hunt (see
[`false-positives/tuning.md`](../false-positives/tuning.md) for the full
rationale behind each exclusion).

---

## T1059 — Command and Scripting Interpreter

```sql
(tgt.process.image.path contains ("\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\cscript.exe")
 and tgt.process.cmdline contains ("-ExecutionPolicy Bypass", "-NoProfile", "Invoke-WebRequest",
 "vssadmin delete shadows", "taskkill /F /IM", "schtasks /create /tn", "wmic process call create"))
and src.process.cmdline != "<IT_MANAGEMENT_AGENT_1>"
and src.process.parent.cmdline != "<PAM_AGENT>"
and src.process.cmdline != "<VULN_MGMT_AGENT>"
and src.process.cmdline != "<IT_DISCOVERY_AGENT>"
and src.process.cmdline != "*<HYPERVISOR_TOOLING>*"
| limit 100000
| group cmdline_count = count() by src.process.parent.cmdline, src.process.cmdline, tgt.process.cmdline
| sort -cmdline_count
```

## T1068 — Exploitation for Privilege Escalation

```sql
(tgt.process.image.path contains ("\\exploit.exe", "\\JuicyPotato.exe", "\\PrintSpoofer.exe",
 "\\msiexec.exe", "\\schtasks.exe"))
AND !(src.process.cmdline contains "<PATCH_MGMT_AGENT>")
AND !(src.process.cmdline contains "<ENDPOINT_AGENT_UPDATER>")
AND !(src.process.cmdline contains "<VULN_MGMT_AGENT>")
AND !(src.process.cmdline contains "Global\MSI0000")
AND !(src.process.cmdline contains "ms-teamsupdate.exe")
| group cmdline1 = count() by tgt.process.image.path, src.process.cmdline
| sort cmdline1
```

```sql
tgt.process.cmdline contains ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
 "schtasks /create /tn", "msiexec /quiet /qn /i")
| group cmdline1 = count() by tgt.process.cmdline, src.process.cmdline
```

## T1027 — Obfuscated Files or Information

```sql
(tgt.process.image.path contains ("\\powershell.exe", "\\cmd.exe", "\\msiexec.exe", "\\rundll32.exe",
 "\\regsvr32.exe")
 and tgt.process.cmdline contains ("-Enc", "FromBase64String", "Invoke-Expression",
 "New-Object System.Net.WebClient", "rundll32.exe javascript:\\..\\mshtml,RunHTMLApplication",
 "regsvr32 /s /n /u /i"))
| group process1 = count() by tgt.process.image.path, src.process.cmdline
| sort process1
```

## T1562.001 — Disable or Modify Security Tools

```sql
(tgt.process.image.path contains ("\\powershell.exe", "\\cmd.exe", "\\taskkill.exe", "\\wmic.exe",
 "\\sc.exe", "\\wevtutil.exe")
 and tgt.process.cmdline contains ("Set-MpPreference -DisableRealtimeMonitoring",
 "Set-MpPreference -DisableBehaviorMonitoring", "taskkill /F /IM", "net stop", "sc stop", "wevtutil cl"))
AND !(src.process.cmdline contains "<PATCH_MGMT_AGENT>")
| group process1 = count() by tgt.process.image.path, src.process.cmdline
| sort process1
```

## T1003 — OS Credential Dumping

```sql
(tgt.process.image.path contains ("\\mimikatz.exe", "\\procdump.exe", "\\reg.exe", "\\ntdsutil.exe"))
AND !(src.process.cmdline contains "<JAVA_RUNTIME_UPDATER>")
AND !(src.process.cmdline contains "<PATCH_MGMT_AGENT>")
AND !(src.process.cmdline contains "<IT_DISCOVERY_AGENT>")
AND !(src.process.cmdline contains "<ERROR_HANDLING_SCRIPT>")
| group process1 = count() by tgt.process.image.path, src.process.cmdline
| sort process1
```

```sql
tgt.process.cmdline contains ("sekurlsa::logonpasswords", "sekurlsa::wdigest", "lsadump::sam",
 "reg save HKLM\\SAM", "ntdsutil \"ac i ntds\" \"ifm\" \"create full\"")
```

## T1046 — Network Service Scanning

```sql
(tgt.process.image.path contains ("\\nmap.exe", "\\netscan.exe", "\\advanced_port_scanner.exe",
 "\\powershell.exe", "\\cmd.exe")
 and tgt.process.cmdline contains ("nmap -sS", "Test-NetConnection", "net view", "net use \\"))
| group process1 = count() by tgt.process.image.path, src.process.cmdline, endpoint.name
| sort process1
```

## T1021 — Remote Services

```sql
(tgt.process.image.path contains ("\\mstsc.exe", "\\cmd.exe", "\\powershell.exe", "\\wmic.exe",
 "\\ssh.exe")
 and tgt.process.cmdline contains ("cmdkey /generic:TERMSRV", "mstsc /v:", "net use \\",
 "wmic /node:", "New-PSSession -ComputerName", "Invoke-Command -Session"))
| group process1 = count() by tgt.process.image.path, src.process.cmdline, endpoint.name
| sort process1
```

## T1486 — Data Encrypted for Impact

```sql
(tgt.process.image.path contains ("\\lockbit3.exe", "\\vssadmin.exe", "\\wbadmin.exe", "\\bcdedit.exe",
 "\\powershell.exe")
 and tgt.process.cmdline contains ("/encrypt /path:", "vssadmin delete shadows /all /quiet",
 "bcdedit /set {default} recoveryenabled No", "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
 "Get-ChildItem -Path \\"))
AND (src.process.cmdline contains ("\\lockbit3.exe", "\\vssadmin.exe", "\\wbadmin.exe", "\\bcdedit.exe",
 "\\powershell.exe")
 and src.process.cmdline contains ("/encrypt /path:", "vssadmin delete shadows /all /quiet",
 "bcdedit /set {default} recoveryenabled No", "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
 "Get-ChildItem -Path \\"))
| group process1 = count() by tgt.process.image.path, src.process.cmdline, endpoint.name
| sort process1
```

## T1490 — Inhibit System Recovery

```sql
tgt.process.cmdline contains ("vssadmin delete shadows /all /quiet", "wbadmin delete catalog -quiet",
 "bcdedit /set {default} recoveryenabled No", "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
 "wmic shadowcopy delete",
 "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v DisableSR /t REG_DWORD /d 1 /f")
| group process1 = count() by tgt.process.cmdline, src.process.cmdline, endpoint.name
| sort process1
```

## T1489 — Service Stop

```sql
(tgt.process.image.path contains ("\\taskkill.exe", "\\sc.exe", "\\net.exe")
 and tgt.process.cmdline contains ("taskkill /F /IM", "sc stop", "net stop", "WinDefend",
 "SecurityHealthService", "MSSQLSERVER", "VSS", "wbengine", "EventLog"))
| group process1 = count() by tgt.process.cmdline, src.process.cmdline, endpoint.name
| sort process1
```
