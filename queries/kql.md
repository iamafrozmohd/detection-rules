# KQL versions (Microsoft Sentinel / Defender XDR)

- Process rules use the Defender for Endpoint table `DeviceProcessEvents`.
- Windows Security event rules use the Sentinel table `SecurityEvent`.

---

### PowerShell Execution With Encoded Command (T1059.001, T1027)
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe") or ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")
| where ProcessCommandLine has_any (" -enc ", " -enco", " -EncodedCommand", " -ec ")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### User Added to Local Administrators Group (T1098)
```kql
SecurityEvent
| where EventID == 4732 and TargetSid == "S-1-5-32-544"
| project TimeGenerated, Computer, SubjectUserName, MemberName, MemberSid, TargetUserName
```

### Local User Account Created (T1136.001)
```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, SubjectUserName, TargetUserName
```

### Windows Security Event Log Cleared (T1070.001)
```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, SubjectUserName
```

### Scheduled Task Created via Schtasks (T1053.005)
```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where AccountDomain !in~ ("NT AUTHORITY", "AUTORITE NT")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### LSASS Memory Dump via Comsvcs MiniDump (T1003.001)
```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE"
| where ProcessCommandLine has "comsvcs" and ProcessCommandLine has "minidump"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### Office Application Spawning a Shell or Script Host (T1566.001, T1204.002)
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

---

### Bonus hunt: password brute force / spraying (T1110)
```kql
SecurityEvent
| where EventID == 4625
| summarize failures = count(), users_tried = dcount(TargetUserName), users = make_set(TargetUserName, 20)
    by IpAddress, bin(TimeGenerated, 10m)
| where failures >= 20
| extend pattern = iff(users_tried >= 10, "possible password spray", "possible brute force")
| order by failures desc
```
