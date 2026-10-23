# Splunk (SPL) versions

Assumptions: Sysmon process events (EventCode 1) and Windows Security events are ingested with the
Splunk Add-on for Microsoft Windows / Sysmon. Adjust `index=` and field names to match your environment.

```
`sysmon`   = index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
`security` = index=* sourcetype="XmlWinEventLog:Security" OR sourcetype="WinEventLog:Security"
```

---

### PowerShell Execution With Encoded Command (T1059.001, T1027)
```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll")
  (CommandLine="* -enc *" OR CommandLine="* -enco*" OR CommandLine="* -EncodedCommand*" OR CommandLine="* -ec *")
| table _time host User ParentImage Image CommandLine
```

### User Added to Local Administrators Group (T1098)
```spl
(index=* sourcetype="XmlWinEventLog:Security" OR sourcetype="WinEventLog:Security") EventCode=4732 TargetSid="S-1-5-32-544"
| table _time host SubjectUserName MemberSid MemberName TargetUserName
```

### Local User Account Created (T1136.001)
```spl
(index=* sourcetype="XmlWinEventLog:Security" OR sourcetype="WinEventLog:Security") EventCode=4720
| table _time host SubjectUserName TargetUserName
```

### Windows Security Event Log Cleared (T1070.001)
```spl
(index=* sourcetype="XmlWinEventLog:Security" OR sourcetype="WinEventLog:Security") EventCode=1102
| table _time host SubjectUserName
```

### Scheduled Task Created via Schtasks (T1053.005)
```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\schtasks.exe" CommandLine="*/create*"
  NOT (User="*AUTHORI*" OR User="*AUTORI*")
| table _time host User ParentImage CommandLine
```

### LSASS Memory Dump via Comsvcs MiniDump (T1003.001)
```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\rundll32.exe" OR OriginalFileName="RUNDLL32.EXE")
  CommandLine="*comsvcs*" CommandLine="*minidump*"
| table _time host User ParentImage CommandLine
```

### Office Application Spawning a Shell or Script Host (T1566.001, T1204.002)
```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe" OR ParentImage="*\\outlook.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe"
   OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe")
| table _time host User ParentImage Image CommandLine
```

---

### Bonus hunt: password brute force / spraying (T1110)
Threshold logic that a single-event Sigma rule can't express. Tune the threshold to your environment.
```spl
(index=* sourcetype="XmlWinEventLog:Security" OR sourcetype="WinEventLog:Security") EventCode=4625
| bin _time span=10m
| stats count AS failures dc(TargetUserName) AS users_tried values(TargetUserName) AS users BY _time IpAddress
| where failures >= 20
| eval pattern=if(users_tried >= 10, "possible password spray", "possible brute force")
| sort - failures
```
