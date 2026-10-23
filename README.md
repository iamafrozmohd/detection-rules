# Detection Rules Library

![Validate Sigma rules](https://github.com/iamafrozmohd/detection-rules/actions/workflows/validate-sigma.yml/badge.svg)

A small, documented library of Windows threat detections written in **[Sigma](https://sigmahq.io/)**, mapped to **MITRE ATT&CK**, with hand-written **Splunk (SPL)** and **KQL (Microsoft Sentinel / Defender XDR)** versions.

Every rule explains *what* it catches, *why attackers do it*, and *what a false positive looks like*, because a detection is only as good as the analyst's ability to triage it.

---

## Rules

| Rule | ATT&CK | Log source | Level |
|---|---|---|---|
| [PowerShell Execution With Encoded Command](rules/powershell_encoded_command.yml) | T1059.001, T1027 | Process creation (Sysmon 1 / EDR) | Medium |
| [Office Application Spawning a Shell or Script Host](rules/office_spawns_shell.yml) | T1566.001, T1204.002 | Process creation | High |
| [LSASS Memory Dump via Comsvcs MiniDump](rules/lsass_dump_comsvcs.yml) | T1003.001 | Process creation | High |
| [Scheduled Task Created via Schtasks](rules/schtasks_create.yml) | T1053.005 | Process creation | Low |
| [User Added to Local Administrators Group](rules/user_added_to_local_admins.yml) | T1098 | Windows Security 4732 | Medium |
| [Local User Account Created](rules/local_user_account_created.yml) | T1136.001 | Windows Security 4720 | Low |
| [Windows Security Event Log Cleared](rules/security_log_cleared.yml) | T1070.001 | Windows Security 1102 | High |

Plus a threshold-based **brute force / password spray hunt** (T1110) in the [Splunk](queries/splunk.md) and [KQL](queries/kql.md) query files.

### ATT&CK coverage by tactic
| Tactic | Techniques covered |
|---|---|
| Initial Access | T1566.001 Spearphishing Attachment |
| Execution | T1059.001 PowerShell · T1204.002 Malicious File · T1053.005 Scheduled Task |
| Persistence | T1136.001 Local Account · T1098 Account Manipulation · T1053.005 Scheduled Task |
| Privilege Escalation | T1098 Account Manipulation |
| Defense Evasion | T1027 Obfuscated Files or Information · T1070.001 Clear Windows Event Logs |
| Credential Access | T1003.001 LSASS Memory · T1110 Brute Force (hunt) |

---

## Repository layout
```
rules/                 Sigma rules (one detection per file)
queries/splunk.md      SPL version of every rule + brute-force hunt
queries/kql.md         KQL version of every rule + brute-force hunt
.github/workflows/     CI: validates every rule with sigma-cli on each push
```

## How it's validated
A GitHub Actions workflow runs on every change to `rules/`:
1. `sigma check` validates syntax, required fields and rule quality.
2. `sigma convert` confirms each rule converts cleanly to Splunk and KQL.

Run the same checks locally:
```bash
pip install sigma-cli
sigma plugin install splunk
sigma check rules/
sigma convert -t splunk --without-pipeline rules/
```

## Triage notes
How I'd approach each alert as a SOC analyst:

- **Encoded PowerShell:** decode the Base64 (`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("..."))`), check the parent process and user, and look for network connections or file writes right after.
- **Office spawning a shell:** treat as likely phishing. Identify the document and email sender, check whether other users received the same attachment, and isolate the host if the child process reached out to the internet.
- **Comsvcs MiniDump:** assume credentials are compromised. Isolate the host, reset credentials for accounts that logged on there, and look for lateral movement.
- **Log cleared:** confirm who cleared it and why. Pull logs from the SIEM (they were forwarded before clearing) for the window just before the event.
- **New local account / added to Administrators:** match against change tickets, check who made the change (SubjectUserName), and check whether the new account has logged on.
- **Schtasks /create:** inspect the task's action and trigger, and the binary it runs. Tasks running from user-writable paths (AppData, Temp, ProgramData) deserve a closer look.

## Roadmap
- [ ] Test each rule against simulated attacks in a home lab (Atomic Red Team) and add screenshots of the detections firing
- [ ] Add Linux rules (SSH brute force, suspicious cron, new sudoers entries)
- [ ] Add cloud rules (Azure sign-in anomalies, Entra ID role assignments)

## References
- [Sigma specification](https://github.com/SigmaHQ/sigma-specification) and [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS project](https://lolbas-project.github.io/)

---
*Author: Afroz Mohammed · [LinkedIn](https://www.linkedin.com/in/iamafrozmohd)*
