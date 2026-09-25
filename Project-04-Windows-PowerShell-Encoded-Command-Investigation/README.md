# Project 4 — Windows PowerShell Encoded Command Investigation

## Overview

A controlled Windows endpoint investigation focused on a PowerShell process launched with `-EncodedCommand`. The objective was to determine what executed, which account and process were involved, what telemetry captured the activity, whether follow-on process or network activity was attributable to the process, and whether the activity indicated persistence or other suspicious behavior.

**Assessment: Benign / Controlled Lab Activity — Low Suspicion**

> This project is a controlled SOC laboratory exercise. The use of encoded PowerShell is treated as a detection signal requiring investigation, not as proof of malicious activity.

## Objectives

- Identify the encoded PowerShell process and its process ID.
- Correlate the process to the user and parent process.
- Use Sysmon Event ID 1 for process-creation evidence.
- Use PowerShell Operational Event ID 4104 for ScriptBlock visibility.
- Check TCP and UDP activity for the investigated PID.
- Check whether the process remained running.
- Separate evidence of execution from evidence of malicious impact.
- Document telemetry strengths and limitations.

## Environment

- Windows 11 virtual machine: `SOC-LAB-WIN11`
- User: `SOCAnalyst\SOCAnalyst2`
- PowerShell: Windows PowerShell 5.1
- Sysmon: installed and operational
- Relevant logs:
  - `Microsoft-Windows-Sysmon/Operational`
  - `Microsoft-Windows-PowerShell/Operational`

## Investigation Timeline

| Time | Evidence | Finding |
|---|---|---|
| 14:46:34 | Sysmon Event ID 1 | `powershell.exe` created as PID **4720**. |
| 14:46:34 | PowerShell Event ID 4104 | ScriptBlock containing the controlled payload was logged. |
| 14:46:34 | Command line | Process used `-NoProfile -ExecutionPolicy Bypass -EncodedCommand`. |
| 15:09 | TCP check | No TCP endpoints were observed for PID 4720. |
| 15:10 | UDP check | No UDP endpoints were observed for PID 4720. |
| 15:11 | Process-state check | PID 4720 was no longer present. |
| 15:12–15:18 | Time-scoped 4104 checks | The controlled ScriptBlock was confirmed in PowerShell logging. |

## Process Evidence

The Sysmon process-creation evidence identified:

- **Process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **PID:** `4720`
- **User:** `SOCAnalyst\SOCAnalyst2`
- **Integrity:** High
- **Parent PID:** `7252`
- **Parent image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Command line:** PowerShell launched with `-NoProfile -ExecutionPolicy Bypass -EncodedCommand`.

The use of `-EncodedCommand` and `-ExecutionPolicy Bypass` are meaningful SOC detection signals. In this controlled context, however, the surrounding evidence did not show persistence, credential access, privilege escalation, malicious network activity, or follow-on process execution.

## PowerShell ScriptBlock Evidence

PowerShell Operational Event ID **4104** captured the controlled ScriptBlock. The relevant content included:

`Write-Output 'SOC-LAB-PROJECT4-ENCODED-TEST'; Get-Date; Get-Process | Select-Object -First 3 Name,Id`

This demonstrates that Script Block Logging provided visibility into the decoded script content.

The marker string was written with `Write-Output`. A subsequent file check found no marker file, which is expected because `Write-Output` writes to the PowerShell output stream rather than creating a file.

## Network Investigation

### TCP

A process-specific TCP query for PID 4720 returned no results:

`Get-NetTCPConnection -OwningProcess 4720 -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess`

**Finding:** No active TCP connections were observed for PID 4720 at the time of the check.

### UDP

A process-specific UDP query for PID 4720 also returned no results:

`Get-NetUDPEndpoint -OwningProcess 4720 -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess`

**Finding:** No active UDP endpoints were observed for PID 4720 at the time of the check.

These are point-in-time observations. They do not prove that the process could never have communicated over the network; they show that no attributable endpoints were present during the checks.

## Process Lifetime

The final process-state check returned no process object for PID 4720:

`Get-Process -Id 4720 -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,StartTime,HasExited`

**Finding:** PID 4720 was no longer present, consistent with a short-lived PowerShell execution.

## Detection and Telemetry Assessment

### Strong visibility

- Sysmon Event ID 1 captured process creation.
- The command line exposed the use of `-EncodedCommand`.
- PowerShell Event ID 4104 exposed the ScriptBlock content.
- User, PID, parent PID, integrity level, and process path were available for correlation.
- Native Windows TCP/UDP queries provided an additional process-scoped network check.

### Important analytical limitation

The evidence establishes that the ScriptBlock was logged, but it should not be overstated as proof of every possible runtime effect. Event 4104 records the ScriptBlock content; it does not independently prove that every output operation produced a visible console result.

Similarly, a negative point-in-time network query is not proof of historical absence of network communication.

## Analyst Assessment

**Verdict: Benign / Controlled Lab Activity — Low Suspicion**

The observed PowerShell execution contained characteristics that would reasonably trigger SOC investigation:

- `powershell.exe`
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`

However, the controlled payload was intentionally benign. Correlated telemetry showed:

- known Windows PowerShell executable path;
- controlled lab user;
- captured ScriptBlock content;
- no attributable TCP endpoints;
- no attributable UDP endpoints;
- no continuing process at the final check;
- no identified persistence mechanism;
- no identified credential access or privilege escalation;
- no identified suspicious child process.

The correct SOC conclusion is therefore **benign controlled activity**, while retaining the detection value of encoded PowerShell as a high-interest signal.

## MITRE ATT&CK Mapping

| Technique | Relevance |
|---|---|
| **T1059.001 — Command and Scripting Interpreter: PowerShell** | PowerShell was the execution mechanism observed in the lab. |
| **T1027 — Obfuscated/Compressed Files and Information** | The controlled PowerShell command used encoded command content; this is relevant as a detection concept, not an assertion of adversary activity. |

## Key SOC Lessons

1. **Encoded PowerShell is a lead, not a verdict.**
2. **Correlate process creation with ScriptBlock logging.**
3. **Use PID + timestamp + user + parent process together.**
4. **Check both process and network telemetry before assessing impact.**
5. **Document negative evidence carefully as point-in-time observations.**
6. **Separate what telemetry proves from what it merely suggests.**

## Evidence

The `screenshots/` directory contains selected evidence screenshots plus raw captures from the investigation session.

Key evidence:

- `01-lab-baseline.png`
- `02-encoded-powershell-execution.png`
- `03-sysmon-process-correlation.png`
- `04-powershell-logging-correlation.png`
- `05-process-tree-and-context.png`
- `06-tcp-check.png`
- `07-udp-check.png`
- `08-process-state.png`
- `09-4104-encoded-scriptblock.png`
- `10-final-4104-confirmation.png`

## Conclusion

This investigation demonstrates a realistic SOC workflow for triaging an encoded PowerShell alert: identify the process, decode and inspect the ScriptBlock through logging, correlate the execution context, check for follow-on processes and network activity, and reach a proportionate conclusion based on the total evidence.

**Final assessment: Benign / Controlled Lab Activity — Low Suspicion.**
