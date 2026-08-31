# Project 1 — Windows Authentication & Endpoint Investigation

## Overview

A hands-on SOC investigation conducted in a controlled Windows 11 laboratory environment.

The investigation focused on:

- Windows authentication failures
- Successful authentication correlation
- Windows Security Event IDs 4625 and 4624
- Sysmon Event ID 1
- Logon ID correlation
- Parent-child process analysis
- System discovery activity
- Evidence-based incident assessment

## Scenario

Four failed authentication attempts against the `LabUser` account were recorded at:

31/08/2026 01:36:18

A successful interactive authentication occurred 13 seconds later at:

31/08/2026 01:36:31

The authentication originated locally from the host using the IPv6 loopback address `::1`.

## Investigation

Security Event ID 4625 identified:

- Target account: `LabUser`
- Logon Type: `2`
- Failure reason: Unknown user name or bad password
- Status: `0xC000006D`
- Sub-status: `0xC000006A`
- Source: `::1`

The subsequent Event ID 4624 recorded a successful authentication for:

`SOCAnalyst\LabUser`

with Logon ID:

`0x1AA763`

Sysmon Event ID 1 subsequently recorded `cmd.exe` running as:

`SOCAnalyst\LabUser`

with the same Logon ID, providing a correlation between the authentication event and process execution.

## Endpoint Activity

Further investigation identified the following system discovery commands in a separate LabUser session:

- `whoami`
- `hostname`
- `ipconfig`

These commands are dual-use and can be used for legitimate administration as well as reconnaissance.

## Assessment

The authentication sequence initially warranted investigation because multiple failed logons were followed shortly by a successful authentication.

However, the activity originated locally and the subsequent discovery commands do not, by themselves, establish malicious activity.

Given the controlled laboratory context and the absence of additional evidence indicating persistence, privilege escalation, credential access, or malicious network activity, the final assessment was:

**Benign / Controlled Lab Activity**

## Skills Demonstrated

- Windows Event Log analysis
- PowerShell
- Sysmon
- Authentication analysis
- Logon ID correlation
- Process-tree analysis
- Timeline reconstruction
- System discovery analysis
- Evidence-based incident classification
- SOC investigation documentation
