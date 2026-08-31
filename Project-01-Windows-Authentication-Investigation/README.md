# Project 1 — Windows Authentication & Endpoint Investigation

## Overview

A hands-on SOC investigation conducted in a controlled Windows 11 laboratory environment.

The investigation examined a sequence of failed and successful authentication events and correlated Windows Security telemetry with Sysmon process-creation data.

## Scenario

Four failed authentication attempts against the `LabUser` account were recorded at:

**31/08/2026 01:36:18**

A successful interactive authentication occurred 13 seconds later:

**31/08/2026 01:36:31**

The authentication originated from the local host using the IPv6 loopback address `::1`.

## Investigation

### Failed Authentication — Event ID 4625

The failed authentication event identified:

- **Target account:** `LabUser`
- **Account domain:** `SOCAnalyst`
- **Subject account:** `SOCAnalyst2`
- **Logon Type:** `2 — Interactive`
- **Failure reason:** Unknown user name or bad password
- **Status:** `0xC000006D`
- **Sub-status:** `0xC000006A`
- **Source:** `::1`
- **Authentication Package:** `Negotiate`
- **Logon Process:** `seclogo`

### Successful Authentication — Event ID 4624

A successful authentication for `LabUser` occurred 13 seconds later.

Key evidence:

- **Account:** `SOCAnalyst\LabUser`
- **Logon Type:** `2 — Interactive`
- **Logon ID:** `0x1AA763`
- **Workstation:** `SOCANALYST`
- **Source:** `::1`
- **Authentication Package:** `Negotiate`
- **Logon Process:** `seclogo`

## Endpoint Correlation

Sysmon Event ID 1 recorded creation of:

`C:\Windows\System32\cmd.exe`

The process ran as:

`SOCAnalyst\LabUser`

The process contained the same Logon ID:

`0x1AA763`

This provided a direct correlation between the successful authentication and the subsequent `cmd.exe` process.

The parent process was:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

running under:

`SOCAnalyst\SOCAnalyst2`

## System Discovery Activity

A separate LabUser session was subsequently used to execute:

- `whoami`
- `hostname`
- `ipconfig`

These commands are commonly used for system and network discovery.

The observed processes were associated with Logon ID:

`0x649075`

This differs from the original successful authentication Logon ID of `0x1AA763`.

Therefore, the discovery activity is documented as a **separate LabUser session** rather than being incorrectly attributed to the original authentication session.

## Process Relationship

```text
SOCAnalyst2
    |
    └── PowerShell (PID 8468)
            |
            └── cmd.exe (PID 8220)
                    |
                    └── conhost.exe (PID 8420)

Logon ID: 0x1AA763
User: SOCAnalyst\LabUser


Separate discovery session:

LabUser
    |
    └── cmd.exe (PID 352)
            ├── whoami.exe (PID 2247)
            ├── hostname.exe (PID 1708)
            └── ipconfig.exe (PID 4132)

Logon ID: 0x649075
