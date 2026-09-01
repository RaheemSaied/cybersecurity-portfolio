# Project 2 — Windows Scheduled Task Persistence Investigation

## Overview

This project investigates a controlled Windows scheduled-task persistence simulation in a Windows 11 SOC lab.

A harmless scheduled task named `SOC-Lab-Discovery-Test` was created with the action:

`C:\Windows\System32\whoami.exe`

The investigation focused on identifying scheduled-task creation, registration, launch activity, and process-execution telemetry.

The project emphasizes evidence correlation and distinguishes confirmed telemetry from activity that could not be independently verified.

---

## Objectives

- Create a controlled scheduled task in a Windows 11 lab
- Enable relevant Windows auditing and Task Scheduler telemetry
- Investigate Security Event ID 4698
- Investigate Task Scheduler Operational events
- Examine the scheduled task configuration
- Attempt to correlate task execution with Sysmon process telemetry
- Reconstruct an evidence-based timeline
- Document telemetry gaps without making unsupported assumptions
- Map the activity to MITRE ATT&CK

---

## Lab Environment

**Platform:** Windows 11  
**Virtualization:** Oracle VirtualBox  
**Endpoint:** SOC-Lab-Win11 / SOCANALYST  
**Primary lab user:** `SOCAnalyst2`  
**Sysmon service:** `Sysmon`  
**Task:** `SOC-Lab-Discovery-Test`

### Scheduled Task Configuration

**Action:**

```text
C:\Windows\System32\whoami.exe
