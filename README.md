# Raheem Saied — Cybersecurity Portfolio

## Associate Cyber Security Professional (ACSP) | SOC Analyst

Welcome to my cybersecurity portfolio.

I am an Associate Cyber Security Professional (ACSP) building practical experience in **Security Operations Centre (SOC) analysis, Windows endpoint investigation, security monitoring, incident analysis and security controls**.

My background includes **8+ years of experience in regulated financial services**, where I developed strong analytical judgement, investigation, risk awareness, control-focused thinking and compliance experience.

This portfolio demonstrates how I am applying those transferable skills to hands-on cybersecurity investigations.

---

## Professional Qualifications & Recognition

- **CompTIA Security+**
- **CompTIA Network+**
- **AWS Certified AI Practitioner**
- **UK Cyber Security Council — Recognised Associate Cyber Security Professional (ACSP)**

---

# Cybersecurity Projects

## Project 1 — Windows Authentication & Endpoint Investigation

Investigated a controlled Windows authentication sequence involving multiple failed logons followed by a successful authentication.

The investigation correlated Windows Security authentication events with Sysmon process telemetry to reconstruct the authentication and endpoint activity timeline.

### Key areas investigated

- Windows Security Event ID **4625** — Failed Logon
- Windows Security Event ID **4624** — Successful Logon
- Logon ID correlation
- Logon Type analysis
- Source address and workstation analysis
- Sysmon Event ID **1** — Process Create
- Parent/child process relationships
- PowerShell and Windows Command Shell activity
- User and session attribution
- Timeline reconstruction
- Evidence-based assessment

### MITRE ATT&CK techniques

- **T1059.001 — Command and Scripting Interpreter: PowerShell**
- **T1059.003 — Command and Scripting Interpreter: Windows Command Shell**
- **T1033 — System Owner/User Discovery**
- **T1082 — System Information Discovery**
- **T1016 — System Network Configuration Discovery**

### Assessment

The activity was assessed as **Benign / Controlled Lab Activity**.

The investigation identified the authentication sequence and associated endpoint activity while distinguishing the original session from separate later activity through Logon ID correlation.

**[View Project 1 →](./Project-01-Windows-Authentication-Investigation)**

---

## Project 2 — Windows Scheduled Task Persistence Investigation

Investigated a controlled scheduled-task persistence simulation on a Windows endpoint.

The investigation used Windows Security auditing, Task Scheduler Operational telemetry and Sysmon process telemetry to examine task creation, registration and execution-related activity.

### Key areas investigated

- Windows Security Event ID **4698** — Scheduled Task Created
- Task Scheduler Operational Event ID **106**
- Task Scheduler Operational Event ID **110**
- Task Scheduler Operational Event ID **325**
- Scheduled task configuration analysis
- Task action and trigger analysis
- `Get-ScheduledTaskInfo`
- Task execution result validation
- Sysmon Event ID **1** process investigation
- Timeline reconstruction
- Telemetry validation
- Identification of monitoring limitations

### MITRE ATT&CK technique

- **T1053.005 — Scheduled Task/Job: Scheduled Task**

### Assessment

The activity was assessed as **Benign / Controlled Lab Activity**.

The investigation confirmed scheduled-task creation and associated Task Scheduler activity. However, independent Sysmon evidence of the `whoami.exe` process execution was not identified.

This was documented as a **telemetry gap rather than assuming execution had occurred solely from the available task results**.

**[View Project 2 →](./Project-02-Windows-Scheduled-Task-Investigation)**

---

## Project 3 — Windows Network Connection & Endpoint Investigation

Investigated outbound network activity from a Windows endpoint using native Windows TCP telemetry and Sysmon process telemetry.

The investigation examined network connections, owning process IDs, executable paths, users, Logon IDs, parent processes and process integrity levels.

A key part of the investigation was validating whether Sysmon Event ID 3 network telemetry was available and documenting the resulting telemetry limitation.

### Key areas investigated

- Sysmon Event ID **3** — Network Connection
- Sysmon Event ID **1** — Process Create
- `Get-NetTCPConnection`
- `Test-NetConnection`
- Network destination IP and port analysis
- Owning PID attribution
- Process identification
- User and Logon ID correlation
- Parent/child process relationships
- Process integrity analysis
- Microsoft Windows process analysis
- PID reuse considerations
- Telemetry-gap identification
- Evidence-based assessment

### MITRE ATT&CK techniques

- **T1049 — System Network Connections Discovery**
- **T1057 — Process Discovery**

### Assessment

The activity was assessed as **Benign / Controlled Lab Activity — Low Suspicion**.

Native Windows TCP telemetry exposed active network connections and associated process IDs. Sysmon Event ID 3 was not available on the endpoint despite a configured `NetworkConnect` filter, creating an important telemetry gap.

The investigation therefore used available Windows and Sysmon process telemetry to correlate network activity with available endpoint telemetry while avoiding unsupported conclusions about the origin of individual connections.

### SOC lesson

A security investigation should not rely on a single telemetry source.

When expected telemetry is unavailable, an analyst should:

1. Validate whether the telemetry source is functioning.
2. Identify alternative data sources.
3. Correlate available evidence.
4. Clearly document limitations.
5. Avoid making conclusions that the evidence cannot support.

**[View Project 3 →](./Project-03-Windows-Network-Connection-Endpoint-Investigation)**

---

# Technical Skills

### Windows Security & Endpoint Investigation

- Windows Event Viewer
- Windows Security Events
- Security Event IDs 4624, 4625 and 4698
- Task Scheduler Operational Events
- Sysmon
- Sysmon Event ID 1 — Process Create
- Sysmon Event ID 3 — Network Connection
- Process and parent/child analysis
- User and session attribution
- Logon ID correlation
- Timeline reconstruction
- Endpoint telemetry validation
- Telemetry-gap analysis

### Networking

- TCP/IP fundamentals
- IP address and port analysis
- Network connection investigation
- `Get-NetTCPConnection`
- `Test-NetConnection`
- `ipconfig`
- Network process attribution

### Security Analysis

- Security event investigation
- Authentication analysis
- Persistence investigation
- Endpoint investigation
- Process analysis
- Evidence correlation
- Timeline reconstruction
- Detection-oriented thinking
- MITRE ATT&CK mapping
- Risk-based assessment
- Identification of monitoring and telemetry gaps

### Cloud & AI

- AWS fundamentals
- AWS Certified AI Practitioner
- AI concepts and responsible AI awareness

---

# Tools & Technologies

- Windows 11
- Oracle VirtualBox
- Windows Event Viewer
- Sysmon
- PowerShell
- Windows Command Shell
- Task Scheduler
- Windows native networking tools
- GitHub
- MITRE ATT&CK

---

# Investigation Approach

My approach to security investigations is evidence-driven and structured around:

### 1. Establish the environment

Identify the endpoint, users, services and relevant telemetry sources.

### 2. Define the activity

Determine what action occurred, when it occurred and which account or process was involved.

### 3. Collect evidence

Use Windows event logs, Sysmon and native Windows tools to gather relevant telemetry.

### 4. Correlate events

Use timestamps, process IDs, Logon IDs, users, parent processes and other available fields to connect related activity.

### 5. Validate the evidence

Check whether expected telemetry is actually present rather than assuming that a configured security control is producing usable data.

### 6. Assess the activity

Determine whether the observed behaviour is benign, suspicious or requires further investigation.

### 7. Document limitations

Clearly distinguish between:

- Confirmed evidence
- Reasonable observations
- Unconfirmed activity
- Telemetry gaps

This approach is intended to reflect the analytical discipline required in a real SOC environment.

---

# Portfolio Goals

I am continuing to develop practical capability in:

- SOC monitoring and alert investigation
- Windows endpoint detection and response
- Security event analysis
- Incident investigation
- Threat detection
- Network security monitoring
- SIEM concepts
- MITRE ATT&CK
- Detection engineering fundamentals
- Security automation
- Cloud security

Future projects will build on the investigations above and introduce additional SOC workflows, detection scenarios and security tooling.

---

# About Me

I am developing my career in cybersecurity with a particular interest in **SOC Analyst, Security Operations, Cyber Defence and Incident Response** roles.

My previous experience in regulated financial services has developed strong skills in:

- Investigation
- Analytical decision-making
- Risk assessment
- Controls and compliance
- Attention to detail
- Handling sensitive information
- Working within regulated environments
- Clear documentation
- Evidence-based decision-making

I am applying these skills to practical cybersecurity investigations through this portfolio.

---

# Professional Links

- **LinkedIn:** [linkedin.com/in/raheemsaied](https://www.linkedin.com/in/raheemsaied/)
- **GitHub:** [github.com/RaheemSaied](https://github.com/RaheemSaied)

---

## Disclaimer

All investigations in this portfolio were conducted in a **controlled Windows laboratory environment** for educational and professional development purposes.

No unauthorised systems, accounts or networks were targeted.

The security activity described in these projects was intentionally generated or investigated within the lab environment.
