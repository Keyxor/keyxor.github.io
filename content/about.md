---
title: "About"
hidemeta: true
ShowToc: false
ShowBreadCrumbs: false
---

## Keyxor

Security practitioner with ten years in IT and four in cybersecurity.

My paid work has been mostly defensive: vulnerability management, incident
response, and threat hunting in Microsoft Defender for Endpoint. My own time
goes mostly to offensive work, focused on web and API exploitation, Active
Directory attack paths, and source-code review.

Before moving into security I spent several years administering Active Directory
and enterprise Windows. That is where I learned authentication flows,
certificate services, and what those systems write to their logs, which has
turned out to be just as useful on the offensive side.

Writeups live in the [Offensive](/offensive/) section.

## Current Focus

- Web and API security, with SSRF as the main focus, plus injection,
  access-control, and business-logic flaws
- Offensive security: Active Directory attack chains, privilege escalation,
  CVE reproduction and n-day analysis
- Detection engineering: mapping offensive techniques to the telemetry they
  generate, then writing hunting queries against it

## What I Work On

**Web and API exploitation**
SSRF, including deny-list and URL-parser bypass, protocol smuggling, and
pivoting to internal APIs and credential exposure. Injection (SQLi to RCE,
command injection), file inclusion, IDOR and broken access control,
authentication and business-logic flaws, insecure deserialization and object
injection with gadget chains.

**Active Directory attack paths**
Kerberos abuse and AS-REP roasting, constrained and resource-based delegation,
AD CS certificate template abuse, Shadow Credentials, ACL abuse escalating to
directory replication, ADIDNS poisoning, NTLM coercion with offline credential
recovery. BloodHound for enumeration and path analysis.

**Source-code review**
Whitebox review across PHP and Python, finding injection sinks and unsafe
patterns such as unsafe subprocess and eval usage, insecure deserialization,
and predictable token generation.

**Threat detection and hunting**
KQL authoring and Advanced Hunting in Microsoft Defender for Endpoint across
process, network, logon, and file telemetry. Hypothesis-driven investigation,
anomaly and outlier analysis, scope confirmation, detection validation and
false-positive analysis, MITRE ATT&CK technique mapping.

**Incident response and forensic artifacts**
Windows Security and Sysmon event analysis: logon types, Kerberos
ticket activity, credential access, and service and scheduled-task creation.
Registry-based persistence artifacts, containment coordination, and case
documentation.

**Vulnerability management**
Triage, validation, and severity assessment (CVSS v3.1 / v4.0). Deduplication
and false-positive elimination, risk-based prioritization, vendor and advisory
research, remediation guidance and tracking to verified closure.

**Automation and tooling**
PowerShell and Python automation of investigation, validation, and reporting
workflows. Burp Suite Pro, Caido, the ProjectDiscovery suite (nuclei, httpx,
subfinder), BloodHound, Nmap, sqlmap, SysReptor, Tenable Security Center /
Nessus, Microsoft Defender for Endpoint, Active Directory and AD CS, SCCM,
Sysmon.

## Experience

**Senior Security Analyst, Vulnerability Management & Incident Response**
*Oct 2023 - Present*

Hunt for evidence of compromise and data leakage in Microsoft Defender for
Endpoint, enriching SOC-reported activity with device, account, and process
context to support response decisions. Write KQL queries to confirm scope
across affected hosts and shorten triage, then hand them to other analysts as
standing checks. Research vendor advisories and threat reporting, assess
exploitability against the environment, and translate that into prioritization
and remediation guidance for system owners. Triage and validate findings across
a large multi-tenant estate, eliminate false positives, and prioritize by risk.
Turn recurring findings into standardized triage criteria, evaluation
checklists, and reporting formats that were adopted beyond my own team.

**Senior Cyber Security Specialist (Contract), IR & Compliance Support**
*Aug 2022 - Oct 2023*

Responded to and documented security incidents including malware, PUAs, and
policy violations, coordinating containment, remediation, and closure with
system owners and the SOC. Investigated endpoint and account activity to
establish scope and impact, and produced case documentation suitable for audit
and leadership review. Executed directed remediation on affected hosts, triaged
scanner findings across enterprise assets, and supported risk assessment and
authorization documentation packages connecting security findings to compliance
obligations.

**Server Technician II, Managed Services**
*Jan 2022 - Aug 2022*

Email authentication (DMARC / SPF), backup deployment, and a Microsoft RDS
virtual desktop environment for managed-services clients.

**Systems Engineer / NOC / Security Operations**
*Jan 2018 - Jan 2022*

Administered Active Directory and enterprise Windows estates, including
authentication and authorization models, Kerberos, trust boundaries, and
certificate services. Wrote PowerShell automation for session invalidation,
forced re-authentication, and stale and duplicate account detection across a
large directory, with secure defaults and service-account safeguards. Served as
NOC shift lead handling Tier II and Tier III escalation. Owned vulnerability
assessment and remediation reporting across many subordinate organizations, and
managed patch and configuration deployment across workstations and servers.
Hardened domain controllers, OCSP responders, DNS, and DHCP against published
baselines, and audited security groups against least-privilege standards.

**Network Technician Intern**
*2015 - 2017*

## Certifications

- CompTIA SecurityX (formerly CASP+)
- CompTIA Security+

## Technical Training

- Completed the Hack The Box CPTS learning path
- Completed the Hack The Box CWES learning path
- Microsoft SC-200 and AZ-500 self-study coursework
- 50+ Hack The Box machines spanning Active Directory attack paths, privilege
  escalation, web and API exploitation, source-code review, and CVE
  reproduction

## Selected Accomplishments

- Executed multi-stage Active Directory intrusion chains in lab environments,
  including AD CS ESC1 certificate template abuse, resource-based constrained
  delegation via machine account creation, NTLM coercion with offline credential
  recovery, and ACL abuse escalating to DCSync. Each chain is documented with
  the commands used, the artifacts produced, and the privilege transition at
  every stage.
- Wrote KQL queries to confirm scope during live investigations that other
  analysts picked up and reused as recurring checks.
- Built PowerShell containment and account-hygiene automation with
  service-account safeguards, saving an estimated 1,000+ man-hours of manual
  work.
- Established vulnerability triage criteria, checklists, and reporting formats
  that were adopted across several organizations.
- Reproduced published CVEs from advisory to working exploit chain, including
  deserialization RCE, SQLi to RCE, LFI to RCE, and file-parser injection.

## Current Projects

- Writeups and research in the [Offensive](/offensive/) section, covering web
  exploitation, Active Directory, and CVE reproduction
- This site, [source on GitHub](https://github.com/Keyxor/Keyxor.github.io)

## Contact

- GitHub: [github.com/Keyxor](https://github.com/Keyxor)
- LinkedIn: [linkedin.com/in/noah-cuberly](https://www.linkedin.com/in/noah-cuberly)
