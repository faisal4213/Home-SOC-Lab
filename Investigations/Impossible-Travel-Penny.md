# 🚨 Investigation: Impossible Travel — Penny Account Compromise

**Incident ID:** IR-002  
**Date:** January 20, 2022  
**Analyst:** Mohammed Faisal Jahangir  
**Severity:** HIGH  
**Status:** Under Investigation  

---

## Executive Summary

User **Penny** was identified connecting to the company VPN from **England and China on the same day** using the **exact same IP address** — a physical impossibility without the use of a proxy or VPN service. Combined with a gap in normal USA activity from January 17-26, this strongly indicates account compromise.

---

## Timeline

```
JAN 1-16:
→ Penny connects normally from USA ✅
→ Consistent pattern, legitimate IPs

JAN 17-26 (GAP PERIOD):
→ No USA connections 🔍
→ Possible attacker took over account
→ Or Penny travelling internationally

JAN 20 — 04:34:19 AM:
→ Connection from England
→ IP: 39.78.152.65
→ Action: teardown (disconnected)

JAN 20 — 19:04:51 PM:
→ Connection from China
→ IP: 39.78.152.65 ← SAME IP! 🚨
→ Action: built (connected)

JAN 27+:
→ USA connections resume ✅
→ Normal pattern returns
```

---

## Evidence

### Finding Suspicious Countries
```spl
index=main
| stats count by Source_Country
| sort -count
```

**Result:** China had only 3 connections — anomalous for a US-based company.

### Investigating China Connections
```spl
index=main Source_Country=China
```

**Result:** All 3 China connections belong to user Penny from IP 39.78.152.65.

### Penny's Full Country Profile
```spl
index=main UserName=Penny
| stats count by Source_Country
```

**Result:**
| Source_Country | Count |
|---|---|
| USA | 114 |
| England | 27 |
| China | 3 |

### The Smoking Gun — Same IP Different Countries
```spl
index=main Source_ip=39.78.152.65
| stats count by UserName Source_Country
```

**Result:**
| UserName | Source_Country | Count |
|---|---|---|
| Penny | England | 27 |
| Penny | China | 3 |

**Only Penny uses this IP — not a corporate proxy.**

### Timeline Verification
```spl
index=main UserName=Penny
| table EventTime Source_Country Source_ip action
| sort EventTime
```

**January 20 specifically:**
```
04:34:19 AM → England → 39.78.152.65 → teardown
19:04:51 PM → China   → 39.78.152.65 → built
```

---

## Why Same IP in Two Countries is Impossible

```
Normal travel scenario:
England IP = UK internet provider address
China IP   = Chinese internet provider address
These are ALWAYS different IPs

What same IP means:
→ Proxy/VPN service being used
→ Both connections routed through same server
→ Attacker masking real location
→ Trying to appear as Penny in different countries
```

---

## IOCs (Indicators of Compromise)

```
TYPE        VALUE              DETAILS
────────────────────────────────────────────
IP          39.78.152.65       Appears in England AND China
                               VirusTotal: 0/94 (proxy/VPN)
Username    Penny              Suspicious account
Country     China              First ever connection from China
Date        2022-01-20         Day of impossible travel
Gap         Jan 17-26          Unusual break in USA activity
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Proxy | T1090 |
| Initial Access | Valid Accounts | T1078 |
| Defense Evasion | Use of VPN | T1133 |

---

## Recommended Actions

```
IMMEDIATE:
→ Force password reset for Penny
→ Enable MFA on Penny's account
→ Block IP 39.78.152.65
→ Interview Penny about Jan 17-26 travel

SHORT TERM:
→ Review all data accessed by Penny Jan 17-26
→ Check for data exfiltration during gap period
→ Enable impossible travel alert in Splunk

LONG TERM:
→ Implement geo-fencing for VPN access
→ Alert on same IP appearing in 2+ countries
→ Zero trust network access implementation
```

---

## Detection Rule Created

```spl
/* Impossible Travel Detection */
index=main
| stats dc(Source_Country) as countries by UserName
| where countries > 2
| sort -countries
```

---

## Lessons Learned

```
1. Same IP in multiple countries = immediate red flag
   → Physical impossibility without proxy/VPN
   → Automated detection rule now in place

2. Low VirusTotal score doesn't clear suspicious behavior
   → 39.78.152.65 was 0/94 but behavior was suspicious
   → Context and correlation matter most

3. Baseline deviation catches what rules miss
   → China connections = only 3 out of 2,862 events
   → Statistical anomaly detection is powerful
```
