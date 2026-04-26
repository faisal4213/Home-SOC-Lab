# 🚨 Investigation: VPN Brute Force Attack — Simon Account Takeover

**Incident ID:** IR-001  
**Date:** January 11, 2022  
**Analyst:** Mohammed Faisal Jahangir  
**Severity:** CRITICAL  
**Status:** Contained  

---

## Executive Summary

A targeted brute force attack was conducted against the VPN account of user **Simon** on January 11, 2022. The attacker made **1,918 failed login attempts** from a Microsoft Azure IP address before successfully compromising the account with **7 successful logins**. The attack was identified through anomalous traffic volume analysis in Splunk.

---

## Timeline

```
BEFORE JAN 11:
→ Simon connects normally from Canada
→ Regular business hours activity
→ Consistent login pattern ✅

JAN 11 — 07:35:27 AM:
→ Brute force begins
→ 1,918 failed login attempts
→ Source: 172.201.60.191 (Azure/Netherlands)
→ Password eventually cracked
→ 7 successful logins achieved
→ Account COMPROMISED 🚨

AFTER JAN 11:
→ No further failed attempts
→ Attacker has valid credentials
→ No longer needs brute force
```

---

## Evidence

### Anomaly Detection — Traffic Spike
```spl
index=main
| stats count by date_mday action
| sort -count
```

**Result:** January 11 showed 1,981 events — 35x above normal daily average of ~56 events.

### Identifying the Culprit
```spl
index=main date_mday=11 date_month=january
| stats count by UserName
| sort -count
```

**Result:**
| UserName | Count |
|---|---|
| Simon | 1,925 |
| Bentle | 28 |
| James | 14 |

Simon = **97% of all January 11 traffic**

### Confirming Brute Force
```spl
index=main UserName=Simon date_mday=11
date_month=january
| stats count by action
```

**Result:**
| Action | Count |
|---|---|
| failed | 1,918 |
| built | 7 |

### Attacker IP Analysis
```spl
index=main UserName=Simon date_mday=11
date_month=january
| stats count by Source_ip Source_Country
```

**Result:**
| Source_ip | Source_Country | Count |
|---|---|---|
| 172.201.60.191 | Canada | 1,925 |

---

## IOCs (Indicators of Compromise)

```
TYPE        VALUE                DETAILS
──────────────────────────────────────────
IP          172.201.60.191       Microsoft Azure — Netherlands
                                 VirusTotal: 0/94 (clean but behavior malicious)
Username    Simon                Compromised VPN account
Action      failed (1918x)       Brute force signature
Time        07:35:27 AM          Attack start time
Date        2022-01-11           Attack date
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Initial Access | Valid Accounts | T1078 |
| Defense Evasion | Use of Cloud Infrastructure | T1583.006 |

---

## Why the IP Was Clean on VirusTotal

The attacker used a **Microsoft Azure cloud server** (172.201.60.191) which:
- Has a clean reputation (0/94 VirusTotal)
- Is a legitimate Microsoft IP range
- Bypasses IP reputation blocking
- Demonstrates that **context matters more than score alone**

1,918 failed attempts from ANY IP = brute force regardless of reputation score.

---

## Recommended Actions

```
IMMEDIATE:
→ Force password reset for Simon
→ Block IP 172.201.60.191 at firewall
→ Enable MFA on Simon's account
→ Audit all activity on Jan 11 by Simon

SHORT TERM:
→ Implement account lockout after 5 failed attempts
→ Enable geo-blocking for unexpected countries
→ Deploy brute force detection alert in Splunk

LONG TERM:
→ Enforce MFA for ALL VPN users
→ Implement Zero Trust network access
→ Regular VPN log review schedule
```

---

## Detection Rule Created

```spl
/* Brute Force VPN Detection Alert */
index=main action=failed
| stats count as failed_attempts by UserName Source_ip
| where failed_attempts > 10
| eval risk = "BRUTE_FORCE_SUSPECTED"
| table UserName Source_ip failed_attempts risk
```

**Alert configured to:** Run daily at 8:00 AM, trigger when results > 0

---

## Lessons Learned

```
1. Volume anomaly detection is critical
   → Simon's 1,925 events caught what 
     location analysis would have missed
     (IP appeared as Canada — normal location)

2. Clean VirusTotal score ≠ Safe
   → Azure IP was clean but behavior was malicious
   → Always analyze behavior, not just reputation

3. Automated alerts save response time
   → Manual review would have taken days
   → Detection rule catches this same-day
```
