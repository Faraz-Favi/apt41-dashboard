# 🛡️ APT41 Detection Dashboard — Complete Splunk SPL Guide

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Splunk Ready](https://img.shields.io/badge/Splunk-Ready-00a1de.svg)](https://www.splunk.com/)

> **A complete Splunk SPL query collection for detecting APT41 (Winnti) threat actor activity across the entire MITRE ATT&CK kill chain**

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Who is APT41?](#-who-is-apt41)
- [MITRE ATT&CK Techniques Used by APT41](#-mitre-attck-techniques-used-by-apt41)
- [Attack Lifecycle & Detection](#-attack-lifecycle--detection)
  - [1. Initial Access](#1-initial-access)
  - [2. Execution](#2-execution)
  - [3. Persistence](#3-persistence)
  - [4. Privilege Escalation](#4-privilege-escalation)
  - [5. Defense Evasion](#5-defense-evasion)
  - [6. Credential Access](#6-credential-access)
  - [7. Discovery](#7-discovery)
  - [8. Lateral Movement](#8-lateral-movement)
  - [9. Collection](#9-collection)
  - [10. Command & Control](#10-command--control)
  - [11. Exfiltration](#11-exfiltration)
- [Event IDs Reference](#-event-ids-reference)
- [Quick Start](#-quick-start)
- [Usage Tips](#-usage-tips)
- [Customizing Queries for Your Environment](#-customizing-queries-for-your-environment)
- [Creating Alerts in Splunk](#-creating-alerts-in-splunk)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)
- [References](#-references)

---

## 🎯 Overview

APT41 (also known as **Winnti**, **Barium**, or **Blackfly**) is a sophisticated threat group attributed to China and active since at least 2012. This dashboard provides **ready-to-use Splunk SPL queries** to detect APT41 activity at every stage of the attack lifecycle.

| Feature | Details |
|---------|---------|
| 🎯 **MITRE Coverage** | 11 ATT&CK phases with 28 detection queries |
| 🔍 **Event Monitoring** | 24 Windows Event IDs across Sysmon and Security logs |
| 🚀 **Quick Access** | One-click copy SPL to Splunk |
| 📊 **Visual Navigation** | Interactive kill chain with progress tracking |
| 🎨 **Dark Theme** | SOC-friendly dark interface optimized for analysts |
| 📱 **Responsive** | Works on desktop, tablet, and mobile devices |

---

## 👤 Who is APT41?

APT41 (also known as **Winnti**, **Barium**, or **Blackfly**) is a sophisticated threat group widely attributed to China and active since at least 2012. They operate with a dual mission:

| Aspect | Description |
|--------|-------------|
| **Primary Targets** | Gaming, technology, healthcare, and telecommunications sectors |
| **Geographic Focus** | Global, with emphasis on East Asia, North America, and Europe |
| **Key Techniques** | Living-off-the-Land (LOTL), fileless execution, PowerShell abuse |
| **Motivations** | Cyber espionage + financially motivated attacks |
| **Known Malware** | ShadowPad, Winnti, Cobalt Strike, PlugX |
| **Signature Behaviors** | Log clearing (T1070.001), DLL sideloading, Kerberoasting |
| **TTPs** | Mimikatz, Pass-the-Hash, scheduled tasks, WMI abuse |

### Why APT41 is Dangerous

- **Dual-purpose attacks**: Combine espionage with financial theft
- **LOTL techniques**: Use legitimate Windows tools to avoid detection
- **Persistence focus**: Deploy multiple backdoors for access redundancy
- **Rapid adaptation**: Quickly adopt new exploits and techniques

### Historical Context

| Year | Notable Activity |
|------|------------------|
| 2012-2015 | Initial operations targeting gaming companies |
| 2016-2018 | Expansion to technology and healthcare sectors |
| 2019-2020 | Use of CVE-2019-19781 (Citrix) and CVE-2020-0688 (Exchange) |
| 2021-2023 | Increased supply chain attacks and ransomware deployment |
| 2024+ | Continued evolution with new TTPs |

---

## 🎯 MITRE ATT&CK Techniques Used by APT41

| Phase | Techniques | Description |
|-------|------------|-------------|
| **Initial Access** | T1566.001, T1133, T1190 | Spearphishing, RDP brute force, exploitation |
| **Execution** | T1059.001, T1059.003, T1047 | PowerShell, WMI, cmd.exe abuse |
| **Persistence** | T1547.001, T1053.005, T1505.003 | Registry Run Keys, scheduled tasks, web shells |
| **Privilege Escalation** | T1055, T1078, T1134 | Process injection, token manipulation |
| **Defense Evasion** | T1070.001, T1036, T1027, T1574.002 | Log clearing, DLL sideloading, obfuscation |
| **Credential Access** | T1003.001, T1558.003, T1110 | LSASS dumping, Kerberoasting, brute force |
| **Discovery** | T1087.001, T1082, T1016, T1018 | System enumeration, network mapping |
| **Lateral Movement** | T1021.001, T1021.002, T1550.002 | RDP, SMB, Pass-the-Hash |
| **Collection** | T1005, T1074.001, T1056.001 | File collection, data staging, keylogging |
| **Command & Control** | T1071.001, T1105, T1573 | HTTP/HTTPS C2, tool downloads |
| **Exfiltration** | T1041, T1048 | Data compression and exfiltration |

---

## 🔍 Attack Lifecycle & Detection

### 1. Initial Access

APT41 gains initial access through:
- **Spearphishing attachments** (T1566.001): Malicious macros in Office documents
- **External remote services** (T1133): Brute-force against RDP, VPN, and web applications
- **Exploit public-facing apps** (T1190): Vulnerability exploitation (e.g., Exchange, Citrix)

#### 🔎 Detection Queries

```spl
# Hidden PowerShell execution
index=wineventlog EventCode=4688
| search CommandLine="*-W Hidden*" OR CommandLine="*-Exec Bypass*" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*"
| table _time host NewProcessName CommandLine
| sort - _time

# RDP brute force detection (failed logons)
index=wineventlog EventCode=4625
| stats count by IpAddress TargetUserName
| where count > 5
| sort - count
| table IpAddress TargetUserName count

# Successful RDP logon (suspicious)
index=wineventlog EventCode=4624
| search LogonType=10
| table _time host TargetUserName IpAddress LogonType
| sort - _time