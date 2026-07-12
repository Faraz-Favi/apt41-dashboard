# 🛡️ APT41 Attack Simulation — Detection Dashboard

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Made with ❤️](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red.svg)](https://github.com/yourusername/apt41-dashboard)
[![Splunk Ready](https://img.shields.io/badge/Splunk-Ready-00a1de.svg)](https://www.splunk.com/)

> A comprehensive Splunk SPL dashboard for detecting APT41 (Winnti) threat actor activity across the entire MITRE ATT&CK kill chain.

![Dashboard Preview](preview.png)

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Covered ATT&CK Tactics](#-covered-attck-tactics)
- [Event IDs Monitored](#-event-ids-monitored)
- [Installation](#-installation)
- [Usage](#-usage)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

## 🎯 Overview

APT41 (also known as Winnti, Barium, or Blackfly) is a sophisticated Chinese threat group active since at least 2012. They are known for:

- Targeting gaming, technology, and healthcare sectors
- Using Living-off-the-Land (LOTL) techniques
- Combining cyber espionage with financially motivated attacks
- Deploying custom malware like ShadowPad and Winnti

This dashboard provides **ready-to-use Splunk SPL queries** to detect APT41 activity at every stage of the attack lifecycle.

## ✨ Features

| Feature | Details |
|---------|---------|
| 🎯 **MITRE Coverage** | 11 ATT&CK phases with 28 detection queries |
| 🔍 **Event Monitoring** | 24 Windows Event IDs across Sysmon and Security logs |
| 🚀 **Quick Access** | One-click copy SPL to Splunk |
| 📊 **Visual Navigation** | Interactive kill chain with progress tracking |
| 🎨 **Dark Theme** | SOC-friendly dark interface optimized for analysts |
| 📱 **Responsive** | Works on desktop, tablet, and mobile devices |

## 🚀 Quick Start

1. **Access the Dashboard**  
   Open: `https://yourusername.github.io/apt41-dashboard`

2. **Navigate the Kill Chain**  
   Click through the 11 phases from Initial Access to Exfiltration

3. **Copy SPL Queries**  
   - Click **"Copy SPL"** to copy any detection query
   - Paste directly into Splunk Search & Reporting
   - Run against your Windows event logs

4. **Customize for Your Environment**  
   - Replace `index=wineventlog` with your actual index names
   - Adjust time ranges as needed
   - Modify thresholds (e.g., `count > 5` for brute force detection)

## 📊 Covered ATT&CK Tactics

| Phase | Techniques | Description |
|-------|------------|-------------|
| 🚪 **Initial Access** | T1566.001, T1133, T1190 | Spearphishing, RDP brute force, exploitation |
| ⚡ **Execution** | T1059.001, T1059.003, T1047 | PowerShell, WMI, cmd.exe abuse |
| 🔗 **Persistence** | T1547.001, T1053.005, T1505.003 | Registry Run Keys, scheduled tasks, web shells |
| ⬆️ **Privilege Escalation** | T1055, T1078, T1134 | Process injection, token manipulation |
| 👁️ **Defense Evasion** | T1070.001, T1036, T1027, T1574.002 | Log clearing, DLL sideloading, obfuscation |
| 🔑 **Credential Access** | T1003.001, T1558.003, T1110 | LSASS dumping, Kerberoasting, brute force |
| 🔍 **Discovery** | T1087.001, T1082, T1016, T1018 | System enumeration, network mapping |
| ↔️ **Lateral Movement** | T1021.001, T1021.002, T1550.002 | RDP, SMB, Pass-the-Hash |
| 💾 **Collection** | T1005, T1074.001, T1056.001 | File collection, data staging, keylogging |
| 📡 **Command & Control** | T1071.001, T1105, T1573 | HTTP/HTTPS C2, tool downloads |
| 📤 **Exfiltration** | T1041, T1048 | Data compression and exfiltration |

## 📋 Event IDs Monitored

| Event Source | Event IDs |
|--------------|-----------|
| **Windows Security** | 4688, 4624, 4625, 4648, 4672, 4673, 4719, 4768, 4769, 4776, 4798, 4799, 5156, 1102, 104 |
| **Windows PowerShell** | 4104, 4103 |
| **Sysmon** | 3, 7, 8, 10, 11, 13 |

## 📦 Installation

### Method 1: GitHub Pages (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/apt41-dashboard.git
cd apt41-dashboard

# Rename the HTML file to index.html
mv apt41_dashboard_presentation.html index.html

# Push to GitHub
git add index.html
git commit -m "Add APT41 detection dashboard"
git push origin main