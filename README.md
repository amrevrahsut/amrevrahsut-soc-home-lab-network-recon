# amrevrahsut-soc-home-lab-network-recon
# SOC Lab: Network Reconnaissance & Host-Based Defense Detection

## 🛡️ Project Overview
This project demonstrates a professional **Security Operations Center (SOC)** investigative workflow. I simulated internal network reconnaissance from an attacker machine (**Kali Linux**) and analyzed the resulting telemetry on a target machine (**Windows 10**) using the **Windows Filtering Platform (WFP)** and native firewall logs.



## 🛠️ Lab Environment
* **Attacker Node:** Kali Linux (VMware)
* **Target Node:** Windows 10 x64 (VMware)
* **Security Stack:** * Windows Defender Firewall
    * Windows Filtering Platform (WFP)
    * Advanced Security Audit Policies (Event ID 5157)

---

## ⚔️ Attacker-Side Activity (Kali Linux)
I used a custom logging script to document all commands and output. This ensures a forensic trail of the reconnaissance phase.

### 1. ICMP Connectivity Check
* **Command:** `ping [Target_IP] -c 4`
* **Result:** **100% packet loss.** The target did not respond to echo requests, indicating that ICMP traffic is blocked.

### 2. Stealth TCP SYN Scan & OS Detection
* **Command:** `sudo nmap -sS -sV -Pn -A [Target_IP]`
* **Observation:** Nmap reported **1000 filtered tcp ports (no-response)**.
* **Analyst Note:** The "Filtered" status confirms that the target's firewall is silently dropping packets rather than rejecting them with a `RST` (Reset) packet.

> **Full Attacker Log:** [View Sanitized Recon Script](./kali_nmap_recon.txt)

---

## 🛡️ Defender-Side Analysis (Windows 10)
From the SOC perspective, I analyzed the telemetry generated during the attack window.

### 1. Windows Firewall Logs (`pfirewall.log`)
By analyzing the raw firewall logs, I identified the system's reaction to the Nmap probes.
* **Pattern Identified:** While local loopback (`127.0.0.1`) and authorized DNS traffic (`Port 53`) were `ALLOW`ed, inbound probes from the Kali IP were silenced (Dropped).

> **Full Firewall Log:** [View Sanitized Firewall Logs](./pfirewall_recon.log)

### 2. Event ID 5157 (WFP Blocked Connection)
This is the critical forensic artifact. The **Windows Filtering Platform** generated events confirming it intercepted the reconnaissance packets.
* **Evidence:** Multiple blocks on high-value ports such as **445 (SMB)**, **135 (RPC)**, and **3389 (RDP)**.
* **Correlation:** The timestamps in these logs match the Nmap scan duration exactly, providing proof of the attack source.



---

## 📊 MITRE ATT&CK Mapping
| Tactic | Technique | ID | Mitigation / Detection |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) | WFP Enforcement (Event ID 5157) |
| **Discovery** | Network Service Scanning | [T1046](https://attack.mitre.org/techniques/T1046/) | Inbound Traffic Filtering |

---

## 🚀 Key Skills Demonstrated
* **Log Correlation:** Matching offensive Nmap outputs with defensive Windows Security logs.
* **Data Masking/Sanitization:** Professionally masking internal IPs and MAC addresses for public reporting.
* **Host Hardening:** Understanding how WFP serves as the engine for Windows network security.
* **Technical Writing:** Presenting raw technical data in an executive-ready SOC report.

---

## 📂 Repository Contents
* `README.md`: Project documentation and analysis.
* `kali_nmap_recon_sanitized.txt`: Sanitized attacker-side terminal output.
* `pfirewall_sanitized.log`: Sanitized Windows Firewall raw telemetry.
* `/Screenshots`: Visual evidence of Nmap scans and Event Viewer logs.

---
*Disclaimer: This lab was conducted in a controlled, isolated virtual environment for educational purposes.*
