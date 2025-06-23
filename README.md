# EagleEye
🦅 A PCAP-based Network Threat Hunter in Python
---

**Automated PCAP analyzer** that detects common malicious behaviors in network traffic such as port scans, reverse shells, brute-force attacks, and data exfiltration.

## 🚀 Features
- Port Scanning Detection
- Reverse Shell / C2 (port 4444)
- Suspicious HTTP payloads
- DNS tunneling activity
- SSH brute force (port 22)
- ICMP flood / ping sweep
- Large data exfiltration (TCP length > 1000)

## 📦 Requirements
```bash
pip install scapy pandas


