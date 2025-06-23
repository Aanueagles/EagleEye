# 🦅 EagleEye - Network Threat Hunter

EagleEye is a Python-based CLI tool for detecting malicious behavior in network traffic by analyzing `.pcap` files. Designed for cybersecurity learners, analysts, and CTF enthusiasts.

## 🚀 Features

- 🔎 Detects Port Scanning
- 🐚 Reverse Shell / C2 (port 4444)
- 🌐 Suspicious HTTP payloads
- 📡 DNS tunneling
- 🛡️ SSH brute force attempts
- 💥 ICMP flood or ping sweep
- 🧳 Large data exfiltration (TCP len > 1000)

## 📦 Install

```bash
git clone https://github.com/yourusername/EagleEye.git
cd EagleEye
pip install -r requirements.txt
```

## ⚡ Usage

```bash
python eagleeye.py -f path/to/file.pcap -c "Capture 1"
```
📊 Example Output
| Capture Number | Malicious Behavior      | Start Packet | End Packet | Attacker IP    | Destination IP | Remarks        |
| -------------- | ----------------------- | ------------ | ---------- | -------------- | -------------- | -------------- |
| Capture 3      | Reverse Shell (C2)      | 63925        | 64095      | 192.168.56.1   | 192.168.56.102 | Port 4444      |
| Capture 3      | Large Data Exfiltration | 17604        | 22191      | 192.168.56.102 | 192.168.56.1   | TCP len > 1000 |




