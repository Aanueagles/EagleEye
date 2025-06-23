# EagleEye
🦅 A PCAP-based Network Threat Hunter in Python
---

## 🚀 Features

✅ Detects:
- 🔍 Port Scanning (`SYN` without `ACK`)
- 🎯 Reverse Shell / C2 Traffic (port 4444)
- 🌐 Suspicious HTTP Payloads
- 📡 DNS Tunneling
- 🛡️ SSH Brute-Force (port 22)
- 💥 ICMP Flood / Ping Sweep
- 🧳 Large Data Exfiltration (TCP len > 1000)

---

## 📦 Installation

```bash
git clone https://github.com/aanueagles/eagleeye.git
cd eagleye
pip install -r requirements.txt

⚡ Usage
python eagleeye.py -f path/to/your.pcap -c "Capture 1"

📊 Sample Output

| Capture Number | Malicious Behavior      | Start Packet | End Packet | Attacker IP    | Destination IP | Remarks        |
| -------------- | ----------------------- | ------------ | ---------- | -------------- | -------------- | -------------- |
| Capture 3      | Reverse Shell (C2)      | 63925        | 64095      | 192.168.56.1   | 192.168.56.102 | Port 4444      |
| Capture 3      | Large Data Exfiltration | 17604        | 22191      | 192.168.56.102 | 192.168.56.1   | TCP len > 1000 |

