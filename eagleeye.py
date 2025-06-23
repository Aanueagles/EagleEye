from scapy.all import rdpcap, TCP, IP, ICMP, Raw, DNS
from collections import defaultdict
import pandas as pd

def load_packets(pcap_file):
    return rdpcap(pcap_file)

def log_event(events, cap_num, behavior, start, end, src, dst, remarks):
    events.append({
        "Capture Number": cap_num,
        "Malicious Behavior": behavior,
        "Start Packet": start,
        "End Packet": end,
        "Attacker IP": src,
        "Destination IP": dst,
        "Remarks": remarks
    })

def detect_port_scan(packets, cap_num, events):
    session = defaultdict(list)
    for i, pkt in enumerate(packets, 1):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].flags == 0x02:
                session[(pkt[IP].src, pkt[IP].dst)].append((i, pkt[TCP].dport))
    for (src, dst), data in session.items():
        if len(data) >= 5:
            log_event(events, cap_num, "Port Scanning", data[0][0], data[-1][0], src, dst,
                      f"Ports: {', '.join(str(p) for _, p in data[:5])}...")

def detect_reverse_shell(packets, cap_num, events):
    filtered = [(i, p) for i, p in enumerate(packets, 1)
                if p.haslayer(TCP) and (p[TCP].sport == 4444 or p[TCP].dport == 4444)]
    if filtered:
        log_event(events, cap_num, "Reverse Shell (C2)", filtered[0][0], filtered[-1][0],
                  filtered[0][1][IP].src, filtered[0][1][IP].dst, "Port 4444")

def detect_http(packets, cap_num, events):
    filtered = [(i, p) for i, p in enumerate(packets, 1)
                if p.haslayer(Raw) and b"http" in bytes(p[Raw]).lower()]
    if filtered:
        log_event(events, cap_num, "Suspicious HTTP Activity", filtered[0][0], filtered[-1][0],
                  filtered[0][1][IP].src, filtered[0][1][IP].dst, "HTTP keywords in payload")

def detect_dns(packets, cap_num, events):
    filtered = [(i, p) for i, p in enumerate(packets, 1) if p.haslayer(DNS) and p.haslayer(IP)]
    if filtered:
        log_event(events, cap_num, "DNS Tunneling", filtered[0][0], filtered[-1][0],
                  filtered[0][1][IP].src, filtered[0][1][IP].dst, "DNS packets found")

def detect_ssh_brute(packets, cap_num, events):
    attempts = defaultdict(list)
    for i, p in enumerate(packets, 1):
        if p.haslayer(TCP) and (p[TCP].sport == 22 or p[TCP].dport == 22):
            attempts[(p[IP].src, p[IP].dst)].append(i)
    for (src, dst), pkts in attempts.items():
        if len(pkts) > 5:
            log_event(events, cap_num, "Brute Force (SSH)", pkts[0], pkts[-1], src, dst, f"Attempts: {len(pkts)}")

def detect_icmp(packets, cap_num, events):
    filtered = [(i, p) for i, p in enumerate(packets, 1) if p.haslayer(ICMP)]
    if filtered:
        log_event(events, cap_num, "ICMP Abuse", filtered[0][0], filtered[-1][0],
                  filtered[0][1][IP].src, filtered[0][1][IP].dst, "Ping sweep/flood")

def detect_data_exfil(packets, cap_num, events):
    filtered = [(i, p) for i, p in enumerate(packets, 1)
                if p.haslayer(TCP) and hasattr(p[TCP], 'len') and p[TCP].len > 1000]
    if filtered:
        log_event(events, cap_num, "Large Data Exfiltration", filtered[0][0], filtered[-1][0],
                  filtered[0][1][IP].src, filtered[0][1][IP].dst, f"TCP len > 1000")

def analyze_capture(pcap_path, capture_number):
    packets = load_packets(pcap_path)
    events = []
    detect_port_scan(packets, capture_number, events)
    detect_reverse_shell(packets, capture_number, events)
    detect_http(packets, capture_number, events)
    detect_dns(packets, capture_number, events)
    detect_ssh_brute(packets, capture_number, events)
    detect_icmp(packets, capture_number, events)
    detect_data_exfil(packets, capture_number, events)
    return events

# CLI to run
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Detect malicious behavior in PCAP file")
    parser.add_argument("-f", "--file", required=True, help="Path to the pcap file")
    parser.add_argument("-c", "--capture", default="Capture X", help="Capture number label")
    args = parser.parse_args()

    results = analyze_capture(args.file, args.capture)
    df = pd.DataFrame(results)
    print("\n=== DETECTION REPORT ===")
    print(df.to_markdown(index=False))
