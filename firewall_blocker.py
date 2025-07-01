import json
import os
from datetime import datetime
import ipaddress

JSON_PATH = "logs/iocs.json"  # Path to save IOCs in JSON format
DRY_RUN = True  # Set to False to actually run iptables
BLOCK_LOG = "logs/blocked_ips.log"  # Log file for blocked IPs

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def log_block(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp} - {msg}"
    print(f"[DEBUG] Writing block log: {entry}")

    with open(BLOCK_LOG, 'a') as f:
        f.write(entry + "\n")

def load_iocs():
    if not os.path.exists(JSON_PATH):
        print(f"[ERROR] IOC file not found at {JSON_PATH}. Please run the threat aggregator first.")
        return []
    with open(JSON_PATH, 'r') as f:
        try:
            data = json.load(f)
            return data
        except json.JSONDecodeError:
            print(f"[ERROR] Failed to decode JSON from {JSON_PATH}. Please check the file format.")
            return []

def simulate_firewall_block(ip):
    log_block(f"Simulating block for IP: {ip}")

def process_iocs(iocs):
    seen_ips = set()
    for ioc in iocs:
        print(f"[DEBUG] Type: {ioc.get('type')} | Indicator: {ioc.get('indicator')}")
        if ioc.get("type", "").strip().lower() == "ipv4":
            ip = ioc.get("indicator")
            if ip and ip not in seen_ips and is_valid_ip(ip):
                seen_ips.add(ip)

                if DRY_RUN:
                    simulate_firewall_block(ip)
                else:
                    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
                    log_block(f"[EXECUTED] Blocked IP via iptables: {ip}")


if __name__ == "__main__":
    ioc_data = load_iocs()
    if ioc_data:
        log_block(f" Staring firwall simulation for {len(ioc_data)} IOCs...")
        process_iocs(ioc_data)
        log_block("Firewall simulation completed.")