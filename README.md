# 🛡️ Threat Feed Aggregator

A Python-based tool that fetches threat intelligence data from AlienVault OTX and logs relevant Indicators of Compromise (IOCs) such as IPs, domains, and URLs. Built for defensive security practice and real-time threat analysis.

## 📦 Features

### Tier 1: Threat Pulse Aggregation
- 📡 Pulls live pulses from [AlienVault OTX](https://otx.alienvault.com/)
- 🧾 Logs summary data or full IOCs to `logs/threat_feed.log`
- 🔄 Toggle `SUMMARY_MODE` in `threat_aggregator.py`
- 📁 Full IOC export to `logs/iocs.json` (structured format)

### Tier 2: Firewall Simulation
- 🔍 Loads IOCs from `iocs.json`
- 🔐 Filters for unique IPv4 indicators
- 🧪 Simulates blocking IPs using `iptables` (dry-run mode)
- 📄 Logs blocking actions to `logs/blocked_ips.log`

## 📁 Project Structure

Threat-Feed-Aggregator/

├── config/otx_api_key.txt

├── logs/

│ ├── threat_feed.log # IOC log file

│ └── iocs.json # Full IOC export (in full mode)

│ └── blockedf_ips.log # Log of blocked IPs

├── .gitignore


├── firewall_blocker.py

└── README.md

├── threat_aggregator.py

## 🚀 Usage


Inside `threat_aggregator.py`:

```python
SUMMARY_MODE = True  # Change to False to enable full IOC logging and JSON export
DRY_RUN = True  # Set to False to actually execute iptables blocking
```
1. Add your OTX API key to `config/otx_api_key.txt`
2. Run:

```bash
python3 threat_aggregator.py
python3 firewall_blocker.py
```
In full mode, you’ll see:
```python
Created logs/iocs.json with full IOC logging.
```

## 🔐 Disclaimer
This project is for educational and authorized use only.

Do not use this tool on networks you do not own or operate without permission.