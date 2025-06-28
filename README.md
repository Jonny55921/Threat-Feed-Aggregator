# 🛡️ Threat Feed Aggregator

A Python-based tool that fetches threat intelligence data from AlienVault OTX and logs relevant Indicators of Compromise (IOCs) such as IPs, domains, and URLs. Built for defensive security practice and real-time threat analysis.

## 📦 Features

- 📡 Pulls live threat pulses from [AlienVault OTX](https://otx.alienvault.com/)
- 🧾 Logs threat pulse summaries with timestamps
- 🛰️ Extracts and logs detailed IOCs in full mode
- 📁 Saves full IOC logs to `logs/threat_feed.log`
- 🧬 Exports structured indicators as `logs/iocs.json` (when not in summary mode)

## 📁 Project Structure

Threat-Feed-Aggregator/

├── config/otx_api_key.txt

├── logs/

│ ├── threat_feed.log # IOC log file

│ └── iocs.json # Full IOC export (in full mode)

├── .gitignore

└── README.md

├── threat_aggregator.py

## 🚀 Usage


Inside `threat_aggregator.py`:

```python
SUMMARY_MODE = True  # Change to False to enable full IOC logging and JSON export
```
1. Add your OTX API key to `config/otx_api_key.txt`
2. Run:

```bash
python3 threat_aggregator.py
```
In full mode, you’ll see:
```python
Created logs/iocs.json with full IOC logging.
```

## 🔐 Disclaimer
This project is for educational and authorized use only.

Do not use this tool on networks you do not own or operate without permission.