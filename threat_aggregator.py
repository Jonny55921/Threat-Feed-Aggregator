'''

@Jonny55921

'''


import requests
import json
from datetime import datetime
import os

API_PATH = "config/otx_api_key.txt"
LOG_PATH = "logs/threat_feed.log"
SUMMARY_MODE = False  # Change to False for full IOC logging
JSON_PATH = "logs/iocs.json" # Path to save IOCs in JSON format

def get_api_key():
    # Retrieve the OTX API key from a file.
    try:
        with open(API_PATH, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        print(f"API key file not found at {API_PATH}. Please create it with your OTX API key.")
        exit(1)

def log_threat(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"
    # Logs are written in year/month/day format and hour/minute/second format

    #print(f"[DEBUG] Writing log: {log_entry}")
    # Uncomment above line for debugging purposes

    try:
        with open(LOG_PATH, 'a') as log_file:
            log_file.write(log_entry + "\n")
        #print(f"[DEBUG] Successfully wrote to {LOG_PATH}")
        # Uncomment above line for debugging purposes
    except Exception as e:
        print(f"[ERROR] Failed to write to log file: {e}")
        


def fetch_threat_data(api_key):
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {'X-OTX-API-KEY': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        log_threat(f"Failed to fetch threat data: {response.status_code} - {response.text}")
        return

    data = response.json()
    pulses = data.get('results', [])
    log_threat(f"Fetched {len(pulses)} threat pulses from OTX.")

    seen_indicators = set()
    all_iocs = []  # Store all extracted IOCs here

    """
    
    IMPORTANT: The following loop processes 5 threat pulses.
    If you want to process all pulses, remove the slicing [:5].
    This is done to limit the output in summary mode.
    If you want to see all IOCs, set SUMMARY_MODE to False.
    If you want to see only the summary, set SUMMARY_MODE to True.

    """
    for pulse in pulses[:5]:
        pulse_name = pulse.get('name', 'Unknown Pulse')
        indicators = pulse.get('indicators', [])
        log_threat(f"Pulse: {pulse_name} - Indicators: {len(indicators)}")

        if not SUMMARY_MODE:
            for ind in indicators:
                indicator = ind.get('indicator')
                ind_type = ind.get('type')

                if not indicator or indicator in seen_indicators:
                    continue

                # Structure for summary mode
                seen_indicators.add(indicator)
                log_msg = f"[{ind_type.upper()}] {indicator} - Source: {pulse_name}"
                log_threat(log_msg)
                
                # Structure the IOC data for JSON output
                all_iocs.append({
                    "indicator": indicator,
                    "type": ind_type,
                    "source": pulse_name
                })
    if not SUMMARY_MODE and all_iocs:
        with open(JSON_PATH, 'w') as json_file:
            json.dump(all_iocs, json_file, indent=4)
        #print(f"[DEBUG] IOC data saved to {JSON_PATH}")
        # Uncomment above line for debugging purposes



if __name__ == "__main__":
    api_key = get_api_key()
    fetch_threat_data(api_key)