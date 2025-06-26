import requests
import json
from datetime import datetime
import os

API_PATH = "config/otx_api_key.txt"
LOG_PATH = "logs/threat_feed.log"

def get_api_key():
    """Retrieve the OTX API key from a file."""
    try:
        with open(API_PATH, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        print(f"API key file not found at {API_PATH}. Please create it with your OTX API key.")
        exit(1)

def log_threat(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"
    print (log_entry, end='')  # Print to console


    """Log messages to a log file."""
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_entry + "\n")

def fetch_threat_data(api_key):
    """Fetch threat data from the OTX API."""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {'X-OTX-API-KEY': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        pulses = data.get('results', [])
        log_threat(f"Fetched {len(pulses)} threat pulses from OTX.")

        for pulse in pulses[:5]:        # For all pulses change to in pulses[]
            name = pulse.get('name', 'Unknown Pulse')
            indicators = pulse.get('indicators', [])
            log_threat(f"Pulse: {name} - Indicators: {len(indicators)}")
    else:
        log_threat(f"Failed to fetch threat data: {response.status_code} - {response.text}")
        return []


if __name__ == "__main__":
    api_key = get_api_key()
    fetch_threat_data(api_key)