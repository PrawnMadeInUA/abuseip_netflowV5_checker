# AbuseIP NetFlow v5 Checker

This tool monitors NetFlow v5 traffic, checks destination IPs against the AbuseIPDB database for malicious activity, and sends Telegram notifications when a threshold is exceeded. It uses SQLite for caching to reduce API requests and is designed to work with MikroTik routers.

## Features
- Parses NetFlow v5 packets from a specified UDP server.
- Checks IPs against AbuseIPDB with a configurable malicious threshold.
- Caches results in SQLite to avoid redundant checks.
- Sends Telegram alerts with details (router IP, source/destination IPs, port, country, abuse score).
- Lightweight: ~150 lines of code.

## Requirements
- Python 3.7+
- Packages: `requests`, `telegram`, `sqlite3` (built-in), `asyncio` (built-in)
- AbuseIPDB API key (free tier available)
- Telegram bot token and chat ID
- MikroTik router (optional, for NetFlow data)

## Installation
1. Clone the repository:
   git clone https://github.com/PrawnMadeInUA/abuseip_netflowV5_checker.git
   cd abuseip_netflowV5_checker

2. Install dependencies:
   pip install requests python-telegram-bot

3. Create and configure settings.txt
   # Your server IP address
   SERVER_IP=192.168.1.100
   # Your server UDP port
   SERVER_PORT=2055
   # AbuseIPDB API key (get from abuseipdb.com)
   ABUSEIPDB_API_KEY=your_api_key_here
   # Telegram bot token (from BotFather)
   TELEGRAM_TOKEN=your_telegram_token_here
   # Telegram chat ID (find via @getidbot)
   TELEGRAM_CHAT_ID=your_chat_id_here
   # Cache duration in days
   CACHE_DURATION_DAYS=30
   # Minimum abuse score to flag as malicious (0-100%)
   MALICIOUS_THRESHOLD=80

## Usage
1. Ensure your router is sending NetFlow v5 data (see ).

2. Run the script:
   python netflow5.py

The tool listens for NetFlow packets, checks IPs, and sends Telegram alerts for malicious activity.
