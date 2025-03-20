import socket
import requests
import time
import struct
import sqlite3
from telegram import Bot
import asyncio

#Read settings from file setting.txt
SETTINGS = {}
try:
    with open("settings.txt", "r") as file:
        for line in file:
            if line.strip() and not line.startswith("#"):
                key, value = line.strip().split("=", 1)
                SETTINGS[key] = value
except FileNotFoundError:
    print("File settings.txt not found in the same folder")
    exit(1)

#Settings
SERVER_IP = SETTINGS["SERVER_IP"]
SERVER_PORT = int(SETTINGS["SERVER_PORT"])
ABUSEIPDB_API_KEY = SETTINGS["ABUSEIPDB_API_KEY"]
CACHE_DURATION_SECONDS = int(SETTINGS["CACHE_DURATION_DAYS"]) * 86400
MALICIOUS_THRESHOLD = int(SETTINGS["MALICIOUS_THRESHOLD"])

#Check if ip in cache
def check_ip_in_cache(ip):
    cursor.execute("SELECT is_malicious, timestamp, country_code FROM ip_cache WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    if result:
        is_malicious, timestamp, country_code = result
        if (time.time() - timestamp) < CACHE_DURATION_SECONDS:
            return is_malicious == 1, country_code
        else:
            return None, None
    return None, None

# Function for check if destination ip is private of public DNS
def is_private_ip(ip):
    if ip == "8.8.8.8":
        return True
    if ip == "8.8.4.4": 
        return True  
    octets = list(map(int, ip.split(".")))
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False

#Check destination ip on abuseipdb.com
def check_ip_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()["data"]
        is_malicious = data["abuseConfidenceScore"] >= MALICIOUS_THRESHOLD
        country_code = data.get("countryCode", "N/A")
        abuse_score = data["abuseConfidenceScore"]
        cursor.execute("INSERT OR REPLACE INTO ip_cache (ip, is_malicious, timestamp, country_code) VALUES (?, ?, ?, ?)",
            (ip, 1 if is_malicious else 0, time.time(), country_code))
        conn.commit()
        return is_malicious, country_code, abuse_score
    return False, "N/A", 0


# Parse netflow segments
def parse_netflow_data(data):
        flow = struct.unpack('!IIIHHIIIIHHBBBBHHBBH', data)
        src_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[0]))))
        dst_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[1]))))
        dst_port = flow[10]
        return{"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port}

# Database for cashing ips
conn = sqlite3.connect("ip_cache.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS ip_cache 
                  (ip TEXT PRIMARY KEY, is_malicious INTEGER, timestamp REAL, country_code TEXT)''')
conn.commit()

#Server for listening netflow v5 traffic
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))

try:
    while True:
        data, addr = sock.recvfrom(4096)
        router_ip = addr[0]

        try:
            header = struct.unpack('!HHIIIIHH', data[:24])
            count = header[1]
            flow_data = data[24:]

            for i in range(count):
                flow_start = i * 48
                flow_end = flow_start + 48
                flow_segment = flow_data[flow_start:flow_end]
                flow = parse_netflow_data(flow_segment)
                dst_ip = flow["dst_ip"]
                if is_private_ip(dst_ip):
                    continue
                is_malicious, country_code = check_ip_in_cache(dst_ip)
                abuse_score = 0
                if is_malicious is None:
                    is_malicious, country_code, abuse_score = check_ip_abuseipdb(dst_ip)
                    message = f"IP is not malicious: {dst_ip}"
                    print(message)

                if is_malicious:
                    message = f"Malicious IP detected: {dst_ip}, Score: {abuse_score}, Country: {country_code}, Port: {flow['dst_port']}"
                    print(message)
        except Exception as e:
            print(f"Error: {e}")

finally:
    conn.close()
    sock.close()