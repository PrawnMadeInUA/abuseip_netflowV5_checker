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
TELEGRAM_TOKEN = SETTINGS["TELEGRAM_TOKEN"]
TELEGRAM_CHAT_ID = SETTINGS["TELEGRAM_CHAT_ID"]


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
    else:
        print(f"AbuseIPDB API error: {response.status_code} - {response.text}")
        return False, "N/A", 0


# Parse netflow segments
def parse_netflow_data(data):
    flow = struct.unpack('!IIIHHIIIIHHBBBBHHBBH', data)
    src_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[0]))))
    dst_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[1]))))
    dst_port = flow[10]
    return{"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port}

# Telegram message sender
async def send_telegram_message(router_ip, src_ip, dst_ip, dst_port, country_code, abuse_score):
    message = (f"On router: {router_ip} detected connetction to malicious IP:\n"
               f"From IP: {src_ip} to IP: {dst_ip} (Country: {country_code})\n"
               f"On port: {dst_port}\n"
               f"ABUSEIP abuse score is: {abuse_score}%.")
    await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)

# Telegram bot initialisation
bot = Bot(TELEGRAM_TOKEN)

#Server for listening netflow v5 traffic
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))

async def main():
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            router_ip = addr[0]
            header = struct.unpack('!HHIIIIHH', data[:24])
            count = header[1]
            flow_data = data[24:]

            for i in range(count):
                flow_start = i * 48
                flow_end = flow_start + 48
                flow_segment = flow_data[flow_start:flow_end]
                flow = parse_netflow_data(flow_segment)
                if flow is None:
                    continue
                dst_ip = flow["dst_ip"]
                if is_private_ip(dst_ip):
                    continue
                is_malicious, country_code = check_ip_in_cache(dst_ip)
                abuse_score = 0
                if is_malicious is None:
                    is_malicious, country_code, abuse_score = check_ip_abuseipdb(dst_ip)

                if is_malicious:
                    await send_telegram_message(router_ip, flow["src_ip"], dst_ip, flow["dst_port"], country_code, abuse_score)
        except socket.error as e:
            print(f"Socket error: {e}")
            time.sleep(1)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    with sqlite3.connect("ip_cache.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS ip_cache 
                          (ip TEXT PRIMARY KEY, is_malicious INTEGER, timestamp REAL, country_code TEXT)''')
        conn.commit()

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            sock.bind((SERVER_IP, SERVER_PORT))
            bot = Bot(TELEGRAM_TOKEN)
            asyncio.run(main())