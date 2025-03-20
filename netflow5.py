import socket
import requests
import struct
from telegram import Bot

#Read settings from file setting.txt
SETTINGS = {}
try:
    with open("settings.txt", "r") as file:
        for line in file:
            key, value = line.strip().split("=", 1)
            SETTINGS[key] = value
except FileNotFoundError:
    print("File settings.txt not found in the same folder")
    exit(1)

#Settings
SERVER_IP = SETTINGS["SERVER_IP"]
SERVER_PORT = int(SETTINGS["SERVER_PORT"])

#Server for listening netflow v5 traffic
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))


while True:
    data, addr = sock.recvfrom(4096)
    router_ip = addr[0]
    print(f"Received from {router_ip}, data length: {len(data)} bytes")
    print(f"Raw data (hex): {data.hex()}")

    try:
        header = struct.unpack('!HHIIIIHH', data[:24])
        count = header[1]
        flow_data = data[24:]

        print(f"Count: {count}, Flow data length: {len(flow_data)}")

        for i in range(count):
            flow_start = i * 48
            flow_end = flow_start + 48
            flow_segment = flow_data[flow_start:flow_end]
            flow = struct.unpack('!IIIIHHIIIIHHBBH', flow_segment)
            src_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[0]))))
            dst_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[1]))))
            dst_port = flow[11]
            print(f"Flow {i + 1}: Source IP = {src_ip}, Destination IP = {dst_ip}, Destination Port = {dst_port}")
    except struct.error as e:
        print(f"Struct error parsing header or flow: {e}")
        print(f"Data causing error: {data.hex()}")
    except Exception as e:
        print(f"Error parsing NetFlow data: {e}")
