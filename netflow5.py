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
    exit()

#Settings
SERVER_IP = SETTINGS["SERVER_IP"]
SERVER_PORT = int(SETTINGS["SERVER_PORT"])

#Server for listening netflow v5 traffic
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))
print(f"Listening for NetFlow on {SERVER_IP}:{SERVER_PORT}")

#Parsing Netflow V5 header
def parse_netflow_v5_header(data):
    header = struct.unpack('!HHIIIIHH', data[:20])
    return {"version": header[0], "count": header[1]}

#Parsing NetFlow V5 to readable format
def parse_netflow_v5_flow(data):
    flow = struct.unpack('!IIIIHHIIIIHH', data)
    src_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[0]))))
    dst_ip = ".".join(map(str, struct.unpack('BBBB', struct.pack('!I', flow[1]))))
    dst_port = flow[11]
    return {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port}

def parse_netflow_v5_header(data):
    header = struct.unpack('!HHIIIIHH', data[:20])
    return {"version": header[0], "count": header[1]}

while True:
    data, addr = sock.recvfrom(4096)
    router_ip = addr[0]
    print(f"Received from {router_ip}, data length: {len(data)} bytes")
    hex_data = data.hex()  # for check
    print(f"Raw data (hex): {hex_data}")  # for check

    try:
        header = parse_netflow_v5_header(data)
        print(f"Header: version={header['version']}, count={header['count']}")
        if header["version"] != 5:
            print("Not NetFlow v5, skipping...")
            continue

        flow_data = data[20:]
        print(f"Flow data length: {len(flow_data)} bytes, expected: {header['count'] * 48} bytes")
        if len(flow_data) < header["count"] * 48:  # for check
            print(f"Error: Flow data too short! Expected {header['count'] * 48} bytes, got {len(flow_data)}")  # for check
            continue  # for check

        for i in range(header["count"]):
            flow_start = i * 48
            flow_end = flow_start + 48
            if flow_end <= len(flow_data):
                flow_segment = flow_data[flow_start:flow_end]  # for check
                print(f"Flow {i+1} segment length: {len(flow_segment)} bytes")  # for check
                flow = parse_netflow_v5_flow(flow_segment)  # for check
                src_ip = flow["src_ip"]
                dst_ip = flow["dst_ip"]
                dst_port = flow["dst_port"]
                
                print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Destination Port: {dst_port}")
    except Exception as e:
        print(f"Error parsing NetFlow data: {e}")
