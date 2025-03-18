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

while True:
    data, addr = sock.recvfrom(4096)
    router_ip = addr[0]
    print(f"Received from {router_ip}, data length: {len(data)} bytes")
    print(f"Raw data (hex): {data.hex()}")

    try:
        header = parse_netflow_v5_header(data)
        print(f"Header: version={header['version']}, count={header['count']}")
        if header["version"] != 5:
            continue
        
        expected_total_length = 20 + (header["count"] * 48)
       
        if len(data) < expected_total_length:
            continue
 
        if len(data) > expected_total_length:
            data = data[:expected_total_length]

        flow_data = data[20:]
        for i in range(header["count"]):
            flow_start = i * 48
            flow_end = flow_start + 48
            flow_segment = flow_data[flow_start:flow_end]

            try:
                flow = parse_netflow_v5_flow(flow_segment)
                src_ip = flow["src_ip"]
                dst_ip = flow["dst_ip"]
                dst_port = flow["dst_port"]
                print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Destination Port: {dst_port}")
            except struct.error as e:
                print(f"Error parsing flow {i+1}: {e}")
                continue
    except Exception as e:
        print(f"Error parsing NetFlow data: {e}")
