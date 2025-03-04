import socket
import requests
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
    exit

#Settings
SERVER_IP = SETTINGS["SERVER_IP"]
SERVER_PORT = int(SETTINGS["SERVER_PORT"])

#Server for listening netflow v5 traffic
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))
print("Listening for NetFlow on {SERVER_IP}:{SERVER_PORT}")

print(sock)



