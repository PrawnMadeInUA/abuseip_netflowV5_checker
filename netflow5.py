import socket
import requests
from telegram import Bot

#Read settings from file setting.txt
SETTINGS={}
try:
    with open("settings.txt", "r") as file:
        for line in file:
            key, value = line.strip().split("=", 1)
            SETTINGS[key] = value
    exit
print(SETTINGS)
