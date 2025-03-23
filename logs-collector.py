import os
import sys

param = '-n' if sys.platform.lower() == 'win32' else '-c'
hostname = "192.168.0.151"
response = os.system(f"ping {param} 4 {hostname}")

if response == 0:
    print(f"{hostname} is up")
else:
    print(f"{hostname} is down")