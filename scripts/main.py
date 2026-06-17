import sqlite3
import subprocess
import re
from datetime import datetime

ALERT_FILE = "/var/log/snort/alert"

conn = sqlite3.connect("../database/intrusion.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS attacks(
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT,
attack_type TEXT,
source_ip TEXT
)
""")

conn.commit()

print("NIDS Started...")
print("Waiting for alerts...\n")

def block_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"[BLOCKED] {ip}")
    except:
        pass

with open(ALERT_FILE, "r") as f:

    f.seek(0, 2)

    while True:

        line = f.readline()

        if not line:
            continue

        print("[ALERT]", line.strip())

        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)

        ip = ip_match.group(1) if ip_match else "Unknown"

        if "ICMP" in line:
            attack = "Ping Attack"

        elif "SSH" in line:
            attack = "SSH Attempt"

        elif "FTP" in line:
            attack = "FTP Attempt"

        elif "Port Scan" in line:
            attack = "Port Scan"

        else:
            attack = "Unknown"

        cursor.execute(
            "INSERT INTO attacks(timestamp,attack_type,source_ip) VALUES(?,?,?)",
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                attack,
                ip
            )
        )

        conn.commit()

        if ip != "Unknown":
            block_ip(ip)