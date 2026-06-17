import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

conn = sqlite3.connect("../database/intrusion.db")

data = pd.read_sql_query(
    "SELECT attack_type FROM attacks",
    conn
)

if data.empty:
    print("No data found")
    exit()

data["attack_type"].value_counts().plot(kind="bar")

plt.title("Detected Attacks")
plt.xlabel("Attack Type")
plt.ylabel("Count")

plt.tight_layout()

plt.savefig("../reports/attack_report.png")

print("Report Generated")