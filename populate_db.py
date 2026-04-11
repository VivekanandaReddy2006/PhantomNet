import sqlite3
import random
import uuid
import datetime

db_path = "phantomnet.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Ensure table exists (just in case)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS packet_logs (
        id VARCHAR PRIMARY KEY,
        src_ip VARCHAR,
        dst_ip VARCHAR,
        dst_port INTEGER,
        protocol VARCHAR,
        length INTEGER,
        payload TEXT,
        timestamp DATETIME,
        is_malicious BOOLEAN,
        attack_type VARCHAR,
        threat_score FLOAT,
        honeypot_type VARCHAR
    )
''')

# Count current rows
cursor.execute("SELECT COUNT(*) FROM packet_logs")
count = cursor.fetchone()[0]

needed = 10001 - count
if needed > 0:
    print(f"Adding {needed} rows to packet_logs...")
    batch = []
    protocols = ["TCP", "UDP", "ICMP"]
    honeypots = ["SSH", "HTTP", "FTP", "NONE"]
    for i in range(needed):
        event = (
            str(uuid.uuid4()),
            f"192.168.1.{random.randint(1, 254)}",
            f"10.0.0.{random.randint(1, 5)}",
            random.randint(22, 8080),
            random.choice(protocols),
            random.randint(40, 1500),
            "mock payload",
            datetime.datetime.now().isoformat(),
            random.choice([True, False]),
            "UNKNOWN",
            random.uniform(0, 100),
            random.choice(honeypots)
        )
        batch.append(event)
    
    cursor.executemany("INSERT INTO packet_logs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", batch)
    conn.commit()
    print("Database populated successfully.")
else:
    print("Database already has 10,000+ rows.")

conn.close()
