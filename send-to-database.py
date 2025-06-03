import json
import mysql.connector
import pandas as pd

# Wczytaj dane z JSON
with open("analysis_results.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Połącz z bazą
conn = mysql.connector.connect(
    host="192.168.57.130",
    port=3306,
    user="LU",
    password="1111",
    database="event_logs"
)
cursor = conn.cursor()

# Wczytaj do DataFrame
def json_to_dataframe(json_data):
    events_data = []
    for event in json_data["events"]:
        specific_events = event.get("specific_events", [])
        for se in specific_events:
            events_data.append({
                "event_id": se.get("event_id", "Unknown"),
                "source": se.get("source", "Unknown"),
                "event_type": se.get("event_type", "Unknown"),
                "date": se.get("date", None),
                "message": se.get("message", "")
            })
    return pd.DataFrame(events_data)

df = json_to_dataframe(data)
df["date"] = pd.to_datetime(df["date"], errors="coerce")

# Wstaw dane do MySQL
for _, row in df.iterrows():
    cursor.execute("""
    	INSERT IGNORE INTO logs (event_id, event_type, source, date, message)
    	VALUES (%s, %s, %s, %s, %s)
    """, (
    	row["event_id"],
    	row["event_type"],
    	row["source"],
    	row["date"].strftime("%Y-%m-%d %H:%M:%S") if pd.notnull(row["date"]) else None,
    	row["message"]
    ))

conn.commit()
cursor.close()
conn.close()
