import json
import mysql.connector
import pandas as pd

def connect_to_database(host, port, user, password, database, **kwargs):
    """Connect to MySQL database - ignore extra parameters"""
    return mysql.connector.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database
    )

def json_to_dataframe(json_data):
    """Convert JSON data to pandas DataFrame"""
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

def send_data_to_database(config_db, json_file="analysis_results.json"):
    """Main function to send data to database"""
    print(f"DEBUG: Received config_db: {config_db}")  # Debug print
    print(f"DEBUG: JSON file: {json_file}")  # Debug print
    
    # Load data from JSON
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    print(f"DEBUG: Loaded {len(data.get('events', []))} event groups from JSON")  # Debug print
    
    # Connect to database
    conn = connect_to_database(**config_db)
    cursor = conn.cursor()
    print("DEBUG: Database connection successful")  # Debug print
    
    # Convert to DataFrame
    df = json_to_dataframe(data)
    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    print(f"DEBUG: Created DataFrame with {len(df)} rows")  # Debug print
    
    # Insert data into MySQL
    inserted_count = 0
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
        if cursor.rowcount > 0:
            inserted_count += 1
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print(f"DEBUG: Successfully inserted {inserted_count} records")  # Debug print
    return inserted_count

# Compatibility wrapper for backward compatibility
if __name__ == "__main__":
    legacy_config = {
        "host": "192.168.57.130",
        "port": 3306,
        "user": "LU",
        "password": "1111",
        "database": "event_logs"
    }
    
    try:
        result = send_data_to_database(legacy_config, "analysis_results.json")
        print(f"Successfully inserted {result} records")
    except Exception as e:
        print(f"Error: {e}")