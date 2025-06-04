# test_connection.py
import mysql.connector
from send_to_database import connect_to_database

config = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root", 
    "password": "1111",
    "database": "event_logs",
    "table": "logs"  # This will be ignored by **kwargs
}

try:
    print("Testing database connection...")
    conn = connect_to_database(**config)
    print("✓ Connection successful!")
    
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    count = cursor.fetchone()[0]
    print(f"✓ Current records in logs table: {count}")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"✗ Connection failed: {e}")