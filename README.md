# Windows Event Log Processing Pipeline

A comprehensive Python-based system for collecting, analyzing, and visualizing Windows Event Logs from remote machines.

## Features

- **Automated Log Collection**: Gather logs from remote Windows machines
- **Log Analysis**: Analyze events against known security event IDs
- **Database Storage**: Store processed logs in MySQL database
- **Web Visualization**: Interactive dashboard for log exploration
- **Configurable Pipeline**: YAML-based configuration system

## Requirements

- Python 3.8+
- Windows environment (for pywin32)
- MySQL database server
- Network access to target Windows machines

## Installation

1. **Clone or download the project files**

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up MySQL database**:
   ```sql
   CREATE DATABASE event_logs;
   CREATE USER 'your_user'@'%' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON event_logs.* TO 'your_user'@'%';
   FLUSH PRIVILEGES;
   ```

## Configuration

1. **Copy and modify the configuration file**:
   - Edit `config.yml` with your specific settings
   - Update database credentials
   - Set target machine hostname/IP
   - Configure log types and levels to collect

2. **Required files**:
   - `config.yml` - Main configuration file
   - `event-classification.csv` - Reference file with known event IDs (optional)

## Usage

### Quick Start

Run the complete pipeline:
```bash
python main.py
```

### Individual Steps

You can also run individual components:

```bash
# Step 1: Gather logs
python gather_logs.py

# Step 2: Analyze logs  
python log_analysis.py

# Step 3: Send to database
python send_to_database.py

# Step 4: Launch visualization
python log_visualization.py
```

## File Structure

```
project/
├── main.py                    # Main orchestrator
├── config.yml                 # Configuration file
├── gather_logs.py            # Log collection module
├── log_analysis.py           # Log analysis module  
├── send_to_database.py       # Database operations
├── log_visualization.py      # Web dashboard
├── requirements.txt          # Python dependencies
├── event-classification.csv  # Reference events (optional)
└── README.md                # This file
```

## Configuration Options

### config.yml Structure

```yaml
target_machine:
  hostname: "192.168.1.100"  # Target machine IP/hostname

log_collection:
  hours_back: 10             # Hours of logs to collect
  log_types:                 # Windows log types to collect
    - "System"
    - "Security"
    - "Application"
  log_levels:                # Log levels to include
    - "CRITICAL"
    - "ERROR"
    - "WARNING"
    - "INFORMATION"

database:
  host: "localhost"
  port: 3306
  user: "username"
  password: "password"
  database: "event_logs"
```

## Pipeline Steps

1. **Log Collection**: Connects to remote Windows machine and collects event logs
2. **Analysis**: Compares collected events against known security event database
3. **Database Storage**: Stores processed events in MySQL for persistence
4. **Visualization**: Launches web dashboard for interactive log exploration

## Troubleshooting

### Common Issues

**Connection refused to target machine**:
- Ensure Windows Remote Management (WinRM) is enabled
- Check firewall settings
- Verify network connectivity

**Database connection failed**:
- Verify MySQL server is running
- Check credentials in config.yml
- Ensure database and user exist

**pywin32 import errors**:
- Install: `pip install pywin32`
- Run: `python Scripts/pywin32_postinstall.py -install`

### Logs

Check `log_processing.log` for detailed execution logs and error messages.

## Security Considerations

- Store database credentials securely
- Use least-privilege accounts for database access
- Consider encrypting log data in transit
- Regularly rotate access credentials

## License

This project is provided as-is for educational and professional use.