import sys
import os
import time
import subprocess
import datetime
import csv
import logging
from typing import List, Dict, Any, Tuple
from contextlib import contextmanager

try:
    import win32evtlog
    import win32con
except ImportError:
    sys.exit("Error: This script requires the pywin32 module. Please install it using 'pip install pywin32'.")

class WindowsEventLogGatherer:
    """A class for gathering logs from remote host by IP address, saves logs to the csv file"""
    def __init__(self, ip_file_name: str, log_types: List[str], log_levels: List[str]):
        if not os.path.exists(ip_file_name):
            raise FileNotFoundError(f"IP file {ip_file_name} does not exists")
        if not log_types:
            raise ValueError("At least one log type must be specified")
        
        self.ip_file_name = ip_file_name
        self.log_types = log_types
        self.log_levels = log_levels
        self.hostname = ''
        self.gathered_events = []
        self.logger = logging.getLogger(__name__)

    def gather_events(self, hours: int) -> List[Dict[str, Any]]:
        """Initialization function to check if host is up and start the process of harversting logs"""
        if 0 >= hours:
            raise ValueError("Hours must be a positive number")
        self.logger.info("Started colleting logs")
        with open(self.ip_file_name, "r", encoding="utf-8") as file:
            self.hostname = file.read().strip()
        self.logger.info(f"Hostname: {self.hostname}")

        if self.ping_host():
            for log in self.log_types:
                events = self.read_event_log(log, hours)
                self.gathered_events.extend(events)
        else:
            self.logger.warning(f"{self.hostname} is down! Exiting...")
        return self.gathered_events

    @contextmanager # Using contextmanager to prevent resource leaks if an error occurs during log processing
    def open_event_log(self, log_type: str):
        log_handle = None
        try:
            log_handle = win32evtlog.OpenEventLog(self.hostname, log_type)
            yield log_handle
        finally:
            if log_handle:
                win32evtlog.CloseEventLog(log_handle)

    def read_event_log(self, log_type: str, hours: int) -> List[Dict[str, Any]]:
        begin_sec = time.time()
        seconds_per_hour = 3600
        how_many_seconds_back_to_search = seconds_per_hour * hours
        events_from_log = []

        try:
            with self.open_event_log(log_type) as log_handle:
                total = win32evtlog.GetNumberOfEventLogRecords(log_handle)
                self.logger.info(f"Scanning through {total} events on {self.hostname} in {log_type}")

                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                event_count = 0
                while True:
                    events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                    if not events:
                        break

                    for event in events:
                        event_count += 1
                        event_object, seconds, event_type_string = self.normalize_logs(event, log_type)

                        if self.should_include_event(event_type_string):
                            events_from_log.append(event_object)

                    if seconds < begin_sec - how_many_seconds_back_to_search:
                        return events_from_log

                self.logger.info(f"Finished processing {event_count} events in {log_type}")

        except win32evtlog.error as e:
            if e.winerror == 5:  # Access denied
                self.logger.error(f"Access denied when connecting to event log {log_type}")
            elif e.winerror == 1722:  # RPC server unavailable
                self.logger.error(f"Cannot connect to remote host {self.hostname}")
            else:
                self.logger.error(f"Win32 error occurred: {e}")
        return events_from_log

    def save_to_csv(self, file_with_logs: str) -> None:
        if not self.gathered_events:
            self.logger.info("No events were gathered skipping CSV export")
            return
        with open(file_with_logs, "w", encoding='utf-8', newline='') as file:
            fieldnames = self.gathered_events[0].keys()
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.gathered_events)
        self.logger.info(f"Saved logs to {file_with_logs} file")

    def normalize_logs(self, event, log_type: str) -> Tuple[Dict[str, Any], float, str]:
        # Get original event time format
        original_event_time = event.TimeGenerated.Format()
        dt = datetime.datetime.strptime(original_event_time, "%a %b %d %H:%M:%S %Y")
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        
        seconds = self.date_to_sec(original_event_time)
        event_type = event.EventType
        
        # Map event type to string representation
        event_type_map = {
            win32con.EVENTLOG_ERROR_TYPE: "ERROR",
            win32con.EVENTLOG_WARNING_TYPE: "WARNING",
            win32con.EVENTLOG_INFORMATION_TYPE: "INFORMATION",
            win32con.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
            win32con.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE"
        }
        event_type_string = event_type_map.get(event_type, "OTHER")
        
        message = event.StringInserts
        if message is None:
            message = "No message data"
        elif isinstance(message, tuple):
            # Keep message as a list format string
            message = str(list(str(m) for m in message if m is not None))

        return {
            "Event": log_type,
            "Time": formatted_time,
            "Event_Type": event_type_string,
            "Event_ID": event.EventID & 0xFFFF,  # Handle large event IDs correctly
            "Event_Category": event.EventCategory,
            "Source": event.SourceName,
            "Message": message,
            "RecordNumber": event.RecordNumber
        }, seconds, event_type_string

    def date_to_sec(self, evt_date: str) -> float:
        dt = datetime.datetime.strptime(evt_date, "%a %b %d %H:%M:%S %Y")
        return dt.timestamp()

    def should_include_event(self, event_type: str) -> bool:
        return event_type in self.log_levels

    def ping_host(self):
        param = '-n' if sys.platform.lower() == 'win32' else '-c'
        timeout_param = '-w' if sys.platform.lower() == 'win32' else '-W' # Timeout parameter to avoid hanging or unresponsive hosts
        try:
            result = subprocess.run(
                ["ping", param, "1", timeout_param, "2", self.hostname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5 # Overall timeout for the subprocess
            )
            return result.returncode == 0
        except Exception:
            self.logger.warning(f"Ping to {self.hostname} failed or timed out")
            return False

    def save_uniqe_event_ids_and_types_to_the_file(self, file_path):
        unique_event_types = set()
        unique_event_ids = set()

        for event in self.gathered_events:
            unique_event_types.add(event["Event_Type"])
            unique_event_ids.add(event["Event_ID"])

        # Write the unique values to a file
        self.logger.info(f"Saved all event types and event IDs to the {file_path} file")
        with open(file_path, "w", encoding="utf-8") as file:
            file.write("Unique Event_Types:\n")
            for event_type in sorted(unique_event_types):
                file.write(str(event_type) + " ")
            file.write("\n")
            file.write("\nUnique Event_IDs:\n")
            for event_id in sorted(unique_event_ids):
                file.write(str(event_id) + " ")

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    file_with_IP = "vm-ip.txt"
    file_with_logs = "logs.csv"
    hours = 10
    log_types = [
        "System", 
        "Security", 
        "Application", 
        "Microsoft-Windows-Sysmon/Operational",
    ]
    log_levels = [
        "AUDIT_FAILURE",
        "AUDIT_SUCCESS",
        "ERROR",
        "INFORMATION",
        "WARNING",
    ]
    logs = WindowsEventLogGatherer(file_with_IP, log_types, log_levels)
    logs.gather_events(hours)
    logs.save_to_csv(file_with_logs)

    logs.save_uniqe_event_ids_and_types_to_the_file("events.txt")

if __name__ == "__main__":
    main()