import os
import sys
import time
import subprocess
import datetime
import win32evtlog ## type: ignore
import win32con ## type: ignore
import traceback


## This function converts dates with format 'Thu Jul 13 08:22:34 2017' to seconds since 1970.
def date2sec(evt_date: str) -> float:
    dt = datetime.datetime.strptime(evt_date, "%a %b %d %H:%M:%S %Y")
    return dt.timestamp()

def shouldIncludeEvent(event_type: str) -> bool:
    return event_type not in {"INFORMATION", "AUDIT_SUCCESS"}

## Reads the log_type (e.g., "Application" or "System") Windows events from the specified server.
def readEventLog(hostname:str, log_type: str, number_of_hours_to_look_back: float) -> list[dict]:
    begin_sec = time.time()

    seconds_per_hour = 60 * 60
    how_many_seconds_back_to_search = seconds_per_hour * number_of_hours_to_look_back

    gathered_events = []

    try:
        log_handle = win32evtlog.OpenEventLog(hostname, log_type) ## Connects to the event log on the specified hostname (open the Windows Event Log)

        total = win32evtlog.GetNumberOfEventLogRecords(log_handle) ## Retrieves the total number of logs available in the specified log type
        print("Scanning through {} events on {} in {}".format(total, hostname, log_type))

        ## EVENTLOG_BACKWARDS_READ -> Reads logs from newest to oldest
        ## EVENTLOG_SEQUENTIAL_READ -> Reads logs in order
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        event_count = 0
        events = 1
        while events:
            events = win32evtlog.ReadEventLog(log_handle, flags, 0) ## Read a batch of logs; 0 means start reading events from the current position
            seconds = begin_sec
            for event in events:
                event_time = event.TimeGenerated.Format()
                seconds = date2sec(event_time)
                event_type = event.EventType
                event_type_string = ""

                if event_type == win32con.EVENTLOG_ERROR_TYPE:
                    event_type_string = "ERROR"
                elif event_type == win32con.EVENTLOG_WARNING_TYPE:
                    event_type_string = "WARNING"
                elif event_type == win32con.EVENTLOG_INFORMATION_TYPE:
                    event_type_string = "INFORMATION"
                elif event_type == win32con.EVENTLOG_AUDIT_SUCCESS:
                    event_type_string = "AUDIT_SUCCESS"
                elif event_type == win32con.EVENTLOG_AUDIT_FAILURE:
                    event_type_string = "AUDIT_FAILURE"
                else:
                    event_type_string = "OTHER"

                event_object = {
                    "Event": log_type,
                    "Time": event_time,
                    "Event_Type": event_type_string,
                    "Event_ID": event.EventID,
                    "Source": event.SourceName,
                    "Message": event.StringInserts
                }

                event_count += 1
                if shouldIncludeEvent(event_type_string):
                    gathered_events.append(event_object)

            if seconds < begin_sec - how_many_seconds_back_to_search:
                break

        win32evtlog.CloseEventLog(log_handle)

    except Exception as e:
        print("An error occurred:", e)
        traceback.print_exc()

    return gathered_events


def pingVM(hostname: str) -> bool:
    param = '-n' if sys.platform.lower() == 'win32' else '-c'
    try: ## here subprocess.run() is safer then os.system(f"ping {param} 1 {hostname}"), gives better control over output, and prevents shell injection risks
        result = subprocess.run(["ping", param, "1", hostname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        return result.returncode == 0
    except:
        return False


def initGathering():
    with open('vm-ip.txt', 'r') as file:
        hostname = file.read().strip()
    print(hostname)

    log_types = ["System", "Security", "Application", "Network Isolation Operational"]
    gathered_events = []

    if pingVM(hostname):
        for log in log_types:
            gathered_events.extend(readEventLog(hostname, log, 10))
    else:
        print(f"[INFO:] {hostname} is down! Exiting...")

    os.makedirs("/app/output", exist_ok=True) ## this ensures that /app/output exists
    with open("/app/output/logs.txt", 'w') as file:
        for i, event in enumerate(gathered_events):
            file.writelines(f'\nUnique_ID: {i}\n')
            for k, v in event.items():
                file.writelines(f'{k}: {v}\n')


if __name__ == "__main__":
    initGathering()
