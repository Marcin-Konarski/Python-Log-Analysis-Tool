import csv
import json
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

@dataclass
class KnownEvent:
    """Reference information about a known event severity level.
    Source: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor"""
    event_id: int
    severity: str
    description: str

@dataclass
class LogEvent:
    """Events gathered directly from logs, filtered with progess_logs.py file"""
    event_id: int
    log_type: str
    source: str
    event_type: str
    date: str
    message: str = ""

class WindowsEventLogAnalyser:
    """Class used to analyze logs by comparing gathered events to known event IDs sevirty levels"""
    def __init__(self):
        self.reference_events: Dict[int, KnownEvent] = {}
        self.log_events: List[LogEvent] = []
        self.event_counter: Counter = Counter()
        self.logger = logging.getLogger(__name__)

    def load_reference_events_from_file(self, csv_events_file_path: str):
        path = Path(csv_events_file_path)
        if not path.exists():
            raise FileNotFoundError(f"File with the specified path {csv_events_file_path} does not exist")

        try:
            with open(path, "r", encoding="utf-8") as file:
                reader = csv.DictReader(file)

                fieldnames = reader.fieldnames
                if not fieldnames or "Event ID" not in fieldnames or "Severity" not in fieldnames or "Description" not in fieldnames:
                    raise ValueError(f"CSV file missing required columns. Found: {fieldnames}")

                for row in reader:
                    if 3 <= len(row):
                        event_id = int(row["Event ID"])
                        event = KnownEvent(
                            event_id,
                            row["Severity"],
                            row["Description"]
                        )
                        self.reference_events[event_id] = event
                self.logger.info(f"Loaded {len(self.reference_events)} reference events from {path}")
        except Exception as e:
            self.logger.error(f"Error loading reference events: {e}")

    def load_logs_from_csv(self, logs_file_path: str) -> List[LogEvent]:
        path = Path(logs_file_path)
        if not path.exists():
            raise FileNotFoundError(f"File with thr sepcified path {logs_file_path} does not exists")
        self.log_events = [] # Reset the log events list

        try:
            with open(path, 'r', encoding='utf-8-sig') as file:
                reader = csv.DictReader(file)

                fieldnames = reader.fieldnames
                required_fields = ["Event_ID", "Event", "Source", "Event_Type", "Time"]
                if not all(field in fieldnames for field in required_fields):
                    raise ValueError(f"CSV file missing required columns. Found: {fieldnames}")
                has_message = "message" in fieldnames if fieldnames else False
                
                for row in reader:
                    try:
                        # Create LogEvent object from the CSV row
                        log_event = LogEvent(
                            event_id=int(row['Event_ID']),
                            log_type=row['Event'],
                            source=row['Source'],
                            event_type=row['Event_Type'],
                            date=row['Time'],
                            message=row.get('Message', "")
                        )
                        self.log_events.append(log_event)
                    except Exception as e:
                        self.logger.warning(f"Error processing row: {row}. Error: {e}")
                        continue
                
                self._update_event_counter()
                self.logger.info(f"Successfully loaded {len(self.log_events)} log events from {logs_file_path}")
                return self.log_events
        except Exception as e:
            self.logger.error(f"Error loading log file {logs_file_path}: {e}")
            return []

    def analyze_events_based_on_event_id(self):
        suspicious_found = False
        self.logger.info("\n===== Matched Events =====")
        for event_id in self.get_unique_event_ids():
            reference = self.reference_events.get(event_id)
            if reference: # and (reference.severity == "Medium" or reference.severity == "High"):
                suspicious_found = True
                #### TODO: DO SOMETHING WITH THOSE EVENTS INSTEAD OF JUST PRINTING THEM TO THE CONSOLE - maybe matplotlib graphs
                self.logger.info(f"[SUSPICIOUS EVENT FOUND: ] {reference.event_id}, {reference.severity}, {reference.description}") 
        if not suspicious_found:
            self.logger.info("No events mached") # This is just to display anything to the console in case of no events from logs match events from refernce 

    def count_number_of_event_occurances(self):
        self.logger.info("\n===== Number of Occurences of Each Event =====")
        for event_id, count in self.event_counter.most_common():
            reference = self.reference_events.get(event_id)
            #### TODO: DO SOMETHING WITH THOSE EVENTS INSTEAD OF JUST PRINTING THEM TO THE CONSOLE - maybe matplotlib graphs
            description = f"({reference.description})" if reference else ""
            self.logger.info(f"Event ID {event_id}, {description} {count} occurrences")

    def _update_event_counter(self):
        self.event_counter = Counter(event.event_id for event in self.log_events)

    def get_unique_event_ids(self):
        return set(self.event_counter.keys())

    def print_all_log_events(self):
        if not self.log_events:
            self.logger.warning("No log events to display")
            return
        
        self.logger.info("\n===== Log Events =====")
        for i, event in enumerate(self.log_events, 1):
            log_info = (
                f"Event #{i}:\n"
                f"  Event ID: {event.event_id}\n"
                f"  Log Type: {event.log_type}\n"
                f"  Source: {event.source}\n"
                f"  Event Type: {event.event_type}\n"
                f"  Date: {event.date}\n"
                f"{'-' * 30}"
            )
            self.logger.info(log_info)
        self.logger.info(f"Total: {len(self.log_events)} log events")

    def save_to_json(self, output_file_path: str):
        """Save analysis results to a JSON file with the specified structure"""
        self.logger.info(f"Saving analysis results to {output_file_path}")

        results: Dict[str, List[Dict[str, Any]]] = {"events": []}
        unique_event_ids = sorted(list(self.get_unique_event_ids()))
        
        # Group events by event_id
        for event_id in unique_event_ids:
            event_data = {
                "event_id": event_id,
                "no_occurances": self.event_counter[event_id],
                "specific_events": []
            }
            
            # Add severity and message if available from reference events
            reference = self.reference_events.get(event_id)
            if reference:
                event_data["severity"] = reference.severity
                event_data["description"] = reference.description
            
            # Get all specific events with this ID
            specific_events = [e for e in self.log_events if e.event_id == event_id]
            
            # Sort events by date in ascending order
            try:
                specific_events.sort(key=lambda e: datetime.strptime(e.date, "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                # If date format is different, log it and continue without sorting
                self.logger.warning(f"Could not sort events by date due to format issues")
            
            # Add each specific event
            for i, event in enumerate(specific_events, 1):
                specific_event = {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "source": event.source,
                    "date": event.date,
                    "message": getattr(event, 'message', "")
                }
                event_data["specific_events"].append(specific_event)
            
            results["events"].append(event_data)
        
        # Write to the JSON file
        try:
            with open(output_file_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Successfully saved analysis results to {output_file_path}")
        except Exception as e:
            self.logger.error(f"Error saving results to JSON: {e}")

def main():
    """Main function for standalone execution"""
    import yaml
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Load configuration
    try:
        with open("config.yml", 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        file_paths = config['file_paths']
        reference_file = file_paths['reference_events']
        logs_file = file_paths['raw_logs']
        results_file = file_paths['analysis_results']
    except Exception as e:
        print(f"Error loading config: {e}")
        # Fallback to hardcoded values
        reference_file = "event-classification.csv"
        logs_file = "logs.csv"
        results_file = "analysis_results.json"

    analyzer = WindowsEventLogAnalyser()
    
    # Try to load reference events
    try:
        analyzer.load_reference_events_from_file(reference_file)
    except FileNotFoundError:
        print(f"Reference file {reference_file} not found, proceeding without it")
    
    analyzer.load_logs_from_csv(logs_file)
    analyzer.count_number_of_event_occurances()
    analyzer.analyze_events_based_on_event_id()
    analyzer.save_to_json(results_file)

if __name__ == "__main__":
    main()
