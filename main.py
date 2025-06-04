"""
Main orchestrator for Windows Event Log processing pipeline.
This script coordinates the execution of all log processing steps.
"""

import os
import sys
import yaml
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List
import time
from dataclasses import dataclass

# Import modules
try:
    from gather_logs import WindowsEventLogGatherer
    from log_analysis import WindowsEventLogAnalyser
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all required Python files are in the same directory")
    sys.exit(1)

@dataclass
class Config:
    """Configuration data class for type safety and easy access"""
    target_hostname: str
    hours_back: int
    log_types: List[str]
    log_levels: List[str]
    reference_events_file: str
    raw_logs_file: str
    analysis_results_file: str
    unique_events_file: str
    db_config: Dict[str, Any]
    save_intermediate_files: bool
    cleanup_temp_files: bool
    log_level: str
    visualization_config: Dict[str, Any]

class LogProcessingOrchestrator:
    """Main orchestrator class for the log processing pipeline"""
    
    def __init__(self, config_file: str = "config.yml"):
        self.config_file = config_file
        self.config = self._load_config()
        self.temp_files = []
        self._setup_logging()
        
    def _load_config(self) -> Config:
        """Load and validate configuration from YAML file"""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Configuration file {self.config_file} not found")
            
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                yaml_config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML configuration: {e}")
        
        # Validate required sections
        required_sections = ['target_machine', 'log_collection', 'file_paths', 'database']
        for section in required_sections:
            if section not in yaml_config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        # Build Config object
        config = Config(
            target_hostname=yaml_config['target_machine']['hostname'],
            hours_back=yaml_config['log_collection']['hours_back'],
            log_types=yaml_config['log_collection']['log_types'],
            log_levels=yaml_config['log_collection']['log_levels'],
            reference_events_file=yaml_config['file_paths']['reference_events'],
            raw_logs_file=yaml_config['file_paths']['raw_logs'],
            analysis_results_file=yaml_config['file_paths']['analysis_results'],
            unique_events_file=yaml_config['file_paths']['unique_events'],
            db_config=yaml_config['database'],
            save_intermediate_files=yaml_config.get('processing', {}).get('save_intermediate_files', True),
            cleanup_temp_files=yaml_config.get('processing', {}).get('cleanup_temp_files', False),
            log_level=yaml_config.get('processing', {}).get('log_level', 'INFO'),
            visualization_config=yaml_config.get('visualization', {})
        )
        
        return config
    
    def _setup_logging(self):
        """Set up logging configuration"""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('log_processing.log', encoding='utf-8')
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _create_temp_hostname_file(self) -> str:
        """Create temporary file with hostname for compatibility with existing code"""
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        temp_file.write(self.config.target_hostname)
        temp_file.close()
        self.temp_files.append(temp_file.name)
        return temp_file.name
    
    def step1_gather_logs(self) -> bool:
        """Step 1: Gather logs from the target machine"""
        self.logger.info("=" * 60)
        self.logger.info("STEP 1: Gathering Windows Event Logs")
        self.logger.info("=" * 60)
        
        try:
            # Create temporary hostname file for compatibility
            hostname_file = self._create_temp_hostname_file()
            
            # Initialize log gatherer
            gatherer = WindowsEventLogGatherer(
                ip_file_name=hostname_file,
                log_types=self.config.log_types,
                log_levels=self.config.log_levels
            )
            
            # Gather events
            self.logger.info(f"Collecting logs from {self.config.target_hostname} for the last {self.config.hours_back} hours")
            events = gatherer.gather_events(self.config.hours_back)
            
            if not events:
                self.logger.warning("No events were gathered")
                return False
            
            # Save logs to CSV
            gatherer.save_to_csv(self.config.raw_logs_file)
            
            # Save unique event IDs and types
            gatherer.save_uniqe_event_ids_and_types_to_the_file(self.config.unique_events_file)
            
            self.logger.info(f"Successfully gathered {len(events)} events")
            return True
            
        except Exception as e:
            self.logger.error(f"Error in log gathering step: {e}")
            return False
    
    def step2_analyze_logs(self) -> bool:
        """Step 2: Analyze collected logs"""
        self.logger.info("=" * 60)
        self.logger.info("STEP 2: Analyzing Event Logs")
        self.logger.info("=" * 60)
        
        try:
            # Check if logs file exists
            if not os.path.exists(self.config.raw_logs_file):
                self.logger.error(f"Raw logs file {self.config.raw_logs_file} not found")
                return False
            
            # Initialize analyzer
            analyzer = WindowsEventLogAnalyser()
            
            # Load reference events if file exists
            if os.path.exists(self.config.reference_events_file):
                analyzer.load_reference_events_from_file(self.config.reference_events_file)
                self.logger.info(f"Loaded reference events from {self.config.reference_events_file}")
            else:
                self.logger.warning(f"Reference events file {self.config.reference_events_file} not found, proceeding without it")
            
            # Load and analyze logs
            log_events = analyzer.load_logs_from_csv(self.config.raw_logs_file)
            
            if not log_events:
                self.logger.warning("No log events were loaded for analysis")
                return False
            
            # Perform analysis
            analyzer.count_number_of_event_occurances()
            analyzer.analyze_events_based_on_event_id()
            
            # Save results to JSON
            analyzer.save_to_json(self.config.analysis_results_file)
            
            self.logger.info(f"Successfully analyzed {len(log_events)} events")
            return True
            
        except Exception as e:
            self.logger.error(f"Error in log analysis step: {e}")
            return False
    
    # def step3_send_to_database(self) -> bool:
    #     """Step 3: Send analyzed data to database"""
    #     self.logger.info("=" * 60)
    #     self.logger.info("STEP 3: Sending Data to Database")
    #     self.logger.info("=" * 60)
        
    #     try:
    #         # Check if analysis results exist
    #         if not os.path.exists(self.config.analysis_results_file):
    #             self.logger.error(f"Analysis results file {self.config.analysis_results_file} not found")
    #             return False
            
    #         # Import database modules
    #         import json
    #         import mysql.connector
    #         import pandas as pd
            
    #         # Load analysis results
    #         with open(self.config.analysis_results_file, "r", encoding="utf-8") as f:
    #             data = json.load(f)
            
    #         # Connect to database
    #         self.logger.info(f"Connecting to database at {self.config.db_config['host']}:{self.config.db_config['port']}")
    #         conn = mysql.connector.connect(**self.config.db_config)
    #         cursor = conn.cursor()
            
    #         # Convert JSON to DataFrame
    #         def json_to_dataframe(json_data):
    #             events_data = []
    #             for event in json_data["events"]:
    #                 specific_events = event.get("specific_events", [])
    #                 for se in specific_events:
    #                     events_data.append({
    #                         "event_id": se.get("event_id", "Unknown"),
    #                         "source": se.get("source", "Unknown"),
    #                         "event_type": se.get("event_type", "Unknown"),
    #                         "date": se.get("date", None),
    #                         "message": se.get("message", "")
    #                     })
    #             return pd.DataFrame(events_data)
            
    #         df = json_to_dataframe(data)
    #         df["date"] = pd.to_datetime(df["date"], errors="coerce")
            
    #         # Insert data into database
    #         inserted_count = 0
    #         for _, row in df.iterrows():
    #             cursor.execute("""
    #                 INSERT IGNORE INTO logs (event_id, event_type, source, date, message)
    #                 VALUES (%s, %s, %s, %s, %s)
    #             """, (
    #                 row["event_id"],
    #                 row["event_type"],
    #                 row["source"],
    #                 row["date"].strftime("%Y-%m-%d %H:%M:%S") if pd.notnull(row["date"]) else None,
    #                 row["message"]
    #             ))
    #             if cursor.rowcount > 0:
    #                 inserted_count += 1
            
    #         conn.commit()
    #         cursor.close()
    #         conn.close()
            
    #         self.logger.info(f"Successfully inserted {inserted_count} new records into database")
    #         return True
            
    #     except Exception as e:
    #         self.logger.error(f"Error in database insertion step: {e}")
    #         return False

    def step3_send_to_database(self) -> bool:
        """Step 3: Send analyzed data to database"""
        self.logger.info("=" * 60)
        self.logger.info("STEP 3: Sending Data to Database")
        self.logger.info("=" * 60)
        
        try:
            # Check if analysis results exist
            if not os.path.exists(self.config.analysis_results_file):
                self.logger.error(f"Analysis results file {self.config.analysis_results_file} not found")
                return False
            
            # Import the function from send_to_database module
            from send_to_database import send_data_to_database
            
            self.logger.info(f"Connecting to database at {self.config.db_config['host']}:{self.config.db_config['port']}")
            
            # Send data to database using the refactored function
            inserted_count = send_data_to_database(
                config_db=self.config.db_config,
                json_file=self.config.analysis_results_file
            )
            
            self.logger.info(f"Successfully inserted {inserted_count} new records into database")
            return True
        
        except Exception as e:
            self.logger.error(f"Error in database insertion step: {e}")
            return False
    
    def step4_launch_visualization(self) -> bool:
        """Step 4: Launch web visualization (optional)"""
        if not self.config.visualization_config.get('auto_launch', False):
            self.logger.info("Visualization auto-launch is disabled")
            return True
            
        self.logger.info("=" * 60)
        self.logger.info("STEP 4: Launching Web Visualization")
        self.logger.info("=" * 60)
        
        try:
            # Check if visualization script exists
            viz_script = "log_visualization.py"
            if not os.path.exists(viz_script):
                self.logger.warning(f"Visualization script {viz_script} not found")
                return False
            
            self.logger.info("Starting web visualization server...")
            self.logger.info(f"Access the dashboard at: http://{self.config.visualization_config.get('host', '127.0.0.1')}:{self.config.visualization_config.get('port', 8050)}")
            
            # Launch the visualization script
            subprocess.run([sys.executable, viz_script], check=True)
            return True
            
        except Exception as e:
            self.logger.error(f"Error launching visualization: {e}")
            return False
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.config.cleanup_temp_files:
            self.logger.info("Cleaning up temporary files...")
            for temp_file in self.temp_files:
                try:
                    os.unlink(temp_file)
                    self.logger.debug(f"Deleted temporary file: {temp_file}")
                except Exception as e:
                    self.logger.warning(f"Failed to delete temporary file {temp_file}: {e}")
    
    def run_pipeline(self) -> bool:
        """Run the complete log processing pipeline"""
        print("here")
        start_time = time.time()
        self.logger.info("Starting Windows Event Log Processing Pipeline")
        self.logger.info(f"Configuration: {self.config_file}")
        self.logger.info(f"Target machine: {self.config.target_hostname}")
        
        steps = [
            ("Gather Logs", self.step1_gather_logs),
            ("Analyze Logs", self.step2_analyze_logs),
            ("Send to Database", self.step3_send_to_database),
            ("Launch Visualization", self.step4_launch_visualization)
        ]
        
        success_count = 0
        
        try:
            for step_name, step_func in steps:
                self.logger.info(f"\nExecuting: {step_name}")
                if step_func():
                    success_count += 1
                    self.logger.info(f"✓ {step_name} completed successfully")
                else:
                    self.logger.error(f"✗ {step_name} failed")
                    if step_name in ["Gather Logs", "Analyze Logs"]:  # Critical steps
                        self.logger.error("Critical step failed, stopping pipeline")
                        break
                
                # Brief pause between steps
                time.sleep(1)
        
        finally:
            self.cleanup()
        
        # Summary
        elapsed_time = time.time() - start_time
        self.logger.info("=" * 60)
        self.logger.info("PIPELINE SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Completed steps: {success_count}/{len(steps)}")
        self.logger.info(f"Total execution time: {elapsed_time:.2f} seconds")
        
        if success_count >= 3:  # At least core steps completed
            self.logger.info("✓ Pipeline completed successfully!")
            return True
        else:
            self.logger.error("✗ Pipeline completed with errors")
            return False

def main():
    """Main entry point"""
    config_file = "config.yml"
    print("aaa")
    # Check if config file exists
    if not os.path.exists(config_file):
        print(f"Error: Configuration file '{config_file}' not found")
        print("Please create the configuration file before running the pipeline")
        sys.exit(1)
    print(f"Config file: {config_file}")

    try:
        # Create and run orchestrator
        orchestrator = LogProcessingOrchestrator(config_file)
        success = orchestrator.run_pipeline()
        
        sys.exit(0 if success else 1)
    
    except KeyboardInterrupt:
        print("\nPipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()