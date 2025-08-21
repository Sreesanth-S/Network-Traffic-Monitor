import csv
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import threading
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
LOG_FILE = 'logs.csv'
BACKUP_DIR = 'log_backups'
MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB
MAX_BACKUP_FILES = 10

# Thread lock for file operations
file_lock = threading.Lock()

def initialize_log_file():
    """Initialize the CSV log file with headers if it doesn't exist"""
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([
                    'Timestamp', 
                    'Source IP', 
                    'Destination IP', 
                    'Source Port', 
                    'Destination Port', 
                    'Protocol', 
                    'Location', 
                    'Alert', 
                    'Alert Level',
                    'Risk Score',
                    'Size',
                    'Flags',
                    'TTL'
                ])
            logger.info(f"Created new log file: {LOG_FILE}")
        else:
            logger.info(f"Using existing log file: {LOG_FILE}")
    except Exception as e:
        logger.error(f"Error initializing log file: {e}")

def check_log_rotation():
    """Check if log file needs rotation based on size"""
    try:
        if os.path.exists(LOG_FILE):
            file_size = os.path.getsize(LOG_FILE)
            if file_size > MAX_LOG_SIZE:
                rotate_log_file()
    except Exception as e:
        logger.error(f"Error checking log rotation: {e}")

def rotate_log_file():
    """Rotate log file when it gets too large"""
    try:
        # Create backup directory if it doesn't exist
        os.makedirs(BACKUP_DIR, exist_ok=True)
        
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"logs_backup_{timestamp}.csv"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Move current log to backup
        if os.path.exists(LOG_FILE):
            os.rename(LOG_FILE, backup_path)
            logger.info(f"Rotated log file to: {backup_path}")
        
        # Create new log file
        initialize_log_file()
        
        # Clean up old backup files
        cleanup_old_backups()
        
    except Exception as e:
        logger.error(f"Error rotating log file: {e}")

def cleanup_old_backups():
    """Remove old backup files to prevent disk space issues"""
    try:
        if not os.path.exists(BACKUP_DIR):
            return
            
        # Get all backup files sorted by modification time
        backup_files = []
        for filename in os.listdir(BACKUP_DIR):
            if filename.startswith('logs_backup_') and filename.endswith('.csv'):
                filepath = os.path.join(BACKUP_DIR, filename)
                backup_files.append((filepath, os.path.getmtime(filepath)))
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x[1], reverse=True)
        
        # Remove old files if we have too many
        if len(backup_files) > MAX_BACKUP_FILES:
            files_to_remove = backup_files[MAX_BACKUP_FILES:]
            for filepath, _ in files_to_remove:
                try:
                    os.remove(filepath)
                    logger.info(f"Removed old backup file: {filepath}")
                except Exception as e:
                    logger.warning(f"Error removing backup file {filepath}: {e}")
                    
    except Exception as e:
        logger.error(f"Error cleaning up old backups: {e}")

def log_packet(data: Dict[str, Any]):
    """
    Log packet data to CSV file with thread safety and error handling
    
    Args:
        data: Dictionary containing packet information
    """
    try:
        with file_lock:
            # Check if log rotation is needed
            check_log_rotation()
            
            # Ensure log file exists
            if not os.path.exists(LOG_FILE):
                initialize_log_file()
            
            # Prepare data for logging
            log_data = prepare_log_data(data)
            
            # Write to CSV
            with open(LOG_FILE, 'a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(log_data)
                
    except Exception as e:
        logger.error(f"Error logging packet: {e}")
        # Try to log to a backup file if main logging fails
        try:
            log_to_backup(data, e)
        except Exception as backup_error:
            logger.error(f"Backup logging also failed: {backup_error}")

def prepare_log_data(data: Dict[str, Any]) -> list:
    """
    Prepare packet data for CSV logging
    
    Args:
        data: Raw packet data dictionary
        
    Returns:
        List of values ready for CSV writing
    """
    try:
        return [
            data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            sanitize_csv_field(data.get('src_ip', '')),
            sanitize_csv_field(data.get('dst_ip', '')),
            sanitize_csv_field(str(data.get('src_port', ''))),
            sanitize_csv_field(str(data.get('dst_port', ''))),
            sanitize_csv_field(data.get('protocol', '')),
            sanitize_csv_field(data.get('location', '')),
            sanitize_csv_field(data.get('alert', '')),
            sanitize_csv_field(data.get('alert_level', '')),
            sanitize_csv_field(str(data.get('risk_score', 0))),
            sanitize_csv_field(str(data.get('size', 0))),
            sanitize_csv_field(str(data.get('flags', ''))),
            sanitize_csv_field(str(data.get('ttl', '')))
        ]
    except Exception as e:
        logger.error(f"Error preparing log data: {e}")
        # Return basic data if preparation fails
        return [
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            data.get('src_ip', ''),
            data.get('dst_ip', ''),
            '',
            '',
            data.get('protocol', ''),
            '',
            'Logging Error',
            'Unknown',
            '0',
            '0',
            '',
            ''
        ]

def sanitize_csv_field(field: str) -> str:
    """
    Sanitize field for CSV output to prevent injection or formatting issues
    
    Args:
        field: Raw field value
        
    Returns:
        Sanitized field value
    """
    if not isinstance(field, str):
        field = str(field)
    
    # Remove or escape problematic characters
    field = field.replace('\r', '').replace('\n', ' ')
    
    # Limit field length to prevent extremely long entries
    if len(field) > 500:
        field = field[:497] + '...'
    
    return field

def log_to_backup(data: Dict[str, Any], original_error: Exception):
    """
    Log to backup file when main logging fails
    
    Args:
        data: Packet data to log
        original_error: The original error that caused logging to fail
    """
    try:
        backup_file = f"emergency_log_{datetime.now().strftime('%Y%m%d')}.csv"
        
        # Create backup file with headers if it doesn't exist
        if not os.path.exists(backup_file):
            with open(backup_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(['Timestamp', 'Error', 'Data'])
        
        # Log the error and data
        with open(backup_file, 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow([
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                str(original_error),
                str(data)
            ])
            
        logger.info(f"Logged to emergency backup: {backup_file}")
        
    except Exception as e:
        logger.critical(f"Emergency backup logging failed: {e}")

def get_log_stats() -> Dict[str, Any]:
    """
    Get statistics about the log file
    
    Returns:
        Dictionary with log file statistics
    """
    try:
        stats = {
            'log_file_exists': os.path.exists(LOG_FILE),
            'log_file_size': 0,
            'log_file_lines': 0,
            'backup_files_count': 0,
            'last_modified': None
        }
        
        if os.path.exists(LOG_FILE):
            # Get file size
            stats['log_file_size'] = os.path.getsize(LOG_FILE)
            
            # Get last modified time
            stats['last_modified'] = datetime.fromtimestamp(
                os.path.getmtime(LOG_FILE)
            ).strftime('%Y-%m-%d %H:%M:%S')
            
            # Count lines (approximate number of log entries)
            with open(LOG_FILE, 'r', encoding='utf-8') as file:
                stats['log_file_lines'] = sum(1 for _ in file) - 1  # Subtract header
        
        # Count backup files
        if os.path.exists(BACKUP_DIR):
            backup_files = [f for f in os.listdir(BACKUP_DIR) 
                          if f.startswith('logs_backup_') and f.endswith('.csv')]
            stats['backup_files_count'] = len(backup_files)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting log stats: {e}")
        return {
            'error': str(e),
            'log_file_exists': False,
            'log_file_size': 0,
            'log_file_lines': 0,
            'backup_files_count': 0,
            'last_modified': None
        }

def read_recent_logs(count: int = 100) -> list:
    """
    Read recent log entries from the file
    
    Args:
        count: Number of recent entries to read
        
    Returns:
        List of dictionaries containing log entries
    """
    logs = []
    try:
        if not os.path.exists(LOG_FILE):
            return logs
        
        with open(LOG_FILE, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            all_logs = list(reader)
            
            # Return the most recent entries
            recent_logs = all_logs[-count:] if len(all_logs) > count else all_logs
            
            for row in recent_logs:
                # Convert back to the format expected by the application
                log_entry = {
                    'timestamp': row.get('Timestamp', ''),
                    'src_ip': row.get('Source IP', ''),
                    'dst_ip': row.get('Destination IP', ''),
                    'src_port': row.get('Source Port', ''),
                    'dst_port': row.get('Destination Port', ''),
                    'protocol': row.get('Protocol', ''),
                    'location': row.get('Location', ''),
                    'alert': row.get('Alert', ''),
                    'alert_level': row.get('Alert Level', ''),
                    'risk_score': row.get('Risk Score', '0'),
                    'size': int(row.get('Size', 0)) if row.get('Size', '').isdigit() else 0,
                    'flags': row.get('Flags', ''),
                    'ttl': row.get('TTL', '')
                }
                logs.append(log_entry)
        
        return logs
        
    except Exception as e:
        logger.error(f"Error reading recent logs: {e}")
        return logs

def export_logs(start_date: Optional[str] = None, end_date: Optional[str] = None, 
                output_file: Optional[str] = None) -> str:
    """
    Export logs within a date range to a new file
    
    Args:
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        output_file: Output filename (optional)
        
    Returns:
        Path to the exported file
    """
    try:
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"exported_logs_{timestamp}.csv"
        
        exported_count = 0
        
        with open(LOG_FILE, 'r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            
            with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
                writer.writeheader()
                
                for row in reader:
                    # Filter by date if specified
                    if start_date or end_date:
                        try:
                            log_date = datetime.strptime(
                                row.get('Timestamp', '').split(' ')[0], 
                                '%Y-%m-%d'
                            ).date()
                            
                            if start_date:
                                start_dt = datetime.strptime(start_date, '%Y-%m-%d').date()
                                if log_date < start_dt:
                                    continue
                            
                            if end_date:
                                end_dt = datetime.strptime(end_date, '%Y-%m-%d').date()
                                if log_date > end_dt:
                                    continue
                                    
                        except ValueError:
                            continue  # Skip rows with invalid dates
                    
                    writer.writerow(row)
                    exported_count += 1
        
        logger.info(f"Exported {exported_count} log entries to {output_file}")
        return output_file
        
    except Exception as e:
        logger.error(f"Error exporting logs: {e}")
        raise

# Initialize the log file when module is imported
initialize_log_file()