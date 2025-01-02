import os
import hashlib
import json
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification

# Configuration
MONITOR_DIR = "./monitor"  # Default directory to monitor
BASELINE_FILE = "baseline.json"  # Default file to store baseline hashes
LOG_FILE = "tripwire_log.txt"  # Default log file
POLL_INTERVAL = 60  # Default polling interval in seconds

# Helper Functions
def calculate_file_hash(filepath):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        return None

def scan_directory(directory):
    """Scan the directory and return a dictionary of file hashes."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                file_hashes[filepath] = file_hash
    return file_hashes

def save_baseline(data):
    """Save the baseline to a file."""
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_baseline():
    """Load the baseline from a file."""
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}

def log_change(change_type, filepath):
    """Log changes to the log file and display a desktop notification."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {change_type}: {filepath}\n"
    with open(LOG_FILE, "a") as log:
        log.write(log_entry)
    print(log_entry.strip())

    # Send desktop notification
    notification.notify(
        title="Tripwire Alert",
        message=f"{change_type}: {filepath}",
        app_name="Tripwire Monitor"
    )

# Watchdog for Real-Time Monitoring
class TripwireHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            log_change("Modified File", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            log_change("New File", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            log_change("Deleted File", event.src_path)

# Main Function
def monitor():
    """Main monitoring function."""
    print(f"Monitoring directory: {MONITOR_DIR}")

    # Ensure monitoring directory exists
    if not os.path.exists(MONITOR_DIR):
        os.makedirs(MONITOR_DIR)

    # Load baseline
    baseline_hashes = load_baseline()

    # Set up real-time monitoring
    event_handler = TripwireHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()

    try:
        while True:
            # Periodic hash check to validate integrity
            current_hashes = scan_directory(MONITOR_DIR)

            for filepath, current_hash in current_hashes.items():
                if filepath not in baseline_hashes:
                    log_change("New File", filepath)
                elif baseline_hashes[filepath] != current_hash:
                    log_change("Modified File", filepath)

            for filepath in baseline_hashes.keys():
                if filepath not in current_hashes:
                    log_change("Deleted File", filepath)

            save_baseline(current_hashes)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("Tripwire monitoring stopped.")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    monitor()
