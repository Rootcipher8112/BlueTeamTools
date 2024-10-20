# Data Exfiltration Detection Scripts

This document contains scripts for detecting potential data exfiltration activities by monitoring network traffic, file changes, and system events.

---

### 1. **Network Traffic Anomaly Detection Script (Python)**
   - **Description:** A Python script that analyzes network traffic logs to detect unusual data transfers, focusing on outbound traffic and large data flows.
   - **Example Usage:**
     ```bash
     python detect_data_exfil.py --log_file /path/to/network.log
     ```
   - **Code:**
     ```python
     import argparse

     def detect_anomalies(log_file):
         with open(log_file, 'r') as f:
             for line in f:
                 # Example: Look for outbound traffic with high data volume
                 if "OUTBOUND" in line and "DATA_VOLUME" in line:
                     data_volume = int(line.split()[-1])
                     if data_volume > 1000000:  # Threshold for large transfers
                         print(f"Potential data exfiltration detected: {line}")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Detect data exfiltration based on network logs.")
         parser.add_argument("--log_file", required=True, help="Path to network traffic log file.")
         args = parser.parse_args()

         detect_anomalies(args.log_file)
     ```

---

### 2. **File Integrity Monitoring Script (Bash)**
   - **Description:** A Bash script that monitors file changes in sensitive directories, such as unauthorized access or abnormal file modifications.
   - **Example Usage:**
     ```bash
     ./file_monitor.sh /path/to/monitor
     ```
   - **Code:**
     ```bash
     #!/bin/bash

     monitor_dir="$1"

     if [ -z "$monitor_dir" ]; then
         echo "Usage: $0 /path/to/directory"
         exit 1
     fi

     echo "Monitoring changes in $monitor_dir..."
     inotifywait -m -r -e modify,create,delete --format '%w%f %e' "$monitor_dir" |
     while read file event; do
         echo "File changed: $file - Event: $event"
         # Add custom logic to detect unusual file changes or exfiltration attempts
     done
     ```

---

### 3. **Large File Transfer Detection Script (Python)**
   - **Description:** A Python script that scans system logs for large file transfers, focusing on suspicious activity that could indicate exfiltration.
   - **Example Usage:**
     ```bash
     python detect_large_transfer.py --log_file /path/to/system.log
     ```
   - **Code:**
     ```python
     import argparse

     def detect_large_transfers(log_file):
         with open(log_file, 'r') as f:
             for line in f:
                 # Example: Detect large file transfers based on size
                 if "TRANSFER" in line and "FILE_SIZE" in line:
                     file_size = int(line.split()[-1])
                     if file_size > 10000000:  # Threshold for large file transfers
                         print(f"Large file transfer detected: {line}")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Detect large file transfers from system logs.")
         parser.add_argument("--log_file", required=True, help="Path to system log file.")
         args = parser.parse_args()

         detect_large_transfers(args.log_file)
     ```

---

## Instructions

1. **Log Files:** Ensure that you provide the correct path to log files for the scripts to analyze. These logs should include network traffic, system events, or file access logs.
2. **Thresholds:** You can customize the data volume and file size thresholds in the scripts to better suit your environment.

---

## Contributing

Feel free to contribute to this repository by suggesting new detection scripts or tools. To contribute, simply create a pull request with your changes.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
