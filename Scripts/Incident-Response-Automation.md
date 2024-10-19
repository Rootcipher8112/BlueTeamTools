# Incident Response Automation Scripts

This folder contains scripts designed to automate key tasks during incident response scenarios. These scripts can help SOC analysts and incident responders respond to incidents more efficiently by automating repetitive tasks like log collection, network isolation, and memory dumps.

---

## Scripts

### 1. **Memory Dump Collection (Windows PowerShell)**
   - **Description:** This script collects a full memory dump of a Windows system during an incident for forensic analysis.
   - **Use Case:** Automate the process of collecting a memory dump during a live incident.
   - **User Input Required:**
     - **Dump Path:** The user needs to modify the `$dump_path` variable to the desired location for storing the memory dump.
   - **Example Usage:**
     ```powershell
     .\collect_memory_dump.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $dump_path = "C:\memory_dump.dmp"  # User must modify this

     # Invoke memory dump using WMI
     Invoke-WmiMethod -Class "Win32_Process" -Name "Create" -ArgumentList "tasklist.exe > $dump_path"
     Write-Host "Memory dump has been collected and saved to $dump_path"
     ```

---

### 2. **Endpoint Isolation via Firewall (Bash)**
   - **Description:** A Bash script that modifies firewall rules to isolate a compromised endpoint by blocking inbound and outbound traffic.
   - **Use Case:** Automate the isolation of an endpoint suspected of being compromised.
   - **User Input Required:**
     - **Endpoint IP:** The `$endpoint_ip` variable must be modified to the IP address of the compromised endpoint.
   - **Example Usage:**
     ```bash
     ./isolate_endpoint.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     endpoint_ip="192.168.1.100"  # User must modify this

     echo "Isolating endpoint with IP: $endpoint_ip"

     iptables -A INPUT -s $endpoint_ip -j DROP
     iptables -A OUTPUT -d $endpoint_ip -j DROP

     echo "Endpoint $endpoint_ip has been isolated."
     ```

---

### 3. **Log Collection Automation (Python)**
   - **Description:** This Python script automates the collection of logs from a compromised system for later forensic analysis.
   - **Use Case:** Collect key log files (e.g., auth.log, syslog) automatically from Linux systems during an incident.
   - **User Input Required:**
     - **Log Paths:** Modify the `log_files` list to include paths to the specific logs you want to collect.
     - **Destination Path:** Set the `$dest_path` to the directory where logs should be saved.
   - **Example Usage:**
     ```bash
     python log_collector.py
     ```
   - **Code Snippet:**
     ```python
     import shutil
     import os

     log_files = [
         "/var/log/syslog",  # Modify this list with paths to log files
         "/var/log/auth.log"
     ]

     dest_path = "/incident_logs/"  # Modify with desired destination path

     if not os.path.exists(dest_path):
         os.makedirs(dest_path)

     for log_file in log_files:
         if os.path.exists(log_file):
             shutil.copy(log_file, dest_path)
             print(f"Copied {log_file} to {dest_path}")
         else:
             print(f"Log file not found: {log_file}")
     ```

---

### 4. **Automatic Malware Upload to VirusTotal (Python)**
   - **Description:** This Python script automatically uploads suspicious files to VirusTotal for analysis during an incident response.
   - **Use Case:** Automate the process of uploading malware samples for analysis.
   - **User Input Required:**
     - **VirusTotal API Key:** Set the `$api_key` variable with your VirusTotal API key.
     - **File Path:** The `$file_path` variable should be set to the path of the suspicious file you want to upload.
   - **Example Usage:**
     ```bash
     python upload_to_virustotal.py
     ```
   - **Code Snippet:**
     ```python
     import requests

     api_key = "YOUR_VIRUSTOTAL_API_KEY"  # User must modify this
     file_path = "/path/to/suspicious/file"  # Modify this with the actual file path

     url = "https://www.virustotal.com/vtapi/v2/file/scan"
     files = {"file": (file_path, open(file_path, "rb"))}
     params = {"apikey": api_key}

     response = requests.post(url, files=files, params=params)
     if response.status_code == 200:
         print("File successfully uploaded to VirusTotal.")
     else:
         print(f"Failed to upload file: {response.status_code}")
     ```

---

### 5. **Incident Triage Automation (Python)**
   - **Description:** This script automates incident triage by collecting system information (e.g., processes, network connections) for initial analysis.
   - **Use Case:** Automate the collection of key forensic data during the first phase of incident response.
   - **User Input Required:**
     - **Output Directory:** Set the `$output_dir` variable to the desired directory where triage data will be saved.
   - **Example Usage:**
     ```bash
     python incident_triage.py
     ```
   - **Code Snippet:**
     ```python
     import os
     import subprocess

     output_dir = "/incident_triage/"  # User must modify this
     if not os.path.exists(output_dir):
         os.makedirs(output_dir)

     # Collect process list
     with open(os.path.join(output_dir, "process_list.txt"), "w") as f:
         subprocess.run(["ps", "aux"], stdout=f)

     # Collect network connections
     with open(os.path.join(output_dir, "network_connections.txt"), "w") as f:
         subprocess.run(["netstat", "-tulnp"], stdout=f)

     # Collect open files
     with open(os.path.join(output_dir, "open_files.txt"), "w") as f:
         subprocess.run(["lsof"], stdout=f)

     print(f"Triage data saved to {output_dir}")
     ```

---

### 6. **Windows Forensic Artifact Collection (PowerShell)**
   - **Description:** A PowerShell script to collect common forensic artifacts from a Windows machine (e.g., Event Logs, Prefetch, Registry).
   - **Use Case:** Automate the collection of critical forensic artifacts from a Windows system during an incident.
   - **User Input Required:**
     - **Output Path:** The user needs to modify the `$output_dir` variable to set the directory where artifacts will be saved.
   - **Example Usage:**
     ```powershell
     .\collect_windows_artifacts.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $output_dir = "C:\incident_artifacts\"  # User must modify this

     # Create output directory if it doesn't exist
     if (-Not (Test-Path $output_dir)) {
         New-Item -ItemType Directory -Path $output_dir
     }

     # Collect Event Logs
     wevtutil epl Application $output_dir\Application.evtx
     wevtutil epl Security $output_dir\Security.evtx
     wevtutil epl System $output_dir\System.evtx

     # Collect Prefetch files
     Copy-Item -Path C:\Windows\Prefetch\* -Destination $output_dir\Prefetch\

     # Collect registry hives
     reg save HKLM\SYSTEM $output_dir\SYSTEM.hiv
     reg save HKLM\SOFTWARE $output_dir\SOFTWARE.hiv

     Write-Host "Forensic artifacts collected and saved to $output_dir"
     ```

---

### 7. **Automated Ransomware Detection (Python)**
   - **Description:** This Python script monitors a directory for the creation of encrypted files, which could indicate a ransomware infection.
   - **Use Case:** Automate the detection of potential ransomware activity by looking for changes in file extensions.
   - **User Input Required:**
     - **Directory to Monitor:** The user must modify the `$directory_to_monitor` variable to set the folder where the script should watch for file changes.
   - **Example Usage:**
     ```bash
     python detect_ransomware.py
     ```
   - **Code Snippet:**
     ```python
     import os
     import time

     directory_to_monitor = "/path/to/monitor"  # User must modify this
     encrypted_extensions = [".locked", ".enc", ".encrypted"]  # Common ransomware extensions

     def monitor_directory(directory):
         print(f"Monitoring {directory} for suspicious file activity...")
         before = dict([(f, None) for f in os.listdir(directory)])

         while True:
             time.sleep(10)
             after = dict([(f, None) for f in os.listdir(directory)])
             added_files = [f for f in after if not f in before]

             for file in added_files:
                 if any(file.endswith(ext) for ext in encrypted_extensions):
                     print(f"Potential ransomware detected: {file}")
                     # Add incident response action here (e.g., alerting)
             before = after

     monitor_directory(directory_to_monitor)
     ```

---

### 8. **Automated Firewall Rule Reversion (Bash)**
   - **Description:** A Bash script to automatically revert firewall rules after a predefined time window, useful for temporary isolation during an incident.
   - **Use Case:** Temporarily block traffic and automatically revert the changes after a set time period.
   - **User Input Required:**
     - **Reversion Time:** Set the `$revert_time` variable to define how long the firewall rule should remain active.
   - **Example Usage:**
     ```bash
     ./firewall_revert.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     endpoint_ip="192.168.1.100"  # User must modify this
     revert_time=300  # Time in seconds before reverting the firewall rule

     echo "Temporarily isolating endpoint $endpoint_ip"
     iptables -A INPUT -s $endpoint_ip -j DROP
     iptables -A OUTPUT -d $endpoint_ip -j DROP

     echo "Waiting $revert_time seconds before reverting firewall rule..."
     sleep $revert_time

     iptables -D INPUT -s $endpoint_ip -j DROP
     iptables -D OUTPUT -d $endpoint_ip -j DROP
     echo "Firewall rule reverted. Endpoint $endpoint_ip is no longer isolated."
     ```

---

### 9. **File Integrity Monitoring (Python)**
   - **Description:** A Python script that checks the integrity of files in a specified directory by comparing file hashes over time.
   - **Use Case:** Automate the detection of unauthorized changes to important files by monitoring their hash values.
   - **User Input Required:**
     - **Directory to Monitor:** The user must modify the `$directory_to_monitor` variable to define the folder that should be monitored for integrity.
   - **Example Usage:**
     ```bash
     python file_integrity_monitor.py
     ```
   - **Code Snippet:**
     ```python
     import os
     import hashlib

     directory_to_monitor = "/path/to/important/files"  # User must modify this

     def hash_file(file_path):
         hasher = hashlib.sha256()
         with open(file_path, 'rb') as f:
             buf = f.read()
             hasher.update(buf)
         return hasher.hexdigest()

     def monitor_files(directory):
         print(f"Monitoring {directory} for integrity changes...")
         file_hashes = {}

         # Initialize with current file hashes
         for file in os.listdir(directory):
             file_path = os.path.join(directory, file)
             file_hashes[file] = hash_file(file_path)

         # Continuously monitor for changes
         while True:
             for file in os.listdir(directory):
                 file_path = os.path.join(directory, file)
                 new_hash = hash_file(file_path)
                 if file in file_hashes and file_hashes[file] != new_hash:
                     print(f"File integrity violation detected for {file}")
                     # Add incident response action here (e.g., alerting)
                 file_hashes[file] = new_hash

     monitor_files(directory_to_monitor)
     ```

---

### 10. **Network Packet Capture (Bash)**
   - **Description:** A Bash script that captures network traffic using `tcpdump` and saves the pcap file for further analysis.
   - **Use Case:** Automate the collection of network traffic during an ongoing incident.
   - **User Input Required:**
     - **Capture Interface:** The `$interface` variable must be set to the network interface you want to capture traffic on.
     - **Capture Duration:** Set the `$duration` variable to define how long the packet capture should run.
   - **Example Usage:**
     ```bash
     ./packet_capture.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     interface="eth0"  # User must modify this
     duration=60  # Capture duration in seconds
     output_file="network_capture.pcap"

     echo "Starting packet capture on interface $interface for $duration seconds..."
     tcpdump -i $interface -w $output_file -G $duration -W 1
     echo "Packet capture complete. File saved to $output_file."
     ```

---

## Contributing

Feel free to contribute to this repository by suggesting new scripts, improvements, or corrections. To contribute, simply create a pull request with your changes or open an issue to discuss further.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

