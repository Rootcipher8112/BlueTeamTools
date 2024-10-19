# Threat Hunting Scripts

This folder contains scripts designed to assist in the threat hunting process. These scripts help SOC analysts proactively search for indicators of compromise (IOCs), suspicious behavior, and malicious activity within their environment.

---

## Scripts

### 1. **Sysmon Log Analysis for Suspicious Processes (PowerShell)**
   - **Description:** This PowerShell script scans Sysmon logs for the creation of suspicious processes (e.g., PowerShell, cmd.exe).
   - **Use Case:** Automate threat hunting by identifying the execution of suspicious processes.
   - **User Input Required:**
     - **Process Names:** Modify the `$suspicious_processes` list to include the process names you want to monitor (e.g., "powershell.exe", "cmd.exe").
   - **Example Usage:**
     ```powershell
     .\hunt_sysmon_process.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $suspicious_processes = @("powershell.exe", "cmd.exe")  # User must modify this
     Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | ForEach-Object {
         $event = $_
         $process_name = $event.Properties[4].Value
         if ($suspicious_processes -contains $process_name) {
             Write-Host "Suspicious process detected: $process_name"
         }
     }
     ```

---

### 2. **Hunt for Unauthorized SSH Connections (Bash)**
   - **Description:** A Bash script that scans SSH logs for suspicious or unauthorized login attempts, such as brute force attacks.
   - **Use Case:** Automate threat hunting by scanning for unauthorized SSH login attempts.
   - **User Input Required:**
     - **Log Path:** Modify the `$log_file` variable to point to your SSH log file (e.g., `/var/log/auth.log`).
   - **Example Usage:**
     ```bash
     ./hunt_ssh_attempts.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     log_file="/var/log/auth.log"  # User must modify this
     echo "Hunting for unauthorized SSH login attempts in $log_file..."

     grep "Failed password" $log_file | awk '{print $1, $2, $3, $9}' | sort | uniq -c | sort -nr | head
     ```

---

### 3. **Yara Rule-Based File Scan (Python)**
   - **Description:** This Python script uses Yara rules to scan a directory for files that match malware patterns.
   - **Use Case:** Automate the scanning of files using custom Yara rules for threat hunting.
   - **User Input Required:**
     - **Directory to Scan:** Modify the `$directory_to_scan` variable to set the path to the folder you want to scan.
     - **Yara Rule File:** Update the `$yara_rules` variable with the path to your Yara rule file.
   - **Example Usage:**
     ```bash
     python yara_file_scan.py
     ```
   - **Code Snippet:**
     ```python
     import yara
     import os

     yara_rules = "/path/to/yara_rules.yar"  # User must modify this
     directory_to_scan = "/path/to/directory"  # User must modify this

     rules = yara.compile(filepath=yara_rules)

     for root, dirs, files in os.walk(directory_to_scan):
         for file in files:
             file_path = os.path.join(root, file)
             matches = rules.match(file_path)
             if matches:
                 print(f"Malicious file detected: {file_path}")
     ```

---

### 4. **Query Sysmon Logs for Suspicious Network Connections (PowerShell)**
   - **Description:** This script searches Sysmon logs for suspicious network connections, such as connections to known malicious IPs or ports.
   - **Use Case:** Automate network connection threat hunting by querying Sysmon logs for unusual connections.
   - **User Input Required:**
     - **Suspicious IP List:** Modify the `$suspicious_ips` list with known malicious IP addresses.
   - **Example Usage:**
     ```powershell
     .\hunt_sysmon_network.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $suspicious_ips = @("1.2.3.4", "5.6.7.8")  # User must modify this
     Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | ForEach-Object {
         $event = $_
         $ip_address = $event.Properties[18].Value
         if ($suspicious_ips -contains $ip_address) {
             Write-Host "Suspicious network connection to $ip_address detected"
         }
     }
     ```

---

### 5. **Hunt for Suspicious DNS Queries (Bash)**
   - **Description:** A Bash script that searches DNS query logs for suspicious domain lookups, such as known malicious or newly registered domains.
   - **Use Case:** Automate the process of detecting suspicious DNS activity by analyzing DNS query logs.
   - **User Input Required:**
     - **Log File:** Modify the `$dns_log_file` variable to point to the DNS query log file.
     - **Suspicious Domains:** Update the `$suspicious_domains` list with known malicious domains.
   - **Example Usage:**
     ```bash
     ./hunt_dns_queries.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     dns_log_file="/var/log/dns.log"  # User must modify this
     suspicious_domains=("malicious.com" "badguy.net")  # User must modify this

     echo "Hunting for suspicious DNS queries in $dns_log_file..."
     for domain in "${suspicious_domains[@]}"; do
         grep "$domain" $dns_log_file
     done
     ```

---

### 6. **Threat Hunting with Sigma Rules (Python)**
   - **Description:** A Python script that automates the search for suspicious activity in logs using Sigma rules.
   - **Use Case:** Automate log analysis with Sigma rules to detect specific attack techniques or patterns.
   - **User Input Required:**
     - **Log File Path:** Set the `$log_file` variable to point to the log file being analyzed.
     - **Sigma Rules Directory:** Modify the `$sigma_rules_dir` variable with the path to your Sigma rules.
   - **Example Usage:**
     ```bash
     python sigma_hunting.py
     ```
   - **Code Snippet:**
     ```python
     import os
     import subprocess

     log_file = "/path/to/log_file"  # User must modify this
     sigma_rules_dir = "/path/to/sigma_rules"  # User must modify this

     for rule in os.listdir(sigma_rules_dir):
         rule_path = os.path.join(sigma_rules_dir, rule)
         subprocess.run(["sigmac", "-t", "json", rule_path, "-f", log_file])
     ```

---

### 7. **Check for Persistence Mechanisms (PowerShell)**
   - **Description:** This PowerShell script checks for common persistence mechanisms, such as scheduled tasks and startup programs, that attackers might use.
   - **Use Case:** Automate threat hunting by identifying persistence mechanisms on compromised systems.
   - **User Input Required:** None required, but users can modify which persistence mechanisms to check.
   - **Example Usage:**
     ```powershell
     .\hunt_persistence.ps1
     ```
   - **Code Snippet:**
     ```powershell
     Get-ScheduledTask | Where-Object { $_.TaskName -like "*malicious*" } | ForEach-Object {
         Write-Host "Potential malicious scheduled task: $($_.TaskName)"
     }

     Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | ForEach-Object {
         Write-Host "Startup program: $($_.PSChildName) = $($_.Run)"
     }
     ```

---

### 8. **Hunt for Unusual User Behavior (Python)**
   - **Description:** This Python script analyzes user behavior logs to detect unusual login times, multiple login failures, or access to critical systems outside of normal hours.
   - **Use Case:** Automate the detection of abnormal user behavior as part of threat hunting efforts.
   - **User Input Required:**
     - **Log File Path:** Modify the `$log_file` variable to specify the path to the user behavior log.
     - **Business Hours:** Adjust the `$business_hours` variable to define normal working hours.
   - **Example Usage:**
     ```bash
     python hunt_user_behavior.py
     ```
   - **Code Snippet:**
     ```python
     import datetime

     log_file = "/path/to/user_log"  # User must modify this
     business_hours = (9, 17)  # User must modify this (9 AM to 5 PM)

     with open(log_file, "r") as f:
         for line in f:
             timestamp, username, action = line.split(" ")
             log_time = datetime.datetime.strptime(timestamp, "%H:%M")
             if log_time.hour < business_hours[0] or log_time.hour > business_hours[1]:
                 print(f"Unusual login outside business hours by {username} at {timestamp}")
     ```

---

### 9. **Hunt for Lateral Movement via SMB (Bash)**
   - **Description:** This script checks logs for SMB connections that may indicate lateral movement within the network.
   - **Use Case:** Automate detection of lateral movement by monitoring SMB traffic.
   - **User Input Required:**
     - **Log File:** Modify the `$log_file` variable to point to your SMB log file.
   - **Example Usage:**
     ```bash
     ./hunt_smb_lateral_movement.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     log_file="/var/log/samba/smb.log"  # User must modify this

     echo "Hunting for lateral movement via SMB in $log_file..."
     grep "smbclient" $log_file | awk '{print $1, $2, $3, $5}'
     ```

---

### 10. **Detect Anomalous Traffic (Python)**
   - **Description:** A Python script that detects anomalous network traffic patterns by analyzing traffic data (e.g., port scans, traffic spikes).
   - **Use Case:** Automate threat hunting by analyzing network traffic for anomalies.
   - **User Input Required:**
     - **Network Traffic File:** Modify the `$traffic_file` variable to specify the file containing network traffic data.
   - **Example Usage:**
     ```bash
     python detect_anomalous_traffic.py
     ```
   - **Code Snippet:**
     ```python
     traffic_file = "/path/to/traffic_data"  # User must modify this

     with open(traffic_file, "r") as f:
         for line in f:
             timestamp, src_ip, dst_ip, bytes_transferred = line.split(" ")
             if int(bytes_transferred) > 1000000:  # Threshold for large data transfers
                 print(f"Anomalous traffic detected from {src_ip} to {dst_ip} at {timestamp}")
     ```

---

## Contributing

Feel free to contribute to this repository by suggesting new scripts, improvements, or corrections. To contribute, simply create a pull request with your changes or open an issue to discuss further.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
