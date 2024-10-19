# Log Parsing Scripts

This folder contains scripts designed to parse, filter, and extract important information from security logs. These scripts are useful for SOC analysts and blue team members working with log data from various systems such as firewalls, web servers, and operating systems.

---

## Scripts

### 1. **Firewall Log Parser (Python)**
   - **Description:** This script parses firewall logs (e.g., from Palo Alto, Cisco ASA) and extracts key information such as source/destination IPs, ports, and allowed/denied traffic.
   - **Use Case:** Quickly filter logs to identify suspicious traffic or unauthorized access attempts.
   - **User Input Required:**
     - **File Path:** The user needs to provide the path to the firewall log file via the `--file` argument.
     - **Filter Type:** The filter (e.g., "ALLOW" or "DENY") needs to be adjusted based on what type of traffic the user wants to focus on.
     - **Regex Pattern:** The regular expression (`pattern = r"SRC=(\S+) DST=(\S+) PROTO=(\S+)"`) may need to be adjusted depending on the specific format of the firewall logs being parsed.
   - **Example Usage:**
     ```bash
     python firewall_parser.py --file firewall.log --filter "DENY"
     ```
   - **Code Snippet:**
     ```python
     import re
     import argparse

     def parse_firewall_log(file, filter_type):
         with open(file, 'r') as log_file:
             for line in log_file:
                 if filter_type in line:
                     # Example regex pattern for parsing logs
                     pattern = r"SRC=(\S+) DST=(\S+) PROTO=(\S+)"
                     match = re.search(pattern, line)
                     if match:
                         src_ip = match.group(1)
                         dst_ip = match.group(2)
                         proto = match.group(3)
                         print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Parse firewall logs.")
         parser.add_argument("--file", help="Log file to parse", required=True)
         parser.add_argument("--filter", help="Filter logs by type (e.g., ALLOW, DENY)", required=True)
         args = parser.parse_args()

         parse_firewall_log(args.file, args.filter)
     ```

---

### 2. **Web Server Log Parser (Bash)**
   - **Description:** A Bash script to parse web server logs (Apache or Nginx) and extract key data like HTTP status codes and IP addresses.
   - **Use Case:** Identify requests returning 404 or 500 errors or filter by specific IP addresses.
   - **User Input Required:**
     - **Log File Path:** The first argument passed to the script is the path to the web server log file. The user must ensure the correct file path is provided.
     - **Status Code:** The second argument is the HTTP status code (e.g., 404, 500) that the user is interested in filtering.
   - **Example Usage:**
     ```bash
     ./web_log_parser.sh access.log 404
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     log_file=$1
     status_code=$2

     if [ -z "$log_file" ] || [ -z "$status_code" ]; then
         echo "Usage: ./web_log_parser.sh <log_file> <status_code>"
         exit 1
     fi

     echo "Filtering for HTTP status code $status_code in $log_file:"
     grep " $status_code " $log_file | awk '{print $1, $9, $7}'
     ```

---

### 3. **Windows Event Log Parser (PowerShell)**
   - **Description:** This PowerShell script filters Windows event logs for specific Event IDs, such as failed login attempts (Event ID 4625).
   - **Use Case:** Detect failed login attempts and monitor for brute force attacks.
   - **User Input Required:**
     - **Event ID:** The user needs to specify the Event ID they want to filter, such as 4625 (failed login attempts). This can be modified in the `-EventID` argument.
     - **Log Source (Optional):** If the user wants to search logs other than the Security log, they can modify the `LogName` parameter in the script (e.g., "System", "Application").
   - **Example Usage:**
     ```powershell
     .\event_log_parser.ps1 -EventID 4625
     ```
   - **Code Snippet:**
     ```powershell
     param(
         [int]$EventID
     )

     Get-WinEvent -FilterHashtable @{LogName="Security"; ID=$EventID} | 
     ForEach-Object {
         $event = $_
         Write-Host "Failed login attempt detected from $($event.Properties[5].Value) at $($event.TimeCreated)"
     }
     ```

---

### 4. **Application Log Parser (Python)**
   - **Description:** A Python script for filtering and extracting application-specific logs, such as SQL errors or application crashes.
   - **Use Case:** Monitor for application crashes or errors in real time.
   - **User Input Required:**
     - **Log File Path:** The user must provide the path to the application log file via the `--file` argument.
     - **Keyword:** The user needs to specify a keyword (e.g., "ERROR", "CRITICAL") that they want to filter from the logs.
   - **Example Usage:**
     ```bash
     python app_log_parser.py --file app.log --keyword "ERROR"
     ```
   - **Code Snippet:**
     ```python
     import argparse

     def parse_app_log(file, keyword):
         with open(file, 'r') as log_file:
             for line in log_file:
                 if keyword in line:
                     print(line.strip())

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Parse application logs.")
         parser.add_argument("--file", help="Log file to parse", required=True)
         parser.add_argument("--keyword", help="Keyword to filter logs by (e.g., ERROR)", required=True)
         args = parser.parse_args()

         parse_app_log(args.file, args.keyword)
     ```

---

### 5. **Linux Syslog Parser (Bash)**
   - **Description:** A simple Bash script to parse Linux syslogs and filter specific messages (e.g., SSH login attempts).
   - **Use Case:** Identify SSH login attempts or system events from `/var/log/syslog`.
   - **User Input Required:**
     - **Log File Path:** The first argument is the path to the syslog file (`/var/log/syslog` or similar). The user must ensure the correct file path is provided.
     - **Keyword:** The second argument is the keyword (e.g., "sshd", "error") that the user wants to filter in the log file.
   - **Example Usage:**
     ```bash
     ./syslog_parser.sh /var/log/syslog "sshd"
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     log_file=$1
     keyword=$2

     if [ -z "$log_file" ] || [ -z "$keyword" ]; then
         echo "Usage: ./syslog_parser.sh <log_file> <keyword>"
         exit 1
     fi

     echo "Filtering for keyword $keyword in $log_file:"
     grep "$keyword" $log_file
     ```

---

## Contributing

Feel free to contribute to this repository by suggesting new scripts, improvements, or corrections. To contribute, simply create a pull request with your changes or open an issue to discuss further.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
