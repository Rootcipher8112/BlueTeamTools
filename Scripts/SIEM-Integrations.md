# SIEM Integrations Scripts

This folder contains scripts designed to integrate or manage log forwarding and data ingestion for SIEM platforms. These scripts help automate the process of sending logs to SIEM systems like Splunk, Elastic Stack (ELK), and others.

---

## Scripts

### 1. **Splunk Universal Forwarder Setup (Bash)**
   - **Description:** This script sets up Splunk Universal Forwarder on a Linux server to forward logs to a Splunk instance.
   - **Use Case:** Automate the setup and configuration of the Splunk Universal Forwarder for collecting and sending logs.
   - **User Input Required:**
     - **Splunk Server IP:** Modify the `$splunk_server` variable to the IP address or hostname of the Splunk server.
     - **Forwarder Token:** Change the `$auth_token` variable to the authentication token provided by the Splunk instance.
     - **Log Path:** Adjust the log file paths in the `inputs.conf` section to match the directories you want to forward logs from.
   - **Example Usage:**
     ```bash
     ./splunk_forwarder_setup.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     splunk_server="192.168.1.10"  # User needs to modify this
     auth_token="SPLUNK_FORWARDER_AUTH_TOKEN"  # Replace with actual token

     echo "Installing Splunk Universal Forwarder..."
     wget -O splunkforwarder.deb "https://www.splunk.com/path/to/splunkforwarder.deb"
     dpkg -i splunkforwarder.deb

     /opt/splunkforwarder/bin/splunk start --accept-license
     /opt/splunkforwarder/bin/splunk add forward-server $splunk_server:9997 -auth admin:changeme
     /opt/splunkforwarder/bin/splunk set deploy-poll $splunk_server:8089 -auth admin:changeme

     # Configure inputs.conf for log forwarding
     cat <<EOT >> /opt/splunkforwarder/etc/system/local/inputs.conf
     [monitor:///var/log/syslog]
     disabled = false
     index = os_logs
     sourcetype = syslog

     [monitor:///var/log/auth.log]
     disabled = false
     index = os_logs
     sourcetype = auth
     EOT

     /opt/splunkforwarder/bin/splunk restart
     echo "Splunk Universal Forwarder setup complete!"
     ```

---

### 2. **Elastic Stack (ELK) Logstash Pipeline Setup (YAML)**
   - **Description:** A sample Logstash pipeline configuration to ingest syslogs and forward them to Elasticsearch.
   - **Use Case:** Automate the creation of a Logstash pipeline for syslog data.
   - **User Input Required:**
     - **Elasticsearch Server IP:** Modify the `hosts` section to point to the correct Elasticsearch instance.
     - **Log File Paths:** Update the `path` directive to point to the log files you want to collect (e.g., `/var/log/syslog`).
   - **Example Usage:** Place the configuration file in your Logstash `pipelines` directory and restart Logstash.
   - **Code Snippet:**
     ```yaml
     input {
       file {
         path => "/var/log/syslog"  # Modify this with your log file path
         start_position => "beginning"
         type => "syslog"
       }
     }

     filter {
       grok {
         match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:program}: %{GREEDYDATA:message}" }
       }
       date {
         match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
       }
     }

     output {
       elasticsearch {
         hosts => ["http://192.168.1.20:9200"]  # User needs to modify this
         index => "syslog-%{+YYYY.MM.dd}"
       }
       stdout { codec => rubydebug }
     }
     ```

---

### 3. **SIEM Log Forwarding Script for Linux (Bash)**
   - **Description:** A script to forward logs from a Linux server to a SIEM via syslog.
   - **Use Case:** Automate the configuration of rsyslog to forward logs to a SIEM system.
   - **User Input Required:**
     - **SIEM IP Address:** The `$siem_server` variable must be modified to the SIEM’s IP address.
     - **Log Path:** Change the log file paths in `/etc/rsyslog.d/siem.conf` as needed.
   - **Example Usage:**
     ```bash
     ./siem_log_forward.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     siem_server="192.168.1.50"  # User needs to modify this

     echo "Configuring rsyslog to forward logs to SIEM at $siem_server..."

     cat <<EOT > /etc/rsyslog.d/siem.conf
     *.* @@$siem_server:514
     EOT

     systemctl restart rsyslog
     echo "Log forwarding configuration complete!"
     ```

---

### 4. **Splunk Saved Search Automation (Python)**
   - **Description:** A Python script to automate the creation of saved searches in Splunk.
   - **Use Case:** Automatically create or update searches in Splunk via the REST API.
   - **User Input Required:**
     - **Splunk Credentials:** Modify the `$username` and `$password` variables to your Splunk admin credentials.
     - **Search Query:** Update the search query in the `data` section to reflect what you're trying to query in Splunk.
   - **Example Usage:**
     ```bash
     python splunk_saved_search.py
     ```
   - **Code Snippet:**
     ```python
     import requests
     from requests.auth import HTTPBasicAuth

     splunk_server = "https://192.168.1.10:8089"
     username = "admin"  # User must provide actual credentials
     password = "changeme"  # Replace with actual password

     search_name = "High CPU Usage Alerts"
     search_query = "index=os_logs sourcetype=syslog | stats avg(cpu_usage) by host | where avg(cpu_usage) > 90"

     url = f"{splunk_server}/servicesNS/admin/search/saved/searches"
     data = {
         'name': search_name,
         'search': search_query,
         'enabled': 1,
         'action.email': 'false',
         'cron_schedule': '*/5 * * * *'
     }

     response = requests.post(url, auth=HTTPBasicAuth(username, password), data=data, verify=False)
     if response.status_code == 201:
         print(f"Saved search '{search_name}' created successfully.")
     else:
         print(f"Failed to create saved search: {response.status_code}")
     ```

---

### 5. **Graylog API Query (Python)**
   - **Description:** A Python script to query logs in Graylog using the Graylog API.
   - **Use Case:** Automate log queries and extract data from Graylog.
   - **User Input Required:**
     - **Graylog Server:** Modify the `$graylog_server` variable to match the IP or hostname of the Graylog instance.
     - **Search Query:** Update the `query` parameter to search for specific log data (e.g., "ssh failed").
   - **Example Usage:**
     ```bash
     python graylog_query.py
     ```
   - **Code Snippet:**
     ```python
     import requests

     graylog_server = "http://192.168.1.30:9000"  # User must modify this
     api_token = "YOUR_GRAYLOG_API_TOKEN"  # Replace with actual API token
     search_query = "ssh failed"
     search_url = f"{graylog_server}/api/search/universal/relative"

     headers = {
         "Authorization": f"Bearer {api_token}",
         "Content-Type": "application/json"
     }

     payload = {
         "query": search_query,
         "range": 3600  # Search logs from the last hour
     }

     response = requests.post(search_url, headers=headers, json=payload)
     if response.status_code == 200:
         print("Search results:")
         print(response.json())
     else:
         print(f"Failed to retrieve logs: {response.status_code}")
     ```
---

### 6. **Log Forwarding for Windows Event Logs (PowerShell)**
   - **Description:** This PowerShell script configures a Windows server to forward event logs to a remote SIEM system via WinRM or Syslog.
   - **Use Case:** Automate log forwarding from Windows event logs to a SIEM system.
   - **User Input Required:**
     - **SIEM Server IP:** Modify the `$siem_server` variable to point to the SIEM server.
     - **Log Types:** Adjust the `Get-WinEvent` filters to include the specific event logs you want to forward (e.g., Security, Application, System).
   - **Example Usage:**
     ```powershell
     .\windows_log_forward.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $siem_server = "192.168.1.50"  # User must modify this

     # Configure the log types and forward them to the SIEM server
     Get-WinEvent -LogName "Security", "System", "Application" |
     ForEach-Object {
         $log_entry = $_
         # Send log entry to SIEM via Syslog or WinRM
         $msg = "$($log_entry.TimeCreated) - $($log_entry.Message)"
         Send-SyslogMessage -Server $siem_server -Message $msg
     }

     function Send-SyslogMessage {
         param ($Server, $Message)
         # Use PowerShell's send method or third-party tool to send to SIEM
         Write-Host "Forwarding log to $Server: $Message"
     }
     ```

---

### 7. **Health Check for Elasticsearch Cluster (Python)**
   - **Description:** A Python script that checks the health status of an Elasticsearch cluster and sends an alert if any node is down or performance is degraded.
   - **Use Case:** Monitor the health of an Elasticsearch cluster and automate alerts.
   - **User Input Required:**
     - **Elasticsearch Server IP:** Modify the `$elastic_server` variable with the Elasticsearch cluster's IP or hostname.
     - **Alert Mechanism:** Adjust the alerting mechanism (e.g., email or Slack) to fit your organization's needs.
   - **Example Usage:**
     ```bash
     python elastic_health_check.py
     ```
   - **Code Snippet:**
     ```python
     import requests

     elastic_server = "http://192.168.1.20:9200"  # User must modify this
     health_url = f"{elastic_server}/_cluster/health"
     response = requests.get(health_url)

     if response.status_code == 200:
         health_data = response.json()
         status = health_data.get('status')

         if status != "green":
             print(f"Cluster health is not green: {status}")
             # Example alerting (user can modify as needed)
             # send_alert(f"Elasticsearch cluster status is {status}")
         else:
             print("Cluster health is green")
     else:
         print(f"Failed to retrieve cluster health: {response.status_code}")

     # Placeholder function for sending alerts
     def send_alert(message):
         print(f"Sending alert: {message}")
         # Implement actual alerting mechanism (e.g., email, Slack, etc.)
     ```

---

### 8. **Automated SIEM Rule Deployment (Bash)**
   - **Description:** This script deploys a set of pre-defined detection rules (e.g., Sigma rules) to a SIEM system (Splunk, Elastic, or others).
   - **Use Case:** Automate the process of deploying or updating detection rules to your SIEM.
   - **User Input Required:**
     - **Rule Directory:** Modify the `$rule_dir` variable to point to the directory where the detection rules are stored.
     - **SIEM System:** Adjust the API endpoint or command used to deploy the rules to match your SIEM system.
   - **Example Usage:**
     ```bash
     ./deploy_siem_rules.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     rule_dir="/path/to/rules"  # User must modify this
     siem_server="https://192.168.1.10:8089"
     auth_token="YOUR_AUTH_TOKEN"  # Replace with your SIEM's authentication token

     echo "Deploying rules from $rule_dir to SIEM at $siem_server..."

     for rule in $rule_dir/*.yml; do
         echo "Deploying rule: $rule"
         curl -k -H "Authorization: Bearer $auth_token" \
              -F "file=@$rule" \
              $siem_server/api/rules/deploy
     done

     echo "SIEM rule deployment complete."
     ```

---

### 9. **Automated Incident Alert Script for Graylog (Python)**
   - **Description:** A Python script that queries Graylog for specific log events (e.g., brute force login attempts) and sends an alert if thresholds are exceeded.
   - **Use Case:** Automate incident detection in Graylog and send alerts based on log thresholds.
   - **User Input Required:**
     - **Graylog Server:** Modify the `$graylog_server` variable to point to the correct Graylog server.
     - **Alert Threshold:** Adjust the `threshold` variable to set the number of events that trigger an alert.
   - **Example Usage:**
     ```bash
     python graylog_alert.py
     ```
   - **Code Snippet:**
     ```python
     import requests

     graylog_server = "http://192.168.1.30:9000"  # User must modify this
     api_token = "YOUR_GRAYLOG_API_TOKEN"  # Replace with actual API token
     search_query = "message: 'brute force'"
     threshold = 5  # Alert if more than 5 brute force attempts in the last hour

     search_url = f"{graylog_server}/api/search/universal/relative"

     headers = {
         "Authorization": f"Bearer {api_token}",
         "Content-Type": "application/json"
     }

     payload = {
         "query": search_query,
         "range": 3600  # Search logs from the last hour
     }

     response = requests.post(search_url, headers=headers, json=payload)
     if response.status_code == 200:
         result_count = len(response.json().get('messages', []))
         if result_count > threshold:
             print(f"ALERT: Detected {result_count} brute force attempts!")
             # Trigger alert (e.g., email, Slack, etc.)
             # send_alert(f"Detected {result_count} brute force attempts")
         else:
             print(f"Detected {result_count} brute force attempts. No alert.")
     else:
         print(f"Failed to retrieve logs: {response.status_code}")

     def send_alert(message):
         print(f"Sending alert: {message}")
         # Implement actual alerting mechanism
     ```

---

### 10. **Elastic Curator Index Cleanup (Python)**
   - **Description:** A Python script that uses Elastic Curator to automatically clean up old Elasticsearch indices based on retention policies.
   - **Use Case:** Automate the removal of old indices in Elasticsearch to free up storage and maintain performance.
   - **User Input Required:**
     - **Elasticsearch Server IP:** Modify the `$elastic_server` variable with the correct IP or hostname.
     - **Retention Period:** Adjust the retention period in the Curator configuration (e.g., delete indices older than 30 days).
   - **Example Usage:**
     ```bash
     python elastic_curator_cleanup.py
     ```
   - **Code Snippet:**
     ```python
     from elasticsearch import Elasticsearch
     from curator import IndexList, DeleteIndices

     elastic_server = "http://192.168.1.20:9200"  # User must modify this
     client = Elasticsearch(elastic_server)

     # Define the indices to delete based on age
     index_list = IndexList(client)
     index_list.filter_by_age(source='creation_date', direction='older', unit='days', unit_count=30)  # Retention policy: 30 days

     if index_list.indices:
         print(f"Deleting {len(index_list.indices)} old indices...")
         delete_indices = DeleteIndices(index_list)
         delete_indices.do_action()
         print("Old indices deleted successfully.")
     else:
         print("No indices to delete.")
     ```

---

## Contributing

Feel free to contribute to this repository by suggesting new scripts, improvements, or corrections. To contribute, simply create a pull request with your changes or open an issue to discuss further.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
