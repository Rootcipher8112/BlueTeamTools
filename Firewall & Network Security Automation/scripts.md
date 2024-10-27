# Firewall & Network Security Automation Scripts

This document contains Python and Bash scripts to automate firewall configurations, manage security rules, and monitor network traffic for unauthorized access.

---

### 1. **Automate Firewall Rule Addition (Bash)**
   - **Description:** A Bash script that automates adding firewall rules in an Iptables firewall, allowing for quick adjustments to security configurations.
   - **Example Usage:**
     ```bash
     ./add_firewall_rule.sh --action accept --src 192.168.1.10 --dst 192.168.1.20 --port 80
     ```
   - **Code:**
     ```bash
     #!/bin/bash

     while [[ "$#" -gt 0 ]]; do case $1 in
       --action) action="$2"; shift;;
       --src) src="$2"; shift;;
       --dst) dst="$2"; shift;;
       --port) port="$2"; shift;;
       *) echo "Unknown parameter: $1"; exit 1;;
     esac; shift; done

     if [ -z "$action" ] || [ -z "$src" ] || [ -z "$dst" ] || [ -z "$port" ]; then
         echo "Usage: $0 --action [accept|reject] --src [source IP] --dst [destination IP] --port [port]"
         exit 1
     fi

     iptables -A INPUT -s "$src" -d "$dst" --dport "$port" -j "$action"
     echo "Firewall rule added: $action traffic from $src to $dst on port $port."
     ```

---

### 2. **Monitor Network Traffic (Python)**
   - **Description:** A Python script that monitors network traffic on a specific interface for unusual activity, logging any high traffic spikes or suspicious connections.
   - **Example Usage:**
     ```bash
     python monitor_network_traffic.py --interface eth0
     ```
   - **Code:**
     ```python
     import psutil
     import time
     import argparse

     def monitor_traffic(interface):
         print(f"Monitoring network traffic on {interface}...")
         while True:
             stats = psutil.net_io_counters(pernic=True)
             sent = stats[interface].bytes_sent
             received = stats[interface].bytes_recv
             print(f"Sent: {sent} bytes, Received: {received} bytes")
             time.sleep(5)

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Monitor network traffic on a specific interface.")
         parser.add_argument("--interface", required=True, help="Network interface to monitor (e.g., eth0).")
         args = parser.parse_args()

         monitor_traffic(args.interface)
     ```

---

### 3. **Automate Firewall Backup (Bash)**
   - **Description:** A Bash script that automatically backs up firewall configurations, saving them to a specified directory.
   - **Example Usage:**
     ```bash
     ./backup_firewall.sh /path/to/backup/
     ```
   - **Code:**
     ```bash
     #!/bin/bash

     backup_dir="$1"
     timestamp=$(date +"%Y%m%d%H%M%S")

     if [ -z "$backup_dir" ]; then
         echo "Usage: $0 /path/to/backup"
         exit 1
     fi

     iptables-save > "$backup_dir/firewall_backup_$timestamp.rules"
     echo "Firewall configuration backed up to $backup_dir/firewall_backup_$timestamp.rules"
     ```

---

## Instructions

1. **Firewall Type:** For firewall management scripts, ensure you are working with the correct firewall type (Iptables, pfSense, etc.) and permissions.
2. **Network Interface:** The network traffic monitoring script should specify the correct network interface based on your environment.

---

## Contributing

Feel free to contribute to this repository by suggesting new firewall automation scripts or tools. To contribute, simply create a pull request with your changes.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
