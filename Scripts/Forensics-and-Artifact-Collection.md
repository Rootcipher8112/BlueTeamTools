# Forensics & Artifact Collection Scripts

This folder contains scripts to automate the collection of forensic artifacts during an investigation. These scripts can help SOC analysts and forensic investigators gather crucial data from systems quickly and efficiently.

---

## Scripts

### 1. **Windows Registry Hive Collection (PowerShell)**
   - **Description:** A PowerShell script that collects and saves critical Windows registry hives for forensic analysis.
   - **Use Case:** Automate the collection of registry hives from a compromised system.
   - **User Input Required:**
     - **Output Path:** Modify the `$output_dir` variable to set the path where the registry hives will be saved.
   - **Example Usage:**
     ```powershell
     .\collect_registry_hives.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $output_dir = "C:\incident_registry_hives\"  # User must modify this

     if (-Not (Test-Path $output_dir)) {
         New-Item -ItemType Directory -Path $output_dir
     }

     # Collect registry hives
     reg save HKLM\SYSTEM $output_dir\SYSTEM.hiv
     reg save HKLM\SOFTWARE $output_dir\SOFTWARE.hiv
     reg save HKLM\SAM $output_dir\SAM.hiv

     Write-Host "Registry hives collected and saved to $output_dir"
     ```

---

### 2. **Collect Prefetch Files for Analysis (PowerShell)**
   - **Description:** A PowerShell script to collect Windows prefetch files for analysis of program execution history.
   - **Use Case:** Automate the collection of prefetch files to analyze recent program executions.
   - **User Input Required:**
     - **Output Path:** Modify the `$output_dir` variable to set the destination for the prefetch files.
   - **Example Usage:**
     ```powershell
     .\collect_prefetch.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $output_dir = "C:\incident_prefetch\"  # User must modify this

     if (-Not (Test-Path $output_dir)) {
         New-Item -ItemType Directory -Path $output_dir
     }

     # Collect prefetch files
     Copy-Item -Path C:\Windows\Prefetch\* -Destination $output_dir

     Write-Host "Prefetch files collected and saved to $output_dir"
     ```

---

### 3. **Linux Memory Dump Collection (Bash)**
   - **Description:** A Bash script that uses `dd` to collect a full memory dump from a Linux system for forensic analysis.
   - **Use Case:** Automate the collection of a memory dump from a Linux system.
   - **User Input Required:**
     - **Dump Path:** Modify the `$dump_path` variable to set the destination path for the memory dump.
   - **Example Usage:**
     ```bash
     ./collect_memory_dump.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     dump_path="/tmp/memory_dump.img"  # User must modify this

     echo "Collecting memory dump..."
     sudo dd if=/dev/mem of=$dump_path bs=1M
     echo "Memory dump saved to $dump_path"
     ```

---

### 4. **Collect Browser History and Cache (Python)**
   - **Description:** This Python script collects browser history, cache, and cookies from major web browsers (Chrome, Firefox) for forensic analysis.
   - **Use Case:** Automate the collection of browser artifacts from a system for analysis.
   - **User Input Required:**
     - **Browser Path:** Modify the `$chrome_path` and `$firefox_path` variables to point to the appropriate directories.
   - **Example Usage:**
     ```bash
     python collect_browser_history.py
     ```
   - **Code Snippet:**
     ```python
     import os
     import shutil

     chrome_path = "/home/user/.config/google-chrome/Default"  # User must modify this
     firefox_path = "/home/user/.mozilla/firefox/profile.default"  # User must modify this
     output_dir = "/incident_browser_data/"

     if not os.path.exists(output_dir):
         os.makedirs(output_dir)

     # Collect Chrome history and cache
     shutil.copy(os.path.join(chrome_path, "History"), output_dir)
     shutil.copy(os.path.join(chrome_path, "Cache"), output_dir)

     # Collect Firefox history and cookies
     shutil.copy(os.path.join(firefox_path, "places.sqlite"), output_dir)
     shutil.copy(os.path.join(firefox_path, "cookies.sqlite"), output_dir)

     print(f"Browser history and cache saved to {output_dir}")
     ```

---

### 5. **Windows Event Log Collection (PowerShell)**
   - **Description:** A PowerShell script that collects Windows event logs (Security, Application, System) for analysis.
   - **Use Case:** Automate the collection of key Windows event logs during a forensic investigation.
   - **User Input Required:**
     - **Output Path:** Modify the `$output_dir` variable to specify where the event logs will be saved.
   - **Example Usage:**
     ```powershell
     .\collect_event_logs.ps1
     ```
   - **Code Snippet:**
     ```powershell
     $output_dir = "C:\incident_event_logs\"  # User must modify this

     if (-Not (Test-Path $output_dir)) {
         New-Item -ItemType Directory -Path $output_dir
     }

     # Export event logs
     wevtutil epl Security $output_dir\Security.evtx
     wevtutil epl Application $output_dir\Application.evtx
     wevtutil epl System $output_dir\System.evtx

     Write-Host "Event logs collected and saved to $output_dir"
     ```

---

### 6. **File Metadata Extraction (Python)**
   - **Description:** A Python script that extracts metadata (e.g., creation time, modification time) from files in a specified directory for forensic analysis.
   - **Use Case:** Automate the collection of file metadata during an investigation.
   - **User Input Required:**
     - **Directory to Scan:** Modify the `$directory` variable to set the folder where files are located.
   - **Example Usage:**
     ```bash
     python extract_file_metadata.py
     ```
   - **Code Snippet:**
     ```python
     import os
     import time

     directory = "/path/to/files"  # User must modify this

     print(f"Extracting file metadata from {directory}...")

     for root, dirs, files in os.walk(directory):
         for file in files:
             file_path = os.path.join(root, file)
             stat = os.stat(file_path)
             creation_time = time.ctime(stat.st_ctime)
             modification_time = time.ctime(stat.st_mtime)
             print(f"File: {file}")
             print(f" - Creation time: {creation_time}")
             print(f" - Modification time: {modification_time}")
     ```

---

### 7. **Memory Artifact Collection via Volatility (Bash)**
   - **Description:** A Bash script that automates the use of the Volatility tool to extract memory artifacts, such as running processes and network connections.
   - **Use Case:** Automate the extraction of memory artifacts for forensic analysis.
   - **User Input Required:**
     - **Memory Dump Path:** Modify the `$memory_dump` variable to set the path of the memory dump file to analyze.
   - **Example Usage:**
     ```bash
     ./volatility_memory_artifacts.sh
     ```
   - **Code Snippet:**
     ```bash
     #!/bin/bash
     memory_dump="/path/to/memory_dump.img"  # User must modify this
     volatility_path="/usr/local/bin/volatility"  # Path to Volatility

     echo "Extracting running processes..."
     $volatility_path -f $memory_dump --profile=Win7SP1x64 pslist > processes.txt

     echo "Extracting network connections..."
     $volatility_path -f $memory_dump --profile=Win7SP1x64 netscan > network_connections.txt

     echo "Artifacts extracted using Volatility."
     ```

---
