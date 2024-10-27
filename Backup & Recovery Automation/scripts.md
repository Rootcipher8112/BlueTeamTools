# Backup & Recovery Automation Scripts

This document contains Python and Bash scripts for automating data backup processes, verifying backup integrity, and restoring data.

---

### 1. **Automate Backup with rsync (Bash)**
   - **Description:** A Bash script that automates backups using rsync, syncing files from a source directory to a backup directory.
   - **Example Usage:**
     ```bash
     ./backup_with_rsync.sh /source/directory /backup/directory
     ```
   - **Code:**
     ```bash
     #!/bin/bash

     source_dir="$1"
     backup_dir="$2"

     if [ -z "$source_dir" ] || [ -z "$backup_dir" ]; then
         echo "Usage: $0 /path/to/source /path/to/backup"
         exit 1
     fi

     rsync -av --delete "$source_dir" "$backup_dir"
     echo "Backup completed from $source_dir to $backup_dir."
     ```

---

### 2. **Verify Backup Integrity (Python)**
   - **Description:** A Python script that verifies the integrity of backup files by comparing checksums between the original and backup directories.
   - **Example Usage:**
     ```bash
     python verify_backup_integrity.py /source/directory /backup/directory
     ```
   - **Code:**
     ```python
     import os
     import hashlib
     import argparse

     def calculate_checksum(file_path):
         sha256 = hashlib.sha256()
         with open(file_path, 'rb') as f:
             while chunk := f.read(8192):
                 sha256.update(chunk)
         return sha256.hexdigest()

     def verify_integrity(source_dir, backup_dir):
         for root, _, files in os.walk(source_dir):
             for file in files:
                 source_file = os.path.join(root, file)
                 backup_file = os.path.join(backup_dir, os.path.relpath(source_file, source_dir))

                 if os.path.exists(backup_file):
                     if calculate_checksum(source_file) != calculate_checksum(backup_file):
                         print(f"Mismatch detected in file: {source_file}")
                 else:
                     print(f"Missing file in backup: {backup_file}")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Verify backup integrity by comparing checksums.")
         parser.add_argument("source_dir", help="Path to source directory.")
         parser.add_argument("backup_dir", help="Path to backup directory.")
         args = parser.parse_args()

         verify_integrity(args.source_dir, args.backup_dir)
     ```

---

### 3. **Restore Data from Backup (Bash)**
   - **Description:** A Bash script that restores files from a backup directory to the original location.
   - **Example Usage:**
     ```bash
     ./restore_from_backup.sh /backup/directory /original/location
     ```
   - **Code:**
     ```bash
     #!/bin/bash

     backup_dir="$1"
     restore_dir="$2"

     if [ -z "$backup_dir" ] || [ -z "$restore_dir" ]; then
         echo "Usage: $0 /path/to/backup /path/to/restore"
         exit 1
     fi

     rsync -av "$backup_dir" "$restore_dir"
     echo "Data restored from $backup_dir to $restore_dir."
     ```

---

## Instructions

1. **Source and Backup Directories:** For backup scripts, ensure that source and backup directories are specified correctly and have appropriate read/write permissions.
2. **Integrity Verification:** Use the integrity verification script regularly to ensure that backup files are complete and uncorrupted.

---

## Contributing

Feel free to contribute to this repository by suggesting new backup and recovery scripts or tools. To contribute, simply create a pull request with your changes.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
