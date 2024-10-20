# Access Control & User Management Scripts

This document contains Python and Bash scripts to automate access control enforcement, user management tasks, and monitor unauthorized access attempts.

---

### 1. **Automate User Account Creation (Python)**
   - **Description:** A Python script that automates the creation of new user accounts and assigns them to specific groups within an Active Directory environment.
   - **Example Usage:**
     ```bash
     python create_user_ad.py --username new_user --password Passw0rd! --group Sales
     ```
   - **Code:**
     ```python
     import subprocess
     import argparse

     def create_user(username, password, group):
         # Create the user in Active Directory
         subprocess.run(["net", "user", username, password, "/add"])
         # Add the user to a specific group
         subprocess.run(["net", "localgroup", group, username, "/add"])
         print(f"User {username} created and added to group {group}.")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Create a new user in Active Directory.")
         parser.add_argument("--username", required=True, help="Username of the new account.")
         parser.add_argument("--password", required=True, help="Password for the new account.")
         parser.add_argument("--group", required=True, help="Group to assign the user.")
         args = parser.parse_args()

         create_user(args.username, args.password, args.group)
     ```

---

### 2. **Monitor Unauthorized Login Attempts (Bash)**
   - **Description:** A Bash script that monitors system logs for unauthorized login attempts and sends alerts if any suspicious activity is detected.
   - **Example Usage:**
     ```bash
     ./monitor_login_attempts.sh /var/log/auth.log
     ```
   - **Code:**
     ```bash
     #!/bin/bash

     log_file="$1"
     alert_threshold=5  # Number of failed login attempts before alerting

     if [ -z "$log_file" ]; then
         echo "Usage: $0 /path/to/log/file"
         exit 1
     fi

     echo "Monitoring $log_file for unauthorized login attempts..."

     tail -f "$log_file" | while read line; do
         if echo "$line" | grep -q "Failed password"; then
             echo "Unauthorized login attempt detected: $line"
             failed_attempts=$((failed_attempts+1))
             if [ "$failed_attempts" -ge "$alert_threshold" ]; then
                 echo "ALERT: $failed_attempts unauthorized login attempts detected!"
                 # Send alert (email, Slack, etc.)
                 failed_attempts=0
             fi
         fi
     done
     ```

---

### 3. **Enforce Least Privilege (Python)**
   - **Description:** A Python script that checks user permissions and ensures that each user only has the necessary privileges for their role.
   - **Example Usage:**
     ```bash
     python enforce_least_privilege.py --user user@example.com --role Employee
     ```
   - **Code:**
     ```python
     import argparse

     def check_user_permissions(user, role):
         # Example: Check permissions based on predefined role access
         required_permissions = {
             "Employee": ["read", "write"],
             "Manager": ["read", "write", "execute"],
             "Admin": ["read", "write", "execute", "admin"]
         }
         user_permissions = get_user_permissions(user)  # Example function to fetch current permissions
         missing_permissions = [p for p in required_permissions[role] if p not in user_permissions]

         if missing_permissions:
             print(f"User {user} is missing the following permissions: {', '.join(missing_permissions)}")
         else:
             print(f"User {user} has the correct permissions for the {role} role.")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Enforce least privilege for a user based on their role.")
         parser.add_argument("--user", required=True, help="User account to check.")
         parser.add_argument("--role", required=True, help="Role to enforce (Employee, Manager, Admin).")
         args = parser.parse_args()

         check_user_permissions(args.user, args.role)
     ```

---

## Instructions

1. **Active Directory:** For user management scripts that interact with Active Directory, ensure the script is run with the necessary privileges and connected to the appropriate directory server.
2. **Logging:** The Bash script for monitoring unauthorized login attempts should be customized to monitor the correct log file, depending on the system being used.

---

## Contributing

Feel free to contribute to this repository by suggesting new access control or user management scripts.
