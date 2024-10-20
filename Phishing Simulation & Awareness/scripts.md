# Phishing Simulation & Awareness Scripts

This document contains Python scripts for automating phishing simulations, including sending phishing emails and tracking user responses.

---

### 1. **Phishing Email Sender Script (Python)**
   - **Description:** A Python script that automates the sending of phishing emails to target users during a simulation campaign.
   - **Example Usage:**
     ```bash
     python send_phishing_email.py --target user@example.com --subject "Urgent: Account Verification Needed"
     ```
   - **Code:**
     ```python
     import smtplib
     import argparse

     def send_email(to_email, subject, body, from_email, smtp_server, smtp_port, smtp_user, smtp_password):
         with smtplib.SMTP(smtp_server, smtp_port) as server:
             server.starttls()
             server.login(smtp_user, smtp_password)
             message = f"Subject: {subject}\n\n{body}"
             server.sendmail(from_email, to_email, message)

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Send phishing email during simulation.")
         parser.add_argument("--target", required=True, help="Target email address.")
         parser.add_argument("--subject", required=True, help="Email subject line.")
         parser.add_argument("--body", required=True, help="Email body content.")
         parser.add_argument("--smtp_server", required=True, help="SMTP server address.")
         parser.add_argument("--smtp_port", required=True, type=int, help="SMTP server port.")
         parser.add_argument("--smtp_user", required=True, help="SMTP username.")
         parser.add_argument("--smtp_password", required=True, help="SMTP password.")
         parser.add_argument("--from_email", required=True, help="Sender's email address.")
         args = parser.parse_args()

         send_email(args.target, args.subject, args.body, args.from_email, args.smtp_server, args.smtp_port, args.smtp_user, args.smtp_password)
     ```

---

### 2. **Track User Responses Script (Python)**
   - **Description:** A Python script that tracks whether users have clicked on phishing links during a simulation.
   - **Example Usage:**
     ```bash
     python track_responses.py --log_file /path/to/click_log.csv
     ```
   - **Code:**
     ```python
     import csv
     import argparse

     def track_responses(log_file):
         with open(log_file, 'r') as f:
             reader = csv.reader(f)
             for row in reader:
                 email, clicked = row
                 if clicked == "Yes":
                     print(f"User {email} clicked on the phishing link.")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Track user responses during phishing simulation.")
         parser.add_argument("--log_file", required=True, help="Path to log file with user responses.")
         args = parser.parse_args()

         track_responses(args.log_file)
     ```

---

### 3. **Phishing Awareness Test Results Script (Python)**
   - **Description:** A Python script that compiles the results of phishing awareness tests and generates a report of user performance.
   - **Example Usage:**
     ```bash
     python awareness_test_results.py --test_file /path/to/test_results.csv
     ```
   - **Code:**
     ```python
     import csv
     import argparse

     def generate_report(test_file):
         total_users = 0
         users_failed = 0

         with open(test_file, 'r') as f:
             reader = csv.reader(f)
             for row in reader:
                 total_users += 1
                 if row[1] == "Fail":
                     users_failed += 1

         print(f"Total Users Tested: {total_users}")
         print(f"Users Who Failed: {users_failed} ({(users_failed / total_users) * 100:.2f}% failure rate)")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Generate report of phishing awareness test results.")
         parser.add_argument("--test_file", required=True, help="Path to phishing awareness test results CSV.")
         args = parser.parse_args()

         generate_report(args.test_file)
     ```

---

## Instructions

1. **Email Configuration:** Ensure you have access to an SMTP server for sending phishing emails, and configure the SMTP credentials correctly.
2. **Logs:** Keep track of responses in a CSV file (as shown in `track_responses.py`) to analyze how users interacted with the phishing simulation.
3. **Test Results:** Use the awareness test script to compile results from phishing awareness tests and generate failure rates.

---

## Contributing

Feel free to contribute to this repository by suggesting new simulation scripts or tools. To contribute, simply create a pull request with your changes.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
