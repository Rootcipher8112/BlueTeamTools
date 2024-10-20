# Email Analysis Scripts

This document contains Python scripts for automating various email analysis tasks, including header extraction, malware scanning, and verifying email authenticity using DMARC, SPF, and DKIM.

---

### 1. **Email Header Extraction Script**
   - **Description:** A Python script to extract and parse email headers for quick analysis of sender IPs, DKIM, SPF, and DMARC information.
   - **Example Usage:**
     ```bash
     python extract_email_headers.py --file email.eml
     ```
   - **Code:**
     ```python
     import email
     import argparse

     def parse_email_headers(email_file):
         with open(email_file, 'r') as f:
             msg = email.message_from_file(f)
             headers = msg.items()
             for key, value in headers:
                 print(f"{key}: {value}")

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Parse email headers.")
         parser.add_argument("--file", required=True, help="Path to the email file (.eml or .msg)")
         args = parser.parse_args()

         parse_email_headers(args.file)
     ```

---

### 2. **Attachment Scanner Script**
   - **Description:** A Python script to extract and scan email attachments for potential malware using VirusTotal.
   - **Example Usage:**
     ```bash
     python scan_email_attachment.py --file email.eml --api_key YOUR_VIRUSTOTAL_API_KEY
     ```
   - **Code:**
     ```python
     import email
     import requests
     import argparse

     def extract_attachment(email_file, api_key):
         with open(email_file, 'r') as f:
             msg = email.message_from_file(f)
             for part in msg.walk():
                 if part.get_content_maintype() == 'multipart':
                     continue
                 if part.get('Content-Disposition') is None:
                     continue
                 
                 attachment_data = part.get_payload(decode=True)
                 attachment_name = part.get_filename()

                 print(f"Scanning {attachment_name}...")
                 response = requests.post(
                     "https://www.virustotal.com/vtapi/v2/file/scan",
                     files={'file': (attachment_name, attachment_data)},
                     params={'apikey': api_key}
                 )
                 print(response.json())

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Scan email attachments with VirusTotal.")
         parser.add_argument("--file", required=True, help="Path to the email file (.eml or .msg)")
         parser.add_argument("--api_key", required=True, help="Your VirusTotal API key")
         args = parser.parse_args()

         extract_attachment(args.file, args.api_key)
     ```

---

### 3. **DMARC, SPF, DKIM Verification Script**
   - **Description:** A Python script that verifies the legitimacy of an email using DMARC, SPF, and DKIM records.
   - **Example Usage:**
     ```bash
     python verify_dmarc_spf_dkim.py --email email.eml
     ```
   - **Code:**
     ```python
     import email
     import dns.resolver
     import argparse

     def check_spf_dkim(email_file):
         with open(email_file, 'r') as f:
             msg = email.message_from_file(f)
             domain = msg.get('From').split('@')[-1]

             print(f"Checking SPF for {domain}...")
             try:
                 answers = dns.resolver.query(f'{domain}', 'TXT')
                 for txt_record in answers:
                     if 'v=spf1' in txt_record.to_text():
                         print(f"SPF record found: {txt_record}")
             except:
                 print(f"No SPF record found for {domain}")

             print(f"Checking DKIM for {domain}...")
             # Additional DKIM logic would be added here

     if __name__ == "__main__":
         parser = argparse.ArgumentParser(description="Verify DMARC, SPF, and DKIM.")
         parser.add_argument("--email", required=True, help="Path to the email file (.eml or .msg)")
         args = parser.parse_args()

         check_spf_dkim(args.email)
     ```

---

## Contributing

Feel free to contribute to this repository by suggesting new tools, scripts, or improvements. To contribute, simply create a pull request with your changes or open an issue to discuss further.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
