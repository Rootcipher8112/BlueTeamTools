# Phishing Alert Investigation Checklist

This checklist outlines the steps for investigating phishing alerts, covering the process from initial triage to resolution.

---

### 1. Verify and Triage

- **Review Email Metadata**: Check sender email, reply-to address, and header information to validate authenticity.
- **Examine Subject and Content**: Look for common phishing indicators, such as urgent language, suspicious links, or requests for sensitive information.

---

### 2. Data Collection

- **Check Email Logs**: Review email server logs for information on recipients, timestamps, and delivery paths.
- **Analyze Links and Attachments**: Use a sandbox environment or threat intelligence sources to examine links and attachments for malicious behavior.

---

### 3. Investigation and Analysis

- **Identify Compromised Users**: Check if any users have clicked links or provided credentials in response to the phishing email.
- **Search for Indicators**: Identify and track associated indicators (e.g., IP addresses, domains) across other logs.

---

### 4. Containment and Mitigation

- **Block Malicious IPs or Domains**: Add indicators to blocklists to prevent further phishing attempts.
- **Educate Affected Users**: Notify users about the phishing attempt and provide guidance on recognizing future threats.

---

### 5. Documentation and Closure

- **Document Findings**: Record all relevant data, analysis, and actions taken.
- **Close Alert**: Ensure that containment measures are in place and the alert can be safely closed.
