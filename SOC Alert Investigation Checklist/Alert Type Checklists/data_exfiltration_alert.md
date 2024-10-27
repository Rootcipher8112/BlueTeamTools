# Data Exfiltration Alert Investigation Checklist

This checklist provides steps for investigating alerts related to potential data exfiltration events, helping to identify and mitigate unauthorized data transfers.

---

### 1. Verify and Triage

- **Identify Exfiltration Method**: Review the alert to understand the method (e.g., large file transfer, unusual outbound traffic).
- **Assess Severity and Sensitivity**: Determine the sensitivity of data potentially affected and the urgency of the response.

---

### 2. Data Collection

- **Gather Network Logs**: Collect relevant logs from network monitoring tools showing unusual outbound connections or data transfers.
- **Review Endpoint Activity**: Check endpoint logs for signs of file access, data transfers, or recent changes in sensitive directories.

---

### 3. Investigation and Analysis

- **Validate Suspicious Activity**: Correlate the alert with other indicators, such as newly connected IPs, high data volumes, or large files accessed.
- **Run Threat Intel Checks**: Query suspicious IPs or domains with threat intelligence sources to validate any outbound connections.

---

### 4. Containment and Mitigation

- **Isolate Involved Systems**: Temporarily isolate affected systems to prevent further data transfer if exfiltration is ongoing.
- **Update Network Rules**: Block specific IPs, ports, or protocols as needed to halt suspicious data transfers.

---

### 5. Documentation and Follow-Up

- **Document Findings**: Record all findings, affected data, and remediation steps taken.
- **Strengthen Controls**: Consider adding DLP (Data Loss Prevention) rules or tightening network monitoring to prevent similar events.
