# General Alert Investigation Checklist

This checklist provides general steps that SOC analysts should follow when investigating any security alert. Use this checklist as a foundation before moving on to more specific checklists for particular alert types.

---

### 1. Alert Verification

- **Review Alert Details**: Gather basic information about the alert, including the alert ID, timestamp, source IP, and any descriptions provided.
- **Determine Alert Source**: Identify where the alert originated (e.g., SIEM, endpoint detection, network monitoring).
- **Validate Alert**: Check if the alert is legitimate or a false positive by verifying against recent changes, configurations, or scheduled tasks.

---

### 2. Initial Triage

- **Classify the Alert**: Determine the type of alert (e.g., phishing, malware, unauthorized access).
- **Assess Severity**: Evaluate the potential impact and urgency based on asset criticality, user roles, and threat indicators.
- **Prioritize for Response**: Assign a priority level based on risk to the organization and resources available.

---

### 3. Data Collection

- **Gather Logs**: Collect relevant logs from SIEM, endpoint logs, network logs, and any other applicable sources.
- **Check Endpoint Data**: Review endpoint activity (processes, network connections) for associated devices.
- **Capture Network Traffic**: If applicable, review or capture network traffic for evidence of suspicious activity.

---

### 4. Investigation and Analysis

- **Correlate Data**: Look for related alerts or incidents that may be connected to this alert.
- **Identify Indicators of Compromise (IOCs)**: Search for any IOCs such as suspicious IP addresses, file hashes, URLs, or domains.
- **Use Threat Intelligence**: Query threat intelligence sources to validate any suspicious IPs, domains, or files identified.

---

### 5. Documentation

- **Record Findings**: Document all findings, steps taken, and observations in a case management system or ticketing system.
- **Save Artifacts**: Store any relevant evidence (e.g., log files, traffic captures, screenshots) for future reference or escalation.

---

### 6. Resolution and Follow-Up

- **Take Action**: Implement appropriate response actions (e.g., block IP, isolate endpoint) based on the investigation’s findings.
- **Review and Close**: Verify that the alert was handled correctly and escalate if necessary. Close the alert if fully resolved.
- **Post-Incident Review**: Conduct a brief review to discuss any lessons learned or improvements needed for future responses.

---

Use this checklist in conjunction with specific alert checklists for detailed steps on handling particular types of alerts.
