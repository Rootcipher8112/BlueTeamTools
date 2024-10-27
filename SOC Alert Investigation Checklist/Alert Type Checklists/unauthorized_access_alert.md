# Unauthorized Access Alert Investigation Checklist

This checklist provides steps for investigating unauthorized access alerts, helping to identify and mitigate unauthorized access attempts.

---

### 1. Verify and Triage

- **Validate Access Type**: Determine if the access attempt was a failed or successful login.
- **Check for Multiple Attempts**: Look for repeated access attempts or unusual login times.

---

### 2. Data Collection

- **Gather Login Logs**: Collect logs showing login times, locations, and any associated IP addresses.
- **Review User Activity**: Check if the user performed any unusual activities during or after the access attempt.

---

### 3. Investigation and Analysis

- **Identify Source**: Trace the origin of the unauthorized attempt (internal/external IP, device).
- **Correlate Events**: Check for related activity across the network, such as lateral movement attempts.

---

### 4. Containment and Remediation

- **Lock Affected Accounts**: Disable affected user accounts to prevent further access.
- **Update Access Controls**: Implement stricter access controls if necessary (e.g., MFA, IP restrictions).

---

### 5. Documentation and Closure

- **Document Steps Taken**: Record all actions, findings, and affected accounts.
- **Conduct a Follow-Up Review**: Reevaluate access controls and consider awareness training if internal access was compromised.
