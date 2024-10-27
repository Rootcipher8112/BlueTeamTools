# Security Incident Investigation Form

This form is designed to document the findings and actions taken during the investigation of a security alert. Each section provides space to gather key information, analysis, and outcomes.

---

### 1. Basic Incident Information

| Field                   | Description                                         |Value                                  |                                        
|-------------------------|-----------------------------------------------------|---------------------------------------|
| **Alert ID**            | Unique ID of the alert.                             |___________________________________    |                                                 
| **Date & Time**         | Date and time the alert was generated.              |___________________________________    |                                                 
| **Investigator**        | Name of the person investigating the alert.         |___________________________________    |                                                
| **Alert Source**        | Source of the alert (e.g., SIEM, EDR, firewall).    |___________________________________    |                                                 
| **Alert Type**          | Type of alert (e.g., phishing, malware, anomaly).   |___________________________________    |                                                 
| **Affected System(s)**  | List of affected systems or devices.                |___________________________________    |                                                 
| **Severity Level**      | Assigned severity level (e.g., low, medium, high).  |___________________________________    |                                                 

---

### 2. Initial Triage and Verification
| Field                          | Description                                                                   |Value                                  |                          
|--------------------------------|-------------------------------------------------------------------------------|---------------------------------------|
| **Alert Verification**         | Steps taken to verify the alert’s legitimacy.                                 |___________________________________    |                                 
| **False Positive Check**       | Outcome of initial triage (legitimate alert or false positive).               |___________________________________    |                                
| **Priority Level**             | Assigned priority for the response effort.                                    |___________________________________    |                                  
| **Initial Findings**           | Brief description of what was found initially.                                |___________________________________    |                                  

---

### 3. Data Collection

| Collected Data                | Source                                   | Description                                             |Value                                  |
|-------------------------------|------------------------------------------|---------------------------------------------------------|---------------------------------------|
| **Logs Collected**            | List sources (e.g., SIEM, network, EDR). | Type of logs gathered and any key findings.             |___________________________________    |                                 
| **Endpoint Information**      | Affected endpoint logs or snapshots.     | Key details such as processes, connections, and files.  |___________________________________    |                                  
| **Network Traffic Data**      | Source (e.g., firewall, packet capture). | Findings from traffic analysis, IPs involved, protocols.|___________________________________    |                                  
| **Threat Intelligence Checks**| Sources (e.g., VirusTotal, AbuseIPDB).   | Results of threat intel lookups on IPs, domains, hashes.|___________________________________    |                                  

---

### 4. Investigation and Analysis

| Field                          | Description                                                                    |Value                                  |
|--------------------------------|--------------------------------------------------------------------------------|---------------------------------------|
| **Indicators of Compromise (IOCs)**  | List any IPs, file hashes, URLs, or domains identified as IOCs.         | ___________________________________    |                                 
| **Correlated Alerts or Events** | List any related alerts or recent events that may be connected to this alert. |___________________________________    |                                  
| **Root Cause Analysis**        | Summary of what caused the alert and how the threat actor attempted access.    |___________________________________    |                                  
| **Other Observations**         | Any unusual behaviors or patterns identified during the analysis.              |___________________________________    |                                  

---

### 5. Actions Taken

| Action Type                    | Description                                                                 |Value                                  |
|--------------------------------|-----------------------------------------------------------------------------|---------------------------------------|
| **Containment Actions**        | List of containment actions (e.g., isolated host, blocked IP).             |___________________________________    |                                  
| **Remediation Steps**          | Actions taken to remediate or remove the threat (e.g., malware removal).   |___________________________________    |                                  
| **Additional Controls Applied**| Any additional security controls implemented (e.g., MFA, rule changes).    |___________________________________    |                                  

---

### 6. Documentation and Evidence

| Evidence Type                  | File/Reference Location                         | Description                             |Value                                 |
|--------------------------------|------------------------------------------------|-----------------------------------------|---------------------------------------|
| **Logs**                       | Path to log files or system logs               | Collected logs for reference.           |___________________________________    |                                  
| **Network Captures**           | Location of PCAP files                         | Relevant network traffic captures.      |___________________________________    |                                  
| **Screenshots**                | Path to screenshots                            | Any visual documentation.               |___________________________________    |                                  
| **Forensic Images**            | Location of forensic images                    | Disk or memory images if applicable.    |___________________________________    |                                  

---

### 7. Summary of Findings

| Field                          | Description                                                               |Value                                  |
|--------------------------------|---------------------------------------------------------------------------|---------------------------------------|
| **Incident Summary**           | Brief summary of the incident, key findings, and context.                 |___________________________________    |                                  
| **Resolution Outcome**         | Description of how the incident was resolved or mitigated.                |___________________________________    |                                  
| **Post-Incident Review**       | Notes for follow-up actions, recommendations, or lessons learned.         |___________________________________    |                                  

---

### 8. Recommendations and Next Steps

| Recommendation                  | Description                                                                 |Value                                  |
|---------------------------------|-----------------------------------------------------------------------------|---------------------------------------|
| **Process Improvements**        | Suggested changes to security processes or monitoring.                     |___________________________________    |                                  
| **Training Needs**              | Identify any awareness or training gaps discovered in the investigation.   |___________________________________    |                                  
| **Future Mitigations**          | Recommendations to prevent similar incidents (e.g., new controls, DLP).    |___________________________________    |                                  

---

### 9. Approval and Sign-Off

| Role                  | Name                                | Date         |
|-----------------------|-------------------------------------|--------------|
| **Investigator**      |___________________________________  |              |
| **SOC Manager**       |___________________________________  |              |
| **Other Approvers**   |___________________________________  |              |

---

This form provides a standardized structure, helping to ensure thorough and consistent investigations. Each section captures key points, making it easy to refer back to findings, actions, and recommendations for future analysis or auditing purposes.
