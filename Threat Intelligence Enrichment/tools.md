# Threat Intelligence Enrichment Tools

This document contains tools and services for enriching raw threat data, such as IP addresses, domain names, and file hashes, with additional context from external sources.

---

### 1. **VirusTotal**
   - **Description:** A multi-antivirus engine that allows users to scan files, URLs, and IP addresses to gather threat intelligence data.
   - **Use Case:** Enrich files, URLs, or IPs with detection results from multiple security vendors.
   - **Official Site:** [VirusTotal](https://www.virustotal.com)

---

### 2. **AbuseIPDB**
   - **Description:** A database of reported malicious IP addresses, allowing users to search for suspicious IPs and receive abuse reports.
   - **Use Case:** Enrich IP addresses by checking them against a global database of reported malicious IPs.
   - **Official Site:** [AbuseIPDB](https://www.abuseipdb.com)

---

### 3. **ThreatMiner**
   - **Description:** An open-source threat intelligence platform that provides enrichment data on IP addresses, domains, file hashes, and more.
   - **Use Case:** Enrich various types of threat data (e.g., IPs, domains, and hashes) using open-source threat intelligence.
   - **Official Site:** [ThreatMiner](https://www.threatminer.org)

---

### 4. **OTX AlienVault**
   - **Description:** A collaborative threat intelligence platform where users can share and search for threat indicators, including IPs, domains, and file hashes.
   - **Use Case:** Enrich threat data using the AlienVault OTX API to retrieve additional context on indicators.
   - **Official Site:** [AlienVault OTX](https://otx.alienvault.com)

---

### 5. **Cymon**
   - **Description:** A platform that collects threat intelligence data on IPs, domains, and URLs from multiple sources.
   - **Use Case:** Enrich IP and domain data by querying Cymon’s API to gather additional context on potential threats.
   - **Official Site:** [Cymon](https://www.cymon.io)

---

## Additional Resources:

- **CIRCL Passive DNS**  
  *Description:* Provides passive DNS replication for incident analysis and threat intelligence enrichment.  
  *Use Case:* Enrich domain data by looking up historical DNS records.  
  *Official Site:* [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns)

- **Shodan**  
  *Description:* A search engine that lets you find information on connected devices by scanning the internet.  
  *Use Case:* Enrich IP addresses by looking up publicly exposed devices associated with them.  
  *Official Site:* [Shodan](https://www.shodan.io)
