# Blue Team Cybersecurity Tools

This repository contains a curated list of essential tools for blue team cybersecurity operations, categorized by their primary function. These tools are useful for SOC analysts, threat hunters, and incident responders.

---

## Network Monitoring

- **Wireshark**  
  *Description:* A powerful packet analyzer for network traffic inspection.  
  *Use Case:* Analyzing packet captures to detect suspicious traffic.  
  [Official Site](https://www.wireshark.org)

- **Zeek**  
  *Description:* A network monitoring framework that detects and logs various network events.  
  *Use Case:* Provides visibility into network traffic patterns and anomalies.  
  [Official Site](https://zeek.org)

- **Tshark**  
  *Description:* A command-line version of Wireshark for network traffic analysis.  
  *Use Case:* Analyzing network traffic directly from the command line for lightweight captures.  
  [Official Site](https://www.wireshark.org/docs/man-pages/tshark.html)

- **NetFlow**  
  *Description:* A network protocol developed by Cisco to collect IP traffic information.  
  *Use Case:* Monitoring and analyzing network traffic flows.  
  [Official Site](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-netflow/index.html)

- **SolarWinds Network Performance Monitor**  
  *Description:* A comprehensive tool for monitoring and analyzing network performance.  
  *Use Case:* Real-time monitoring of network traffic, identifying bottlenecks and suspicious activity.  
  [Official Site](https://www.solarwinds.com/network-performance-monitor)

---

## Endpoint Detection and Response (EDR)

- **OSQuery**  
  *Description:* A SQL-powered tool to query system-level information from endpoints.  
  *Use Case:* Useful for querying and monitoring endpoint activity across a fleet of systems.  
  [Official Site](https://osquery.io)

- **Velociraptor**  
  *Description:* An endpoint visibility tool that collects system artifacts for threat hunting.  
  *Use Case:* Proactive threat hunting and forensic artifact collection.  
  [Official Site](https://www.velocidex.com)

- **Carbon Black**  
  *Description:* A next-gen EDR platform for endpoint monitoring and response.  
  *Use Case:* Continuous endpoint monitoring and threat detection.  
  [Official Site](https://www.carbonblack.com)

- **CylancePROTECT**  
  *Description:* An AI-driven EDR solution that uses machine learning for endpoint security.  
  *Use Case:* Blocking malicious activity using AI-driven models.  
  [Official Site](https://www.cylance.com)

- **CrowdStrike Falcon**  
  *Description:* A leading EDR solution with real-time detection, prevention, and response.  
  *Use Case:* Monitoring, detecting, and responding to endpoint threats.  
  [Official Site](https://www.crowdstrike.com)

---

## Intrusion Detection Systems (IDS)

- **Suricata**  
  *Description:* An open-source network threat detection engine.  
  *Use Case:* Detecting intrusions and identifying malicious activities in real-time.  
  [Official Site](https://suricata.io)

- **Snort**  
  *Description:* A widely used IDS/IPS system for real-time traffic analysis and packet logging.  
  *Use Case:* Detection and prevention of network-based attacks.  
  [Official Site](https://www.snort.org)

- **Bro/Zeek**  
  *Description:* A robust network security monitoring tool that logs and inspects network traffic.  
  *Use Case:* Behavioral analysis and network event logging.  
  [Official Site](https://zeek.org)

- **Security Onion**  
  *Description:* An open-source security monitoring platform that combines multiple tools, including Suricata, Bro/Zeek, and Elastic Stack.  
  *Use Case:* Comprehensive network monitoring and intrusion detection.  
  [Official Site](https://securityonion.net)

- **OpenNMS**  
  *Description:* A scalable open-source network management platform.  
  *Use Case:* Monitoring and detecting network anomalies in large environments.  
  [Official Site](https://www.opennms.org)

---

## Log Management

- **Elastic Stack (ELK)**  
  *Description:* A powerful stack for log management, analysis, and visualization.  
  *Use Case:* Collecting, indexing, and visualizing logs from multiple sources.  
  [Official Site](https://www.elastic.co/what-is/elk-stack)

- **Splunk**  
  *Description:* A leading platform for machine data analysis and operational intelligence.  
  *Use Case:* Indexing logs and monitoring security events.  
  [Official Site](https://www.splunk.com)

- **Graylog**  
  *Description:* A popular log management platform for collecting, indexing, and analyzing logs.  
  *Use Case:* Real-time log analysis and alerting.  
  [Official Site](https://www.graylog.org)

- **LogRhythm**  
  *Description:* A log management and SIEM platform.  
  *Use Case:* Security event detection and compliance reporting.  
  [Official Site](https://logrhythm.com)

- **NXLog**  
  *Description:* A multi-platform log collector supporting various log formats.  
  *Use Case:* Collecting and forwarding logs for analysis.  
  [Official Site](https://nxlog.co)

---

## Threat Hunting

- **Sysmon**  
  *Description:* A Windows system service that logs key system events for forensic investigation.  
  *Use Case:* Monitoring system processes, network connections, and changes in file creation.  
  [Sysinternals Page](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

- **Sigma**  
  *Description:* A generic signature format for SIEM systems.  
  *Use Case:* Writing and sharing threat detection rules across SIEM platforms.  
  [Official Site](https://github.com/SigmaHQ/sigma)

- **Atomic Red Team**  
  *Description:* A framework for testing security controls by executing real-world attack scenarios.  
  *Use Case:* Validating threat detection capabilities and incident response.  
  [Official Site](https://github.com/redcanaryco/atomic-red-team)

- **Yara**  
  *Description:* A tool to create rules for identifying malware based on patterns and signatures.  
  *Use Case:* Detecting malware based on binary patterns and strings.  
  [Official Site](https://virustotal.github.io/yara/)

- **MISP (Malware Information Sharing Platform)**  
  *Description:* A platform for sharing threat intelligence with peers.  
  *Use Case:* Collaborative threat intelligence sharing and detection.  
  [Official Site](https://www.misp-project.org)

---

## Vulnerability Scanning

- **OpenVAS**  
  *Description:* A full-featured vulnerability scanner.  
  *Use Case:* Scanning systems for vulnerabilities in both network services and operating systems.  
  [Official Site](https://www.openvas.org)

- **Nmap**  
  *Description:* A network scanner used for host discovery and vulnerability detection.  
  *Use Case:* Mapping the network and detecting vulnerable services.  
  [Official Site](https://nmap.org)

- **Nessus**  
  *Description:* A comprehensive vulnerability scanner widely used by security professionals.  
  *Use Case:* Scanning and identifying known vulnerabilities in network services and applications.  
  [Official Site](https://www.tenable.com/products/nessus)

- **QualysGuard**  
  *Description:* A cloud-based vulnerability management platform.  
  *Use Case:* Continuous vulnerability scanning and risk management.  
  [Official Site](https://www.qualys.com)

- **Rapid7 Nexpose**  
  *Description:* An enterprise vulnerability management solution.  
  *Use Case:* Detecting vulnerabilities across large infrastructures.  
  [Official Site](https://www.rapid7.com/products/nexpose/)

---

## Malware Analysis

- **Cuckoo Sandbox**  
  *Description:* An open-source automated malware analysis system.  
  *Use Case:* Running suspicious files in a sandbox environment to observe behavior.  
  [Official Site](https://cuckoosandbox.org)

- **CAPE**  
  *Description:* A tool for malware analysis, with a focus on unpacking and monitoring malware families.  
  *Use Case:* Unpacking and analyzing various malware samples.  
  [Official Site](https://cape.contextis.com)

- **REMnux**  
  *Description:* A Linux toolkit for malware analysis and reverse engineering.  
  *Use Case:* Analyzing and reversing malware in a safe environment.  
  [Official Site](https://remnux.org)

- **IDABin**  
  *Description:* A disassembler and debugger tool for reverse-engineering malware binaries.  
  *Use Case:* Reverse-engineering to understand malware behavior.  
  [Official Site](https://www.hex-rays.com/products/ida/)

- **Radare2**  
  *Description:* A free and open-source software framework for reverse engineering.  
  *Use Case:* Binary analysis and reverse engineering of malware.  
  [Official Site](https://rada.re/n/)

---

## Email Analysis

- **PhishTool**  
  *Description:* An email analysis tool for phishing threat detection.  
  *Use Case:* Analyzing email headers and attachments to identify phishing attacks.  
  [Official Site](https://phishtool.com)

- **Mail Header Analyzer**  
  *Description:* A web tool for analyzing email headers.  
  *Use Case:* Investigating email headers for anomalies or phishing indicators.  
  [Official Site](https://mxtoolbox.com/EmailHeaders.aspx)

- **O365 Advanced Threat Protection (ATP)**  
  *Description:* Microsoft’s email threat protection tool.  
  *Use Case:* Protecting email accounts from phishing and malware.  
  [Official Site](https://www.microsoft.com/en-us/security/business/threat-protection)

- **Dmarcian**  
  *Description:* A tool for analyzing DMARC (Domain-based Message Authentication) policies.  
  *Use Case:* Ensuring domain integrity and preventing email spoofing.  
  [Official Site](https://dmarcian.com)

- **VirusTotal Email Analysis**  
  *Description:* A feature of VirusTotal that allows for file and URL scanning through email submission.  
  *Use Case:* Verifying attachments and links in suspicious emails.  
  [Official Site](https://www.virustotal.com/gui/home/email)

---

## Enrichment Tools

- **VirusTotal**  
  *Description:* A free service that analyzes files and URLs for viruses and malware.  
  *Use Case:* Verifying malicious files and links.  
  [Official Site](https://www.virustotal.com)

- **IPVoid**  
  *Description:* A service to check if an IP is listed in a blackhole list.  
  *Use Case:* Checking for blacklisted IP addresses involved in malicious activity.  
  [Official Site](https://www.ipvoid.com)

- **Shodan**  
  *Description:* A search engine for Internet-connected devices and vulnerabilities.  
  *Use Case:* Discovering vulnerable IoT and internet-facing assets.  
  [Official Site](https://www.shodan.io)

- **Have I Been Pwned**  
  *Description:* A service for checking if an email or password has been exposed in data breaches.  
  *Use Case:* Investigating email accounts that may have been compromised.  
  [Official Site](https://haveibeenpwned.com)

- **CIRCL Passive DNS**  
  *Description:* A service that tracks DNS resolutions passively to provide enrichment for investigations.  
  *Use Case:* Investigating domain resolutions without querying live DNS.  
  [Official Site](https://www.circl.lu/services/passive-dns/)

---

### Contributing

Feel free to contribute to this repository by suggesting new tools, improvements, or corrections. To contribute, simply create a pull request with your changes or open an issue to discuss further.
