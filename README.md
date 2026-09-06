# 🔍 Splunk Practice Labs & SOC Threat Hunting Repository

Welcome to the **Splunk Practice Labs** repository! This repository contains hands-on cybersecurity labs, real-world log datasets, Splunk Search Processing Language (SPL) queries, investigation scenarios, and SIEM detection engineering exercises.

Designed for SOC Analysts, Threat Hunters, Incident Responders, and Security Engineers preparing for Splunk certification and practical SOC roles.

---

## 📁 Repository Structure

```
Splunk-Practice-Labs/
│
├── README.md                          # Master Repository Overview & Lab Roadmap
├── .gitignore                         # Git exclusion rules
│
├── Lab 1/                             # Lab 1: SSH Authentication Log & Threat Analysis
│   ├── README.md                      # Complete Lab 1 Guide, 10 Tasks, SPL Queries & Solutions
│   └── ssh_logs.json                  # Dataset (1,200 JSON log entries)
│
├── Lab 2/                             # Lab 2: DNS Traffic Log & Network Intelligence Analysis
│   ├── README.md                      # Complete Lab 2 Guide, 13 Tasks, SPL Queries & Solutions
│   └── dns_logs.json                  # Dataset (1,200 JSON log entries)
│
├── Lab 3/                             # [Upcoming] Windows Event Logs & Sysmon Threat Hunting
├── Lab 4/                             # [Upcoming] Firewall & Network Traffic Analysis (Palo Alto/pfSense)
├── Lab 5/                             # [Upcoming] DNS Tunneling & Data Exfiltration Detection
├── Lab 6/                             # [Upcoming] Email & Phishing Investigation
├── Lab 7/                             # [Upcoming] Cloud Incident Response (AWS CloudTrail / Azure AD)
├── Lab 8/                             # [Upcoming] Endpoint Detection & Response (EDR / CrowdStrike)
├── Lab 9/                             # [Upcoming] SOC Automation & Custom Alerting Engineering
└── Lab 10/                            # [Upcoming] Enterprise SIEM Dashboard & Capstone Investigation
```

---

## 🚀 Lab Index & Curriculum Roadmap

| Lab # | Topic / Focus Area | Log Sources | Status | Lab Manual |
| :---: | :--- | :--- | :---: | :---: |
| **Lab 1** | **SSH Authentication & Brute-Force Threat Analysis** | JSON SSH Telemetry (Zeek) | 🟢 **Completed** | [Lab 1 Manual](./Lab%201/README.md) |
| **Lab 2** | **DNS Traffic Log & Network Intelligence Analysis** | JSON DNS Telemetry (Zeek) | 🟢 **Completed** | [Lab 2 Manual](./Lab%202/README.md) |
| **Lab 3** | **Windows Host Intrusion & Sysmon Threat Hunting** | Event IDs 4624, 4688, 1, 3 | 🟡 *Planned* | Upcoming |
| **Lab 4** | **Perimeter Firewall & Network Traffic Analysis** | Palo Alto / Cisco ASA | 🟡 *Planned* | Upcoming |
| **Lab 5** | **Web Application Attack Analysis (SQLi, XSS, Path Traversal)** | Apache / Nginx / IIS | 🟡 *Planned* | Upcoming |
| **Lab 6** | **Phishing Email Analysis & Malicious Attachment Tracking** | Office 365 / Exchange / Gateway | 🟡 *Planned* | Upcoming |
| **Lab 7** | **Cloud Threat Detection & IAM Privilege Abuse** | AWS CloudTrail / Azure AD | 🟡 *Planned* | Upcoming |
| **Lab 8** | **Endpoint Malware & Ransomware Investigation** | CrowdStrike / Defender / EDR | 🟡 *Planned* | Upcoming |
| **Lab 9** | **SIEM Detection Engineering & Threat Alerting** | Multi-source Correlation | 🟡 *Planned* | Upcoming |
| **Lab 10** | **Comprehensive Enterprise SOC Dashboard Capstone** | Full Cyber Kill Chain | 🟡 *Planned* | Upcoming |

---

## 🛠️ Lab 1 Quick Summary: SSH Authentication Log Analysis

- **Dataset**: `Lab 1/ssh_logs.json` (1,200 events)
- **Tasks**: 10 hands-on SPL exercises
- **Key Objectives**:
  - Ingest JSON telemetry into Splunk (`sourcetype="_json"`).
  - Quantify event types (`Successful SSH Login`, `Failed SSH Login`, `Multiple Failed Authentication Attempts`, `Connection Without Authentication`).
  - Identify top threat actors conducting brute-force attempts.
  - Calculate host failure rates and discover compromised credentials.
  - Track unauthenticated port scanners and measure network data volume.
  - Write production SIEM alert rules (`auth_attempts >= 8`).

👉 **Read the full Lab 1 Guide with queries and verified answers**: [Lab 1 README](./Lab%201/README.md)

---

## 🛠️ Lab 2 Quick Summary: DNS Traffic Log & Network Intelligence Analysis

- **Dataset**: `Lab 2/dns_logs.json` (1,200 events)
- **Tasks**: 13 hands-on SPL exercises
- **Key Objectives**:
  - Ingest Zeek DNS JSON telemetry into Splunk (`sourcetype="_json"`).
  - Classify DNS query types (`A`, `AAAA`, `PTR`, `CNAME`) and measure distribution.
  - Identify the most active internal DNS clients and their behavioral profiles.
  - Map top queried domains and classify internal vs. external traffic scope.
  - Analyze DNS resolver load distribution across the infrastructure.
  - Measure query response times (RTT) and categorize latency performance bands.
  - Compare IPv4 vs. IPv6 address resolution to assess network readiness.
  - Detect reverse DNS (PTR) enumeration activity per host.
  - Analyze CNAME alias chains and TTL caching efficiency.

👉 **Read the full Lab 2 Guide with queries and verified answers**: [Lab 2 README](./Lab%202/README.md)

---

## ⚙️ How to Get Started with Splunk

### 1. Set Up Splunk Environment
- **Splunk Enterprise (Free License)**: Download from [Splunk Official Website](https://www.splunk.com).
- **Docker Splunk**:
  ```bash
  docker run -d -p 8000:8000 -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=YourPassword123" --name splunk splunk/splunk:latest
  ```

### 2. Ingest Dataset
1. Open Splunk UI (`http://localhost:8000`).
2. Navigate to **Settings > Add Data > Upload**.
3. Select the lab dataset file (e.g., `Lab 1/ssh_logs.json` or `Lab 2/dns_logs.json`).
4. Set Source Type to `_json`.
5. Select Index `main` or create a dedicated index (e.g., `ssh_labs`, `dns_labs`).
6. Click **Submit** and begin querying in **Search & Reporting**.

---

## 💡 Essential Splunk SPL Cheat Sheet

| Operation | SPL Example |
| :--- | :--- |
| **Count Events** | `index=main \| stats count` |
| **Group & Count** | `index=main \| stats count by event_type` |
| **Calculate Sum** | `index=main \| stats sum(auth_attempts) as Total by "id.orig_h"` |
| **Conditional Count** | `index=main \| stats count(eval(auth_success="true")) as Passed` |
| **Filter Results** | `index=main \| where auth_attempts > 5` |
| **Calculate Fields** | `index=main \| eval Total_Bytes = orig_ip_bytes + resp_ip_bytes` |
| **Format Columns** | `index=main \| table "id.orig_h", event_type, auth_attempts` |
| **Regex Match** | `index=main \| eval Scope = if(match(query,"\\.local$"),"Internal","External")` |
| **RTT Stats** | `index=main \| stats avg(rtt) as Avg_RTT, max(rtt) as Max_RTT by "id.resp_h"` |
| **Top N Results** | `index=main \| stats count by query \| sort - count \| head 10` |
| **Latency Buckets** | `index=main \| eval Band = case(rtt<=0.2,"Fast",rtt<=0.4,"Medium",true(),"Slow")` |
| **Multi-field Stats** | `index=main \| stats count by "id.orig_h", qtype \| sort "id.orig_h", - count` |

---

## 🤝 Contributing & Updates

Contributions and feedback are welcome! Additional labs will be uploaded sequentially.

- **Author / Repository**: [shii9/Splunk-Practice-Labs](https://github.com/shii9/Splunk-Practice-Labs)
- **License**: MIT License
