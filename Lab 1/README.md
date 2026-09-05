# Lab 1: SSH Authentication Log & Threat Analysis

## Overview & Scenario
In this lab, you assume the role of a **SOC Security Analyst** investigating authentication logs and SSH network telemetry captured across an enterprise network. The dataset contains **1,200 JSON log entries** representing SSH connections, login attempts, authentication failures, brute-force activity, unauthenticated port scans, and successful user sessions.

The primary objective is to use **Splunk Search Processing Language (SPL)** to analyze the ingested SSH logs (`ssh_logs.json`), detect brute-force attacks, identify target systems, uncover potential compromised hosts, and construct SIEM detection rules.

---

## Dataset Details
- **File Name**: `ssh_logs.json`
- **Total Log Count**: 1,200 events
- **Log Format**: JSON
- **Recommended Splunk Sourcetype**: `_json` or `ssh:zeek:json`
- **Recommended Index**: `ssh_labs` or `main`

### Sample Log Structure
```json
{
  "ts": "2025-04-24T10:20:09.508780Z",
  "uid": "SH4886434",
  "id.orig_h": "10.0.0.43",
  "id.orig_p": 58221,
  "id.resp_h": "10.0.1.6",
  "id.resp_p": 22,
  "proto": "tcp",
  "conn_state": "SF",
  "missed_bytes": 0,
  "history": "ShADadfF",
  "orig_pkts": 49,
  "orig_ip_bytes": 3234,
  "resp_pkts": 34,
  "resp_ip_bytes": 1700,
  "auth_success": true,
  "auth_attempts": 1,
  "event_type": "Successful SSH Login"
}
```

---

## Splunk Data Ingestion Setup

To ingest this dataset into your Splunk environment:
1. Log in to **Splunk Enterprise** (or Splunk Cloud / Docker Splunk).
2. Go to **Settings > Add Data**.
3. Choose **Upload** and upload `Lab 1/ssh_logs.json`.
4. Set Source Type to `_json` (or create a custom sourcetype `ssh:json`).
5. Set Index to `main` or create index `ssh_labs`.
6. Save and launch Search & Reporting.

---

## Lab Tasks & Hands-On Exercises

### Task 1: Dataset Verification & Total Log Count
**Objective**: Verify data ingestion and calculate the total number of ingested SSH log records.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" 
| stats count as Total_Logs
```

#### Query Breakdown
- `index=main sourcetype="_json"`: Filters search results to the ingested JSON dataset.
- `stats count as Total_Logs`: Aggregates all matching log events into a single count metric.

#### Expected Output
| Total_Logs |
| :--- |
| **1200** |

---

### Task 2: SSH Event Categorization & Breakdown
**Objective**: Classify the logs by `event_type` to understand overall network activity and authentication trends.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count by event_type
| sort - count
```

#### Query Breakdown
- `stats count by event_type`: Groups total records by the `event_type` field values.
- `sort - count`: Orders categories in descending numerical order.

#### Expected Output
| event_type | count |
| :--- | :--- |
| Successful SSH Login | **306** |
| Failed SSH Login | **305** |
| Multiple Failed Authentication Attempts | **303** |
| Connection Without Authentication | **286** |

---

### Task 3: Top 5 Originating Source IPs by Activity Volume
**Objective**: Identify which source IP addresses (`id.orig_h`) generated the highest volume of SSH connections.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Total_Events by "id.orig_h"
| sort - Total_Events
| head 5
| rename "id.orig_h" as Source_IP
```

#### Query Breakdown
- `stats count as Total_Events by "id.orig_h"`: Calculates total log entries originating from each host.
- `sort - Total_Events`: Ranks origin IPs by total event volume.
- `head 5`: Limits results to the top 5 source hosts.
- `rename`: Formats field names for report readability.

#### Expected Output
| Source_IP | Total_Events |
| :--- | :--- |
| **10.0.0.25** | 39 |
| **10.0.0.21** | 32 |
| **10.0.0.48** | 32 |
| **10.0.0.18** | 32 |
| **10.0.0.44** | 31 |

---

### Task 4: Most Targeted Internal SSH Servers
**Objective**: Determine which internal servers (`id.resp_h`) received the highest number of SSH connection requests.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Hits by "id.resp_h"
| sort - Hits
| head 5
| rename "id.resp_h" as Target_Server
```

#### Query Breakdown
- `stats count as Hits by "id.resp_h"`: Counts connection events targeting each internal host IP.
- `sort - Hits | head 5`: Extracts the top 5 targeted server IPs.

#### Expected Output
| Target_Server | Hits |
| :--- | :--- |
| **10.0.1.6** | 115 |
| **10.0.1.2** | 115 |
| **10.0.1.9** | 113 |
| **10.0.1.4** | 109 |
| **10.0.1.10** | 104 |

---

### Task 5: Identifying High-Frequency Brute-Force Attackers
**Objective**: Detect attackers executing repeated authentication attempts by summing total `auth_attempts` per source IP.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats sum(auth_attempts) as Total_Auth_Attempts, count as Event_Count by "id.orig_h"
| sort - Total_Auth_Attempts
| head 5
| rename "id.orig_h" as Attacker_IP
```

#### Query Breakdown
- `sum(auth_attempts)`: Sums the total individual password guesses/attempts recorded across sessions.
- `sort - Total_Auth_Attempts`: Ranks IPs conducting aggressive brute-force behavior.

#### Expected Output
| Attacker_IP | Total_Auth_Attempts | Event_Count |
| :--- | :--- | :--- |
| **10.0.0.25** | **99** | 39 |
| **10.0.0.22** | **97** | 31 |
| **10.0.0.11** | **82** | 30 |
| **10.0.0.48** | **77** | 32 |
| **10.0.0.21** | **76** | 32 |

---

### Task 6: Authentication Failure vs. Success Rate per Source IP
**Objective**: Compare successful logins against failed authentication attempts per host to calculate failure rates.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count(eval(event_type="Successful SSH Login")) as Successes, count(eval(event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts")) as Failures, count as Total_Sessions by "id.orig_h"
| eval Failure_Rate_Pct = round((Failures / Total_Sessions) * 100, 2)
| sort - Failures
| head 5
| rename "id.orig_h" as Source_IP
```

#### Query Breakdown
- `count(eval(...))`: Conditional counting of specific login events.
- `eval Failure_Rate_Pct`: Computes percentage of failed sessions per source host.

#### Expected Output
| Source_IP | Successes | Failures | Total_Sessions | Failure_Rate_Pct |
| :--- | :--- | :--- | :--- | :--- |
| **10.0.0.25** | 8 | 22 | 39 | 56.41% |
| **10.0.0.48** | 6 | 20 | 32 | 62.50% |
| **10.0.0.46** | 7 | 20 | 30 | 66.67% |
| **10.0.0.21** | 7 | 19 | 32 | 59.38% |
| **10.0.0.22** | 4 | 19 | 31 | 61.29% |

---

### Task 7: Detecting Potential Account Compromise (Brute Force Followed by Success)
**Objective**: Identify source IPs that engaged in `Multiple Failed Authentication Attempts` AND subsequently achieved a `Successful SSH Login`.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count(eval(event_type="Multiple Failed Authentication Attempts")) as Multi_Failures, count(eval(event_type="Successful SSH Login")) as Successful_Logins by "id.orig_h"
| where Multi_Failures > 0 AND Successful_Logins > 0
| sort - Multi_Failures
| head 10
| rename "id.orig_h" as Suspicious_IP
```

#### Query Breakdown
- `where Multi_Failures > 0 AND Successful_Logins > 0`: Filters for hosts demonstrating high failure counts followed by valid authentication (indicative of password cracking or credential guessing success).

#### Expected Output Sample
| Suspicious_IP | Multi_Failures | Successful_Logins |
| :--- | :--- | :--- |
| **10.0.0.25** | 13 | 8 |
| **10.0.0.22** | 13 | 4 |
| **10.0.0.11** | 11 | 5 |
| **10.0.0.48** | 10 | 6 |
| **10.0.0.33** | 10 | 7 |

---

### Task 8: Reconnaissance & Unauthenticated Probing Detection
**Objective**: Track hosts engaging in `Connection Without Authentication` (port scanning, SSH banner grabbing, or quick disconnects without attempting login).

#### Splunk SPL Query
```spl
index=main sourcetype="_json" event_type="Connection Without Authentication"
| stats count as Scan_Events by "id.orig_h"
| sort - Scan_Events
| head 5
| rename "id.orig_h" as Scanner_IP
```

#### Query Breakdown
- `event_type="Connection Without Authentication"`: Isolates sessions where network handshakes completed but no authentication credentials were sent.

#### Expected Output
| Scanner_IP | Scan_Events |
| :--- | :--- |
| **10.0.0.14** | **13** |
| **10.0.0.18** | **13** |
| **10.0.0.53** | **10** |
| **10.0.0.27** | **10** |
| **10.0.0.44** | **10** |

---

### Task 9: Network Data Exfiltration & Bandwidth Analysis
**Objective**: Calculate the total data volume (inbound + outbound bytes) transferred during SSH sessions to identify potential data exfiltration.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| eval Total_Bytes = orig_ip_bytes + resp_ip_bytes
| stats sum(orig_ip_bytes) as Bytes_Sent, sum(resp_ip_bytes) as Bytes_Received, sum(Total_Bytes) as Total_Transfer_Bytes by "id.orig_h"
| sort - Total_Transfer_Bytes
| head 5
| rename "id.orig_h" as Host_IP
```

#### Query Breakdown
- `eval Total_Bytes`: Sums client-sent bytes (`orig_ip_bytes`) and server-sent bytes (`resp_ip_bytes`).
- `stats sum(...)`: Aggregates overall network traffic metrics per source address.

#### Expected Output
| Host_IP | Bytes_Sent | Bytes_Received | Total_Transfer_Bytes |
| :--- | :--- | :--- | :--- |
| **10.0.0.25** | 73,892 | 65,287 | **139,179** |
| **10.0.0.48** | 64,888 | 60,732 | **125,620** |
| **10.0.0.14** | 56,128 | 64,460 | **120,588** |
| **10.0.0.57** | 59,576 | 59,895 | **119,471** |
| **10.0.0.21** | 60,358 | 53,476 | **113,834** |

---

### Task 10: Production SIEM Alert Rule & Saved Search
**Objective**: Build a production Splunk Alert rule to flag SSH Brute-Force attacks in real-time when an IP attempts 8 or more authentication attempts in a single session.

#### Alert SPL Query
```spl
index=main sourcetype="_json" auth_attempts>=8
| stats count as High_Risk_Burst_Events, max(auth_attempts) as Max_Attempts_In_Burst by "id.orig_h", "id.resp_h"
| where High_Risk_Burst_Events > 0
| sort - Max_Attempts_In_Burst
```

#### Alert Rule Settings in Splunk
- **Alert Title**: SOC-ALT-SSH-BruteForce-Burst
- **Trigger Condition**: Number of Results > 0
- **Severity**: High / Critical
- **Action**: Log SOC Incident Ticket / Send Email Notification / Trigger Webhook

---

## Conclusion & Key Takeaways
1. **Attacker Activity**: Host `10.0.0.25` is the primary threat actor, responsible for **99 authentication attempts** and **139,179 bytes** of traffic.
2. **Target Vulnerability**: Internal servers `10.0.1.6` and `10.0.1.2` received the highest concentration of connection attempts (115 events each).
3. **Reconnaissance**: Hosts `10.0.0.14` and `10.0.0.18` exhibited port scanning / banner grabbing behavior with 13 unauthenticated connections each.
