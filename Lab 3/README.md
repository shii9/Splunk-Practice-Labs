# Lab 3: HTTP Traffic & Web Application Threat Analysis

## Overview & Scenario
In this lab, you assume the role of a **SOC Security Analyst** investigating HTTP web traffic logs captured from an internal enterprise network. The dataset contains **over 3,000 JSON log entries** representing HTTP requests, response codes, requested URIs, user agents, methods, and payload sizes.

The primary objective is to use **Splunk Search Processing Language (SPL)** to analyze the ingested HTTP logs (`http_logs.json`), detect web-based attacks (e.g., SQL injection tools, forced browsing), identify data exfiltration patterns, and understand general web traffic behavior.

---

## Dataset Details
- **File Name**: `http_logs.json`
- **Total Log Count**: 3,001 events
- **Log Format**: JSON (Zeek HTTP log format)
- **Recommended Splunk Sourcetype**: `_json` or `zeek:http`
- **Recommended Index**: `http_lab` or `main`

### Sample Log Structure
```json
{
  "ts": "2025-04-25T10:46:18.860765Z",
  "uid": "HT1031308",
  "id.orig_h": "10.0.0.49",
  "id.resp_h": "10.0.1.6",
  "method": "GET",
  "uri": "/index.html",
  "status_code": 200,
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "resp_body_len": 1958305,
  "event_type": "Large Transfer"
}
```

### Key Fields Reference
| Field | Description |
| :--- | :--- |
| `ts` | Timestamp of the HTTP event |
| `uid` | Unique connection identifier |
| `id.orig_h` | Client IP address making the HTTP request |
| `id.resp_h` | Web server IP address responding to the request |
| `method` | HTTP request method (e.g., GET, POST, DELETE, OPTIONS) |
| `uri` | The requested URI path (e.g., `/index.html`, `/admin`) |
| `status_code` | HTTP response status code (e.g., 200, 404, 500) |
| `user_agent` | The web browser or tool making the request |
| `resp_body_len` | Size of the response body in bytes |
| `event_type` | Categorization of the HTTP event |

---

## Splunk Data Ingestion Setup

To ingest this dataset into your Splunk environment:
1. Log in to **Splunk Enterprise** (or Splunk Cloud / Docker Splunk).
2. Go to **Settings > Add Data**.
3. Choose **Upload** and upload `Lab 3/http_logs.json`.
4. Set Source Type to `_json` (or create a custom sourcetype `zeek:http`).
5. Set Index to `main` or create index `http_lab`.
6. Save and launch Search & Reporting.

---

## Lab Tasks & Hands-On Exercises

### Task 1: Dataset Verification & Total Log Count
**Objective**: Verify data ingestion and confirm the total number of ingested HTTP log records.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json"
| stats count as Total_Logs
```

#### Query Breakdown
- `index=http_lab sourcetype="_json"`: Filters search results to the ingested JSON dataset.
- `stats count as Total_Logs`: Aggregates all matching HTTP log events into a single count metric.

---

### Task 2: HTTP Event Type Categorization
**Objective**: Classify the logs by `event_type` to understand overall web activity and security-relevant events.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json"
| stats count by event_type
| sort - count
```

#### Query Breakdown
- `stats count by event_type`: Groups total records by the `event_type` field values.
- `sort - count`: Orders categories in descending numerical order.

---

### Task 3: Top 10 Endpoints Generating Web Traffic
**Objective**: Identify which client IPs (`id.orig_h`) generated the highest volume of web requests.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json"
| stats count as Total_Requests by "id.orig_h"
| sort - Total_Requests
| head 10
| rename "id.orig_h" as Client_IP
```

#### Query Breakdown
- `stats count as Total_Requests by "id.orig_h"`: Calculates total HTTP requests originating from each client.
- `sort - Total_Requests`: Ranks clients by total request volume.
- `head 10`: Limits results to the top 10 most active clients.

---

### Task 4: Web Traffic by HTTP Request Method
**Objective**: Determine the distribution of HTTP methods (GET, POST, OPTIONS, PUT, etc.) used across the network.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json"
| stats count as Method_Count by method
| sort - Method_Count
```

#### Query Breakdown
- `stats count by method`: Groups the HTTP logs based on the requested HTTP verb.
- `sort - Method_Count`: Sorts the methods in descending order of frequency.

---

### Task 5: Server Error (5xx) Monitoring
**Objective**: Count the number of server errors (HTTP 5xx status codes) observed to detect potential service outages or crashing web applications.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json" status_code>=500 status_code<600
| stats count as Server_Errors
```

#### Query Breakdown
- `status_code>=500 status_code<600`: Filters logs to include only HTTP 5xx Server Error responses.
- `stats count as Server_Errors`: Computes the total number of errors encountered.

---

### Task 6: Identify Possible Scripted Attacks & Bots
**Objective**: Identify suspicious User-Agents associated with possible scripted attacks, vulnerability scanners, or automated botnets.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count as Attack_Count by user_agent
| sort - Attack_Count
```

#### Query Breakdown
- `user_agent IN (...)`: Filters the search to explicitly match known malicious, testing, or automated user agents.
- `stats count by user_agent`: Aggregates the volume of requests generated by each automated agent.

---

### Task 7: Find Large File Transfers & Data Exfiltration
**Objective**: Identify large file transfers (greater than 500 KB / 500,000 bytes) to uncover potential data exfiltration or massive downloads.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json" resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort - resp_body_len
```

#### Query Breakdown
- `resp_body_len>500000`: Filters out standard web browsing to surface only abnormally large HTTP response bodies.
- `table ...`: Formats the output into a clean tabular view.
- `sort - resp_body_len`: Organizes the results to highlight the largest transfers at the top.

---

### Task 8: Detect Suspicious URI Access (Admin & LFI)
**Objective**: Detect suspicious URIs accessed (e.g., `/admin`, `/shell.php`, `/etc/passwd`) which indicate forced browsing, backdoor access, or Local File Inclusion (LFI) attacks.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json" uri IN ("/admin","/shell.php","/etc/passwd")
| stats count as Access_Attempts by uri, "id.orig_h"
| sort - Access_Attempts
```

#### Query Breakdown
- `uri IN (...)`: Looks specifically for highly sensitive administrative paths or common attack vectors.
- `stats count by uri, "id.orig_h"`: Displays which clients attempted to access which specific sensitive URI.

---

### Task 9: Client Error (4xx) Analysis & Directory Busting
**Objective**: Identify client IP addresses generating a high number of HTTP 4xx errors (e.g., 400 Bad Request, 404 Not Found), which often indicates directory brute-forcing or vulnerability scanning.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json" status_code>=400 status_code<500
| stats count as Client_Errors by "id.orig_h"
| sort - Client_Errors
| head 5
| rename "id.orig_h" as Scanning_Client
```

#### Query Breakdown
- `status_code>=400 status_code<500`: Filters for client-side errors resulting from bad requests or nonexistent resources.
- `stats count by "id.orig_h"`: Aggregates the errors per source IP to spot noisy scanners.

---

### Task 10: Most Targeted Internal Web Servers
**Objective**: Discover which internal servers (`id.resp_h`) are handling the most web traffic, helping map the critical web infrastructure.

#### Splunk SPL Query
```spl
index=http_lab sourcetype="_json"
| stats count as Total_Hits by "id.resp_h"
| sort - Total_Hits
| head 5
| rename "id.resp_h" as Web_Server
```

#### Query Breakdown
- `stats count as Total_Hits by "id.resp_h"`: Calculates total incoming HTTP requests per server IP.
- `sort - Total_Hits | head 5`: Extracts the 5 busiest web servers in the network.

---

## Conclusion & Key Takeaways
1. **Automated Scanning**: Presence of `sqlmap`, `curl`, and `python-requests` User-Agents indicates automated vulnerability scanning and potential scripted exploitation against the network.
2. **Data Exfiltration Risk**: Numerous connections involved `resp_body_len` values far exceeding typical baseline limits, potentially signifying data exfiltration or improper large asset hosting.
3. **Targeted Attacks**: Repeated attempts to access sensitive paths like `/shell.php` and `/etc/passwd` highlight aggressive attempts to compromise web servers via Local File Inclusion (LFI) and webshell execution.
4. **Server Stability**: Monitoring for 5xx errors identifies internal services struggling under load or crashing during application layer attacks.
