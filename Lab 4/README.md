# Lab 4: Splunk Dashboard for SSH Logs & Threat Intelligence

## Overview & Scenario
In this lab, you assume the role of a **SOC Dashboard Engineer** tasked with building a real-time operational dashboard for monitoring SSH authentication telemetry across the enterprise. The dataset contains over **1,200 JSON log entries** capturing SSH events, including a new `username` field for deeper attribution.

The primary objective is to use **Splunk Search Processing Language (SPL)** combined with Splunk's visualization capabilities to construct an interactive **SSH Security Monitoring Dashboard**. This dashboard will feature time-range inputs, single-value KPIs, trend lines, statistical tables, and geographic attack mapping (Choropleth map).

---

## Dataset Details
- **File Name**: `ssh_logs_new.json`
- **Total Log Count**: 1,201 events
- **Log Format**: JSON (Zeek SSH log format with added `username`)
- **Recommended Splunk Sourcetype**: `_json` or `ssh:json`
- **Recommended Index**: `ssh_dash_lab` or `main`

### Sample Log Structure
```json
{
  "ts": "2025-04-24T10:20:09.508780Z",
  "uid": "SH4886434",
  "id.orig_h": "31.184.137.182",
  "id.resp_h": "164.254.24.82",
  "proto": "tcp",
  "auth_success": true,
  "auth_attempts": 1,
  "event_type": "Successful SSH Login",
  "username": "admin"
}
```

---

## Splunk Data Ingestion Setup

To ingest this dataset into your Splunk environment:
1. Log in to **Splunk Enterprise**.
2. Go to **Settings > Add Data > Upload**.
3. Upload `Lab 4/ssh_logs_new.json` (extract the ZIP if necessary).
4. Set Source Type to `_json`.
5. Set Index to `main` or create index `ssh_dash_lab`.
6. Save and launch Search & Reporting.

---

## Lab Tasks & Hands-On Exercises

### Task 1: Creating the Base Dashboard and Time Range Input
**Objective**: Create a new dashboard and configure a global time picker to dynamically control all visualization panels.
1. In the Search bar, run a simple search: `index=main sourcetype="_json"`.
2. Click **Save As > Dashboard Panel**.
3. Name the dashboard **SSH Security Operations Center**.
4. In the Dashboard Edit view, click **Add Input > Time**.
5. Edit the Time input, assign a token name (e.g., `global_time`), and ensure all panels use this token for their time range.

---

### Task 2: Single Value Panel - Total SSH Events
**Objective**: Create a high-level KPI displaying the total volume of monitored SSH connections.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count
```
- **Visualization Type**: Single Value
- **Dashboard Action**: Save to Dashboard

---

### Task 3: Single Value Panel - Successful Logins
**Objective**: Display the total number of successful authentication events.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" event_type="Successful SSH Login"
| stats count
```
- **Visualization Type**: Single Value (Set color to Green)
- **Dashboard Action**: Save to Dashboard

---

### Task 4: Single Value Panel - Failed Logins
**Objective**: Track the total number of denied authentication attempts to gauge baseline attack noise.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts"
| stats count
```
- **Visualization Type**: Single Value (Set color to Red)
- **Dashboard Action**: Save to Dashboard

---

### Task 5: Single Value Panel - Connection Without Authentication
**Objective**: Monitor stealthy reconnaissance (port scanning, banner grabbing) where attackers drop the connection before authenticating.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" event_type="Connection Without Authentication"
| stats count
```
- **Visualization Type**: Single Value (Set color to Orange)
- **Dashboard Action**: Save to Dashboard

---

### Task 6: Bar Chart - Top 10 Targeted Usernames
**Objective**: Discover which accounts attackers are attempting to compromise the most.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count by username
| sort - count
| head 10
```
- **Visualization Type**: Bar Chart or Column Chart
- **Dashboard Action**: Save to Dashboard

---

### Task 7: Pie Chart - SSH Event Type Distribution
**Objective**: Visualize the proportion of success vs. failure vs. recon across the network.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count by event_type
```
- **Visualization Type**: Pie Chart
- **Dashboard Action**: Save to Dashboard

---

### Task 8: Line Chart - Login Activity Trends Over Time
**Objective**: Plot a timeline of successful vs. failed logins to identify attack spikes or automated bursts.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| timechart count by event_type
```
- **Visualization Type**: Line Chart (Area Chart optional)
- **Dashboard Action**: Save to Dashboard

---

### Task 9: Statistics Table - Possible Brute Force by IP Address
**Objective**: Generate a sorted tabular view of the top offensive source IPs based on cumulative authentication attempts.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats sum(auth_attempts) as Total_Attempts, values(username) as Targeted_Users by "id.orig_h"
| where Total_Attempts > 5
| sort - Total_Attempts
| rename "id.orig_h" as Attacker_IP
```
- **Visualization Type**: Statistics Table
- **Dashboard Action**: Save to Dashboard

---

### Task 10: Choropleth Map - Brute Force Attack Geo-Location
**Objective**: Use `iplocation` to map the geographic origins of the attacking IPs on a global map.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" event_type!="Successful SSH Login"
| iplocation "id.orig_h"
| geostats count by Country
```
- **Visualization Type**: Cluster Map or Choropleth Map (requires Splunk Maps)
- **Dashboard Action**: Save to Dashboard

---

## Conclusion & Key Takeaways
1. **Executive Visibility**: The finished dashboard provides SOC analysts with immediate situational awareness of SSH perimeter health via Single Value KPI panels.
2. **Attribution**: Leveraging the `username` field revealed exactly which accounts (e.g., `root`, `admin`, `oracle`) were heavily brute-forced.
3. **Geo-Intelligence**: Integrating `iplocation` combined with `geostats` allows analysts to visually identify rogue infrastructure origins across the globe.
