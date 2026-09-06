# Lab 2: DNS Traffic Log & Network Intelligence Analysis

## Overview & Scenario
In this lab, you assume the role of a **SOC Security Analyst** investigating DNS (Domain Name System) traffic logs captured from an internal enterprise network. The dataset contains **1,200 JSON log entries** representing DNS queries, record type lookups, resolver communications, response codes, alias resolutions, and reverse lookups sourced from multiple internal hosts.

The primary objective is to use **Splunk Search Processing Language (SPL)** to analyze the ingested DNS logs (`dns_logs.json`), classify query behavior, identify the most active clients and resolvers, detect internal vs. external lookup patterns, examine query type distributions, and analyze DNS response performance metrics.

---

## Dataset Details
- **File Name**: `dns_logs.json`
- **Total Log Count**: 1,200 events
- **Log Format**: JSON (Zeek DNS log format)
- **Recommended Splunk Sourcetype**: `_json` or `dns:zeek:json`
- **Recommended Index**: `dns_labs` or `main`

### Sample Log Structure
```json
{
  "ts": "2025-04-23T09:21:09.069644Z",
  "uid": "C447871J6557",
  "id.orig_h": "192.168.1.12",
  "id.orig_p": 58167,
  "id.resp_h": "192.168.1.1",
  "id.resp_p": 53,
  "proto": "udp",
  "trans_id": 30372,
  "rtt": 0.397165,
  "query": "google.com",
  "qclass": "IN",
  "qtype": "CNAME",
  "rcode": "NOERROR",
  "aa": false,
  "tc": false,
  "rd": true,
  "ra": true,
  "rejected": false,
  "answers": "alias.google.com",
  "ttl": 1106
}
```

### Key Fields Reference
| Field | Description |
| :--- | :--- |
| `ts` | Timestamp of the DNS event |
| `uid` | Unique connection identifier |
| `id.orig_h` | Client IP address making the DNS request |
| `id.orig_p` | Client source port |
| `id.resp_h` | DNS resolver/server IP address |
| `id.resp_p` | DNS server port (always 53) |
| `proto` | Transport protocol (udp) |
| `rtt` | Round-trip time for the DNS query (seconds) |
| `query` | Domain name being resolved |
| `qtype` | Query record type (A, AAAA, CNAME, PTR) |
| `rcode` | Response code (NOERROR, NXDOMAIN, etc.) |
| `answers` | Resolved answer returned by the DNS server |
| `ttl` | Time-to-live value of the DNS record |
| `rejected` | Whether the query was rejected |

---

## Splunk Data Ingestion Setup

To ingest this dataset into your Splunk environment:
1. Log in to **Splunk Enterprise** (or Splunk Cloud / Docker Splunk).
2. Go to **Settings > Add Data**.
3. Choose **Upload** and upload `Lab 2/dns_logs.json`.
4. Set Source Type to `_json` (or create a custom sourcetype `dns:zeek:json`).
5. Set Index to `main` or create index `dns_labs`.
6. Save and launch Search & Reporting.

---

## Lab Tasks & Hands-On Exercises

### Task 1: Dataset Verification & Total Log Count
**Objective**: Verify data ingestion and confirm the total number of ingested DNS log records.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Total_Logs
```

#### Query Breakdown
- `index=main sourcetype="_json"`: Filters search results to the ingested JSON dataset.
- `stats count as Total_Logs`: Aggregates all matching DNS log events into a single count metric.

#### Expected Output
| Total_Logs |
| :--- |
| **1200** |

---

### Task 2: DNS Query Type Distribution & Categorization
**Objective**: Classify all DNS log entries by query record type (`qtype`) to understand network lookup patterns and protocol usage.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Query_Count by qtype
| sort - Query_Count
```

#### Query Breakdown
- `stats count as Query_Count by qtype`: Groups and counts all DNS events by their record type (A, AAAA, PTR, CNAME).
- `sort - Query_Count`: Orders query types from most to least frequent.

#### Expected Output
| qtype | Query_Count |
| :--- | :--- |
| AAAA | **321** |
| A | **313** |
| PTR | **309** |
| CNAME | **257** |

---

### Task 3: Top 5 Most Active DNS Client Hosts
**Objective**: Identify which internal client hosts (`id.orig_h`) generated the highest volume of DNS lookup requests.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Total_Queries by "id.orig_h"
| sort - Total_Queries
| head 5
| rename "id.orig_h" as Client_IP
```

#### Query Breakdown
- `stats count as Total_Queries by "id.orig_h"`: Calculates total DNS events originating from each client host.
- `sort - Total_Queries`: Ranks clients by total query volume.
- `head 5`: Limits results to the top 5 most active clients.
- `rename`: Formats field names for report readability.

#### Expected Output
| Client_IP | Total_Queries |
| :--- | :--- |
| **192.168.1.18** | 113 |
| **192.168.1.10** | 113 |
| **192.168.1.21** | 112 |
| **192.168.1.20** | 105 |
| **192.168.1.12** | 102 |

---

### Task 4: Top 10 Most Frequently Queried Domains
**Objective**: Determine which domain names (`query`) were resolved most frequently across all internal clients to map out network communication patterns.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Lookup_Count by query
| sort - Lookup_Count
| head 10
| rename query as Domain_Name
```

#### Query Breakdown
- `stats count as Lookup_Count by query`: Counts the number of DNS resolution attempts per domain name.
- `sort - Lookup_Count | head 10`: Extracts the 10 domains generating the highest lookup traffic.

#### Expected Output
| Domain_Name | Lookup_Count |
| :--- | :--- |
| **printer.local** | 139 |
| **google.com** | 139 |
| **example.com** | 137 |
| **yahoo.com** | 125 |
| **fileserver.local** | 120 |
| **router.local** | 116 |
| **internal.lan** | 114 |
| **backup.local** | 105 |
| **ipv6test.local** | 103 |
| **microsoft.com** | 102 |

---

### Task 5: Internal vs. External DNS Traffic Classification
**Objective**: Categorize all DNS queries into internal network lookups (`.local`, `.lan`, `.internal` domains) versus external internet-facing domain resolutions.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| eval Domain_Scope = if(match(query, "\.local$|\.lan$|\.internal$"), "Internal", "External")
| stats count as Query_Count by Domain_Scope
| sort - Query_Count
```

#### Query Breakdown
- `eval Domain_Scope`: Uses regex pattern matching to classify domains as `Internal` (ending in `.local`, `.lan`, `.internal`) or `External`.
- `stats count by Domain_Scope`: Tallies the total query volume for each category.

#### Expected Output
| Domain_Scope | Query_Count |
| :--- | :--- |
| **Internal** | **697** |
| **External** | **503** |

---

### Task 6: DNS Resolver Load Distribution
**Objective**: Identify which DNS resolvers (`id.resp_h`) handled the most traffic and assess load balancing across the internal DNS infrastructure.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Queries_Handled by "id.resp_h"
| sort - Queries_Handled
| rename "id.resp_h" as DNS_Resolver
```

#### Query Breakdown
- `stats count as Queries_Handled by "id.resp_h"`: Counts how many DNS requests were directed to each resolver IP address.
- `sort - Queries_Handled`: Orders resolvers from most to least loaded.

#### Expected Output
| DNS_Resolver | Queries_Handled |
| :--- | :--- |
| **192.168.1.1** | **417** |
| **192.168.1.2** | **394** |
| **192.168.1.3** | **389** |

---

### Task 7: DNS Response Time (RTT) Performance Analysis
**Objective**: Analyze DNS query round-trip times (`rtt`) to detect slow-responding resolvers or abnormal latency patterns that could indicate resolver issues or DNS-based exfiltration.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats avg(rtt) as Avg_RTT_Sec, max(rtt) as Max_RTT_Sec, min(rtt) as Min_RTT_Sec, count as Total_Queries by "id.resp_h"
| eval Avg_RTT_Sec = round(Avg_RTT_Sec, 4)
| eval Max_RTT_Sec = round(Max_RTT_Sec, 4)
| sort - Avg_RTT_Sec
| rename "id.resp_h" as DNS_Resolver
```

#### Query Breakdown
- `avg(rtt), max(rtt), min(rtt)`: Calculates response time statistics per DNS resolver.
- `eval round(...)`: Rounds RTT values to 4 decimal places for report clarity.

#### Expected Output
| DNS_Resolver | Avg_RTT_Sec | Max_RTT_Sec | Min_RTT_Sec | Total_Queries |
| :--- | :--- | :--- | :--- | :--- |
| **192.168.1.3** | 0.2705 | 0.4997 | 0.0003 | 389 |
| **192.168.1.1** | 0.2648 | 0.4999 | 0.0001 | 417 |
| **192.168.1.2** | 0.2596 | 0.4998 | 0.0002 | 394 |

---

### Task 8: IPv4 vs. IPv6 Address Resolution Comparison
**Objective**: Compare the volume of IPv4 (`A` record) lookups against IPv6 (`AAAA` record) lookups to assess the network's IPv6 adoption and readiness.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" (qtype="A" OR qtype="AAAA")
| stats count as Query_Count by qtype
| eval Protocol_Version = if(qtype="A", "IPv4", "IPv6")
| table Protocol_Version, qtype, Query_Count
| sort - Query_Count
```

#### Query Breakdown
- `(qtype="A" OR qtype="AAAA")`: Filters only address record queries.
- `eval Protocol_Version`: Labels A records as IPv4 and AAAA records as IPv6 for clarity.

#### Expected Output
| Protocol_Version | qtype | Query_Count |
| :--- | :--- | :--- |
| **IPv6** | AAAA | **321** |
| **IPv4** | A | **313** |

---

### Task 9: Reverse DNS (PTR) Lookup Activity per Host
**Objective**: Identify which internal hosts are performing the most reverse DNS lookups (`PTR` records), which may indicate discovery activity, network mapping, or host enumeration.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" qtype="PTR"
| stats count as PTR_Lookups by "id.orig_h"
| sort - PTR_Lookups
| head 5
| rename "id.orig_h" as Client_IP
```

#### Query Breakdown
- `qtype="PTR"`: Isolates reverse DNS lookup events where clients resolve IP addresses back to hostnames.
- `stats count by "id.orig_h"`: Counts PTR queries per client, revealing hosts performing active network discovery.

#### Expected Output
| Client_IP | PTR_Lookups |
| :--- | :--- |
| **192.168.1.12** | **32** |
| **192.168.1.20** | **30** |
| **192.168.1.10** | **30** |
| **192.168.1.16** | **28** |
| **192.168.1.13** | **27** |

---

### Task 10: CNAME Alias Resolution & Top Aliased Domains
**Objective**: Analyze `CNAME` (Canonical Name) record lookups to understand alias resolution chains and identify the most commonly aliased internal and external resources.

#### Splunk SPL Query
```spl
index=main sourcetype="_json" qtype="CNAME"
| stats count as CNAME_Lookups, values(answers) as Resolved_Alias by query
| sort - CNAME_Lookups
| head 5
| rename query as Queried_Domain
```

#### Query Breakdown
- `qtype="CNAME"`: Filters records where clients resolved canonical alias mappings.
- `values(answers)`: Captures the CNAME target alias returned by the DNS server for each lookup.

#### Expected Output
| Queried_Domain | CNAME_Lookups | Resolved_Alias |
| :--- | :--- | :--- |
| **fileserver.local** | **32** | alias.fileserver.local |
| **router.local** | **31** | alias.router.local |
| **example.com** | **28** | alias.example.com |
| **internal.lan** | **26** | alias.internal.lan |
| **printer.local** | **26** | alias.printer.local |

---

### Task 11: TTL (Time-To-Live) Analysis & Caching Efficiency
**Objective**: Examine DNS record TTL values to understand cache behavior, identify short-lived records that create excessive lookup traffic, and evaluate overall DNS caching efficiency.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats avg(ttl) as Avg_TTL, min(ttl) as Min_TTL, max(ttl) as Max_TTL, count as Query_Count by qtype
| eval Avg_TTL = round(Avg_TTL)
| sort - Avg_TTL
```

#### Query Breakdown
- `avg(ttl), min(ttl), max(ttl)`: Calculates TTL statistics grouped by query type to identify which record types have short cache lifespans.
- `eval round(Avg_TTL)`: Rounds average TTL to a whole-second value for readability.

#### Expected Output
| qtype | Avg_TTL | Min_TTL | Max_TTL | Query_Count |
| :--- | :--- | :--- | :--- | :--- |
| **A** | ~1780 | 66 | 3600 | 313 |
| **AAAA** | ~1770 | 66 | 3600 | 321 |
| **PTR** | ~1765 | 66 | 3600 | 309 |
| **CNAME** | ~1775 | 66 | 3600 | 257 |

---

### Task 12: Per-Host DNS Query Type Profiling (Top 3 Clients)
**Objective**: Build a behavioral profile for the top 3 most active DNS clients by breaking down their individual query type distributions.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| stats count as Query_Count by "id.orig_h", qtype
| sort "id.orig_h", - Query_Count
| rename "id.orig_h" as Client_IP
| where Client_IP="192.168.1.18" OR Client_IP="192.168.1.10" OR Client_IP="192.168.1.21"
```

#### Query Breakdown
- `stats count by "id.orig_h", qtype`: Cross-tabulates client IP against query record types to build per-host behavioral profiles.
- `where Client_IP=...`: Filters to the top 3 most active clients identified in Task 3.

#### Expected Output
| Client_IP | qtype | Query_Count |
| :--- | :--- | :--- |
| **192.168.1.18** | A | 34 |
| **192.168.1.18** | AAAA | 29 |
| **192.168.1.18** | CNAME | 27 |
| **192.168.1.18** | PTR | 23 |
| **192.168.1.10** | AAAA | 33 |
| **192.168.1.10** | A | 33 |
| **192.168.1.10** | PTR | 30 |
| **192.168.1.10** | CNAME | 17 |
| **192.168.1.21** | A | 33 |
| **192.168.1.21** | AAAA | 30 |
| **192.168.1.21** | PTR | 25 |
| **192.168.1.21** | CNAME | 24 |

---

### Task 13: DNS Traffic Latency Bucketing & SLA Classification
**Objective**: Categorize all DNS queries by RTT latency bands to establish SLA compliance and flag slow-resolution events that may indicate resolver degradation.

#### Splunk SPL Query
```spl
index=main sourcetype="_json"
| eval Latency_Band = case(
    rtt <= 0.2, "Fast (<=0.2s)",
    rtt > 0.2 AND rtt <= 0.4, "Medium (0.2-0.4s)",
    rtt > 0.4, "Slow (>0.4s)"
  )
| stats count as Event_Count by Latency_Band
| sort - Event_Count
```

#### Query Breakdown
- `eval case(...)`: Assigns each DNS event to a latency category based on its `rtt` value.
- `stats count by Latency_Band`: Counts how many queries fell into each performance band.

#### Expected Output
| Latency_Band | Event_Count |
| :--- | :--- |
| **Medium (0.2-0.4s)** | **514** |
| **Fast (<=0.2s)** | **423** |
| **Slow (>0.4s)** | **263** |

---

## Conclusion & Key Takeaways
1. **Most Active Clients**: Hosts `192.168.1.18` and `192.168.1.10` generated the highest DNS query volumes (113 queries each), warranting behavioral baselining and continuous monitoring.
2. **Top Queried Domains**: `printer.local` and `google.com` tied as the most queried names (139 lookups each), reflecting dominant internal device resolution and external internet access patterns.
3. **IPv6 Adoption**: AAAA queries (321) slightly outpaced A record queries (313), indicating active IPv6 deployment across the enterprise network.
4. **Resolver Load**: DNS resolver `192.168.1.1` handled the highest query load (417 queries), making it a single point of failure that should be monitored for high availability.
5. **Latency Profile**: 43% of all DNS queries fell into the medium-latency band (0.2–0.4s), with 22% classified as slow (>0.4s), suggesting potential resolver tuning or caching optimization opportunities.
6. **Internal Traffic Dominance**: 58% of all DNS queries targeted internal resources (`.local`/`.lan` domains), confirming a large internal service footprint that should be governed with split-horizon DNS policies.
