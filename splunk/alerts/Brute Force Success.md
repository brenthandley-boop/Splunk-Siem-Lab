### Alert 3 — Brute Force Success (Critical)

**Severity:** High | **Trigger:** IP with 3+ failures has at least one success

```splunk
index=main EventCode=4625                         /* start with failures */
| stats count as fail_count by src_ip            /* count failures per IP */
| where fail_count >= 3                          /* threshold: 3+ failures */
| join type=inner src_ip                         /* correlate with successes */
    [search index=main EventCode=4624            /* successful logon events */
     | stats count by src_ip]                    /* same IP must have a success */
| table src_ip, fail_count                       /* output: attacker IP + failure count */
```

**Why this alert is the most valuable:** Any IP that failed 3+ times and then succeeded is the exact behavioral fingerprint of a brute force that worked. This is what a SOC L1 escalates immediately — not the individual failures, but the success that follows them.

---
