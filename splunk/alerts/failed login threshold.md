### Alert 1 — Failed Login Threshold (Baseline Brute Force)

**Severity:** High | **Trigger:** 5+ EventCode 4625 from one IP within 5 seconds

```splunk
index=main EventCode=4625              /* failed logon events only */
| bucket _time span=5s                 /* group into 5-second time windows */
| stats count as fail_count            /* count failures per window */
    by src_ip, _time                   /* grouped by source IP and window */
| where fail_count >= 5                /* threshold: 5+ = automated attack pattern */
```

**False positive scenario:** A user's keyboard autorepeat fires multiple password attempts. Mitigation: add `NOT src_ip IN ("known-admin-workstations")` and raise threshold to 10 during business hours.

---
