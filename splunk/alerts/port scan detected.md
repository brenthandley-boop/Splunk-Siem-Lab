### Alert 2 — Port Scan Detected

**Severity:** High | **Trigger:** One IP contacts 20+ unique destination ports within 60 seconds

```splunk
index=main (EventCode=5156 OR EventCode=5157)   /* firewall allow/block events */
| stats dc(dest_port) as unique_ports            /* count distinct destination ports */
    by src_ip                                    /* per source IP */
| where unique_ports > 20                        /* 20+ unique ports = scan pattern */
| sort - unique_ports                            /* highest scanner first */
```

**Prerequisite:** Windows Filtering Platform auditing must be enabled on the target host (`auditpol` command).

---
