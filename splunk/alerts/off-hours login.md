### Alert 5 — Off-Hours Login Activity

**Severity:** Medium | **Trigger:** Successful login before 08:00 or after 20:00

```splunk
index=main EventCode=4624                            /* successful logins */
| eval hour=tonumber(strftime(_time, "%H"))          /* extract hour of day (UTC) */
| where hour < 8 OR hour > 20                        /* outside business hours */
| table _time, user, src_ip, host, hour              /* analyst output */
```

---
