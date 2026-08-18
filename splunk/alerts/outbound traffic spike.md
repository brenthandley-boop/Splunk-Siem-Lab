### Alert 7 — Outbound Traffic Spike (Exfiltration Signal)

**Severity:** Medium | **Trigger:** Single host transmits >50MB outbound in one session

```splunk
index=main
| stats sum(bytes_out) as total_bytes_out by src_ip, host  /* sum outbound bytes per host */
| where total_bytes_out > 50000000                         /* 50MB threshold */
| eval MB_sent=round(total_bytes_out/1048576, 2)           /* convert to readable MB */
| table src_ip, host, MB_sent
| sort - MB_sent
```

---
