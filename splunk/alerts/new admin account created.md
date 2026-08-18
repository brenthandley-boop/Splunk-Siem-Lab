### Alert 4 — New Admin Account Created

**Severity:** High | **Trigger:** EventCode 4720 (account created) or 4728 (added to privileged group)

```splunk
index=main (EventCode=4720 OR EventCode=4728)    /* account creation/modification events */
| eval event_type=case(                          /* human-readable label */
    EventCode=4720, "Account Created",
    EventCode=4728, "Added to Privileged Group"
  )
| table _time, event_type, user, src_user, host  /* analyst-ready output */
```

---
