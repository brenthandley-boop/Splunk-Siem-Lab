### Alert 6 — Password Spraying

**Severity:** Low | **Trigger:** One IP targets 5+ unique usernames with failures

```splunk
index=main EventCode=4625                                  /* failed logins */
| stats dc(user) as unique_users,                          /* count unique usernames */
        count as total_attempts by src_ip                  /* and total attempts per IP */
| where unique_users >= 5                                  /* 5+ accounts = spray pattern */
| sort - unique_users
| table src_ip, unique_users, total_attempts
```

**Why this differs from brute force:** Brute force = one account, many passwords. Spraying = many accounts, one password. Spray attacks evade account lockout policies that would trigger on a single account.

---
