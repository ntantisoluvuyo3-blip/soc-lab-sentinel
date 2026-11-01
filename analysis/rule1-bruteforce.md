Rule 1: Brute Force Login Attempts (T1110.001)

Purpose
Detect source IPs making multiple SSH login attempts in a short window, consistent with
credential brute-forcing.

Query
CowrieLog_CL
| where eventid in ("cowrie.login.failed", "cowrie.login.success")
| summarize
    FailedCount = countif(eventid == "cowrie.login.failed"),
    SuccessCount = countif(eventid == "cowrie.login.success"),
    TotalAttempts = count(),
    Usernames = make_set(username),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by src_ip
| where TotalAttempts >= 5
| order by TotalAttempts desc

Result
Correctly identified 192.168.56.20 (the Hydra attacker VM) as exceeding the threshold, with
no false positive on 127.0.0.1 (manual test logins). Verified to generate a Sentinel
incident from the ingested data.

Threshold note
5 total attempts was chosen as a reasonable baseline for a lab of this size; a production
deployment would tune this against real traffic volume and a defined time window rather
than an unbounded lookback.
