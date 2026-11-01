Rule 3: Anomalous Password Attempt Truncation

Purpose
Automatically surface a pattern originally found through manual log analysis in the
honeypot project: Hydra's per-user password attempts stopped after exactly 4 passwords,
not the full 6-password wordlist, for every targeted user.

Query
CowrieLog_CL
| where eventid in ("cowrie.login.failed", "cowrie.login.success")
| summarize
    AttemptsPerUser = count(),
    PasswordsTried = make_set(password),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by src_ip, username
| extend PasswordCount = array_length(PasswordsTried)
| where PasswordCount == 4
| order by username asc

Result
Confirmed exactly 4 distinct passwords tried for admin, test, ubuntu, and root (root shows
5 total attempts due to a duplicate login event from a separate manual session, but still
only 4 distinct passwords). Matches the original manual finding exactly. Verified to
generate a Sentinel incident from the ingested data.

Note
This rule is analytical rather than threat-detecting: it validates a finding about the
attacking tool's behavior rather than flagging malicious activity on its own.
