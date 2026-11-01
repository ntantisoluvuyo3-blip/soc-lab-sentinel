Rule 2: Post-Login Reconnaissance Commands (T1078)

Purpose
Detect sessions where a successful login is quickly followed by commands typical of an
attacker exploring a system after gaining access.

Query
let logins = CowrieLog_CL
    | where eventid == "cowrie.login.success"
    | project LoginTime = TimeGenerated, session, src_ip, username, password;
let commands = CowrieLog_CL
    | where eventid == "cowrie.command.input"
    | project CommandTime = TimeGenerated, session, input;
logins
| join kind=inner commands on session
| where CommandTime - LoginTime <= 2m
| where input has_any ("passwd", "whoami", "id", "uname", "cat /etc/shadow", "ls -la")
| project LoginTime, CommandTime, session, src_ip, username, password, input
| order by LoginTime asc

Result
Correctly matched all 5 commands from the manual root session (session c3466e00ce2b) to
their login event, each within the 2-minute window. Verified to generate a Sentinel
incident from the ingested data.

Caveat
The command list is not exhaustive; it reflects the specific commands observed in this
lab's manual session rather than a comprehensive reconnaissance command set.
