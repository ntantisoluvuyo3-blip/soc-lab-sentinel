SOC Lab: Cowrie Honeypot Detection Pipeline (Microsoft Sentinel)

Extends my Cowrie SSH Honeypot Lab (https://github.com/ntantisoluvuyo3-blip/SOC-Lab-Honeypot)
into a detection engineering exercise: ingesting honeypot logs into Microsoft Sentinel and
building analytics rules that automatically surface the findings from the original manual
log analysis.

Architecture
Cowrie honeypot logs (cowrie.json) -> Python script (Azure Monitor Ingestion SDK) ->
Data Collection Endpoint + Data Collection Rule -> Custom Log Analytics table (CowrieLog_CL) ->
Microsoft Sentinel Analytics Rules -> Incidents

What was built
- A custom ingestion pipeline using the Azure Monitor Logs Ingestion API, authenticated via
  a Microsoft Entra ID app registration, to push the honeypot's JSON logs into a custom
  Log Analytics table.
- Three scheduled analytics rules, each mapped to a finding from the original honeypot
  analysis, each verified to produce a real Sentinel incident from the ingested data.

Analytics rules
- Brute Force Login Attempts (T1110.001) - flags source IPs with 5+ login attempts.
- Post-Login Reconnaissance Commands (T1078) - flags sessions where a successful login is
  followed within 2 minutes by recon commands (whoami, id, cat /etc/passwd, etc.).
- Anomalous Password Attempt Truncation - flags username/source pairs where login attempts
  stopped after exactly 4 distinct passwords, surfacing a Hydra behavior (per-user attempts
  capped by task count) found during manual log analysis in the original honeypot project.

Analysis
- Architecture and pipeline details
- Rule 1: Brute force detection
- Rule 2: Post-login reconnaissance
- Rule 3: Password attempt truncation
- Limitations

Notes
All data in this repo was generated in a personal lab. No external or real-world incident
data is included.
