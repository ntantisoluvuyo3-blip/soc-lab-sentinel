Architecture and Pipeline

Source data
Cowrie SSH honeypot (192.168.56.10:2222) JSON log, same dataset used in the original
honeypot analysis (https://github.com/ntantisoluvuyo3-blip/SOC-Lab-Honeypot).

Ingestion
A Python script (using the azure-monitor-ingestion and azure-identity SDKs) reads
cowrie.json, maps each line's fields to the target table's schema, and pushes the records
via the Azure Monitor Logs Ingestion API.

Authentication
A Microsoft Entra ID app registration, granted the Monitoring Metrics Publisher role on the
Data Collection Rule, authenticates the script via client credentials (tenant ID, client ID,
client secret).

Routing
A Data Collection Endpoint (DCE) and Data Collection Rule (DCR), both in a region supporting
DCE/DCR (North Europe region for DCE in this deployment, due to a feature gap in the
workspace's home region at time of build), route the ingested data into a custom Log
Analytics table, CowrieLog_CL, in the South Africa North workspace.

Table schema
TimeGenerated (mapped from the log's timestamp field via a KQL transformation at ingestion),
session, protocol, src_ip, src_port, dst_ip, dst_port, eventid, username, password, input,
message.

Detection
Three scheduled KQL analytics rules in Microsoft Sentinel query the table on an hourly
schedule and generate incidents when their conditions are met.
