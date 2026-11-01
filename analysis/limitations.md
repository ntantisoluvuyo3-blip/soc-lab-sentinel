Limitations

1. Static, historical data: logs were bulk-uploaded from a single cowrie.json snapshot
   rather than ingested live, so the pipeline demonstrates ingestion and detection logic
   but not real-time log streaming.
2. Small dataset: 132 log lines is too small to meaningfully tune alert thresholds; values
   used here (e.g., 5+ attempts for brute force) are reasonable for this lab but not
   validated against production-scale traffic.
3. Regional constraint: the workspace's home region (South Africa North) required the DCE
   to be created in North Europe at one point during setup due to a feature gap; a second
   DCE was later created successfully in South Africa North, and the final deployment uses
   matching regions throughout.
4. Single attacker source: all detections were tested against one attacking IP
   (192.168.56.20) from one lab session, so false-positive behavior against varied or
   legitimate traffic patterns is untested.
5. Rule 3 is lab-specific: it validates a finding tied to this lab's specific Hydra
   configuration (-t 4) and would not generalize to other brute-force tools or settings
   without adjustment.
