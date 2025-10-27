# Splunk SOC Lab — Detection Engineering Project

**Author:** Freya Jindal  
**Contact:** freyajindal22@gmail.com  
**Date:** October 2025

## Summary
Built a local Splunk SIEM lab ingesting Windows Event Logs and Sysmon. Implemented detection rules and alerts for:
- Brute force / repeated failed logons (EventCode 4625)
- Suspicious PowerShell usage (EncodedCommand, Invoke-Expression, Invoke-WebRequest)
- Persistence via Service Creation (DemoPersistence)

This project demonstrates Tier-1 SOC alert triage, detection engineering, and playbook simulation.

## Repo contents
- `splunk/alerts.md` — Exact SPLs and alert configuration details
- `scripts/` — Simulation scripts (if included)
- `sysmon/sysmon_install.txt` — Sysmon install command and config notes
- `screenshots/` — Dashboard & search screenshots (9 images)
- `splunk_alerts.md` — Alert metadata (cron, time range, throttle)

## How to reproduce (high level)
1. Install Splunk (local instance) and add Sysmon event channel.
2. Use `scripts/` to simulate events (run as Admin), or manually trigger simulated events.
3. Enter SPLs from `splunk/alerts.md` into Splunk Search & Reporting and save as Alerts (use cron `*/5 * * * *`).
4. Verify alerts in **Search & Reporting → Activity → Triggered Alerts** and view the dashboard.

## Notes & privacy
- All screenshots in `/screenshots` are lab artifacts (no real personal data).  
- Redact or blur any real hostnames/IPs before publishing if present.

## Author statement
This lab was built for hands-on practice in detection engineering and incident response. For a walkthrough or questions, contact me at freyajindal22@gmail.com.
