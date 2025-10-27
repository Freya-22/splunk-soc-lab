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

## Tech Stack
- **SIEM:** Splunk Enterprise (local)  
- **Telemetry:** Sysmon (Microsoft Sysinternals), Windows Security Event Logs  
- **OS:** Windows 10/11 (lab host)  
- **Scripting / Simulation:** PowerShell (simulation scripts included)  
- **Detection Language:** Splunk SPL (Search Processing Language)  
- **Other:** Simple local automation via PowerShell scripts (no cloud required)

## Learning Outcomes
By completing this project I gained hands-on experience with:
- Building and configuring a local Splunk SIEM lab and ingesting Sysmon + Windows events.
- Writing and tuning SPL detection logic for real attacker behaviors (brute-force, PowerShell abuse, persistence).
- Designing scheduled alerts with sensible thresholds and throttling to reduce alert fatigue.
- Validating detections with safe, repeatable simulations and documenting incident triage steps.
- Creating a compact SOC dashboard to visualize alerts and support a Tier-1 analyst workflow.

## How to reproduce (concise)
1. Install Splunk Enterprise on Windows (local).  
2. Install Sysmon (Sysmon64.exe -i -accepteula) and optionally use the SwiftOnSecurity sysmon-config.  
3. Add Sysmon & Windows Security logs to Splunk (monitor EVTX or local event logs).  
4. Run the simulation scripts in `/scripts` as Administrator to generate test telemetry.  
5. Paste the SPL queries from `splunk/alerts.md` into Splunk Search & Reporting and save them as scheduled alerts (cron `*/5 * * * *`).  
6. Open `SOC Monitoring Dashboard` to view detections and check **Search & Reporting → Activity → Triggered Alerts** for fired alerts.

## What to include when sharing / demoing
- Screenshots: `dashboard_full.png`, `panel_bruteforce.png`, `panel_powershell.png`, `panel_persistence.png`, `alerts_triggered.png`  
- Explain the simulation steps (see `/scripts`), and mention that the lab runs fully locally (no cloud required).

## Notes & privacy
- All screenshots in `/screenshots` are lab artifacts (no real personal data).  
- Redact or blur any real hostnames/IPs before publishing if present.

## Author statement
This lab was built for hands-on practice in detection engineering and incident response. For a walkthrough or questions, contact me at freyajindal22@gmail.com.

