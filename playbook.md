# SOC Playbook — Splunk Lab (Brute Force, PowerShell Misuse, Persistence)

## Overview
This playbook supports initial triage and containment steps for three detections implemented in the Splunk SOC lab:
1. Excessive Failed Logons (Brute Force)  
2. Suspicious PowerShell Activity  
3. New Windows Service Created (Persistence)

Each section contains: trigger, quick triage checklist, enrichment queries, immediate containment, and recommended follow-ups.

---

## A. Excessive Failed Logons (Brute Force)
**Trigger:** Splunk alert `Excessive Failed Logons (Brute Force Detection)` — multiple EventCode 4625 within 5 minutes.

**Triage (Tier-1):**
1. Note alert time, host, account(s) involved and count.  
2. Run Splunk:  
   - `index=main sourcetype="WinEventLog:Security" EventCode=4625 Account_Name=<acct> | sort -_time | head 50`  
   - `index=main EventCode=4624 Account_Name=<acct> | sort -_time | head 20` (look for successful logins around same time)  
3. Check `Source IP` values (if present) and geolocation.  
4. Identify if the account is privileged (domain/local admin) or service account.

**Enrichment (Tier-2):**
- Query firewall/VPN logs for same source IP.  
- Check recent failed/successful logins across other hosts:  
  `index=main (EventCode=4625 OR EventCode=4624) Account_Name=<acct> | stats count by host, EventCode`

**Containment:**
- If confirmed malicious: disable/lock the account (or force password reset) and block offending IP at the perimeter.  
- If uncertain: raise to Tier-2 for deeper analysis (is there lateral movement evidence?).

**Follow-up:**
- Review MFA logs / require password reset.  
- Add IOC (source IP, suspicious user) to watchlist and tune alert thresholds if a benign cause is found.

---

## B. Suspicious PowerShell Activity
**Trigger:** Splunk alert `Suspicious PowerShell Activity` — PowerShell process with `EncodedCommand`, `Invoke-Expression`, `IEX`, `Invoke-WebRequest`, etc.

**Triage (Tier-1):**
1. Capture alert time, host, user, and the `CommandLine` field from Splunk.  
2. Run Splunk queries:
   - `index=sysmon OR index=main Image="*\\powershell.exe" | table _time host User CommandLine`  
   - `index=sysmon EventCode=1 ParentImage=*\\powershell* ProcessId=* | stats values(CommandLine) by host, User`  
3. Look for process parent (`ParentImage`) — determine if launched from Office, WMI, scheduled task, or lsass.

**Enrichment (Tier-2):**
- Pull process tree and network connections for the host (EDR / netstat).  
- Hunt for file writes/downloads near timestamps (e.g., `index=sysmon FileWrite`).

**Containment:**
- Isolate host (if active malicious activity or exfil evidence).  
- Kill processes only under guidance from Tier-2/IR to preserve evidence.

**Remediation & Recovery:**
- Remove malicious scripts, clean persistence (scheduled tasks, services, registry).  
- Reimage host if rootkit/malicious persistence found.

**Mitigation:**
- Restrict PowerShell usage via AppLocker/Constrained Language or logging hardening.  
- Enforce execution policies and script signing where feasible.

---

## C. Persistence — New Windows Service Created
**Trigger:** Splunk alert `Persistence: Service Created` — new service creation detected (service name or command line contains suspicious token, e.g., DemoPersistence).

**Triage (Tier-1):**
1. Identify service name, host, creating user, and timestamp.  
2. Query Splunk:
   - `index=sysmon (EventCode=7045 OR EventCode=1) | table _time host User ServiceName CommandLine`  
3. Check if the service executable path is legitimate (signed, located under Windows\System32 vs user profile).

**Enrichment (Tier-2):**
- Search for parent process that created the service.  
- Check for other persistence modifications (Scheduled Tasks, Registry Run keys).

**Containment:**
- If malicious, disable service (do not delete immediately) and isolate host.  
- Collect memory image if active process suspicious.

**Remediation:**
- Remove service, delete persistence artifacts, and restore from clean image if required.  
- Rotate any credentials potentially compromised.

---

## Forensic & Documentation Checklist (for every incident)
- Record alert name, detection SPL, timestamps, host, user, and raw event IDs.  
- Preserve logs: export relevant Splunk search results to JSON/CSV.  
- Note actions taken (containment, remediation) and who performed them.  
- Post-incident: update detection thresholds, add blocking rules, improve telemetry.

---

## Useful Splunk Queries (copy-paste)
- Recent failed logons (quick):  
  `index=main EventCode=4625 | stats count by Account_Name, host, _time | sort -count`
 
-   PowerShell suspicious commands (quick):
    
    `index=sysmon Image="*\\powershell.exe" | eval cmd=coalesce(CommandLine, Command_Line) | where like(lower(cmd), "%invoke-expression%") OR like(lower(cmd), "%encodedcommand%") | table _time host User cmd` 
    
-   Service creation events:
    
    `index=sysmon (EventCode=7045 OR EventCode=1) | table _time host User ServiceName CommandLine`

## Notes on evidence preservation

-   Do not reboot hosts that may hold evidence.
    
-   If isolating, preserve network captures if possible.
    
-   Keep chronological incident notes; they are invaluable for post-incident review.
