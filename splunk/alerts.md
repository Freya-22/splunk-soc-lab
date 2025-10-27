# Splunk Alert Queries & Settings

## 1) Brute Force (Failed Logons)
SPL:
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, host
| sort -count

Alert settings:
- Title: Excessive Failed Logons (Brute Force Detection)
- Schedule: cron `*/5 * * * *`
- Time Range: Last 5 minutes (or Last 60 minutes acceptable for lab)
- Trigger: Number of Results > 0
- Throttle: Suppress 30 minutes
- Action: Add to Triggered Alerts

---

## 2) PowerShell Misuse
SPL:
index=sysmon OR index=main
( Image="\powershell.exe" OR Image="\pwsh.exe" OR Image="*\powershell_ise.exe" )
| eval cmd = coalesce(CommandLine, Command_Line, Command, command, CommandLine0)
| eval lc = lower(cmd)
| where lc LIKE "%encodedcommand%" OR lc LIKE "%invoke-expression%" OR lc LIKE "%iex%"
OR lc LIKE "%downloadstring%" OR lc LIKE "%invoke-webrequest%" OR lc LIKE "%invoke-restmethod%"
| table _time host User cmd
| sort -_time
| head 20

Alert settings:
- Title: Suspicious PowerShell Activity
- Schedule: cron `*/5 * * * *`
- Time Range: Last 5 minutes
- Trigger: Number of Results > 0
- Throttle: 30 minutes
- Action: Add to Triggered Alerts

---

## 3) Persistence — New Service Created
SPL:
index=sysmon Image="*notepad.exe"
| eval ServiceDetected=if(like(CommandLine, "%DemoPersistence%"), "DemoPersistence", "Other")
| stats count by ServiceDetected, host, User
| sort -count

Alert settings:
- Title: Persistence: Service Created
- Schedule: cron `*/5 * * * *`
- Time Range: Last 60 minutes
- Trigger: Number of Results > 0
- Throttle: 30 minutes
- Action: Add to Triggered Alerts