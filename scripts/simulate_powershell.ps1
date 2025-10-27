# simulate_powershell.ps1
Invoke-Expression 'Write-Output "pwstest: invoke-expression"'
Start-Sleep -Seconds 5

$plain = "Write-Output 'pwstest: encoded'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($plain)
$b64 = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $b64
Start-Sleep -Seconds 5

Invoke-WebRequest -Uri 'http://127.0.0.1/nonexistent' -UseBasicParsing -ErrorAction SilentlyContinue