# simulate_service.ps1
New-Service -Name "DemoPersistence" -BinaryPathName "C:\Windows\System32\notepad.exe" -DisplayName "DemoPersistence" -StartupType Manual
# To remove:
# Stop-Service -Name "DemoPersistence"
# Remove-Service -Name "DemoPersistence"