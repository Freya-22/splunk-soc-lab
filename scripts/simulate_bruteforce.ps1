# simulate_bruteforce.ps1
for ($i=1; $i -le 20; $i++) {
  net use \\localhost\C$ /user:labuser WrongPass$i 2>$null
  Start-Sleep -Milliseconds 200
}