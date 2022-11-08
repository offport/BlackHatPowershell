# Reconnaissance

## Basic Machine Enumeration

- List users `Get-LocalUser`
- Basic networking information `ipconfig /all`
-  file permissions 
-  registry permissions
-  scheduled and running tasks
-  insecure files
- Print Domain `systeminfo | findstr /B "Domain"`
- Check Powershell version `$PSVersionTable. PSVersion`
- List processes `Get-Process`

## Find Files on Local Machine

### Find Files

Find GPP Passwords in SYSVOL

```
findstr /S cpassword $env:logonserver\sysvol\*.xml
findstr /S cpassword %logonserver%\sysvol\*.xml (cmd.exe)
```

TODO. Add more methods to find sensitive files.

## Simple Enumeration Script

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

*Note - Yes, Nmap is better. However, you may find yourself in a situation where you cannot install nmap or anything else.*

