# Introduction

## Running Powershell
### Where to Find Powershell

**Powershell Locations**
		
		C:\windows\syswow64\windowspowershell\v1.0\powershell
		C:\Windows\System32\WindowsPowerShell\v1.0\powershell
	
### Running Powershell as a Different User

**Run Powershell prompt as a different user** without loading profile to the machine [replace DOMAIN and USER]

`runas /user:domain\user /noprofile powershell.exe`

Or using the following script

```
$username = 'domain\user'
$password = 'password'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process powershell.exe -Credential $credential
```
You can also execute any executable like reverseshell as the new user by replacing `powershell.exe` with another executable.

### Running Powershell on Another System Remotely

Commect to a remote machine with the current user credentials

-  `Enter-PSSession -ComputerName machine01.domain.local`
-  `Enter-PSSession -ComputerName machine01`

Starts an interactive Powershell session with a remote computer.

```
$username = 'domain\user'
$password = 'password'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Enter-PSSession -ComputerName Server01 -Credential $credential
```

Or invoke a command on a remote computer. *Useful for testing*

```
$username = 'domain\user'
$password = 'password'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName Server01 -Credential $credential
```


### Loading Scripts and Modules

**Load a Script (Dot Sourcing)**

`. C:\AD\Tools\PowerView.ps1`

**Load a Module**

`ImportModule C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1`

**List all commands in a module**

`Get-Command -Module <modulename>`


### 9 Ways to Open Powershell
https://www.howtogeek.com/662611/9-ways-to-open-powershell-in-windows-10


