# Introduction

## Powershell

### What is Powershell

PowerShell is a command-line shell and scripting language developed by Microsoft for Windows and cross-platform usage. It was first released in 2006 as a replacement for the traditional Windows command prompt, with the goal of providing more powerful and flexible command-line tools for system administrators and developers.

PowerShell is built on top of the .NET Framework, and as such, it is highly extensible and customizable. It provides a powerful object-oriented scripting language that can be used to automate a wide range of system administration tasks, such as managing user accounts, configuring network settings, and controlling system services.

PowerShell also includes a rich set of built-in cmdlets (pronounced "command-lets"), which are small, single-purpose commands that can be combined together to perform more complex operations. These cmdlets can be used to interact with a variety of Windows and other Microsoft technologies, such as Active Directory, SQL Server, and Azure.

Truly, PowerShell is a versatile and powerful tool that can be used to automate and streamline a wide variety of system administration and development tasks. It provides a rich set of features and is highly extensible, making it a popular choice for Windows administrators and developers.

### Powershell in Offensive Security

It is important to note that while PowerShell is a powerful tool for automating system administration tasks, it can also be used for malicious purposes if it falls into the wrong hands. As such, PowerShell is often used by attackers as a tool for offensive security.

One of the reasons PowerShell is popular for offensive security is its ability to bypass security measures that may be in place. For example, PowerShell can be used to execute commands and scripts without writing any files to disk, which can help avoid detection by anti-virus software.

PowerShell can also be used to perform a wide range of tasks, such as enumerating network resources, manipulating system configurations, and executing code remotely, making it a versatile tool for attackers.

In addition, PowerShell is often used as a delivery mechanism for malware, as attackers can use it to download and execute payloads, such as Trojans and backdoors, on a compromised system.

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




