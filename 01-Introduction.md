# Introduction

### Disclaimer

As you read this book, I want to take a moment to emphasize that it contains programming scripts and tools authored by other creators. I have made every effort to credit all sources appropriately, but it is possible that some may have been missed inadvertently. I want to assure you that I have done my best to be diligent in my research and credit all authors and developers whose work is included in this book.

If you come across any omissions or inaccuracies, please don't hesitate to contact me via the contact information provided in the book. I want to ensure that this book remains accurate and up-to-date, and I appreciate any feedback you can provide.

It is important to note that the offensive security techniques, commands, and scripts provided in this guide are intended for educational and research purposes only. The author does not condone the use of these techniques for any illegal or unethical activities. The information provided in this guide is meant to help security professionals improve their offensive capabilities and ethical hacking skills. It is the reader's responsibility to ensure that any techniques or scripts provided in the book are used in a legal and ethical manner. The author of this guide cannot be held responsible for any damages resulting from the use or misuse of the information contained within. It is strongly recommended that readers use these techniques in a safe and controlled environment, with the express permission of the system owner.

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

### Mitre Att&ck Framework

The MITRE ATT&CK framework is a knowledge base of known tactics and techniques used by adversaries to conduct cyber attacks. 

The MITRE ATT&CK framework is a comprehensive, constantly updated list of tactics and techniques that attackers use during the different phases of a cyber attack. The tactics are grouped into categories such as Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, and Command and Control. Each tactic is then further broken down into specific techniques that can be used to achieve the overall goal of the tactic.

### This Field Manual

This field manual is a constant work-in-progress and a must must-have guide for ethical hackers, penetration testers, red teamers and security enthusiasts who appreciate the power of powershell but cannot memorize commands or spend a long time looking for scripts online. The book is specifically designed to provide a well-structured comprehensive set of offensive security commands, techniques, and scripts, organized by the MITRE ATT&CK framework.


## Running Powershell
### Where to Find Powershell

**Powershell Locations**
		
		C:\windows\syswow64\windowspowershell\v1.0\powershell
		C:\Windows\System32\WindowsPowerShell\v1.0\powershell
	
### Running Powershell as a Different User

This section shows you how to run PowerShell as a different user with limited profile loading. This can be useful in situations where you need to run PowerShell with elevated privileges or to perform tasks that require different permissions than your current user account.

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




