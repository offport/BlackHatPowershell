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

TODO

```
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


