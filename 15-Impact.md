# Impact

## Enable Disable and Stop Services

### General

TODO

###  RDP

**Enable RDP**

*Requires admin privileges*

Enable the remote desktop protocol

`Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0`

Enable remote desktop through the Windows Firewall

`Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`


**Disable RDP**

Disable the remote desktop protocol

`Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1`

Disable remote desktop through the Windows Firewall

`Disable-NetFirewallRule -DisplayGroup "Remote Desktop"`