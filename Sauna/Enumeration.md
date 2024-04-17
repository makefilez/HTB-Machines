# About Sauna
 Sauna is an easy difficulty Windows machine that features Active Directory enumeration and exploitation. Possible usernames can be derived from employee full names listed on the website. With these usernames, an ASREPRoasting attack can be performed, which results in hash for an account that doesn&amp;amp;#039;t require Kerberos pre-authentication. This hash can be subjected to an offline brute force attack, in order to recover the plaintext password for a user that is able to WinRM to the box. Running WinPEAS reveals that another system user has been configured to automatically login and it identifies their password. This second user also has Windows remote management permissions. BloodHound reveals that this user has the *DS-Replication-Get-Changes-All* extended right, which allows them to dump password hashes from the Domain Controller in a DCSync attack. Executing this attack returns the hash of the primary domain administrator, which can be used with Impacket&amp;amp;#039;s psexec.py in order to gain a shell on the box as `NT_AUTHORITY\SYSTEM`. 

# Nmap
```shell
nmap -A 10.10.10.175 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-16 10:06 EDT
Nmap scan report for 10.10.10.175
Host is up (0.012s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-16 21:11:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h01m04s
| smb2-time: 
|   date: 2024-04-16T21:12:19
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 319.54 seconds

```

# Enum4linux
```shell
$ enum4linux-ng -P 10.10.10.175 -oA sauna          
ENUM4LINUX - next generation (v1.3.2)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.10.175
[*] Username ......... ''
[*] Random Username .. 'whtpyzmv'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.10.10.175    |
 =====================================
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =========================================
|    SMB Dialect Check on 10.10.10.175    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                                         
  SMB 1.0: false                                                                                                                                            
  SMB 2.02: true                                                                                                                                            
  SMB 2.1: true                                                                                                                                             
  SMB 3.0: true                                                                                                                                             
  SMB 3.1.1: true                                                                                                                                           
Preferred dialect: SMB 3.0                                                                                                                                  
SMB1 only: false                                                                                                                                            
SMB signing required: true                                                                                                                                  

 ===========================================================
|    Domain Information via SMB session for 10.10.10.175    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: SAUNA                                                                                                                                
NetBIOS domain name: EGOTISTICALBANK                                                                                                                        
DNS domain: EGOTISTICAL-BANK.LOCAL                                                                                                                          
FQDN: SAUNA.EGOTISTICAL-BANK.LOCAL                                                                                                                          
Derived membership: domain member                                                                                                                           
Derived domain: EGOTISTICALBANK                                                                                                                             

 =========================================
|    RPC Session Check on 10.10.10.175    |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 ===================================================
|    Domain Information via RPC for 10.10.10.175    |
 ===================================================
[+] Domain: EGOTISTICALBANK
[+] Domain SID: S-1-5-21-2966785786-3096785034-1186376766
[+] Membership: domain member

 =========================================
|    Policies via RPC for 10.10.10.175    |
 =========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

Completed after 1.15 seconds

```

# Team
![[Pasted image 20240417083803.png]]
