# Nmap
```sh
└─$ nmap -p- -A 10.10.11.9                                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-19 07:35 EDT
Nmap scan report for 10.10.11.9
Host is up (0.025s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:72:62:48:99:33:4f:fc:59:f8:6c:05:59:db:a7:7b (ECDSA)
|_  256 62:c6:35:7e:82:3e:b1:0f:9b:6f:5b:ea:fe:c5:85:9a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: magicgardens.magicgardens.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
80/tcp   open  http     nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://magicgardens.htb/
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, TerminalServer, TerminalServerCookie, X11Probe, afp, giop, ms-sql-s: 
|_    [x] Handshake error
5000/tcp open  ssl/http Docker Registry (API: 2.0)
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2023-05-23T11:57:43
|_Not valid after:  2024-05-22T11:57:43
|_http-title: Site doesn't have a title.

```