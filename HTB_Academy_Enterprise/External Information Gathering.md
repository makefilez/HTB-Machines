# Nmap Scan
`
`Nmap scan report for inlanefreight.local (10.129.229.147)`
`Host is up (0.077s latency).`
`Not shown: 61668 closed tcp ports (reset), 3856 filtered tcp ports (no-response)`
`Some closed ports may be reported as filtered due to --defeat-rst-ratelimit`
`PORT     STATE SERVICE  VERSION`
`21/tcp   open  ftp      vsftpd 3.0.3`
`| ftp-anon: Anonymous FTP login allowed (FTP code 230)`
`|_-rw-r--r--    1 0        0              38 May 30  2022 flag.txt`
`| ftp-syst:` 
`|   STAT:` 
`| FTP server status:`
`|      Connected to ::ffff:10.10.15.80`
`|      Logged in as ftp`
`|      TYPE: ASCII`
`|      No session bandwidth limit`
`|      Session timeout in seconds is 300`
`|      Control connection is plain text`
`|      Data connections will be plain text`
`|      At session startup, client count was 3`
`|      vsFTPd 3.0.3 - secure, fast, stable`
`|_End of status`
`22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)`
`| ssh-hostkey:` 
`|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)`
`|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)`
`|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)`
`25/tcp   open  smtp     Postfix smtpd`
`|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING`
`53/tcp   open  domain   (unknown banner: 1337_HTB_DNS)`
`| dns-nsid:` 
`|_  bind.version: 1337_HTB_DNS`
`| fingerprint-strings:` 
`|   DNSVersionBindReqTCP:` 
`|     version`
`|     bind`
`|_    1337_HTB_DNS`
`80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))`
`|_http-server-header: Apache/2.4.41 (Ubuntu)`
`|_http-title: Inlanefreight`
`110/tcp  open  pop3     Dovecot pop3d`
`|_pop3-capabilities: RESP-CODES SASL UIDL STLS PIPELINING AUTH-RESP-CODE CAPA TOP`
`|_ssl-date: TLS randomness does not represent time`
`| ssl-cert: Subject: commonName=ubuntu`
`| Subject Alternative Name: DNS:ubuntu`
`| Not valid before: 2022-05-30T17:15:40`
`|_Not valid after:  2032-05-27T17:15:40`
`111/tcp  open  rpcbind  2-4 (RPC #100000)`
`| rpcinfo:` 
`|   program version    port/proto  service`
`|   100000  2,3,4        111/tcp   rpcbind`
`|   100000  2,3,4        111/udp   rpcbind`
`|   100000  3,4          111/tcp6  rpcbind`
`|_  100000  3,4          111/udp6  rpcbind`
`143/tcp  open  imap     Dovecot imapd (Ubuntu)`
`|_ssl-date: TLS randomness does not represent time`
`|_imap-capabilities: listed IMAP4rev1 more ENABLE LOGIN-REFERRALS have LITERAL+ ID SASL-IR post-login OK Pre-login capabilities LOGINDISABLEDA0001 STARTTLS IDLE`
`| ssl-cert: Subject: commonName=ubuntu`
`| Subject Alternative Name: DNS:ubuntu`
`| Not valid before: 2022-05-30T17:15:40`
`|_Not valid after:  2032-05-27T17:15:40`
`993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)`
`| ssl-cert: Subject: commonName=ubuntu`
`| Subject Alternative Name: DNS:ubuntu`
`| Not valid before: 2022-05-30T17:15:40`
`|_Not valid after:  2032-05-27T17:15:40`
`|_imap-capabilities: listed IMAP4rev1 ENABLE LOGIN-REFERRALS AUTH=PLAINA0001 LITERAL+ ID SASL-IR more have post-login capabilities Pre-login OK IDLE`
`|_ssl-date: TLS randomness does not represent time`
`995/tcp  open  ssl/pop3 Dovecot pop3d`
`|_pop3-capabilities: RESP-CODES SASL(PLAIN) UIDL USER PIPELINING AUTH-RESP-CODE CAPA TOP`
`| ssl-cert: Subject: commonName=ubuntu`
`| Subject Alternative Name: DNS:ubuntu`
`| Not valid before: 2022-05-30T17:15:40`
`|_Not valid after:  2032-05-27T17:15:40`
`|_ssl-date: TLS randomness does not represent time`
`8080/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))`
`|_http-title: Support Center`
`| http-open-proxy: Potentially OPEN proxy.`
`|_Methods supported:CONNECTION`
`|_http-server-header: Apache/2.4.41 (Ubuntu)`
`1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :`
`SF-Port53-TCP:V=7.94SVN%I=7%D=3/31%Time=6609A38A%P=x86_64-pc-linux-gnu%r(D`
`SF:NSVersionBindReqTCP,39,"\x007\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07versio`
`SF:n\x04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\r\x0c1337_HTB_DNS`
`SF:");`
`No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).`
`TCP/IP fingerprint:`
`OS:SCAN(V=7.94SVN%E=4%D=3/31%OT=21%CT=1%CU=34753%PV=Y%DS=2%DC=T%G=Y%TM=6609`
`OS:A3DB%P=x86_64-pc-linux-gnu)SEQ(TS=A)SEQ(SP=103%GCD=1%ISR=10A%TI=Z%CI=Z%I`
`OS:I=I%TS=A)SEQ(SP=103%GCD=2%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7`
`OS:%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST1`
`OS:1)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=N)ECN(R=Y%DF`
`OS:=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%`
`OS:Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R`
`OS:=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%T=40`
`OS:%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=`
`OS:%RD=0%Q=)U1(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=`
`OS:G%RUD=G)IE(R=N)IE(R=Y%DFI=N%T=40%CD=S)`

`Network Distance: 2 hops`
`Service Info: Host:  ubuntu; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel`

`TRACEROUTE (using port 110/tcp)`
`HOP RTT      ADDRESS`
`1   91.41 ms 10.10.14.1`
`2   91.51 ms inlanefreight.local (10.129.229.147)`

`OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .`

# Vhosts

vpn                     [Status: 200, Size: 1578, Words: 414, Lines: 35, Duration: 2249ms]
status                  [Status: 200, Size: 878, Words: 105, Lines: 43, Duration: 120ms]
blog                    [Status: 200, Size: 8708, Words: 1509, Lines: 232, Duration: 4882ms]
dev                     [Status: 200, Size: 2048, Words: 643, Lines: 74, Duration: 4887ms]
support                 [Status: 200, Size: 26635, Words: 11730, Lines: 523, Duration: 4887ms]
monitoring              [Status: 200, Size: 56, Words: 3, Lines: 4, Duration: 104ms]
careers                 [Status: 200, Size: 51806, Words: 22041, Lines: 732, Duration: 103ms]
tracking                [Status: 200, Size: 35211, Words: 10413, Lines: 791, Duration: 154ms]
ir                      [Status: 200, Size: 28548, Words: 2885, Lines: 210, Duration: 902ms]
gitlab                  [Status: 302, Size: 113, Words: 5, Lines: 1, Duration: 118ms]


# Subdomains

inlanefreight.local.    86400   IN      SOA     ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 
inlanefreight.local.    86400   IN      NS      inlanefreight.local.
inlanefreight.local.    86400   IN      A       127.0.0.1
blog.inlanefreight.local. 86400 IN      A       127.0.0.1
careers.inlanefreight.local. 86400 IN   A       127.0.0.1
dev.inlanefreight.local. 86400  IN      A       127.0.0.1
flag.inlanefreight.local. 86400 IN      TXT     "HTB{DNs_ZOn3_Tr@nsf3r}"
gitlab.inlanefreight.local. 86400 IN    A       127.0.0.1
ir.inlanefreight.local. 86400   IN      A       127.0.0.1
status.inlanefreight.local. 86400 IN    A       127.0.0.1
support.inlanefreight.local. 86400 IN   A       127.0.0.1
tracking.inlanefreight.local. 86400 IN  A       127.0.0.1
vpn.inlanefreight.local. 86400  IN      A       127.0.0.1
inlanefreight.local.    86400   IN      SOA     ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 