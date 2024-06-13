# Nmap
```shell
└─$ nmap -A -p- 10.10.11.16   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-13 11:28 EDT
Stats: 0:03:19 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.86% done; ETC: 11:31 (0:00:00 remaining)
Nmap scan report for 10.10.11.16
Host is up (0.041s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
|_http-server-header: nginx/1.24.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

## Guest share enumeration
The guest user has read access to a couple of shares most notably documents
![[Pasted image 20240515073747.png]]
```shell
└─$ sudo mount -t cifs -o 'username=Guest,password=' //10.10.11.16/Documents /mnt
```
## RPC Null Access
```shell
RPC         10.10.11.16     135    SOLARLAB         [+] solarlab\: (Default allow anonymous login)

```
## SMB Access
```shell
└─$ nxc smb 10.10.11.16 -u usernames.txt -p passwords.txt
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)                                                                                                                      
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\Alexander.knight@gmail.com:al;ksdhfewoiuh 

```
![[Pasted image 20240515081024.png]]


# Services
```
Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5808
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       892
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       1476
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:6791           0.0.0.0:0              LISTENING       5808
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       516
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       908
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1376
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       656
  TCP    10.10.11.16:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.11.16:55440      10.10.14.25:6565       ESTABLISHED     744
  TCP    10.10.11.16:55443      10.10.14.25:1234       ESTABLISHED     2280
  TCP    10.10.11.16:55446      10.10.14.25:6565       ESTABLISHED     3624
  TCP    127.0.0.1:5000         0.0.0.0:0              LISTENING       3812
  TCP    127.0.0.1:5222         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:5223         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:5262         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:5263         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:5269         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:5270         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:5275         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:5276         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:7070         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:7443         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3096
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3096
```