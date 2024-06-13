# Nmap
```shell
─$ nmap -p- -A 10.10.11.15     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-28 03:03 EDT
Nmap scan report for 10.10.11.15
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Subdomain
```shell
─$ curl -s -I http://10.10.11.15 -H "HOST: defnotvalid.comprezzor.htb" | grep "Content-Length"                
Content-Length: 178


└─$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://comprezzor.htb -H "Host: FUZZ.comprezzor.htb" -fs 178

auth                    [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 41ms]
dashboard               [Status: 302, Size: 251, Words: 18, Lines: 6, Duration: 41ms]
report                  [Status: 200, Size: 3166, Words: 1102, Lines: 109, Duration: 72ms]

```

### Custom wordlists
I made some custom wordlists just in case
```shell
└─$ cewl http://auth.comprezzor.htb/ -d 5 -w auth_wl.txt --auth_type Digest --auth_user simon --auth_pass simon123!

└─$ cewl http://report.comprezzor.htb/ -d 5 -w report_wl.txt  

└─$ cewl http://comprezzor.htb/ -d 5 -w comprezzor_wl.txt   
```

# PDF Generator
```shell
─$ exiftool ///home/kali/Downloads/report_85495.pdf  
ExifTool Version Number         : 12.76
File Name                       : report_85495.pdf
Directory                       : ///home/kali/Downloads
File Size                       : 7.3 kB
File Modification Date/Time     : 2024:04:28 07:36:25-04:00
File Access Date/Time           : 2024:04:28 07:36:32-04:00
File Inode Change Date/Time     : 2024:04:28 07:36:29-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : 
Creator                         : wkhtmltopdf 0.12.6
Producer                        : Qt 5.15.2
Create Date                     : 2024:04:28 11:37:11Z
Page Count                      : 1

```

# FTP welcome note
![[Pasted image 20240428182522.png]]
Y27SH19HDIWD


# Privilege Escalation
## Users
```shell
root:x:0:0:root:/root:/bin/bash
adam:x:1002:1002:,,,:/home/adam:/bin/bash
dev_acc:x:1001:1001:,,,:/home/dev_acc:/bin/bash
lopez:x:1003:1003:,,,:/home/lopez:/bin/bash

```

## Active Ports
```shell
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                              
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                                                          
tcp        0      0 127.0.0.1:21            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.21.0.1:21           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:37209         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4444          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   
```

## PostgreSQL Files
```shell
╔══════════╣ Analyzing PostgreSQL Files (limit 70)
Version: psql Not Found                                                                                                                    
                                                                                                                                           

-rw-r--r-- 1 root root 475 Feb  9  2021 /usr/lib/python3/dist-packages/ansible_collections/community/general/tests/integration/targets/setup_postgresql_db/files/pg_hba.conf
local   all         {{ pg_user }}                     trust
local   all         all                               md5
host    all         all         127.0.0.1/32          md5
host    all         all         ::1/128               md5
-rw-r--r-- 1 root root 475 Feb  9  2021 /usr/lib/python3/dist-packages/ansible_collections/community/postgresql/tests/integration/targets/setup_postgresql_db/files/pg_hba.conf
local   all         {{ pg_user }}                     trust
local   all         all                               md5
host    all         all         127.0.0.1/32          md5
host    all         all         ::1/128               md5

```

## DB files
```shell
╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/command-not-found-backup/commands.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 881, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 3, database pages 6, cookie 0x5, schema 4, UTF-8, version-valid-for 3
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/www/app/blueprints/auth/users.db: SQLite 3.x database, last written using SQLite version 3034001, file counter 19, database pages 4, cookie 0x1, schema 4, UTF-8, version-valid-for 19
Found /var/www/app/blueprints/report/reports.db: SQLite 3.x database, last written using SQLite version 3043000, file counter 56, database pages 3, cookie 0x1, schema 4, UTF-8, version-valid-for 56

 -> Extracting tables from /var/lib/command-not-found-backup/commands.db (limit 20)
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                                            
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)                                                                  
 -> Extracting tables from /var/www/app/blueprints/auth/users.db (limit 20)                                                                
 -> Extracting tables from /var/www/app/blueprints/report/reports.db (limit 20)   
```

# Lopez
## Sudo Rights
```shell
lopez@intuition:/home/dev_acc$ sudo -l
[sudo] password for lopez: 
Matching Defaults entries for lopez on intuition:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2

```

## Strings runner2
```text
~$ strings /opt/runner2/runner2 | grep 0fe
0feda17076d793c2ef2870d7427ad4ed

```