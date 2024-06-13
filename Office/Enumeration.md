# Nmap
```shell
└─$ nmap -A -p- 10.10.11.3   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-02 04:01 EDT
Stats: 0:00:56 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 16.75% done; ETC: 04:06 (0:03:19 remaining)
Stats: 0:04:09 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 50.01% done; ETC: 04:09 (0:03:53 remaining)
Stats: 0:04:13 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 50.65% done; ETC: 04:09 (0:03:51 remaining)
Nmap scan report for 10.10.11.3
Host is up (0.037s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-title: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-02 16:10:45Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: TLS randomness does not represent time
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: 403 Forbidden
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49680/tcp open  msrpc         Microsoft Windows RPC
54016/tcp open  msrpc         Microsoft Windows RPC
61249/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 8h00m50s
| smb2-time: 
|   date: 2024-05-02T16:11:34
|_  start_date: N/A

```

# Gobuster
```shell
└─$ gobuster dir -u http://10.10.11.3 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt      
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.3
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 334] [--> http://10.10.11.3/images/]
/media                (Status: 301) [Size: 333] [--> http://10.10.11.3/media/]
/templates            (Status: 301) [Size: 337] [--> http://10.10.11.3/templates/]
/modules              (Status: 301) [Size: 335] [--> http://10.10.11.3/modules/]
/Images               (Status: 301) [Size: 334] [--> http://10.10.11.3/Images/]
/plugins              (Status: 301) [Size: 335] [--> http://10.10.11.3/plugins/]
/includes             (Status: 301) [Size: 336] [--> http://10.10.11.3/includes/]
/language             (Status: 301) [Size: 336] [--> http://10.10.11.3/language/]
/components           (Status: 301) [Size: 338] [--> http://10.10.11.3/components/]
/api                  (Status: 301) [Size: 331] [--> http://10.10.11.3/api/]
/cache                (Status: 301) [Size: 333] [--> http://10.10.11.3/cache/]
/libraries            (Status: 403) [Size: 300]
/Media                (Status: 301) [Size: 333] [--> http://10.10.11.3/Media/]
/examples             (Status: 503) [Size: 400]
/licenses             (Status: 403) [Size: 419]
/Templates            (Status: 301) [Size: 337] [--> http://10.10.11.3/Templates/]
/tmp                  (Status: 301) [Size: 331] [--> http://10.10.11.3/tmp/]
/layouts              (Status: 301) [Size: 335] [--> http://10.10.11.3/layouts/]
/IMAGES               (Status: 301) [Size: 334] [--> http://10.10.11.3/IMAGES/]
/%20                  (Status: 403) [Size: 300]
/Libraries            (Status: 403) [Size: 300]
/Components           (Status: 301) [Size: 338] [--> http://10.10.11.3/Components/]
/Language             (Status: 301) [Size: 336] [--> http://10.10.11.3/Language/]
/administrator        (Status: 301) [Size: 341] [--> http://10.10.11.3/administrator/]
/Modules              (Status: 301) [Size: 335] [--> http://10.10.11.3/Modules/]
/*checkout*           (Status: 403) [Size: 300]
/Plugins              (Status: 301) [Size: 335] [--> http://10.10.11.3/Plugins/]
/phpmyadmin           (Status: 403) [Size: 300]
/API                  (Status: 301) [Size: 331] [--> http://10.10.11.3/API/]
/webalizer            (Status: 403) [Size: 419]
/*docroot*            (Status: 403) [Size: 300]
/*                    (Status: 403) [Size: 300]
/con                  (Status: 403) [Size: 300]
/cli                  (Status: 301) [Size: 331] [--> http://10.10.11.3/cli/]
/Cache                (Status: 301) [Size: 333] [--> http://10.10.11.3/Cache/]
/http%3A              (Status: 403) [Size: 300]
/MEDIA                (Status: 301) [Size: 333] [--> http://10.10.11.3/MEDIA/]
/Includes             (Status: 301) [Size: 336] [--> http://10.10.11.3/Includes/]
/**http%3a            (Status: 403) [Size: 300]
/*http%3A             (Status: 403) [Size: 300]
/aux                  (Status: 403) [Size: 300]
/**http%3A            (Status: 403) [Size: 300]
/%C0                  (Status: 403) [Size: 300]
/CLI                  (Status: 301) [Size: 331] [--> http://10.10.11.3/CLI/]
/server-status        (Status: 403) [Size: 419]
/%3FRID%3D2671        (Status: 403) [Size: 300]
Progress: 105372 / 220561 (47.77%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 105452 / 220561 (47.81%)
===============================================================
Finished
===============================================================

```

# Joomla Enum
## Robots.txt
```text
User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

## Version 
```shell
└─$ curl -s http://10.10.11.3/administrator/manifests/files/joomla.xml | xmllint --format - 
<?xml version="1.0" encoding="UTF-8"?>
<extension type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2019 Open Source Matters, Inc.</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>4.2.7</version>
  <creationDate>2023-01</creationDate>
  <description>FILES_JOOMLA_XML_DESCRIPTION</description>
  <scriptfile>administrator/components/com_admin/script.php</scriptfile>
  <update>
    <schemas>
      <schemapath type="mysql">administrator/components/com_admin/sql/updates/mysql</schemapath>
      <schemapath type="postgresql">administrator/components/com_admin/sql/updates/postgresql</schemapath>
    </schemas>
  </update>
  <fileset>
    <files>
      <folder>administrator</folder>
      <folder>api</folder>
      <folder>cache</folder>
      <folder>cli</folder>
      <folder>components</folder>
      <folder>images</folder>
      <folder>includes</folder>
      <folder>language</folder>
      <folder>layouts</folder>
      <folder>libraries</folder>
      <folder>media</folder>
      <folder>modules</folder>
      <folder>plugins</folder>
      <folder>templates</folder>
      <folder>tmp</folder>
      <file>htaccess.txt</file>
      <file>web.config.txt</file>
      <file>LICENSE.txt</file>
      <file>README.txt</file>
      <file>index.php</file>
    </files>
  </fileset>
  <updateservers>
    <server name="Joomla! Core" type="collection">https://update.joomla.org/core/list.xml</server>
  </updateservers>
</extension>

```

# Valid Kerberos users
```shell
└─$ kerbrute userenum -d office.htb --dc 10.10.11.3 /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 05/02/24 - Ronnie Flathers @ropnop

2024/05/02 11:17:57 >  Using KDC(s):
2024/05/02 11:17:57 >   10.10.11.3:88

2024/05/02 11:18:03 >  [+] VALID USERNAME:       administrator@office.htb
2024/05/02 11:18:44 >  [+] VALID USERNAME:       Administrator@office.htb
2024/05/02 11:19:02 >  [+] VALID USERNAME:       ewhite@office.htb
2024/05/02 11:19:02 >  [+] VALID USERNAME:       etower@office.htb
2024/05/02 11:19:02 >  [+] VALID USERNAME:       dwolfe@office.htb
2024/05/02 11:19:02 >  [+] VALID USERNAME:       dmichael@office.htb
2024/05/02 11:19:02 >  [+] VALID USERNAME:       dlanor@office.htb
2024/05/02 11:27:13 >  [+] VALID USERNAME:       hhogan@office.htb
2024/05/02 11:29:34 >  [+] VALID USERNAME:       DWOLFE@office.htb
2024/05/02 11:52:19 >  [+] VALID USERNAME:       DLANOR@office.htb
2024/05/02 12:24:48 >  [+] VALID USERNAME:       tstark@office.htb
```

# Shares for dwolfe
```shell
─$ crackmapexec smb 10.10.11.3 --shares -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [+] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis    READ            
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share 

```

# RPC Client enum
```shell
└─$ rpcclient 10.10.11.3 -U "tstark"
Password for [WORKGROUP\tstark]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[PPotts] rid:[0x453]
user:[HHogan] rid:[0x454]
user:[EWhite] rid:[0x455]
user:[etower] rid:[0x456]
user:[dwolfe] rid:[0x457]
user:[dmichael] rid:[0x458]
user:[dlanor] rid:[0x459]
user:[tstark] rid:[0x45a]
user:[web_account] rid:[0x45e]
rpcclient $> exit
```

# Reverse shell
```shell
SHELL> type passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     
SHELL> 

```

# Bloodhound
```shell
└─$ bloodhound-python -u 'tstark' -p 'playboy69' -d office.htb -dc DC.office.htb -c all -ns 10.10.11.3
INFO: Found AD domain: office.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: DC.office.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC.office.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 13 users
INFO: Found 54 groups
INFO: Found 8 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.office.htb
INFO: Done in 00M 10S

```