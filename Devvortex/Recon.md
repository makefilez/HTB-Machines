# Nmap

`nmap -A -p22,80 10.10.11.242`
`Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-04 15:38 EDT`
`Nmap scan report for 10.10.11.242`
`Host is up (0.11s latency).`

`PORT   STATE SERVICE VERSION`
`22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)`
`| ssh-hostkey:` 
`|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)`
`|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)`
`|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)`
`80/tcp open  http    nginx 1.18.0 (Ubuntu)`
`|_http-server-header: nginx/1.18.0 (Ubuntu)`
`|_http-title: Did not follow redirect to http://devvortex.htb/`
`Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel``


# Subdomains
## Enumeration
```bash
curl -s -I http://devvortex.htb -H "HOST: defnotvalid.devvortex.htb" | grep "Content-Length"
Content-Length: 154

```
```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -fs 154  
 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 419ms]

```

# Gobuster
```shell
gobuster dir -u http://dev.devvortex.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/home                 (Status: 200) [Size: 23221]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]

```

# dev.devvortex.htb
### Robots.txt
```
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

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

### Admin login
![[Pasted image 20240408162719.png]]

### Joomla Enumeration
```shell
curl -s http://dev.devvortex.htb/README.txt | head -n 10
Joomla! CMS™

1- Overview
        * This is a Joomla! 4.x installation/upgrade package.
        * Joomla! Official site: https://www.joomla.org
        * Joomla! 4.2 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_4.2_version_history
        * Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/4.2-dev

```
### Interesting Files
```html
curl -s http://dev.devvortex.htb/administrator/manifests/files/joomla.xml | xmllint --format -
<?xml version="1.0" encoding="UTF-8"?>
<extension type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2019 Open Source Matters, Inc.</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>4.2.6</version>
  <creationDate>2022-12</creationDate>
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