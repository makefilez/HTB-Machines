# Nmap
```sh
nmap -p- -A 10.10.11.11 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-26 03:09 EDT
Stats: 0:01:15 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 03:11 (0:00:06 remaining)
Nmap scan report for 10.10.11.11
Host is up (0.055s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
# WhatWeb
```sh
└─$ whatweb -v -a 3 10.10.11.11                                                                                                             
WhatWeb report for http://10.10.11.11
Status    : 200 OK
Title     : <None>
IP        : 10.10.11.11
Country   : RESERVED, ZZ

Summary   : Apache[2.4.41], Bootstrap[4.3.1], Email[info@board.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], JQuery[3.4.1], Script[text/javascript], X-UA-Compatible[IE=edge]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.41 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Bootstrap ]
        Bootstrap is an open source toolkit for developing with 
        HTML, CSS, and JS. 

        Version      : 4.3.1
        Version      : 4.3.1
        Website     : https://getbootstrap.com/

[ Email ]
        Extract email addresses. Find valid email address and 
        syntactically invalid email addresses from mailto: link 
        tags. We match syntactically invalid links containing 
        mailto: to catch anti-spam email addresses, eg. bob at 
        gmail.com. This uses the simplified email regular 
        expression from 
        http://www.regular-expressions.info/email.html for valid 
        email address matching. 

        String       : info@board.htb

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.41 (Ubuntu) (from server string)

[ JQuery ]
        A fast, concise, JavaScript that simplifies how to traverse 
        HTML documents, handle events, perform animations, and add 
        AJAX. 

        Version      : 3.4.1
        Website     : http://jquery.com/

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 

        String       : text/javascript

[ X-UA-Compatible ]
        This plugin retrieves the X-UA-Compatible value from the 
        HTTP header and meta http-equiv tag. - More Info: 
        http://msdn.microsoft.com/en-us/library/cc817574.aspx 

        String       : IE=edge

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Sun, 26 May 2024 09:12:06 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 2991
        Connection: close
        Content-Type: text/html; charset=UTF-8

```

# Subdomain
```sh
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.10.11.11 -H "Host: FUZZ.board.htb" -fs 15949 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.11
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 204ms]

```