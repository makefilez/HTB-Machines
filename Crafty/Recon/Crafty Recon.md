IP - 10.10.11.249

# Crafty.htb
	![[Pasted image 20240403162046.png]]

# Vhosts
	curl -s -I http://10.10.11.249 -H "HOST: defnotvalid.crafty.htb" | grep "Content-Length"
Content-Length: 140

``ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.10.11.249 -H "Host: FUZZ.crafty.htb" -fs 140``
No results


# Nmap
`nmap --open -p- 10.10.11.249`
`Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-03 11:16 EDT`
`Stats: 0:02:47 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan`
`Connect Scan Timing: About 79.65% done; ETC: 11:19 (0:00:39 remaining)`
`Nmap scan report for 10.10.11.249`
`Host is up (0.013s latency).`
`Not shown: 65534 filtered tcp ports (no-response)`
`Some closed ports may be reported as filtered due to --defeat-rst-ratelimit`
`PORT   STATE SERVICE`
`80/tcp open  http`

`Nmap done: 1 IP address (1 host up) scanned in 210.98 seconds`

`PORT   STATE SERVICE VERSION`
`80/tcp open  http    Microsoft IIS httpd 10.0`
`|_http-server-header: Microsoft-IIS/10.0`
`| http-methods:` 
`|_  Potentially risky methods: TRACE`
`|_http-title: Crafty - Official Website`
`Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows`


`PORT      STATE SERVICE`
`80/tcp    open  http`
`PORT      STATE SERVICE   VERSION`
`25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 1/100)`


# Gobuster
`gobuster dir -u crafty.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` 
===============================================================
`Gobuster v3.6`
===============================================================
`[+] Url:                     http://crafty.htb`
`[+] Method:                  GET`
`[+] Threads:                 10`
`[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
`[+] Negative Status codes:   404`
`[+] User Agent:              gobuster/3.6`
`[+] Timeout:                 10s`
===============================================================
`Starting gobuster in directory enumeration mode`
===============================================================
`/home                 (Status: 200) [Size: 1826]`
`/img                  (Status: 301) [Size: 145] [--> http://crafty.htb/img/]`
`/Home                 (Status: 200) [Size: 1826]`
`/css                  (Status: 301) [Size: 145] [--> http://crafty.htb/css/]`
`/js                   (Status: 301) [Size: 144] [--> http://crafty.htb/js/]`
`/IMG                  (Status: 301) [Size: 145] [--> http://crafty.htb/IMG/]`
`/CSS                  (Status: 301) [Size: 145] [--> http://crafty.htb/CSS/]`
`/Img                  (Status: 301) [Size: 145] [--> http://crafty.htb/Img/]`
`/JS                   (Status: 301) [Size: 144] [--> http://crafty.htb/JS/]`
`/HOME                 (Status: 200) [Size: 1826]`
`/coming-soon          (Status: 200) [Size: 1206]`
`Progress: 220560 / 220561 (100.00%)`
===============================================================
`Finished`
===============================================================`
`