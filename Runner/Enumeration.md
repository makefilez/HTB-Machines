# Nmap
```shell
└─$ nmap -A -p- 10.10.11.13
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 01:57 EDT
Nmap scan report for runner.htb (10.10.11.13)
Host is up (0.018s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Runner - CI/CD Specialists
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

# Gobuster
```shell
$ gobuster dir -u http://runner.htb:8000/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://runner.htb:8000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/health               (Status: 200) [Size: 3]
/version              (Status: 200) [Size: 9]
Progress: 141708 / 141709 (100.00%)
===============================================================
Finished
===============================================================

```

Using a custom wordlist it was seen that the sub-domain was found

Use CEWL to make a custom wordlists
```
teamcity.runner.htb
```

# TeamCity users
![[Pasted image 20240424090837.png]]
![[Pasted image 20240424204238.png]]
# LinPeas
Running linpeas on the john user account revealed something interesting
```shell
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Apr  4 10:24 /etc/nginx/sites-enabled                                                                                           
drwxr-xr-x 2 root root 4096 Apr  4 10:24 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 36 Feb 28 20:31 /etc/nginx/sites-enabled/portainer -> /etc/nginx/sites-available/portainer
server {
    listen 80;
    server_name portainer-administration.runner.htb;
    location / {
        proxy_pass https://localhost:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

```

Putting the portainer-adinistration.runner.htb into my /etc/hosts file and browsing to the website
![[Pasted image 20240425065522.png]]
I think the matthew creds are for this. It works!
![[Pasted image 20240425065604.png]]
