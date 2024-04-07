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
`