# Nmap Scan
`$nmap 10.10.11.239 -A -p22,80,3000$`
`Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-06 08:56 EDT`
`Nmap scan report for 10.10.11.239`
`Host is up (0.30s latency).`

`PORT     STATE SERVICE VERSION`
`22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)`
`| ssh-hostkey:` 
`|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)`
`|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)`
`80/tcp   open  http    Apache httpd 2.4.52`
`|_http-server-header: Apache/2.4.52 (Ubuntu)`
`|_http-title: Did not follow redirect to http://codify.htb/`
`3000/tcp open  http    Node.js Express framework`
`|_http-title: Codify`
`Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel`

`Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .`
`Nmap done: 1 IP address (1 host up) scanned in 39.62 seconds``
`
# Gobuster
	`gobuster dir -u http://codify.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` 
	===============================================================
	`Gobuster v3.6`
	`by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)`
	===============================================================
	`[+] Url:                     http://codify.htb/`
	`[+] Method:                  GET`
	`[+] Threads:                 10`
	`[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
	`[+] Negative Status codes:   404`
	`[+] User Agent:              gobuster/3.6`
	`[+] Timeout:                 10s`
	===============================================================
	`Starting gobuster in directory enumeration mode`
	===============================================================
	`/about                (Status: 200) [Size: 2921]`
	`/About                (Status: 200) [Size: 2921]`
	`/editor               (Status: 200) [Size: 3123]`
	`/Editor               (Status: 200) [Size: 3123]`
	`/ABOUT                (Status: 200) [Size: 2921]`
	`/limitations          (Status: 200) [Size: 2665]`
	`/server-status        (Status: 403) [Size: 275]``


# Svc@codify

```bash
svc@codify:~$ ls -a
ls -a
.
..
.bash_history
.bash_logout
.bashrc
.cache
ddy_shell
.gnupg
my_shell.sh
.pm2
.profile
pwned
shell
.sqlite_history
.ssh
.vimrc

```

```bash
svc@codify:~cat .sqlite_history
cat .sqlite_history
.open /contact/tickets.db
exit
exit();
quit
;
.help
.quit
.tables
SELECT * FROM tickets;
SELECT * FROM users;
.quit
.tables
select * from tickets
;
select * from users;
ls
;
quit
;
.qui

```
```bash
cat abkp
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCw6ZcN/WXpqxkxasjRvgF3KtB1pibA7AZpsu6jHUrWreYbRlZO/Z5eZTg06NCEolW4gp5yJKHXW09uJ7S3Ci4ciUE/xm59ypwEudOlZ8lhFZY1pKpo2vV80u8gJGHvUy69jf5SV7LlXikeOzMFDK07nDxcgPBMB5Cn2mH7QM47UecK2bFt8IvV3d/x/Lbp294q8Np9kVYCsb/TQatYPg7j57w6NletqLXapZyAe8SnI7AIEdFYBsTGSiDIKrlg7A56roIWfgTMBd+sglll1JW4BfZkaAyUoaxiedtBriD2dhT5IGIewQzR3n511kWksfHosPkdi53LreQsZDxhaLYhs17/FPGUQt+OhHnqJ/nGFhxeQYmQs7Q2llb6QyL6Mqmks1csszLy6bP2RLqHQ3CL6jM9BlspZ02dTPmMsJ2B/WYW8qoc5wD65EEsVuP2vHOV834MawlY6LgQ6cVpwMVZNSfaX+xGq5FvXlX9WZKeUGeZurCktL44VxSWOyHxsM0= vinay@hackvm

```

```bash
cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCPZZVMRCtCx8nAWDBn4GOL7C+hk6nT4tryg9iibZt5UeDvKBMabvNfO/WaWzCTv/ZpKvQ7YfdnM04g2/0E8EhwesIUkeZFQ4TiCbVPsT26Fo5WZg4Q0WfvWy2eCSmlTqN9j5O+23AWL6Ct4x/6lOOw4+Da/iLwjCBiaFrnYtFe5QqDyigR8XhNf/Wzdg65tqXcUwICeBh4Vx8xKOW9YaIwl+kQJn2qYsxx8AJj7anbU1/5r2zajsi/SWD2Q8Sp2MwZ/+s8mciWFbO17MPBtwi2R1Km5owHJjmppJ2cAtjLvka+0kI7PhP54KApG9mQukfA2Kx/C9Rf/AxhkVopC0fPwB9XncuUl1TBZczbPJDLKh4Y0M1xi48HvnMoP4oKgF0M1wuoDlD630Wipolg+gyZsaS43eJfKsckSkTlXqKFHVnGmQWvLyLG2alGILWoz26XRyOAR+H9lOcgpe0HNo79yvrIU9IF4RPULTant0ICoV88K3ljXpcU5fRuMDLt+5U= svc@codify

```

## svc's id_rsa
```bash
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
j/m+ELPRbfPKybAAAACnN2Y0Bjb2RpZnk=
-----END OPENSSH PRIVATE KEY-----

```
