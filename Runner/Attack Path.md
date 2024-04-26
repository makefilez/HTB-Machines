
# TeamCity CVE-2023-42793
So the jetbrains login page was vulnerable to  CVE-2023-42793. Using the following [POC](https://github.com/H454NSec/CVE-2023-42793) I was able to create a new administrative user account.
```shell
python3 CVE-2023-42793.py  -u http://teamcity.runner.htb/            

[+] http://teamcity.runner.htb/login.html [H454NSec7623:@H454NSec]
```

# Changed Johns Password
In the admin portal I changed johns password to abc123! I was not able to ssh in with those creds
![[Pasted image 20240424090636.png]]

# Dumping the Database
If you browse to the backup directory in the Administration tab you will be able to back up everything including the database. Inside that on your local machine you will be able to find ssh keys users hashes etc.
![[Pasted image 20240425060650.png]]
![[Pasted image 20240425060708.png]]
![[Pasted image 20240425061930.png]]

# Johns SSH 
With the id_rsa we can ssh into Johns pc
```shell
└─$ ssh -i id_rsa john@10.10.11.13

```

# Getting Root
Once you log into the portainer-administrator page you can create a new container using the ubuntu image and following the commands from this [blog](https://nitroc.org/en/posts/cve-2024-21626-illustrated/#why-the-file-descriptor-of-sysfscgroup-is-7) you will be able to get the root.txt flag