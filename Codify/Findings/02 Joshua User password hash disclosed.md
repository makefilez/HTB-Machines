The user Joshua's password was disclosed in the /var/www/contact/template/ticket.db file
![[Pasted image 20240406190608.png]]

The password was then crack with the tool Hashcat using the following command:
```shell
hashcat -m 3200 -a 0 joshua_hash.txt /usr/share/wordlists/rockyou.txt 

```
Joshua's password was cracked

![[Pasted image 20240406190725.png]]
