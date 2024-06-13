After mounting the Data share I was able to find the HR welcome email.txt

```text
└─$ cat HR/Welcome\ Email.txt              
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR                   
```
# RU SCANNER
In the DATA smb share there is a file in the RU Scanner folder
```xml
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile> 
```
The hash look to be base64 but it is encoded well

There is a another file:
```xml
History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />

```
Got some interesting file paths let us try and access them

Once you use the decrpyt function in the RUscanner

you can find some more info about:

# Allinfo Smbclient
```shell
smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt" 
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 07:06:12 PM 2019 EDT
access_time:    Thu Aug  8 07:06:12 PM 2019 EDT
write_time:     Thu Aug  8 07:08:17 PM 2019 EDT
change_time:    Wed Jul 21 02:47:12 PM 2021 EDT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
smb: \C.Smith\HQK Reporting\> 

```

## Debug password
in the debug file there is a password
```shell
 WBQ201953D8w
```