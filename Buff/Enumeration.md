# Nmap
```shell
PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-title: mrb3n's Bro Hut
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION

```

# Windows Priv Esc
Some Interesting ports
```cmd
TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       8304
TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       3148

```