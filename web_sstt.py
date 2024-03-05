# coding=utf-8
# !/usr/bin/env python3

import socket
import selectors    # https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os           # Obtener ruta y extension
from datetime import datetime, timedelta  # Fechas de los mensajes HTTP
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging      # Para imprimir logs
import urllib.parse

BUFSIZE = 8192              # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 24     # Timout para la conexión persistente
SERVER_TIMEOUT_DELAY = 1    # Delay para que el servidor termine la conexcion por timeout antes que el cliente
MAX_ACCESOS = 10

HTTP_REGEX_TXT = r"(?P<METHOD>.+) (?P<RESOURCE>.+) HTTP\/(?P<HTTPVER>.+)\r\n(.+?:.+?\r\n)*\r\n(?P<CONTENT>(.+\r\n)*.+)?$"
HTTP_REGEX = re.compile(HTTP_REGEX_TXT)

REMOVE_PARAMS_TXT = r"\?.+?$"
REMOVE_PARAMS = re.compile(REMOVE_PARAMS_TXT)

COOKIE_MAX_AGE = 120

COOKIE_COUNTER_HDR = "cookie_counter_6206"

VALID_USERS = ["juandios.melgarejof@um.es", "adrian.m.t@um.es"]

# Configuracion de respuestas HTTP
SERVER_NAME = "web.ssttenyoyers6206.org"
CONNECTION_HEADER = "Keep-Alive"

# Extensiones admitidas (extension, name in HTTP)
FILE_TYPES = {"gif": "image/gif", "jpg": "image/jpg", "jpeg": "image/jpeg", "png": "image/png", "htm": "text/htm",
             "html": "text/html", "css": "text/css", "js": "text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()



def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """

    sent = cs.send(bytes(data, encoding='latin-1'))
    print("")
    print(" SENT >>>>>>>>>>>>>>>>>>>>>>>>> ")
    print("")
    split = data.split("\r\n\r\n")
    print(split[0])
    print("<< content omitted >>")
    # print("DEBUG: Sent " + str(sent) + " bytes")


def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """

    data_recv = cs.recv(BUFSIZE)
    # print("DEBUG: Received " + len(data_recv) + " bytes")

def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """

    cs.close()


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
    """
    cookies = {}

    # 1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
    if 'Cookie' in headers:
        cookies_str = headers['Cookie'].strip()

        if ',' in cookies_str:
            for cookie in cookies_str.split(','):
                c = cookie.split('=')
                cookies[c[0]] = c[1]
        elif cookies_str != '':
            c = cookies_str.split('=')
            cookies[c[0]] = c[1]

        
    # 2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
    if COOKIE_COUNTER_HDR in cookies:
        cookie_counter = int(cookies[COOKIE_COUNTER_HDR])
        # 4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        # 5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
        return MAX_ACCESOS if cookie_counter == MAX_ACCESOS else cookie_counter + 1 
    else:
        # 3. Si no se encuentra cookie_counter , se devuelve 1
        return 1

def format_message(http_version, date, status_code, status_msg, additional_headers, content_length):
    respuesta = ""
    respuesta += "HTTP/"+http_version+" "+ status_code+" "+ status_msg+"\r\n"
    respuesta += "Server: "+SERVER_NAME+"\r\n"
    respuesta += "Date: "+date+"\r\n"
    respuesta += "Connection: "+CONNECTION_HEADER+"\r\n"
    for header in additional_headers:
        respuesta += header
    respuesta += "Content-Length: "+str(content_length)+"\r\n"
    respuesta += "Keep-Alive: timeout="+str(TIMEOUT_CONNECTION)+"\r\n"
    respuesta += "\r\n"
    return respuesta

def format_error_message(http_version, date, status_code, status_msg):
    content = ""
    content += "<html><body><h1>"
    content += status_code + " " + status_msg
    content += "</h1></body></html>"

    respuesta = ""
    respuesta += "HTTP/"+http_version+" "+ status_code+" "+ status_msg+"\r\n"
    respuesta += "Date: "+date+"\r\n"
    respuesta += "Server: "+SERVER_NAME+"\r\n"
    respuesta += "Connection: "+CONNECTION_HEADER+"\r\n"
    respuesta += "Content-Length: "+str(len(content))+"\r\n"
    respuesta += "\r\n"
    respuesta += content

    return respuesta

def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)
    """

    # * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()
    while True: 
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        # Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
        # sin recibir ningún mensaje o hay datos. Se utiliza select.select
        
        [r,w,x] = select.select([cs], [], [], TIMEOUT_CONNECTION - SERVER_TIMEOUT_DELAY)
        if len(r) == 0 and len(w) == 0 and len(x) == 0:
            print("DBG: Timeout")
            # Si es por timeout, se cierra el socket tras el período de persistencia.
            # NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
            cerrar_conexion(cs)
            break

        # Si no es por timeout y hay datos en el socket cs.
        # Leer los datos con recv.
        recv_data = cs.recv(BUFSIZE).decode()

        # Fix para no acceder a contenidos invalidos
        if len(recv_data) == 0:
            print("DBG: Cerramos por 0 bytes")
            cerrar_conexion(cs)
            break

        print("")
        print(" RECEIVED " + str(len(recv_data)) + "<<<<<<<<<<<<<<<<<<<<<<<< ")
        print("")
        print(recv_data)

        # Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
        data_match = HTTP_REGEX.search(recv_data)
        if not data_match:
            respuesta = format_error_message("1.1", date, "400", "Bad Request")
            enviar_mensaje(cs, respuesta)
            return

        method = data_match.group("METHOD")
        resource = data_match.group("RESOURCE")
        http_version = data_match.group("HTTPVER")
        content = data_match.group("CONTENT")

        # Mapa de cabeceras
        # Devuelve una lista con los atributos de las cabeceras.
        headers = {}
        for line in recv_data.splitlines()[1:]:
            if line == "":
                break
            split = line.split(":", 1)
            headers[split[0]] = split[1]

        if "Host" not in headers:
            respuesta = format_error_message(http_version, date, "405", "Method Not Allowed")
            enviar_mensaje(cs, respuesta)
            break

        # Comprobar si la versión de HTTP es 1.1
        if http_version != "1.1":
            break

        if method == "GET":
            # Leer URL y eliminar parámetros si los hubiera
            resource = REMOVE_PARAMS.sub("", resource)
            
            # Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
            resource_path = webroot
            if resource == "/":
                resource_path += "/index.html"
            else:
                # Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                resource_path += resource
            
            # Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
            if not os.path.isfile(resource_path):
                respuesta = format_error_message(http_version, date, "404", "Not Found")
                enviar_mensaje(cs, respuesta)
                break
            
            # Analizar las cabeceras. Imprimir cada cabecera y su valor. 
            # for header in headers:
            #     print("\t" + header + ": " + headers[header])

            # Si la cabecera es Cookie comprobar el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
            # Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
            set_cookie_counter_header = ""
            if resource_path == webroot + "/index.html":
                cookie_counter = process_cookies(headers, cs)
                if cookie_counter == MAX_ACCESOS:
                    respuesta = format_error_message(http_version, date, "403", "Forbidden")
                    enviar_mensaje(cs, respuesta)
                    break
                set_cookie_counter_header = "Set-Cookie: "+COOKIE_COUNTER_HDR+"="+str(cookie_counter)+"; Max-Age="+str(COOKIE_MAX_AGE)+"\r\n"
            else:
                set_cookie_counter_header = "Set-Cookie: " + headers["Cookie"]+"; Max-Age="+str(COOKIE_MAX_AGE)+"\r\n"
            
            # Obtener el tamaño del recurso en bytes.
            file_bytes_len = os.stat(resource_path).st_size


            # Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
            file_name, file_extension = os.path.splitext(resource_path)
            file_extension = file_extension.replace(".", "")
            content_type = ""
            content_type += FILE_TYPES[file_extension]
            content_type += "; charset=ISO-8859-1"
            content_type_header = "Content-Type: "+content_type+"\r\n";

            # Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
            # las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
            # Content-Length y Content-Type.
            respuesta = format_message(http_version, date, "200", "OK", [set_cookie_counter_header, content_type_header], file_bytes_len)

            # Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
            # Se abre el fichero en modo lectura y modo binario
            file = open(resource_path, "rb")

            file_string = ""
            while True:
                read_bytes = file.read(BUFSIZE)
                if not read_bytes:
                    # Cuando ya no hay más información para leer, se corta el bucle
                    break     
                
                file_string += str(read_bytes, encoding='latin-1')

            respuesta += file_string

            enviar_mensaje(cs, respuesta)
        elif method == "POST":
            content_values = {}
            for line in content.splitlines():
                if line == "":
                    break
                split = line.split("=", 1)
                content_values[urllib.parse.unquote(split[0])] = urllib.parse.unquote(split[1])
            
            email = content_values["email"]
            content_type = FILE_TYPES["html"]
            content_type += "; charset=ISO-8859-1"
            content_type_header = "Content-Type: "+content_type+"\r\n";
            if email not in VALID_USERS:
                message = "El correo es erroneo"
                respuesta = format_message(http_version, date, "200", "OK", [content_type_header], len(message))
                respuesta += message
                enviar_mensaje(cs, respuesta)
            else:
                # Usuario valido
                message = "El correo es valido"
                respuesta = format_message(http_version, date, "200", "OK", [content_type_header], len(message))
                respuesta += message
                enviar_mensaje(cs, respuesta)
            
            break
        else:
            # Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".
            respuesta = format_error_message(http_version, date, "405", "Method Not Allowed")
            enviar_mensaje(cs, respuesta)

        



def main():
    """ Función principal del servidor
    """

    try:
        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))

        # Crea un socket TCP(SOCK_STREAM)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Vinculamos el socket a una IP y puerto elegidos
            s.bind((args.host, args.port))
            s.listen(MAX_ACCESOS)
            # Escucha conexiones entrantes
            print('Listening on {}, {}', args.host, args.port)

            # Bucle infinito para mantener el servidor activo indefinidamente
            while True:
                
                # - Aceptamos la conexión
                conn, client_addr = s.accept()

                # - Creamos un proceso hijo
                pid = os.fork()
                if pid == 0:
                    # Hijo - Si es el proceso hijo se cierra el socket del padre y
                    s.close()
                    # procesar la petición con process_web_request()
                    process_web_request(conn, os.getcwd())
                    
                    exit()
                else:
                    # Padre - Si es el proceso padre cerrar el socket que gestiona el hijo.
                    conn.close()

        print("Done!")

    except KeyboardInterrupt:
        True


if __name__ == "__main__":
    main()