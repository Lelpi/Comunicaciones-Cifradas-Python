import socket
from abc import ABC, abstractmethod
import json
import sys
import threading
import os
from time import sleep
from Cryptodome.PublicKey import RSA
from base64 import b64decode, b64encode
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad

"""
  CLASE: Element
  DESCRIPCIÓN: Implementa la funcionalidad común para los elementos del sistema
  AUTHORS: luis.lepore@estudiante.uam.es
           oriol.julian@estudiante.uam.es
"""


class Element(ABC):
    HOST = "127.0.0.1"  # localhost
    MAX_BUFFER = 4098
    BO_PORT = 10000

    """
      FUNCIÓN: void __init__()
      DESCRIPCIÓN: Constructor
    """
    def __init__(self):
        # sockets
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET,
                                      socket.SO_REUSEADDR,
                                      1)
        self.send_socket = None

        # claves
        keys = RSA.generate(2048)
        self.private_key = keys.export_key('PEM').decode()
        self.public_key = keys.public_key().export_key('PEM').decode()

        self.linked_aes = {}

        class_name = self.__class__.__name__
        if class_name == "ET" or class_name == "Drone":
            send_json = {'msg_type': 'GET_ID',
                         'class': class_name}
            if not self.connect_socket("BO0"):
                print(f"{Color.RED}Error: {Color.BLUE}BO{Color.END}" +
                      " no encontrada")
                sys.exit(1)
            self.send_msg(json.dumps(send_json), self.send_socket)
            self.ID = self.recv_msg(self.send_socket)
            self.disconnect_socket(self.send_socket)

        # threads
        self.menu_thread = threading.Thread(target=self.menu)
        self.listen_thread = threading.Thread(target=self.listen)
        self.menu_thread.start()
        self.listen_thread.start()

    """
      FUNCIÓN: void menu()
      DESCRIPCIÓN: Lee los comandos escritos por el usuario
    """
    def menu(self):
        print("-h / --help for help")
        print("ID: " + Color.BLUE + self.ID + Color.END)
        exit_menu = False
        while not exit_menu:
            str_input = input(">>> ")
            if str_input.strip().lower() == "exit" or exit_menu is True:
                exit_menu = True
                self.exit()
            else:
                try:
                    self.parse_arguments(str_input)
                except:
                    pass

    """
      FUNCIÓN: void finish()
      DESCRIPCIÓN: Espera a que menu_thread termine (se escriba 'exit') 
                   y termina listen_thread cerrando el socket de escucha
    """
    def finish(self):
        self.menu_thread.join()

    """
      FUNCIÓN: void parse_arguments(String input_str)
      ARGS_IN: input_str - Comando escrito por el usuario para ser parseado
      DESCRIPCIÓN: Analiza la cadena de caracteres escrita por el usuario 
                   en el menú y ejecuta las funciones correspondientes
    """
    @abstractmethod
    def parse_arguments(self, input_str):
        pass

    """
      FUNCIÓN: void link(String id_dest)
      ARGS_IN: id_dest - ID de la BO o de la ET
      DESCRIPCIÓN: Función que permite que una ET se conecte a otra ET temporalmente o a la BO.
                   También la utilizan los drones para conectarse a una ET
    """
    def link(self, id_dest):
        if id_dest in self.linked_aes:
            print(f"{Color.BLUE}{id_dest}{Color.END} ya está vinculada")
            return
        if not self.connect_socket(id_dest):
            print(f"{Color.BLUE}{id_dest}{Color.END} no encontrada")
            return

        send_json = {'src_id': self.ID,
                     'msg_type': 'LINK', 'p_key': self.public_key}
        self.send_msg(json.dumps(send_json), self.send_socket)
        recv_json = json.loads(self.recv_msg(self.send_socket))
        self.disconnect_socket(self.send_socket)
        iv = b64decode(recv_json["iv"])
        key = PKCS1_OAEP.new(RSA.importKey(self.private_key)).decrypt(
            b64decode(recv_json["key"]))
        encrypt_aes = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypt_aes = AES.new(key, AES.MODE_CBC, iv=iv)
        self.linked_aes[id_dest] = (encrypt_aes, decrypt_aes)
        print(f"{Color.GREEN}LINK:{Color.END} " +
              f"{Color.BLUE}{id_dest}{Color.END}")

    """
      FUNCIÓN: void unlink(String id_dest)
      ARGS_IN: id_dest - ID de la BO o de la ET
      DESCRIPCIÓN: Función que permite que una ET se desconecte de otra ET o de la BO.
                   También la utilizan los drones para desconectarse de una ET
    """
    def unlink(self, id_dest):
        if id_dest not in self.linked_aes:
            print(f"{Color.BLUE}{id_dest}{Color.END} no está vinculada")
            return
        if not self.connect_socket(id_dest):
            print(f"{Color.BLUE}{id_dest}{Color.END} no encontrada")
            return

        enc_json = self.enc_json({}, "UNLINK", id_dest)
        self.send_msg(json.dumps(enc_json), self.send_socket)
        self.disconnect_socket(self.send_socket)
        self.linked_aes.pop(id_dest, None)
        print(f"{Color.GREEN}UNLINK:{Color.END} " +
              f"{Color.BLUE}{id_dest}{Color.END}")

    """
      FUNCIÓN: void send_msg_to_element(String message, String id_dest)
      ARGS_IN: message - mensaje a enviar
               id_dest - ID de la BO o de la ET
      DESCRIPCIÓN: Función que permite que una ET envíe un mensaje a otra ET o la BO.
                   También permite que la BO le envíe mensajes a una ET
    """
    def send_msg_to_element(self, message, dest_id):
        if dest_id not in self.linked_aes:
            print(f"{Color.RED}Error:{Color.END} " +
                  f"No se ha vinculado a {Color.BLUE}{dest_id}{Color.END}")
            return

        if not self.connect_socket(dest_id):
            print("No se puede conectar al elemento " +
                  Color.BLUE + dest_id + Color.END)
            return

        enc_json = self.enc_json({"message": message}, "SEND_MSG", dest_id)
        self.send_msg(json.dumps(enc_json), self.send_socket)
        self.disconnect_socket(self.send_socket)
        print(f"{Color.GREEN}SEND MSG:{Color.END} " +
              f"{Color.GRAY}{message}{Color.END} a " +
              f"{Color.BLUE}{dest_id}{Color.END}")

    """
      FUNCIÓN: void send_msg_to_element(String f_path, String dest_id)
      ARGS_IN: f_path - nombre del fichero a enviar
               dest_id - ID de la BO o de la ET
      DESCRIPCIÓN: Función que permite que una ET envíe un fichero a otra ET o la BO.
                   También permite que la BO le envíe ficheros a una ET
    """
    def send_file(self, f_path, dest_id):
        if not os.path.isfile(f_path):
            print(f"{Color.RED}Error:{Color.END} " +
                  f"El fichero {f_path} no existe")
            return

        if dest_id not in self.linked_aes:
            print(f"{Color.RED}Error:{Color.END} " +
                  f"No se ha vinculado a {Color.BLUE}{dest_id}{Color.END}")
            return

        if not self.connect_socket(dest_id):
            print(f"{Color.BLUE}{dest_id}{Color.END} no encontrada")
            return

        enc_json = self.enc_json({"name": os.path.basename(f_path)},
                                 "SEND_FILE", dest_id)
        self.send_socket.send(json.dumps(enc_json).encode())
        sleep(1)
        with open(f_path, 'rb') as f:
            data_enc = self.encrypt_bytes(f.read(), dest_id)
            i = 0
            while i*self.MAX_BUFFER < len(data_enc):
                self.send_socket.sendall(
                    data_enc[i*self.MAX_BUFFER:
                             min((i+1)*self.MAX_BUFFER, len(data_enc))])
                i += 1
            self.disconnect_socket(self.send_socket)
            print(f"{Color.GREEN}SEND FILE:{Color.END} " +
                  f"{Color.GRAY}{f_path}{Color.END} a " +
                  f"{Color.BLUE}{dest_id}{Color.END}")

    """
      FUNCIÓN: int send_msg_to_element(String id)
      ARGS_IN: id - ID del elemento
      DESCRIPCIÓN: Devuelve el puerto de escucha de cada elemento en base a su ID
    """
    def get_port(self, id):
        id = id.strip()
        if "BO" in id:
            return self.BO_PORT
        elif "ET" in id:
            return self.BO_PORT + int(id[2:]) * 2 + 1
        elif "Drone" in id:
            return self.BO_PORT + int(id[5:]) * 2 + 2
        else:
            return -1

    def connect_socket(self, dest, is_send_socket=True):
        if is_send_socket:
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s = self.send_socket
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_port = self.get_port(dest)
        try:
            s.connect((self.HOST, send_port))
        except:
            return None
        return s

    def send_msg(self, message, s):
        s.sendall(message.encode())

    def recv_msg(self, conn):
        data = conn.recv(self.MAX_BUFFER)
        return data.decode()

    def open_listen_socket(self):
        try:
            self.listen_socket.bind((self.HOST, self.get_port(self.ID)))
            self.listen_socket.listen()
        except Exception:
            self.listen_socket.close()
            raise Exception("No se puede abrir el puerto de escucha")

    def listen(self):
        self.open_listen_socket()
        while True:
            try:
                conn, _ = self.listen_socket.accept()
                recv_str = self.recv_msg(conn)
            except OSError:
                return

            try:
                recv_json = json.loads(recv_str)
            except ValueError:
                self.print_listen(f"{Color.RED}Error: {Color.END}" +
                                  "Tipo de mensaje no reconocido: " + recv_str)
                continue
            self.parse_listen(recv_json, conn)

    def disconnect_socket(self, s):
        s.shutdown(socket.SHUT_RDWR)
        s.close()

    """
      FUNCIÓN: void parse_listen(JSON recv_json, socket connection)
      ARGS_IN: recv_json - JSON con el mensaje recibido
               connection - socket utilizado para responder al emisor
      DESCRIPCIÓN: Función encargada de parsear el JSON recibido en el socket de escucha
    """
    @abstractmethod
    def parse_listen(self, recv_json, connection):
        pass

    """
      FUNCIÓN: void print_listen(String s)
      ARGS_IN: s - string a imprimir
      DESCRIPCIÓN: Permite imprimir los comandos recibidos en parse_listen 
                   y mantener la estructura del menu
    """
    @staticmethod
    def print_listen(s):
        print("\n" + str(s) + "\n>>> ", end="")

    """
      FUNCIÓN: String parse_listen(JSON d)
      ARGS_IN: d - JSON
      ARGS_OUT: string con las claves
      DESCRIPCIÓN: Devuelve la claves de un diccionario en color azul (para los ID)
    """
    @staticmethod
    def get_keys(d):
        ret_str = ""
        for key in d:
            ret_str += f"{Color.BLUE}{key}{Color.END}, "
        return ret_str[:-2]

    """
      FUNCIÓN: String encrypt_str(String string, String dest_id)
      ARGS_IN: string - string a cifrar
               dest_id - ID del destino
      ARGS_OUT: string cifrada
      DESCRIPCIÓN: Cifra la cadena pasada por argumento según la clave simétrica de dest_id
    """
    def encrypt_str(self, string, dest_id):
        aes = self.linked_aes[dest_id][0]
        return b64encode(aes.encrypt(pad(string.encode(),
                                         AES.block_size))).decode()

    """
      FUNCIÓN: String decrypt_str(String string, String src_id)
      ARGS_IN: string - string a descifrar
               dest_id - ID del emisor
      ARGS_OUT: string descifrada
      DESCRIPCIÓN: Descifra la cadena pasada por argumento según la clave simétrica de src_id
    """
    def decrypt_str(self, string, src_id):
        aes = self.linked_aes[src_id][1]
        return unpad(aes.decrypt(b64decode(string)), AES.block_size).decode()

    """
      FUNCIÓN: String encrypt_bytes(Bytes bytes, String dest_id)
      ARGS_IN: bytes - bytes a cifrar
               dest_id - ID del destino
      ARGS_OUT: bytes cifrados
      DESCRIPCIÓN: Cifra los bytes pasados por argumento según la clave simétrica de dest_id
    """
    def encrypt_bytes(self, bytes, dest_id):
        aes = self.linked_aes[dest_id][0]
        return aes.encrypt(pad(bytes, AES.block_size))

    """
      FUNCIÓN: String decrypt_bytes(Bytes bytes, String src_id)
      ARGS_IN: bytes - bytes a cifrar
               src_id - ID del emisor
      ARGS_OUT: bytes descifrados
      DESCRIPCIÓN: Descifra los bytes pasados por argumento según la clave simétrica de src_id
    """
    def decrypt_bytes(self, bytes, src_id):
        aes = self.linked_aes[src_id][1]
        return unpad(aes.decrypt(bytes), AES.block_size)

    """
      FUNCIÓN: JSON enc_json(JSON send_json, String msg_type, String src_id)
      ARGS_IN: send_json - JSON con el resto de parámetros necesarios a enviar
               msg_type - mensaje a enviar
               src_id - ID del destino
      ARGS_OUT: JSON cifrado
      DESCRIPCIÓN: Cifra el valor de "msg_type" y las claves y valores del resto de etiquetas
    """
    def enc_json(self, send_json, msg_type, dest_id):
        enc_json = {"src_id": self.ID,
                    "msg_type": self.encrypt_str(msg_type, dest_id)}
        for key in send_json:
            enc_key = self.encrypt_str(key, dest_id)
            enc_val = self.encrypt_str(send_json[key], dest_id)
            enc_json[enc_key] = enc_val
        return enc_json

    """
      FUNCIÓN: String, String, JSON dec_json(JSON recv_json)
      ARGS_IN: recv-json - JSON a descifrar
      ARGS_OUT: ID emisor, tipo de mensaje y JSON descifrado
      DESCRIPCIÓN: Descifra el valor de "msg_type" y las claves y valores del resto de etiquetas
    """
    def dec_json(self, recv_json):
        src_id = recv_json["src_id"]
        msg_type = self.decrypt_str(recv_json["msg_type"], src_id)
        dec_json = {}
        for key in recv_json:
            if key != "src_id" and key != "msg_type":
                dec_key = self.decrypt_str(key, src_id)
                dec_val = self.decrypt_str(recv_json[key], src_id)
                dec_json[dec_key] = dec_val

        return src_id, msg_type, dec_json

    """
      FUNCIÓN: void exit()
      DESCRIPCIÓN: Se encarga de que cada elemento finalice correctamente
    """
    @abstractmethod
    def exit(self):
        pass


"""
  CLASE: Color
  DESCRIPCIÓN: Constantes para imprimir colores por terminal
  AUTHORS: luis.lepore@estudiante.uam.es
           oriol.julian@estudiante.uam.es
"""


class Color:
    GREEN = "\033[032m"
    RED = "\033[031m"
    END = "\033[0m"
    BLUE = "\033[034m"
    YELLOW = "\033[033m"
    PURPLE = "\033[035m"
    TURQUOISE = "\033[036m"
    GRAY = "\033[037m"
