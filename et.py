import argparse
import json
import sys
import os
from base64 import b64encode
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from element import Element, Color

"""
  CLASE: ET
  DESCRIPCIÓN: Implementa todos los comandos de las estaciones de tierra
  AUTHORS: luis.lepore@estudiante.uam.es
           oriol.julian@estudiante.uam.es
"""


class ET(Element):

    """
      FUNCIÓN: void __init__()
      DESCRIPCIÓN: Constructor
    """
    def __init__(self):
        self.linked_drones = []
        self.connected_drones = {}
        super().__init__()

    """
      FUNCIÓN: void parse_arguments(String input_str)
      ARGS_IN: input_str - Comando escrito por el usuario para ser parseado
      DESCRIPCIÓN: Analiza la cadena de caracteres escrita por el usuario 
                   en el menú y ejecuta las funciones correspondientes
    """
    def parse_arguments(self, input_str):
        parser = argparse.ArgumentParser()
        parser.add_argument('--dest', nargs=1, help="Id destino")
        parser.add_argument('--drone-id', nargs=1)

        parser.add_argument('--send_msg', nargs='+',
                            help="Envía un mensaje. " +
                            "Debe contener un --dest (id)")
        parser.add_argument('--send_file', nargs=1,
                            help="Envía un fichero. " +
                            "Debe contener un --dest (id)")
        parser.add_argument('--fly', action='store_true', default=None,
                            help="Hace volar a un drone. " +
                            "Debe contener un --drone-id")
        parser.add_argument('--land', action='store_true', default=None,
                            help="Hace aterrizar a un drone. " +
                            "Debe contener un --drone-id")
        parser.add_argument('--link', action='store_true', default=None,
                            help="Vincular con la BO")
        parser.add_argument('--unlink', action='store_true', default=None,
                            help="Desvincular de la BO")
        parser.add_argument('--disconnect', action='store_true', default=None,
                            help="Hace desconectarse a un drone. " +
                            "Debe contener un --drone-id")

        args = parser.parse_args(input_str.split())

        if args.send_msg is not None:
            if args.dest is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un id en --dest")
                return
            if args.dest[0].startswith("ET"):
                self.link(args.dest[0])
            self.send_msg_to_element(' '.join(args.send_msg), args.dest[0])
            if args.dest[0].startswith("ET"):
                self.unlink(args.dest[0])

        elif args.send_file is not None:
            if args.dest is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --dest")
                return
            if args.dest[0].startswith("ET"):
                self.link(args.dest[0])
            self.send_file(args.send_file[0], args.dest[0])
            if args.dest[0].startswith("ET"):
                self.unlink(args.dest[0])
        elif args.fly is not None:
            if args.drone_id is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --drone-id")
            self.fly(args.drone_id[0])
        elif args.land is not None:
            if args.drone_id is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --drone-id")
            self.land(args.drone_id[0])
        elif args.link is not None:
            self.link("BO0")
        elif args.unlink is not None:
            self.unlink("BO0")
        elif args.disconnect is not None:
            if args.drone_id is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --drone-id")
            self.disconnect(args.drone_id[0])

    """
      FUNCIÓN: void fly_land(String message, String drone_id)
      ARGS_IN: message - "FLY" o "LAND" respectivamente
               drone_id - ID del dron
      DESCRIPCIÓN: Hace que un dron vuele o aterrice
    """
    def fly_land(self, message, drone_id):
        if drone_id not in self.connected_drones:
            print(f"{Color.RED}Error: {Color.BLUE}{drone_id}{Color.END} " +
                  "no está conectado")
            return
        if not self.connect_socket(drone_id):
            print(f"{Color.BLUE}{drone_id}{Color.END} no encontrado")
            return
        enc_json = self.enc_json({}, message, drone_id)
        self.send_msg(json.dumps(enc_json), self.send_socket)
        stat_msg = self.decrypt_str(self.recv_msg(self.send_socket), drone_id)
        self.disconnect_socket(self.send_socket)
        print(f"{Color.GREEN}{message}:{Color.END} " +
              f"{Color.BLUE}{drone_id}{Color.END} ({stat_msg})")

    """
      FUNCIÓN: void fly(String drone_id)
      ARGS_IN: drone_id - ID del dron
      DESCRIPCIÓN: Llama a fly_land con "FLY" como message
    """
    def fly(self, drone_id):
        self.fly_land("FLY", drone_id)

    """
      FUNCIÓN: void land(String drone_id)
      ARGS_IN: drone_id - ID del dron
      DESCRIPCIÓN: Llama a fly_land con "LAND" como message
    """
    def land(self, drone_id):
        self.fly_land("LAND", drone_id)

    """
      FUNCIÓN: void disconnect(String drone_id)
      ARGS_IN: drone_id - ID del dron
      DESCRIPCIÓN: Desconecta un dron conectado a la ET
    """
    def disconnect(self, drone_id):
        if drone_id not in self.connected_drones:
            print(f"{Color.RED}Error: {Color.BLUE}{drone_id}{Color.END} " +
                  "no está conectado")
            return
        if not self.connect_socket(drone_id):
            print(f"{Color.BLUE}{drone_id}{Color.END} no encontrado")
            return

        enc_json = self.enc_json({}, "DISCONNECT", drone_id)
        self.send_msg(json.dumps(enc_json), self.send_socket)
        self.disconnect_socket(self.send_socket)
        print(f"{Color.GREEN}DISCONNECT:{Color.END} " +
              f"{Color.BLUE}{drone_id}{Color.END}")

    """
      FUNCIÓN: void parse_listen(JSON recv_json, socket connection)
      ARGS_IN: recv_json - JSON con el mensaje recibido
               connection - socket utilizado para responder al emisor
      DESCRIPCIÓN: Función encargada de parsear el JSON recibido en el socket de escucha
    """
    def parse_listen(self, recv_json, connection):
        if recv_json["msg_type"] == "LINK":
            if recv_json["src_id"] in self.linked_drones:
                self.print_listen(Color.RED + "Error: " +
                                  Color.BLUE + recv_json["src_id"] +
                                  Color.END + " ya está vinculado")
                return
            key = get_random_bytes(32)
            encrypt_aes = AES.new(key, AES.MODE_CBC)
            decrypt_aes = AES.new(key, AES.MODE_CBC, iv=encrypt_aes.iv)
            send_json = {
                'iv': b64encode(encrypt_aes.iv).decode(),
                'key': b64encode(PKCS1_OAEP.new(
                    RSA.importKey(recv_json["p_key"])).encrypt(key)).decode()
            }
            self.send_msg(json.dumps(send_json), connection)
            self.linked_aes[recv_json["src_id"]] = (encrypt_aes, decrypt_aes)
            if recv_json["src_id"].startswith("ET"):
                return
            self.linked_drones.append(recv_json["src_id"])
            self.print_listen(Color.BLUE + recv_json["src_id"] + Color.END +
                              " vinculado\nDrones vinculados: " +
                              Color.BLUE + str(self.linked_drones) + Color.END)
            return

        src_id, msg_type, dec_json = self.dec_json(recv_json)

        if msg_type == "UNLINK":
            self.linked_aes.pop(src_id, None)
            if src_id.startswith("ET"):
                return
            self.linked_drones.remove(src_id)
            self.print_listen(Color.BLUE + src_id + Color.END +
                              " desvinculado\nDrones vinculados: " +
                              Color.BLUE + str(self.linked_drones) + Color.END)

        elif msg_type == "CONNECT":
            self.connected_drones[src_id] = {
                "battery": -1, "fly": False
            }
            self.print_listen(Color.BLUE + src_id + Color.END +
                              " conectado\nDrones conectados: " +
                              self.get_keys(self.connected_drones))

        elif msg_type == "DISCONNECT":
            self.connected_drones.pop(src_id, None)
            self.print_listen(Color.BLUE + src_id + Color.END +
                              " desconectado\nDrones conectados: " +
                              self.get_keys(self.connected_drones))

        elif msg_type == "TELEMETRY":
            self.connected_drones[src_id]["battery"] = dec_json["battery"]
            self.connected_drones[src_id]["fly"] = bool(eval(dec_json["fly"]))

        elif msg_type == "GET_STATUS":
            status = {"vinculados": [], "conectados": {}}
            for linked in self.linked_drones:
                status["vinculados"].append(linked)
            for connected_id, connected_status in self.connected_drones.items():
                status["conectados"][connected_id] = {
                    "battery": connected_status["battery"],
                    "fly": connected_status["fly"]
                }
            self.send_msg(self.encrypt_str(json.dumps(status), src_id),
                          connection)

        elif msg_type == "SHUTDOWN":
            print()
            for drone_id in self.connected_drones:
                self.disconnect(drone_id)
            self.unlink("BO0")
            print(">>> ", end="")
            sys.stdout.flush()

        elif msg_type == "SEND_FILE":
            root = os.path.dirname(os.path.abspath(__file__))
            if not os.path.exists(root + "/docs/"):
                os.mkdir(root + "/docs/")
            if not os.path.exists(root + "/docs/" + self.ID):
                os.mkdir(root + "/docs/" + self.ID)
            name = dec_json["name"]
            f_path = root + "/docs/" + self.ID + "/" + name
            f_out = open(f_path, 'wb')
            line = connection.recv(self.MAX_BUFFER)
            data_enc = b''
            while line:
                data_enc += line
                line = connection.recv(self.MAX_BUFFER)
            f_out.write(self.decrypt_bytes(data_enc, src_id))
            f_out.close()
            self.print_listen(f"{Color.GRAY}docs/{self.ID}/{name}{Color.END}" +
                              " recibido")

        elif msg_type == "SEND_MSG":
            self.print_listen(Color.GREEN + "SEND MSG: " + Color.END +
                              dec_json["message"])

        elif msg_type == "REDIRECT":
            dest_json_str = dec_json["dest_json"]
            dest_id = dec_json["dest_id"]
            if dest_id not in self.linked_aes:
                self.print_listen(f"{Color.RED}Error: " +
                                  f"{Color.BLUE}{dest_id}{Color.END} " +
                                  "no está conectado/a")
                return
            if not self.connect_socket(dest_id):
                self.print_listen(f"{Color.BLUE}{dest_id}{Color.END} " +
                                  "no encontrado/a")
                return

            self.send_msg(dest_json_str, self.send_socket)
            self.send_msg(self.recv_msg(self.send_socket), connection)
            self.print_listen(f"{Color.GREEN}REDIRECT:{Color.END} de " +
                              f"{Color.BLUE}{src_id}{Color.END} a " +
                              f"{Color.BLUE}{dest_id}{Color.END}")
        else:
            print(Color.RED + "Error: " + Color.END +
                  "Tipo de mensaje no reconocido en " + json.dumps(dec_json))

    """
      FUNCIÓN: void exit()
      DESCRIPCIÓN: Se desconecta de la BO en caso de estar conectado 
                   y cierra el socket de escucha
    """
    def exit(self):
        if "BO0" in self.linked_aes:
            self.unlink("BO0")
        self.disconnect_socket(self.listen_socket)


if __name__ == '__main__':
    et = ET()
    et.finish()
