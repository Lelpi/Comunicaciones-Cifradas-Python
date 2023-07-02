import argparse
import json
from time import sleep
import threading
import sys
from base64 import b64encode
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from element import Element, Color

"""
  CLASE: Drone
  DESCRIPCIÓN: Implementa todos los comandos de los drones
  AUTHORS: luis.lepore@estudiante.uam.es
           oriol.julian@estudiante.uam.es
"""


class Drone(Element):

    """
      FUNCIÓN: void __init__()
      DESCRIPCIÓN: Constructor
    """
    def __init__(self):
        self.connected_et = "-1"
        self.linked_aes = {}
        self.battery = 100
        self.fly = False
        self.telemetry_thread = None
        super().__init__()

    """
      FUNCIÓN: void parse_arguments(String input_str)
      ARGS_IN: input_str - Comando escrito por el usuario para ser parseado
      DESCRIPCIÓN: Analiza la cadena de caracteres escrita por el usuario 
                   en el menú y ejecuta las funciones correspondientes
    """
    def parse_arguments(self, input_str):
        parser = argparse.ArgumentParser()
        # TODO: Añadir comentarios de explicacion para el --help
        parser.add_argument('--et-id', nargs=1)

        parser.add_argument('--link', action='store_true', default=None,
                            help="Desvincular de una ET. " +
                            "Debe contener un --et-id")
        parser.add_argument('--unlink', action='store_true', default=None,
                            help="Vincular a una ET. " +
                            "Debe contener un --et-id")
        parser.add_argument('--connect', action='store_true', default=None,
                            help="Conectar a una ET. " +
                            "Debe contener un --et-id")
        parser.add_argument('--disconnect', action='store_true', default=None,
                            help="Desconectar de su ET")

        args = parser.parse_args(input_str.split())

        if args.disconnect is not None:
            self.disconnect()

        if args.link is not None:
            if not args.et_id[0].startswith("ET"):
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un id de una ET")
                return
            self.link(args.et_id[0])

        elif args.unlink is not None:
            self.unlink(args.et_id[0])

        elif args.connect is not None:
            self.connect(args.et_id[0])

    """
      FUNCIÓN: void unlink(String et_id)
      ARGS_IN: et_id - ID de la ET
      DESCRIPCIÓN: Desvincula el dron de una ET
    """
    def unlink(self, et_id):
        if et_id == self.connected_et:
            print(f"{Color.RED}Error: {Color.END}El dron está conectado a " +
                  f"{Color.BLUE}{et_id}{Color.END}. Se debe desconectar antes")
            return

        super().unlink(et_id)

    """
      FUNCIÓN: void connect(String et_id)
      ARGS_IN: et_id - ID de la ET
      DESCRIPCIÓN: Conecta el dron con una ET
    """
    def connect(self, et_id):
        if self.connected_et != "-1":
            print("Ya estás conectado a " +
                  f"{Color.BLUE}{self.connected_et}{Color.END}")
            return

        if et_id not in self.linked_aes:
            print(f"{Color.RED}Error: {Color.BLUE}{et_id}{Color.END} " +
                  "no está vinculada")
            return

        if not self.connect_socket(et_id):
            print(f"{Color.BLUE}{et_id}{Color.END} no encontrada")
            return

        enc_json = self.enc_json({}, "CONNECT", et_id)
        self.send_msg(json.dumps(enc_json), self.send_socket)
        self.disconnect_socket(self.send_socket)

        self.connected_et = et_id
        self.telemetry_thread = threading.Thread(target=self.telemetry)
        self.telemetry_thread.start()
        print(f"{Color.GREEN}CONNECT:{Color.END} " +
              f"{Color.BLUE}{et_id}{Color.END}")

    """
      FUNCIÓN: void disconnect()
      DESCRIPCIÓN: Desconecta el dron de su ET
    """
    def disconnect(self):
        if self.connected_et == "-1":
            print("No está conectado a ninguna ET")
            return

        if not self.connect_socket(self.connected_et):
            print(f"{Color.BLUE}{self.connected_et}{Color.END} " +
                  "no encontrada")
        else:
            enc_json = self.enc_json({}, "DISCONNECT", self.connected_et)
            self.send_msg(json.dumps(enc_json), self.send_socket)

        print(f"{Color.GREEN}DISCONNECT:{Color.END} " +
              f"{Color.BLUE}{self.connected_et}{Color.END}")
        self.connected_et = "-1"
        self.telemetry_thread.join()
        self.telemetry_thread = None
        self.disconnect_socket(self.send_socket)

    """
      FUNCIÓN: void telemetry()
      DESCRIPCIÓN: Función que envía cada 2 segundos el estado 
                   del dron a la ET a la que esté conectado
    """
    def telemetry(self):
        while self.connected_et != "-1":
            enc_json = self.enc_json(
                {"battery": "{:.2f}".format(round(self.battery, 2)),
                 "fly": str(self.fly)
                 }, "TELEMETRY", self.connected_et)
            s = self.connect_socket(self.connected_et, False)
            if not s:
                self.print_listen(f"{Color.RED}Error: {Color.BLUE}" +
                                  f"{self.connected_et}{Color.END} " +
                                  "desconectada")
            try:
                self.send_msg(json.dumps(enc_json), s)
                self.disconnect_socket(s)
            except:
                self.connected_et = "-1"
                break
            sleep(2)
            if self.fly:
                self.battery = self.battery - (100 / 30)
                if self.battery <= 0:
                    self.fly = False
                    self.battery = 0
        self.fly = False  # Si se desconecta la batería se pone al máximo y aterriza
        self.battery = 100

    """
      FUNCIÓN: void parse_listen(JSON recv_json, socket connection)
      ARGS_IN: recv_json - JSON con el mensaje recibido
               connection - socket utilizado para responder al emisor
      DESCRIPCIÓN: Función encargada de parsear el JSON recibido en el socket de escucha
    """
    def parse_listen(self, recv_json, connection):
        if recv_json["msg_type"] == "LINK":  # For temp links w/ BO (fly/land)
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
            self.print_listen(f"{Color.GREEN}TEMP_LINK: {Color.END}" +
                              f"{Color.BLUE}{recv_json['src_id']}{Color.END}" +
                              " creado")
            return

        src_id, msg_type, dec_json = self.dec_json(recv_json)

        if msg_type == "FLY":
            self.fly = True
            self.send_msg(self.encrypt_str("OK", src_id), connection)
            self.print_listen(Color.TURQUOISE + "VOLANDO" + Color.END)
        elif msg_type == "LAND":
            self.fly = False
            self.battery = 100
            self.send_msg(self.encrypt_str("OK", src_id), connection)
            self.print_listen(Color.YELLOW + "EN TIERRA" + Color.END)
        elif msg_type == "DISCONNECT":
            print()
            self.disconnect()
            print(">>> ", end="")
            sys.stdout.flush()  # output previous print without a \n
        elif msg_type == "UNLINK":  # For temp links w/ BO (fly/land)
            self.send_msg(self.encrypt_str("OK", src_id), connection)
            self.linked_aes.pop(src_id, None)
            self.print_listen(f"{Color.GREEN}TEMP_UNLINK: {Color.END}" +
                              f"{Color.BLUE}{src_id}{Color.END} eliminado")
        else:
            print(Color.RED + "Error: " + Color.END +
                  "Tipo de mensaje no reconocido en " + json.dumps(dec_json))

    """
      FUNCIÓN: void exit()
      DESCRIPCIÓN: Se desconecta de la ET en caso de estar conectado 
                   y cierra el socket de escucha
    """
    def exit(self):
        if self.connected_et != "-1":
            self.disconnect()
        self.disconnect_socket(self.listen_socket)


if __name__ == '__main__':
    drone = Drone()
    drone.finish()
