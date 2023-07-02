import argparse
import json
import os
from base64 import b64encode, b64decode
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from element import Element, Color

"""
  CLASE: BO
  DESCRIPCIÓN: Implementa todos los comandos de la base de operaciones
  AUTHORS: luis.lepore@estudiante.uam.es
           oriol.julian@estudiante.uam.es
"""


class BO(Element):

    """
      FUNCIÓN: void __init__()
      DESCRIPCIÓN: Constructor
    """
    def __init__(self):
        self.ID = "BO0"
        self.LISTEN_PORT = self.BO_PORT  # 10000
        self.elements = {
            self.ID: self.BO_PORT,
            "ET": [],
            "Drone": []
        }
        super().__init__()

    """
      FUNCIÓN: void parse_arguments(String input_str)
      ARGS_IN: input_str - Comando escrito por el usuario para ser parseado
      DESCRIPCIÓN: Analiza la cadena de caracteres escrita por el usuario 
                   en el menú y ejecuta las funciones correspondientes
    """
    def parse_arguments(self, input_str):
        parser = argparse.ArgumentParser()
        parser.add_argument('--et-id', nargs=1)
        parser.add_argument('--drone-id', nargs=1)

        parser.add_argument('--send_msg', nargs='+',
                            help="Envía un mensaje. Debe contener un --et-id")
        parser.add_argument('--send_file', nargs=1,
                            help="Envía un fichero. Debe contener un --et-id")
        parser.add_argument('--fly', action='store_true', default=None,
                            help="Hace volar a un drone. " +
                            "Debe contener un --drone-id")
        parser.add_argument('--land', action='store_true', default=None,
                            help="Hace aterrizar a un drone. " +
                            "Debe contener un --drone-id")
        parser.add_argument('--get_status', action='store_true', default=None,
                            help="Obtiene el status de " +
                            "todos los elementos del sistema")
        parser.add_argument('--shutdown', action='store_true', default=None,
                            help="Manda desvincular a " +
                            "todas las ETs y desconecta sus drones")

        args = parser.parse_args(input_str.split())

        if args.send_msg is not None:
            if args.et_id is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --et-id")
                return
            self.send_msg_to_element(' '.join(args.send_msg), args.et_id[0])

        elif args.send_file is not None:
            if args.et_id is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --et-id")
                return
            self.send_file(args.send_file[0], args.et_id[0])
        elif args.fly is not None:
            if args.drone_id is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --drone-id")
                return
            self.fly(args.drone_id[0])
        elif args.land is not None:
            if args.drone_id is None:
                print(f"{Color.RED}Error:{Color.END} " +
                      "Se debe introducir un --drone-id")
                return
            self.land(args.drone_id[0])
        elif args.get_status is not None:
            status = self.get_status()
            print(Color.GREEN + "GET STATUS:" + Color.END)
            if not status:
                print("No se ha encontrado ninguna ET")
                return
            for et_id in status:
                print(f"{Color.BLUE}{et_id}{Color.END}:")
                print("  Drones vinculados: " + Color.BLUE +
                      str(status[et_id]["vinculados"]) + Color.END)
                print("  Drones conectados: ")
                for drone_id in status[et_id]["conectados"]:
                    print(f"    {Color.BLUE}{drone_id}{Color.END}: " +
                          (f"{Color.TURQUOISE}Volando " if
                           status[et_id]["conectados"][drone_id]["fly"]
                           else f"{Color.YELLOW}En tierra ") + Color.END +
                          status[et_id]["conectados"][drone_id]["battery"]
                          + "%")
        elif args.shutdown is not None:
            self.shutdown()

    """
      FUNCIÓN: void fly_land(String drone_id, String message)
      ARGS_IN: drone_id - ID del dron
               message - "FLY" o "LAND" respectivamente
      DESCRIPCIÓN: Hace que un dron vuele o aterrice utilizando una ET como intermediario
    """
    def fly_land(self, drone_id, message):
        status = self.get_status()
        et_id = [et_id for et_id in status
                 if drone_id in status[et_id]["conectados"]]
        if len(et_id) == 0:
            print(f"{Color.RED}Error: {Color.BLUE}{drone_id}{Color.END} " +
                  "no está conectado a ninguna ET")
            return
        et_id = et_id[0]

        # LINK
        if not self.connect_socket(et_id):
            print(f"{Color.BLUE}{et_id}{Color.END} no encontrada")
            return

        drone_json = {'src_id': self.ID,
                      'msg_type': "LINK", 'p_key': self.public_key}
        enc_et_json = self.enc_json(
            {"dest_json": json.dumps(drone_json),
             'dest_id': drone_id}, "REDIRECT", et_id)
        self.send_msg(json.dumps(enc_et_json), self.send_socket)
        recv_json = json.loads(self.recv_msg(self.send_socket))
        self.disconnect_socket(self.send_socket)
        iv = b64decode(recv_json["iv"])
        key = PKCS1_OAEP.new(RSA.importKey(self.private_key)).decrypt(
            b64decode(recv_json["key"]))
        encrypt_aes = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypt_aes = AES.new(key, AES.MODE_CBC, iv=iv)
        self.linked_aes[drone_id] = (encrypt_aes, decrypt_aes)
        print(f"{Color.GREEN}TEMP_LINK:{Color.END} " +
              f"{Color.BLUE}{drone_id}{Color.END}")

        # FLY/LAND
        if not self.connect_socket(et_id):
            print(f"{Color.BLUE}{et_id}{Color.END} no encontrada")
            return

        enc_drone_json = self.enc_json({}, message, drone_id)
        enc_et_json = self.enc_json(
            {'dest_json': json.dumps(enc_drone_json), 'dest_id': drone_id},
            "REDIRECT", et_id)
        self.send_msg(json.dumps(enc_et_json), self.send_socket)
        stat_msg = self.decrypt_str(self.recv_msg(self.send_socket), drone_id)
        self.disconnect_socket(self.send_socket)
        print(f"{Color.GREEN}{message}: " +
              f"{Color.BLUE}{drone_id}{Color.END} de " +
              f"{Color.BLUE}{et_id}{Color.END} ({stat_msg})")

        # UNLINK
        if not self.connect_socket(et_id):
            print(f"{Color.BLUE}{et_id}{Color.END} no encontrada")
            return

        enc_drone_json = self.enc_json({}, "UNLINK", drone_id)
        enc_et_json = self.enc_json(
            {'dest_json': json.dumps(enc_drone_json), 'dest_id': drone_id},
            "REDIRECT", et_id)
        self.send_msg(json.dumps(enc_et_json), self.send_socket)
        stat_msg = self.decrypt_str(self.recv_msg(self.send_socket), drone_id)
        self.disconnect_socket(self.send_socket)
        self.linked_aes.pop(drone_id, None)
        print(f"{Color.GREEN}TEMP_UNLINK:{Color.END} " +
              f"{Color.BLUE}{drone_id}{Color.END} ({stat_msg})")

    """
      FUNCIÓN: void fly(String drone_id)
      ARGS_IN: drone_id - ID del dron
      DESCRIPCIÓN: Llama a fly_land con "FLY" como message
    """
    def fly(self, drone_id):
        self.fly_land(drone_id, "FLY")

    """
      FUNCIÓN: void land(String drone_id)
      ARGS_IN: drone_id - ID del dron
      DESCRIPCIÓN: Llama a fly_land con "LAND" como message
    """
    def land(self, drone_id):
        self.fly_land(drone_id, "LAND")

    """
      FUNCIÓN: JSON get_status()
      ARGS_OUT: JSON con las ETs conectadas y con la información 
                de los drones vinculados y conectados a estas ETs
      DESCRIPCIÓN: Método que permite averiguar el estado actual
                   de todos los elementos en el sistema
    """
    def get_status(self):
        status = {}
        for et in self.linked_aes:
            if not self.connect_socket(et):
                print(f"{Color.BLUE}{et}{Color.END} no encontrada")
                continue
            enc_json = self.enc_json({}, "GET_STATUS", et)
            self.send_msg(json.dumps(enc_json), self.send_socket)
            status[et] = json.loads(
                self.decrypt_str(self.recv_msg(self.send_socket), et))
            self.disconnect_socket(self.send_socket)
        return status

    """
      FUNCIÓN: void shutdown()
      DESCRIPCIÓN: Hace que todas las ETs se deconecten y que 
                   sus drones asociados aterricen y se desconecten 
    """
    def shutdown(self):
        status = self.get_status()
        for et_id in status:
            if not self.connect_socket(et_id):
                print(f"{Color.BLUE}{et_id}{Color.END} no encontrada")
                return

            enc_json = self.enc_json({}, "SHUTDOWN", et_id)
            self.send_msg(json.dumps(enc_json), self.send_socket)
            self.disconnect_socket(self.send_socket)

    """
      FUNCIÓN: void parse_listen(JSON recv_json, socket connection)
      ARGS_IN: recv_json - JSON con el mensaje recibido
               connection - socket utilizado para responder al emisor
      DESCRIPCIÓN: Función encargada de parsear el JSON recibido en el socket de escucha
    """
    def parse_listen(self, recv_json, connection):
        if recv_json["msg_type"] == "GET_ID":
            class_name = recv_json["class"]
            id_generated = class_name + str(len(self.elements[class_name]))
            self.elements[class_name].append(id_generated)
            self.send_msg(id_generated, connection)
            return

        elif recv_json["msg_type"] == "LINK":
            if recv_json["src_id"] in self.linked_aes:
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
            self.print_listen(Color.BLUE + recv_json["src_id"] + Color.END +
                              " vinculada\nETs vinculadas: " +
                              self.get_keys(self.linked_aes))
            return

        src_id, msg_type, dec_json = self.dec_json(recv_json)

        if msg_type == "UNLINK":
            self.linked_aes.pop(src_id, None)
            self.print_listen(Color.BLUE + src_id + Color.END +
                              " desvinculada\nETs vinculadas: " +
                              self.get_keys(self.linked_aes))

        elif msg_type == "SEND_MSG":
            self.print_listen(Color.GREEN + "SEND MSG: " + Color.END +
                              dec_json["message"])

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

        else:
            print(Color.RED + "Error: " + Color.END +
                  "Tipo de mensaje no reconocido en " + json.dumps(dec_json))

    """
      FUNCIÓN: void exit()
      DESCRIPCIÓN: Ejecuta shutdown() y cierra el socket de escucha
    """
    def exit(self):
        self.shutdown()
        self.disconnect_socket(self.listen_socket)


if __name__ == '__main__':
    bo = BO()
    bo.finish()
