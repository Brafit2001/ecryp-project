import json
import base64
from ownRsa import generate_keypair, encrypt, decrypt
from random import randint as rand
from ownHmac import hmac_verify_password, hmac_derive_password
from symetricEncrypt import encrypt_password, decrypt_password, encrypt_key, decrypt_key

ANSI_RESET = "\u001B[0m"
ANSI_BLACK = "\u001B[30m"
ANSI_RED = "\u001B[31m"
ANSI_GREEN = "\u001B[32m"
ANSI_YELLOW = "\u001B[33m"
ANSI_BLUE = "\u001B[34m"
ANSI_PURPLE = "\u001B[35m"
ANSI_CYAN = "\u001B[36m"
ANSI_WHITE = "\u001B[37m"
TAB = '\t' * 7


class Admin:
    def __init__(self):
        self.users = self.recover_json_information("./JSONS/app_users.json")
        self.external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
        self.shared_accounts = self.recover_json_information("./JSONS/shared_accounts.json")
        self.passphrase = "ECRYP"

    # versión para diccionario

    def add_user(self, user: str, password: str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            self.users[user]
            print("User already taken, choose another one.")
        except KeyError:
            p = rand(1, 1000)
            q = rand(1, 1000)
            bit_length = 3
            public_key, private_key = generate_keypair(p, q, 2 ** bit_length)
            self.save_keys(public_key, private_key, user)
            self.save_users_information(user, password)
            self.external_accounts[user] = {}
            self.shared_accounts[user] = {"shared_with_me": {}, "shared_with_other": []}
            self.save_json_information(self.external_accounts, "JSONS/users_external_accounts.json")
            self.save_json_information(self.shared_accounts, "JSONS/shared_accounts.json")

    def save_keys(self, public_key, private_key, user):
        private_key = str(private_key)
        ek = encrypt_key(private_key, self.passphrase)

        path_private_key = f"./RSA_keys/PRK_{user}.pem"
        with open(path_private_key, "wb") as f:
            f.write(ek)

        # Guarda la clave pública en un archivo PEM
        public_key = str(public_key)
        path_public_key = f"./RSA_keys/PUB_{user}.pem"
        with open(path_public_key, "w") as f:
            f.write(public_key)

    def log_in_check_user(self, user_name, user_password):
        try:
            pwderivated = self.users[user_name]  # recoge la información cifrada
            key, salt = self.extract_password(pwderivated)

            if hmac_verify_password(user_password, salt, key):
                return [True, self.users]

            print("Error - User not registered!")
            return [False, None]

        except KeyError:
            # no existe
            return [False, None]

    @staticmethod
    def recover_json_information(route):
        with open(route, "r", encoding="utf-8", newline="") as file:
            json_content = json.load(file)
        return json_content

    def save_users_information(self, user: str, password: str):
        # función que deriva la contraseña
        salt, derivated_key = hmac_derive_password(password)
        # convertimos a bytes y luego a string para guardarlo en el json
        b64_salt, b64_key = base64.urlsafe_b64encode(salt), base64.urlsafe_b64encode(derivated_key)
        b64_string_salt, b64_string_key = b64_salt.decode("ascii"), b64_key.decode("ascii")
        self.users[user] = [b64_string_salt, b64_string_key]
        self.save_json_information(self.users, "./JSONS/app_users.json")

    @staticmethod
    def extract_password(pwderivated):
        b64_salt = pwderivated[0]
        b64_key = pwderivated[1]
        b64_salt_bytes = b64_salt.encode("ascii")
        salt = base64.urlsafe_b64decode(b64_salt_bytes)
        b64_key_bytes = b64_key.encode("ascii")
        key = base64.urlsafe_b64decode(b64_key_bytes)
        return key, salt

    @staticmethod
    def save_json_information(dicc: dict, route: str):
        """Auxiliar method to dump a dictionary"""
        with open(route, "w", newline="") as file:
            json.dump(dicc, file, indent=2)  # lo vuelcas

    def add_external_account(self, site: str, app_user: str, user_name: str, password: str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            json_app_users = self.recover_json_information("JSONS/app_users.json")
            json_app_users[user_name]
            print("User already taken, choose another one.")
        except KeyError:
            self.save_external_account(site, app_user, user_name, password, "", "")

    def save_external_account(self, site: str, user: str, site_user: str, password: str, sec_quest: str, notes: str, ):
        # recuperamos la información antigua del external accounts
        # encriptar
        try:
            pwderivated = self.users[user]

            key, salt = self.extract_password(pwderivated)
            # guardamos la info en un str
            ciph = "User:" + str(site_user) + "," + "Password:" + str(password) + "," + "sec_quest:" + str(
                sec_quest) + "," + "notes:" + str(notes)

            answer = encrypt_password(ciph, key)  # en formato de lista, ver si da error

            json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
            json_external_accounts[user][site] = answer
            self.save_json_information(json_external_accounts, "./JSONS/users_external_accounts.json")

        except KeyError:
            print(ANSI_RED + "Error: unable to save account" + ANSI_RESET)

    def show(self, user: str, option):

        try:

            if option == 'shared_woth':
                user_sites = self.recover_json_information("./JSONS/shared_accounts.json")[user]['shared_with_other']

                for site in user_sites:
                    print(TAB + ANSI_RED + site + ANSI_RESET)

            elif option == 'shared_wme':
                user_sites = self.recover_json_information("./JSONS/shared_accounts.json")[user]['shared_with_me']
                l2 = []
                for site in user_sites:
                    for field in user_sites[site]:
                        l2.append(field)

                    key2 = self.load_private_key(user)


                    message = ""
                    for element in l2:
                        message += decrypt(element, key2)
                    print(TAB + ANSI_RED + site + ":" + ANSI_RESET)
                    characters = ''
                    for i in message:
                        characters += i
                        if i == ",":
                            print(TAB + "\t" + ANSI_CYAN + characters + ANSI_RESET)
                            characters = ''
                    l2 = []

            else:
                user_sites = self.recover_json_information("./JSONS/users_external_accounts.json")[user]

                pwderivated = self.users[user]
                key, salt = self.extract_password(pwderivated)

                for site in user_sites:
                    message = decrypt_password(user_sites[site][0], user_sites[site][1], key)
                    print(TAB + ANSI_RED + site + ":" + ANSI_RESET)
                    characters = ''
                    for i in message:
                        characters += i
                        if i == ",":
                            print(TAB + ANSI_CYAN + characters + ANSI_RESET)
                            characters = ''
                    print(TAB + "__________________________________________________________")

        except KeyError:
            print(str(user)+": {}")

    def delete_password(self, user:str,site:str):
        """método para borrar el site de user"""
        try:
            json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
            del json_external_accounts[user][site]
            self.save_json_information(json_external_accounts,"./JSONS/users_external_accounts.json")

        except KeyError:
            print(ANSI_RED+"Error: site not found"+ANSI_RESET)

    def load_private_key(self, user):
        file_path = f"./RSA_keys/PRK_{user}.pem"
        with open(file_path, 'r') as f:
            content = f.read()
            k = decrypt_key(content, self.passphrase)
            p_list = k.replace("(", '').replace(")", '').split(', ')
            t = (int(p_list[0]), int(p_list[1]))
            return t

    def load_public_key(self, user):
        file_path = f"./RSA_keys/PUB_{user}.pem"
        with open(file_path, 'r') as f:
            content = f.read()
            p_list = content.replace("(", '').replace(")", '').split(', ')
            t = (int(p_list[0]), int(p_list[1]))
            return t

    def share_password(self, user1: str, user2: str, site: str):
        """método para que user1 le comparta a user2 la contraseña de site"""

        json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
        shared_accounts = self.recover_json_information("./JSONS/shared_accounts.json")

        try:
            u1 = json_external_accounts[user1]  # comprobamos que el usuario que va a compartir está registrado en external_accounts
            u2 = json_external_accounts[user2]  # comprobamos que el usuario que va a compartir está registrado en external_accounts

            user_sites = json_external_accounts[user1]
            pwderivated = self.users[user1]

            key, salt = self.extract_password(pwderivated)

            message = decrypt_password(user_sites[site][0], user_sites[site][1], key)
            lista = []
            characters = ''
            for i in message:
                characters += i
                if i == ",":
                    lista.append(characters)
                    characters = ''

            public_key = self.load_public_key(user2)

            e_list = []
            for element in lista:
                encrypted_message = encrypt(element, public_key)
                e_list.append(encrypted_message)

            shared_accounts[user1]["shared_with_other"].append(site)
            shared_accounts[user2]['shared_with_me'][
                site] = e_list  # se guarda en una lista la info con el sitio y la contraseña

            self.save_json_information(json_external_accounts, "./JSONS/users_external_accounts.json")
            self.save_json_information(shared_accounts, "./JSONS/shared_accounts.json")

        except KeyError as e:  # si no ha encontrado alguno de los dos sites de los usuarios emisor y receptor
            print("ERROR: ",e)
            print(TAB + ANSI_RED + "Error: unable to share password" + ANSI_RESET)