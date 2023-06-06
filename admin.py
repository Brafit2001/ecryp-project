import json
import base64
from ownRsa import generate_keypair, encrypt, decrypt
from random import randint as rand
from ownHmac import hmac_verify_password, hmac_derive_password, extract_password
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

    def add_user(self, user: str, password: str):
        try:
            # Check if the user exists, if yes, we return error
            self.users[user]
            print("User already taken, choose another one.")
        except KeyError:
            # We select two prime numbers at random
            p = rand(1, 1000)
            q = rand(1, 1000)
            bit_length = 3
            # Generate the public and private keys
            public_key, private_key = generate_keypair(p, q, 2 ** bit_length)
            # Save keys in a .pem file
            self.save_keys(public_key, private_key, user)
            # Store the user information in the jsons files
            self.save_users_information(user, password)
            self.external_accounts[user] = {}
            self.shared_accounts[user] = {"shared_with_me": {}, "shared_with_other": []}
            self.save_json_information(self.external_accounts, "JSONS/users_external_accounts.json")
            self.save_json_information(self.shared_accounts, "JSONS/shared_accounts.json")

    def save_keys(self, public_key, private_key, user):
        private_key = str(private_key)
        # Encrypt the private key to provide greater security.
        ek = encrypt_key(private_key, self.passphrase)
        # Store the public key in a PEM file
        path_private_key = f"./RSA_keys/PRK_{user}.pem"
        with open(path_private_key, "wb") as f:
            f.write(ek)

        # Store the public key in a PEM file
        public_key = str(public_key)
        path_public_key = f"./RSA_keys/PUB_{user}.pem"
        with open(path_public_key, "w") as f:
            f.write(public_key)

    def log_in_check_user(self, user_name, user_password):
        try:
            # Retrieve the password derived from the user
            pwderivated = self.users[user_name]
            # Decode and extract the key
            key, salt = extract_password(pwderivated)
            # Verify the password is correct
            if hmac_verify_password(user_password, salt, key):
                return [True, self.users, ""]
            # Wrong Password
            return [False, None, "Error - Invalid credentials, please try again"]

        except KeyError:
            # Does not exist
            return [False, None, "Error - User not registered!"]

    @staticmethod
    def recover_json_information(route):
        # Return the json information
        with open(route, "r", encoding="utf-8", newline="") as file:
            json_content = json.load(file)
        return json_content

    def save_users_information(self, user: str, password: str):
        # function deriving the password
        salt, derivated_key = hmac_derive_password(password)
        # convert to bytes and then to string to store in the json
        b64_salt, b64_key = base64.urlsafe_b64encode(salt), base64.urlsafe_b64encode(derivated_key)
        b64_string_salt, b64_string_key = b64_salt.decode("ascii"), b64_key.decode("ascii")
        self.users[user] = [b64_string_salt, b64_string_key]
        self.save_json_information(self.users, "./JSONS/app_users.json")

    @staticmethod
    def save_json_information(dicc: dict, route: str):
        """Auxiliar method to dump a dictionary"""
        with open(route, "w", newline="") as file:
            json.dump(dicc, file, indent=2)  # lo vuelcas

    def add_external_account(self, site: str, app_user: str, user_name: str, password: str):
        try:
            # If there is no error, the user exists and therefore we print the message
            json_app_users = self.recover_json_information("JSONS/app_users.json")
            json_app_users[user_name]
            print("User already taken, choose another one.")
        except KeyError:
            self.save_external_account(site, app_user, user_name, password, "", "")

    def save_external_account(self, site: str, user: str, site_user: str, password: str, sec_quest: str, notes: str, ):
        # Password saving function
        try:
            # Retrieve the password derived from the user
            pwderivated = self.users[user]
            # Decode and extract the key
            key, salt = extract_password(pwderivated)

            # We gather all the information in a single field.
            ciph = "User:" + str(site_user) + "," + "Password:" + str(password) + "," + "sec_quest:" + str(
                sec_quest) + "," + "notes:" + str(notes)

            # Encrypt the message
            answer = encrypt_password(ciph, key)

            # Save the encrypted message
            json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
            json_external_accounts[user][site] = answer
            self.save_json_information(json_external_accounts, "./JSONS/users_external_accounts.json")

        except KeyError:
            print(ANSI_RED + "Error: unable to save account" + ANSI_RESET)

    def show(self, user: str, option):
        """Function to print passwords """
        try:

            if option == 'shared_woth':
                # Prints out passwords that the user shares with others
                user_sites = self.recover_json_information("./JSONS/shared_accounts.json")[user]['shared_with_other']

                for site in user_sites:
                    print(TAB + ANSI_RED + site + ANSI_RESET)

            elif option == 'shared_wme':
                # Prints out passwords that have been shared with the user
                user_sites = self.recover_json_information("./JSONS/shared_accounts.json")[user]['shared_with_me']
                l2 = []
                for site in user_sites:
                    # Go through each site saved by the user and collect the information.
                    for field in user_sites[site]:
                        l2.append(field)

                    # Retrieve the private key of the user
                    key2 = self.load_private_key(user)

                    # Decrypts the stored information with the private key
                    message = ""
                    for element in l2:
                        message += decrypt(element, key2)
                    # Prints the information on the screen
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
                # Retrieve the password derived from the user
                pwderivated = self.users[user]
                # Decode and extract the key
                key, salt = extract_password(pwderivated)

                for site in user_sites:
                    # For each site saved by the user, the information is decrypted and printed on the screen.
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
        """method for deleting the user site"""
        try:
            json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
            del json_external_accounts[user][site]
            self.save_json_information(json_external_accounts,"./JSONS/users_external_accounts.json")

        except KeyError:
            print(ANSI_RED+"Error: site not found"+ANSI_RESET)

    def load_private_key(self, user):
        """Method for obtaining a user's private key"""
        file_path = f"./RSA_keys/PRK_{user}.pem"
        with open(file_path, 'r') as f:
            # We read the contents of the file and decrypt it.
            content = f.read()
            k = decrypt_key(content, self.passphrase)
            p_list = k.replace("(", '').replace(")", '').split(', ')
            t = (int(p_list[0]), int(p_list[1]))
            return t

    def load_public_key(self, user):
        """Method for obtaining a user's public key"""
        file_path = f"./RSA_keys/PUB_{user}.pem"
        with open(file_path, 'r') as f:
            content = f.read()
            p_list = content.replace("(", '').replace(")", '').split(', ')
            t = (int(p_list[0]), int(p_list[1]))
            return t

    def share_password(self, user1: str, user2: str, site: str):
        """method for user1 to share the site password with user2"""

        json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
        shared_accounts = self.recover_json_information("./JSONS/shared_accounts.json")

        try:
            u1 = json_external_accounts[user1]  # check that the user to be shared is registered in external_accounts
            u2 = json_external_accounts[user2]

            user_sites = json_external_accounts[user1]
            # Retrieve the password derived from the user
            pwderivated = self.users[user1]
            # Decode and extract the key
            key, salt = extract_password(pwderivated)

            # Decrypt the message (Information to be shared with the user 2)
            message = decrypt_password(user_sites[site][0], user_sites[site][1], key)
            lista = []
            characters = ''
            for i in message:
                characters += i
                if i == ",":
                    lista.append(characters)
                    characters = ''

            # Obtain the public key of user 2
            public_key = self.load_public_key(user2)

            e_list = []
            for element in lista:
                # Encrypt with the public key of user2
                encrypted_message = encrypt(element, public_key)
                e_list.append(encrypted_message)

            shared_accounts[user1]["shared_with_other"].append(site)
            shared_accounts[user2]['shared_with_me'][
                site] = e_list  # the info is saved in a list with the site and the password.

            self.save_json_information(json_external_accounts, "./JSONS/users_external_accounts.json")
            self.save_json_information(shared_accounts, "./JSONS/shared_accounts.json")

        except KeyError as e:  # if you have not found either of the two sites of the sending and receiving users
            print("ERROR: ",e)
            print(TAB + ANSI_RED + "Error: unable to share password" + ANSI_RESET)