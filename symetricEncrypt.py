import base64

from ownHmac import generate_hmac, hmac_derive_password, hmac_verify_password


def encrypt_key(key, passphrase):
    # Convierte la clave y la contraseña en bytes
    key_bytes = key.encode()
    passphrase_bytes = passphrase.encode()

    # Realiza el cifrado XOR byte a byte usando la contraseña
    encrypted_key = bytearray()
    for i, byte in enumerate(key_bytes):
        encrypted_byte = byte ^ passphrase_bytes[i % len(passphrase_bytes)]
        encrypted_key.append(encrypted_byte)

    # Codifica el resultado en Base64
    encoded_key = base64.b64encode(encrypted_key)

    return encoded_key


def decrypt_key(encrypted_key, passphrase):
    # Decodifica la clave encriptada en Base64
    encrypted_key = base64.b64decode(encrypted_key)

    # Convierte la contraseña en bytes
    passphrase_bytes = passphrase.encode()

    # Realiza el descifrado XOR byte a byte usando la contraseña
    decrypted_key = bytearray()
    for i, byte in enumerate(encrypted_key):
        decrypted_byte = byte ^ passphrase_bytes[i % len(passphrase_bytes)]
        decrypted_key.append(decrypted_byte)

    # Convierte la clave descifrada a una cadena de texto
    key = decrypted_key.decode()

    return key


def encrypt_password(message, key):
    answer = [None, None]
    encrypted_message = ""
    key_length = len(key)

    for i in range(len(message)):
        char = message[i]
        key_char = chr(key[i % key_length])
        encrypted_char = chr(ord(char) ^ ord(key_char))
        encrypted_message += encrypted_char

    # Generar el código de autenticación HMAC
    hmac_signature = generate_hmac(key, encrypted_message)
    answer[0] = encrypted_message
    answer[1] = hmac_signature

    return answer


def decrypt_password(encrypted_password, hmac_signature, key):
    # Verificar el código de autenticación HMAC
    expected_hmac_signature = generate_hmac(key, encrypted_password)

    if expected_hmac_signature == hmac_signature:
        # Descifrado XOR
        decrypted_password = ""
        key_length = len(key)

        for i in range(len(encrypted_password)):
            char = encrypted_password[i]
            key_char = chr(key[i % key_length])
            decrypted_char = chr(ord(char) ^ ord(key_char))
            decrypted_password += decrypted_char

        return decrypted_password
    else:
        return None
