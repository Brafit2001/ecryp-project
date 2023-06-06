import base64

from ownHmac import generate_hmac, hmac_derive_password, hmac_verify_password


def encrypt_key(key, passphrase):
    # Convert the key and passphrase to bytes
    key_bytes = key.encode()
    passphrase_bytes = passphrase.encode()

    # Perform XOR encryption byte by byte using the passphrase
    encrypted_key = bytearray()
    for i, byte in enumerate(key_bytes):
        encrypted_byte = byte ^ passphrase_bytes[i % len(passphrase_bytes)]
        encrypted_key.append(encrypted_byte)

    # Encode the result in Base64
    encoded_key = base64.b64encode(encrypted_key)

    return encoded_key


def decrypt_key(encrypted_key, passphrase):
    # Decode the encrypted key from Base64
    encrypted_key = base64.b64decode(encrypted_key)

    # Convert the passphrase to bytes
    passphrase_bytes = passphrase.encode()

    # Perform XOR decryption byte by byte using the passphrase
    decrypted_key = bytearray()
    for i, byte in enumerate(encrypted_key):
        decrypted_byte = byte ^ passphrase_bytes[i % len(passphrase_bytes)]
        decrypted_key.append(decrypted_byte)

    # Convert the decrypted key to a string
    key = decrypted_key.decode()

    return key


def encrypt_password(message, key):
    # Initialize the answer list with None values
    answer = [None, None]

    # Initialize an empty string for the encrypted message
    encrypted_message = ""

    # Determine the length of the key
    key_length = len(key)

    # Perform XOR encryption character by character
    for i in range(len(message)):
        char = message[i]
        key_char = chr(key[i % key_length])
        encrypted_char = chr(ord(char) ^ ord(key_char))
        encrypted_message += encrypted_char

    # Generate the HMAC signature
    hmac_signature = generate_hmac(key, encrypted_message)

    # Store the encrypted message and HMAC signature in the answer list
    answer[0] = encrypted_message
    answer[1] = hmac_signature

    return answer


def decrypt_password(encrypted_password, hmac_signature, key):
    # Verify the HMAC signature
    expected_hmac_signature = generate_hmac(key, encrypted_password)

    if expected_hmac_signature == hmac_signature:
        # XOR decryption
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
