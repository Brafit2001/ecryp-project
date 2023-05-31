import hashlib
import os


def generate_hmac(key, message):
    # Generar el HMAC utilizando SHA-256
    hmac_key = hashlib.sha256(key).digest()
    hmac_hash = hashlib.sha256(hmac_key + message.encode('utf-8')).hexdigest()
    return hmac_hash


def hmac_derive_password(password, salt=None, iterations=100000, key_length=32, hash_function=hashlib.sha256):
    password = password.encode('utf-8')

    if salt is None:
        salt = os.urandom(16)  # Genera un salt aleatorio si no se proporciona uno

    block_size = hash_function().block_size
    if len(password) > block_size:
        password = hash_function(password).digest()
    password = password.ljust(block_size, b'\x00')

    inner_padding = b"\x36" * block_size
    outer_padding = b"\x5C" * block_size

    inner_key = bytes([x ^ y for x, y in zip(password, inner_padding)])
    outer_key = bytes([x ^ y for x, y in zip(password, outer_padding)])

    def hmac_hash(data):
        inner_hash = hash_function(inner_key + data).digest()
        return hash_function(outer_key + inner_hash).digest()

    derived_key = salt
    for _ in range(iterations):
        derived_key = hmac_hash(derived_key)

    # Devuelve el salt y la clave derivada
    return salt, derived_key[:key_length]


def hmac_verify_password(password, salt, derived_key, iterations=100000, key_length=32, hash_function=hashlib.sha256):
    derived_key_check = hmac_derive_password(password, salt, iterations, key_length, hash_function)[1]
    return derived_key_check == derived_key


