import base64
import hashlib
import os


def generate_hmac(key, message):
    # Generate the HMAC using SHA-256

    # Compute the HMAC key by hashing the key with SHA-256
    hmac_key = hashlib.sha256(key).digest()

    # Compute the HMAC hash by concatenating the HMAC key with the UTF-8 encoded message
    # and hashing the result with SHA-256
    hmac_hash = hashlib.sha256(hmac_key + message.encode('utf-8')).hexdigest()

    # Return the HMAC hash
    return hmac_hash


def hmac_derive_password(password, salt=None, iterations=100000, key_length=32, hash_function=hashlib.sha256):
    password = password.encode('utf-8')  # Convert password to bytes using UTF-8 encoding

    if salt is None:
        salt = os.urandom(16)  # Generates a random salt if one is not provided.

    block_size = hash_function().block_size  # Get the block size of the hash function
    if len(password) > block_size:
        password = hash_function(password).digest()  # Hash password if it exceeds block size
    password = password.ljust(block_size, b'\x00')  # Pad password with null bytes if necessary

    inner_padding = b"\x36" * block_size  # Inner padding consists of repeating bytes 0x36
    outer_padding = b"\x5C" * block_size  # Outer padding consists of repeating bytes 0x5C

    inner_key = bytes([x ^ y for x, y in zip(password, inner_padding)])  # Compute inner key using XOR operation
    outer_key = bytes([x ^ y for x, y in zip(password, outer_padding)])  # Compute outer key using XOR operation

    def hmac_hash(data):
        inner_hash = hash_function(inner_key + data).digest()  # Compute inner hash
        return hash_function(outer_key + inner_hash).digest()  # Compute outer hash

    derived_key = salt
    for _ in range(iterations):
        derived_key = hmac_hash(derived_key)  # Iterate and compute derived key

    # Returns the salt and derived key
    return salt, derived_key[:key_length]


def hmac_verify_password(password, salt, derived_key, iterations=100000, key_length=32, hash_function=hashlib.sha256):
    # Compute the derived key using the same parameters as the derivation process
    derived_key_check = hmac_derive_password(password, salt, iterations, key_length, hash_function)[1]

    # Compare the derived key with the provided derived key
    return derived_key_check == derived_key


def extract_password(pwderivated):
    # Extract the base64-encoded salt and key from the input
    b64_salt = pwderivated[0]
    b64_key = pwderivated[1]

    # Convert the base64-encoded salt and key to bytes
    b64_salt_bytes = b64_salt.encode("ascii")
    b64_key_bytes = b64_key.encode("ascii")

    # Decode the base64-encoded salt and key to obtain the original bytes
    salt = base64.urlsafe_b64decode(b64_salt_bytes)
    key = base64.urlsafe_b64decode(b64_key_bytes)

    # Return the key and salt
    return key, salt

