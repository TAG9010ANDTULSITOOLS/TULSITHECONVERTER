# encryptors/chacha20_encryptor.py
# Licensed under the TAG9010 LICENSE
# (See LICENSE file for full license text.)

from Crypto.Cipher import ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 260000

class ChaCha20Encryptor:
    def __init__(self, password, salt=None):
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        self.password = password.encode('utf-8')
        self.salt = salt if salt else get_random_bytes(16)
        self.key = PBKDF2(self.password, self.salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

    def encrypt(self, plaintext_bytes):
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext_bytes)
        return self.salt + nonce + ciphertext

    def decrypt(self, encrypted_package):
        if len(encrypted_package) < 24:
            raise ValueError("Invalid encrypted package for ChaCha20.")
        salt = encrypted_package[:16]
        nonce = encrypted_package[16:24]
        ciphertext = encrypted_package[24:]
        key = PBKDF2(self.password, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(ciphertext)
