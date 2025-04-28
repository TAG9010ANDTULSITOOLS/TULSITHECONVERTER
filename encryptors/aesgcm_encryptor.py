# encryptors/aesgcm_encryptor.py
# Licensed under the TAG9010 LICENSE
# (See LICENSE file for full license text.)

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 260000

class AESGCMEncryptor:
    def __init__(self, password, salt=None):
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        self.password = password.encode('utf-8')
        self.salt = salt if salt else get_random_bytes(16)
        self.key = PBKDF2(self.password, self.salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

    def encrypt(self, plaintext_bytes):
        cipher = AES.new(self.key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        return self.salt + nonce + tag + ciphertext

    def decrypt(self, encrypted_package):
        if len(encrypted_package) < 48:
            raise ValueError("Invalid encrypted package for AES-GCM.")
        salt = encrypted_package[:16]
        nonce = encrypted_package[16:32]
        tag = encrypted_package[32:48]
        ciphertext = encrypted_package[48:]
        key = PBKDF2(self.password, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
