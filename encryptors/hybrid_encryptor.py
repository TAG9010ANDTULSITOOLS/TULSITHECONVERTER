# encryptors/hybrid_encryptor.py
# Licensed under the TAG9010 LICENSE
# (See LICENSE file for full license text.)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 260000

class HybridRSA_AES_Encryptor:
    def __init__(self, public_key_pem, password):
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        self.public_key = RSA.import_key(public_key_pem)
        self.password = password.encode('utf-8')

    def encrypt(self, plaintext_bytes):
        # Generate AES key
        aes_key = PBKDF2(self.password, get_random_bytes(16), dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

        # Encrypt plaintext with AES
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        nonce = cipher_aes.nonce
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_bytes)

        # Encrypt AES key with RSA
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        return encrypted_aes_key + nonce + tag + ciphertext

    def decrypt(self, private_key_pem, encrypted_package, password):
        private_key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        encrypted_aes_key = encrypted_package[:private_key.size_in_bytes()]
        nonce = encrypted_package[private_key.size_in_bytes():private_key.size_in_bytes()+16]
        tag = encrypted_package[private_key.size_in_bytes()+16:private_key.size_in_bytes()+32]
        ciphertext = encrypted_package[private_key.size_in_bytes()+32:]

        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        return cipher_aes.decrypt_and_verify(ciphertext, tag)
