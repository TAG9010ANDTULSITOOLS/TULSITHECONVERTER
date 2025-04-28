# encryptors/hybrid_chacha_encryptor.py
# Licensed under the TAG9010 LICENSE
# (See LICENSE file for full license text.)

from Crypto.Cipher import ChaCha20, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 260000

class HybridRSA_ChaCha20_Encryptor:
    def __init__(self, public_key_pem, password):
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        self.public_key = RSA.import_key(public_key_pem)
        self.password = password.encode('utf-8')

    def encrypt(self, plaintext_bytes):
        chacha_key = PBKDF2(self.password, get_random_bytes(16), dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        nonce = get_random_bytes(8)
        cipher_chacha = ChaCha20.new(key=chacha_key, nonce=nonce)
        ciphertext = cipher_chacha.encrypt(plaintext_bytes)
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_chacha_key = cipher_rsa.encrypt(chacha_key)
        return encrypted_chacha_key + nonce + ciphertext

    def decrypt(self, private_key_pem, encrypted_package, password):
        private_key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        encrypted_chacha_key = encrypted_package[:private_key.size_in_bytes()]
        nonce = encrypted_package[private_key.size_in_bytes():private_key.size_in_bytes()+8]
        ciphertext = encrypted_package[private_key.size_in_bytes()+8:]
        chacha_key = cipher_rsa.decrypt(encrypted_chacha_key)
        cipher_chacha = ChaCha20.new(key=chacha_key, nonce=nonce)
        return cipher_chacha.decrypt(ciphertext)
