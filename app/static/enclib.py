import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import os

class enc:
    def __init__(self, key):
        self.key = key
        self.salt = None

    def encode_base64(self, message):
        return base64.b64encode(message)

    def decode_base64(self, encoded_message):
        return base64.b64decode(encoded_message)


    def aes_encrypt(self, plaintext, iv):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return (iv, ciphertext)

    def aes_decrypt(self, ciphertext, iv):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def salting(self):
        salt = os.urandom(16)
        hashed_password = hashlib.pbkdf2_hmac('sha512', self.key.encode('utf-8'), salt, 189389)
        self.salt = salt
        self.key = hashed_password
        return (salt, hashed_password)
        
