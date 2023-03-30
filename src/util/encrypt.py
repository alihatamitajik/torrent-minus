from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes


def encrypt(msg, key):
    cipher = Salsa20.new(key)
    return cipher.nonce + cipher.encrypt(msg)


def decrypt(msg, key):
    return Salsa20.new(key, msg[:8]).decrypt(msg[8:])


def generate_key():
    return get_random_bytes(32)
