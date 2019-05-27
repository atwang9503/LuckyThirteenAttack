from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA

def main():
    message = b'To be encrypted'
    h = SHA.new(message)
    key = RSA.importKey(open('key').read())
    cipher = PKCS1_v1_5.new(key)
    ciphertext = cipher.encrypt(message+h.digest())
    print(ciphertext)