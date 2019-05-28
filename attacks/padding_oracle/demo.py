import base64
import binascii
import os
import struct
import time
import timeit

import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


class InvalidToken(Exception):
    pass


class InvalidPadding(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class VulnerableFernet():
    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "VulnerableFernet key must be 32 url-safe base64-encoded bytes."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        # PROBLEM: MAC-then-Encrypt

        # HMAC(HDR|R)
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        basic_parts = (b"\x80" + struct.pack(">Q", current_time) + data)
        h.update(basic_parts)
        hmac = h.finalize()

        # R|T|pad
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data + hmac) + padder.finalize()

        encryptor = Cipher(algorithms.AES(self._encryption_key),
                           modes.CBC(iv), self._backend).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        final_message = b"\x80" + \
            struct.pack(">Q", current_time) + iv + ciphertext

        return base64.urlsafe_b64encode(final_message)

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        iv = data[9:25]
        ciphertext = data[25:]
        decryptor = Cipher(algorithms.AES(self._encryption_key),
                           modes.CBC(iv), self._backend).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        # TODO: interpret data as 0 length pad when padding error raised
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidPadding

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[0:9] + unpadded[:-32])
        try:
            h.verify(unpadded[-32:])
        except InvalidSignature:
            raise InvalidToken

        return unpadded[:-32]


class Server():
    def __init__(self, fernet):
        self.fernet = fernet
        self.database = list()

    def receive(self, token):
        message = fernet.decrypt(token)
        self.database.append(message)  # fake operation


def run_demo():
    key = VulnerableFernet.generate_key()
    f = VulnerableFernet(key)
    message = 'hello'.encode(encoding='utf-8')
    token = f.encrypt(message)
    server = Server(f)
    mitm(server, token)


'''
assumes that attacker has no access to key or message
'''


def mitm(server, token):
    data = base64.urlsafe_b64decode(token)
    ciphertext = data[25:]
    ciphertext[-1] = (0).to_bytes(length=1)
    server.receive()


# if __name__ == '__main__':
    # time = timeit.timeit(stmt='client()', setup='from __main__ import client', number=1, timer=time.perf_counter)
    # print(time)
run_demo()
