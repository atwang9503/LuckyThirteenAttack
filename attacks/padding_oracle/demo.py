import base64
import binascii
import os
import struct
import sys
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

        # HMAC(HDR+R)
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        basic_parts = (b"\x80" + struct.pack(">Q", current_time) + data)
        h.update(basic_parts)
        hmac = h.finalize()

        # R+T+pad
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data + hmac) + padder.finalize()
        print(padded_data)
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
        # print(plaintext_padded)
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
        message = self.fernet.decrypt(token)
        self.database.append(message)  # fake operation


def run_demo():
    key = VulnerableFernet.generate_key()
    # key = b'nRx_kgi8Y9FQhT0euQ7Ppk4TTbgzVaLhupmv9pPc9_E='
    f = VulnerableFernet(key)
    message = 'hello'.encode(encoding='utf-8')
    token = f.encrypt(message)
    server = Server(f)
    mitm(server, token)
    # print(bitwise_xor(token, token))


def bitwise_xor(b1, b2):
    if len(b1) != len(b2):
        raise Exception('mismatching byte lengths')
    ret = bytes()
    for i in range(len(b1)):
        c = b1[i] ^ b2[i]
        ret += c.to_bytes(1, 'big')
    return ret


def mitm(server, token):
    data = base64.urlsafe_b64decode(token)
    iv = data[9:25]
    ciphertext = iv + data[25:]
    block_size = algorithms.AES.block_size // 8
    num_blocks = len(ciphertext) // block_size
    # def block_divider(x): return (x[:-16], x[-16:])

    def try_toggle(ciphertext, block_index, byte_index):
        if byte_index < 0:
            byte_index = byte_index % block_size
        if block_index < 0:
            block_index = block_index % num_blocks
        try:
            mod = bytes(byte_index) + (0x01).to_bytes(1, 'big') + \
                bytes(block_size - byte_index - 1)
            modded_text = ciphertext[:block_index * block_size] + bitwise_xor(ciphertext[block_index * block_size:(
                block_index + 1) * block_size], mod) + ciphertext[(block_index + 1) * block_size:]
            assert len(modded_text) == len(ciphertext)
            modded_data = data[:9] + modded_text
            server.receive(base64.urlsafe_b64encode(modded_data))
            return True
        except InvalidPadding:
            return False
        except InvalidToken:
            return True

    def decode_block(ciphertext, block_index):
        plaintext = bytes()
        mask_array = bytes()
        # Figure out the mask corresponding to making the first block's last byte 0x00
        for byte_index in range(1, 16):
            for i in range(256):
                mask = bytes(16 - byte_index) + (i).to_bytes(1, 'big')
                for j in range(-byte_index + 1, 0):
                    mask += (plaintext[j] ^ byte_index).to_bytes(1, 'big')
                assert len(mask) == block_size
                # a = bitwise_xor(ciphertext[-2 * block_size:-1 * block_size], mask)
                # (C_{i-1} ^ mask) ^ D(C_{i}) = P_{i} ^ mask
                modded_text = ciphertext[:-2 * block_size] + bitwise_xor(
                    ciphertext[-2 * block_size: -1 * block_size], mask) + ciphertext[-1 * block_size:]
                modded_data = data[:9] + modded_text
                try:
                    server.receive(base64.urlsafe_b64encode(modded_data))
                    if try_toggle(modded_text, - block_index - 1, - byte_index - 1):
                        mask_array = mask[-byte_index].to_bytes(
                            1, 'big') + mask_array
                        break
                except InvalidPadding:
                    pass
                except InvalidToken:
                    if try_toggle(modded_text, - block_index - 1, - byte_index - 1):
                        mask_array = mask[-byte_index].to_bytes(
                            1, 'big') + mask_array
                        break
            plaintext = (
                byte_index ^ mask_array[-byte_index]).to_bytes(1, 'big') + plaintext
            # print(plaintext)
        for i in range(256):
            mask = (i).to_bytes(1, 'big')
            for j in range(-15, 0):
                mask += (plaintext[j] ^ 16).to_bytes(1, 'big')
            assert len(mask) == block_size
            modded_text = ciphertext[:-2 * block_size] + bitwise_xor(
                ciphertext[-2 * block_size: -1 * block_size], mask) + ciphertext[-1 * block_size:]
            modded_data = data[:9] + modded_text
            try:
                server.receive(base64.urlsafe_b64encode(modded_data))
                mask_array = mask[-16].to_bytes(1, 'big') + mask_array
                break
            except InvalidPadding:
                pass
            except InvalidToken:
                mask_array = mask[-16].to_bytes(1, 'big') + mask_array
                break
        plaintext = (16 ^ mask_array[-16]).to_bytes(1, 'big') + plaintext
        return plaintext
    plaintext_array = bytes()
    for block_index in range(1, num_blocks):
        plaintext_array = decode_block(
            ciphertext, block_index) + plaintext_array
        ciphertext = ciphertext[:-block_size]
    print(plaintext_array)
    print(len(plaintext_array))

    '''
    for i in range(256):
        mask = bytes(15) + (i).to_bytes(1, 'big')
        c_minus1 = ciphertext[-2 * block_size: -1 * block_size]
        changed_block = bitwise_xor(c_minus1, mask)
        # a = bitwise_xor(ciphertext[-2 * block_size:-1 * block_size], mask)
        # (C_{i-1} ^ mask) ^ D(C_{i}) = P{i} ^ mask
        modded_text = ciphertext[:-2 * block_size] + \
            changed_block + ciphertext[-1 * block_size:]
        modded_data = data[:25] + modded_text
        try:
            server.receive(base64.urlsafe_b64encode(modded_data))
            if try_toggle(-2, ciphertext, changed_block):
                mask_array = mask[-1].to_bytes(1, 'big') + mask_array
                break
        except InvalidPadding:
            pass
        except InvalidToken:
            if try_toggle(-2, ciphertext, changed_block):
                mask_array = mask[-1].to_bytes(1, 'big') + mask_array
                break
    plaintext = (0x01 ^ mask_array[-1]).to_bytes(1, 'big') + plaintext
    print(plaintext)
    # set last byte to 0x02 to find out what second to last byte is
    for i in range(256):
        mask = bytes(14) + (i).to_bytes(1, 'big') + (plaintext[-1] ^ 0x02).to_bytes(1, 'big')
        c_minus1 = ciphertext[-2 * block_size: -1 * block_size]
        changed_block = bitwise_xor(c_minus1, mask)
        modded_text = ciphertext[:-2 * block_size] + \
            changed_block + ciphertext[-1 * block_size:]
        modded_data = data[:25] + modded_text
        try:
            server.receive(base64.urlsafe_b64encode(modded_data))
            if try_toggle(-3, ciphertext, changed_block):
                mask_array = mask[-2].to_bytes(1, 'big') + mask_array
                break
        except InvalidPadding:
            pass
        except InvalidToken:
            if try_toggle(-3, ciphertext, changed_block):
                mask_array = mask[-2].to_bytes(1, 'big') + mask_array
                break
    plaintext = (0x02 ^ mask_array[-2]).to_bytes(1, 'big') + plaintext
    print(plaintext)
    '''


# if __name__ == '__main__':
    # time = timeit.timeit(stmt='client()', setup='from __main__ import client', number=1, timer=time.perf_counter)
    # print(time)
run_demo()
