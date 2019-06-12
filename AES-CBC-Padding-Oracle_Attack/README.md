# Padding Oracle Attack on AES-CBC AE schemes
The core vulnerability demonstrated in [`demo.py`](./demo.py) is a padding oracle on a MAC-then-Encrypt AE scheme. Because this design, the decryption algorithm needs to work out how much padding bytes there needs to be, otherwise it cannot operate on the data. In doing so, it will leak information about the message.

One method to prevent this attack is to switch to an Encrypt-then-MAC scheme, which allows the decryption algorithm to not care about how the ciphertext was put together.

## Usage
```
LuckyThirteenAttack/AES-CBC-Padding-Oracle_Attack$ python3 demo.py
```
The demo asks for an input message which will be encrypted using AES-CBC-HMAC256.
```
Enter a message: MAC-then-Encrypt is not a secure AE scheme!!!

Message: b'MAC-then-Encrypt is not a secure AE scheme!!!' MAC: b'\x95K\xce\x8e\x15\xbeQ\x9ba\x01D\x0f\xd9\xd9\xd4/\xfa%\xa47\x89u\xde+\r\x8c\x07 2\x99\x93\xfc' Pad: b'\x03\x03\x03'

Plaintext to be encrypted:  b'MAC-then-Encrypt is not a secure AE scheme!!!\x95K\xce\x8e\x15\xbeQ\x9ba\x01D\x0f\xd9\xd9\xd4/\xfa%\xa47\x89u\xde+\r\x8c\x07 2\x99\x93\xfc\x03\x03\x03'
```
The program encrypts the message, then passes the resulting token to `mitm(server, token)` which uses `server` as a padding oracle to recover the plaintext bytes from `token`. The program recovers the plaintext starting from the last to first block, from last to first byte.
```
Block: 5 Byte: 16 Mask: b'\x02'
Block: 5 Byte: 15 Mask: b'\x01'
Block: 5 Byte: 14 Mask: b'\x00'
Block: 5 Byte: 13 Mask: b'\xf8'
Block: 5 Byte: 12 Mask: b'\x96'
Block: 5 Byte: 11 Mask: b'\x9f'
Block: 5 Byte: 10 Mask: b'5'
Block: 5 Byte: 9 Mask: b'('
Block: 5 Byte: 8 Mask: b'\x0e'
Block: 5 Byte: 7 Mask: b'\x86'
Block: 5 Byte: 6 Mask: b'\x06'
Block: 5 Byte: 5 Mask: b"'"
Block: 5 Byte: 4 Mask: b'\xd3'
Block: 5 Byte: 3 Mask: b'{'
Block: 5 Byte: 2 Mask: b'\x86'
Block: 5 Byte: 1 Mask: b"'"
Block: 4 Byte: 16 Mask: b'\xa5'
Block: 4 Byte: 15 Mask: b"'"
Block: 4 Byte: 14 Mask: b'\xf9'
Block: 4 Byte: 13 Mask: b'+'
Block: 4 Byte: 12 Mask: b'\xd1'
Block: 4 Byte: 11 Mask: b'\xdf'
Block: 4 Byte: 10 Mask: b'\xde'
Block: 4 Byte: 9 Mask: b'\x07'
Block: 4 Byte: 8 Mask: b'M'
Block: 4 Byte: 7 Mask: b'\x0b'
Block: 4 Byte: 6 Mask: b'j'
Block: 4 Byte: 5 Mask: b'\x97'
Block: 4 Byte: 4 Mask: b'\\'
Block: 4 Byte: 3 Mask: b'\xb0'
Block: 4 Byte: 2 Mask: b'\x1a'
Block: 4 Byte: 1 Mask: b'\x9e'
Block: 3 Byte: 16 Mask: b'\xcf'
Block: 3 Byte: 15 Mask: b'I'
Block: 3 Byte: 14 Mask: b'\x96'
Block: 3 Byte: 13 Mask: b'%'
Block: 3 Byte: 12 Mask: b'$'
Block: 3 Byte: 11 Mask: b"'"
Block: 3 Byte: 10 Mask: b'b'
Block: 3 Byte: 9 Mask: b'e'
Block: 3 Byte: 8 Mask: b'l'
Block: 3 Byte: 7 Mask: b'b'
Block: 3 Byte: 6 Mask: b'h'
Block: 3 Byte: 5 Mask: b'\x7f'
Block: 3 Byte: 4 Mask: b'-'
Block: 3 Byte: 3 Mask: b'K'
Block: 3 Byte: 2 Mask: b'N'
Block: 3 Byte: 1 Mask: b'0'
Block: 2 Byte: 16 Mask: b'd'
Block: 2 Byte: 15 Mask: b'p'
Block: 2 Byte: 14 Mask: b'v'
Block: 2 Byte: 13 Mask: b'g'
Block: 2 Byte: 12 Mask: b'`'
Block: 2 Byte: 11 Mask: b'u'
Block: 2 Byte: 10 Mask: b"'"
Block: 2 Byte: 9 Mask: b'i'
Block: 2 Byte: 8 Mask: b')'
Block: 2 Byte: 7 Mask: b'~'
Block: 2 Byte: 6 Mask: b'd'
Block: 2 Byte: 5 Mask: b'b'
Block: 2 Byte: 4 Mask: b'-'
Block: 2 Byte: 3 Mask: b'}'
Block: 2 Byte: 2 Mask: b'f'
Block: 2 Byte: 1 Mask: b'0'
Block: 1 Byte: 16 Mask: b'u'
Block: 1 Byte: 15 Mask: b'r'
Block: 1 Byte: 14 Mask: b'z'
Block: 1 Byte: 13 Mask: b'v'
Block: 1 Byte: 12 Mask: b'f'
Block: 1 Byte: 11 Mask: b'h'
Block: 1 Byte: 10 Mask: b'B'
Block: 1 Byte: 9 Mask: b'%'
Block: 1 Byte: 8 Mask: b'g'
Block: 1 Byte: 7 Mask: b'o'
Block: 1 Byte: 6 Mask: b'c'
Block: 1 Byte: 5 Mask: b'x'
Block: 1 Byte: 4 Mask: b' '
Block: 1 Byte: 3 Mask: b'M'
Block: 1 Byte: 2 Mask: b'N'
Block: 1 Byte: 1 Mask: b']'
```
Each mask byte corresponds to the mask value that, when XOR's with the previous ciphertext block which is then XOR'd to the decryption of the current ciphertext block, makes a valid padding byte value 0x01, ..., 0x10. For example, the mask value of block 1 byte 16 is the value that makes byte 16 in the current block turn into 0x01 for a 1 byte pad. The mask value of block 1 byte 3 is the value that makes byte 3 in the current block turn into 0x0E for a 13 byte pad i.e. \x0E\x0E... .
```
Decoded plaintext: b'MAC-then-Encrypt is not a secure AE scheme!!!\x95K\xce\x8e\x15\xbeQ\x9ba\x01D\x0f\xd9\xd9\xd4/\xfa%\xa47\x89u\xde+\r\x8c\x07 2\x99\x93\xfc\x03\x03\x03'
```
## References
[Al Fardan, Nadhem J., and Kenneth G. Paterson. "Lucky thirteen: Breaking the TLS and DTLS record protocols." 2013 IEEE Symposium on Security and Privacy. IEEE, 2013.](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)

[Albrecht, Martin R., and Kenneth G. Paterson. "Lucky microseconds: a timing attack on Amazon’s s2n implementation of TLS." Annual International Conference on the Theory and Applications of Cryptographic Techniques. Springer, Berlin, Heidelberg, 2016.](https://eprint.iacr.org/2015/1129.pdf)
