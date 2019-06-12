# Padding Oracle Attack on AES-CBC AE schemes
The core vulnerability demonstrated in `demo.py` is a padding oracle on a MAC-then-Encrypt AE scheme. Because this design, the decryption algorithm needs to work out how much padding bytes there needs to be, otherwise it cannot operate on the data. In doing so, it will leak information about the message.

One method to prevent this attack is to switch to an Encrypt-then-MAC scheme, which allows the decryption algorithm to not care about how the ciphertext was put together.

## Usage
```
LuckyThirteenAttack/AES-CBC-Padding-Oracle_Attack$ python3 demo.py
```
The demo asks for an input message which will be encrypted using AES-CBC-HMAC256.
```
Enter a message: Unsafe Message: MAC-then-Encrypt is not the best AE scheme!!!!!!!!!

Message: b'Unsafe Message: MAC-then-Encrypt is not the best AE scheme!!!!!!!!!' MAC: b'\x10q\xf4w\xfbm\r\xef[M\xa3\x90\xb0\xfc\x86:\xdd\xce\x95\x82"\x9c\t6\xe9^e\xde\xf3\x95\x19,' Pad: b'\r\r\r\r\r\r\r\r\r\r\r\r\r'

Plaintext to be encrypted:  b'Unsafe Message: MAC-then-Encrypt is not the best AE scheme!!!!!!!!!\x10q\xf4w\xfbm\r\xef[M\xa3\x90\xb0\xfc\x86:\xdd\xce\x95\x82"\x9c\t6\xe9^e\xde\xf3\x95\x19,\r\r\r\r\r\r\r\r\r\r\r\r\r'

Press enter to continue...
```
The program encrypts the message, then passes the resulting token to `mitm(server, token)` which uses `server` as a padding oracle to recover the plaintext bytes from `token`. The program recovers the plaintext starting from the last to first block, from last to first byte.
```
Block: 7 Byte: 16 Mask: b'\x0c'
Block: 7 Byte: 15 Mask: b'\x0f'
Block: 7 Byte: 14 Mask: b'\x0e'
Block: 7 Byte: 13 Mask: b'\t'
Block: 7 Byte: 12 Mask: b'\x08'
Block: 7 Byte: 11 Mask: b'\x0b'
Block: 7 Byte: 10 Mask: b'\n'
Block: 7 Byte: 9 Mask: b'\x05'
Block: 7 Byte: 8 Mask: b'\x04'
Block: 7 Byte: 7 Mask: b'\x07'
Block: 7 Byte: 6 Mask: b'\x06'
Block: 7 Byte: 5 Mask: b'\x01'
Block: 7 Byte: 4 Mask: b'\x00'
Block: 7 Byte: 3 Mask: b'"'
Block: 7 Byte: 2 Mask: b'\x16'
Block: 6 Byte: 16 Mask: b'\xf2'
Block: 6 Byte: 15 Mask: b'\xdc'
Block: 6 Byte: 14 Mask: b'f'
Block: 6 Byte: 13 Mask: b'Z'
Block: 6 Byte: 12 Mask: b'\xec'
Block: 6 Byte: 11 Mask: b'0'
Block: 6 Byte: 10 Mask: b'\x0e'
Block: 6 Byte: 9 Mask: b'\x94'
Block: 6 Byte: 8 Mask: b'+'
Block: 6 Byte: 7 Mask: b'\x88'
Block: 6 Byte: 6 Mask: b'\x9e'
Block: 6 Byte: 5 Mask: b'\xc2'
Block: 6 Byte: 4 Mask: b'\xd0'
Block: 6 Byte: 3 Mask: b'4'
Block: 6 Byte: 2 Mask: b'\x89'
Block: 5 Byte: 16 Mask: b'\xb1'
Block: 5 Byte: 15 Mask: b'\x92'
Block: 5 Byte: 14 Mask: b'\xa0'
Block: 5 Byte: 13 Mask: b'I'
Block: 5 Byte: 12 Mask: b'^'
Block: 5 Byte: 11 Mask: b'\xe9'
Block: 5 Byte: 10 Mask: b'\n'
Block: 5 Byte: 9 Mask: b'e'
Block: 5 Byte: 8 Mask: b'\xf2'
Block: 5 Byte: 7 Mask: b'}'
Block: 5 Byte: 6 Mask: b'\xff'
Block: 5 Byte: 5 Mask: b'}'
Block: 5 Byte: 4 Mask: b'\x1d'
Block: 5 Byte: 3 Mask: b'/'
Block: 5 Byte: 2 Mask: b'.'
Block: 4 Byte: 16 Mask: b' '
Block: 4 Byte: 15 Mask: b'#'
Block: 4 Byte: 14 Mask: b'"'
Block: 4 Byte: 13 Mask: b'%'
Block: 4 Byte: 12 Mask: b'$'
Block: 4 Byte: 11 Mask: b"'"
Block: 4 Byte: 10 Mask: b'b'
Block: 4 Byte: 9 Mask: b'e'
Block: 4 Byte: 8 Mask: b'l'
Block: 4 Byte: 7 Mask: b'b'
Block: 4 Byte: 6 Mask: b'h'
Block: 4 Byte: 5 Mask: b'\x7f'
Block: 4 Byte: 4 Mask: b'-'
Block: 4 Byte: 3 Mask: b'K'
Block: 4 Byte: 2 Mask: b'N'
Block: 3 Byte: 16 Mask: b'u'
Block: 3 Byte: 15 Mask: b'q'
Block: 3 Byte: 14 Mask: b'f'
Block: 3 Byte: 13 Mask: b'f'
Block: 3 Byte: 12 Mask: b'%'
Block: 3 Byte: 11 Mask: b'c'
Block: 3 Byte: 10 Mask: b'o'
Block: 3 Byte: 9 Mask: b'|'
Block: 3 Byte: 8 Mask: b')'
Block: 3 Byte: 7 Mask: b'~'
Block: 3 Byte: 6 Mask: b'd'
Block: 3 Byte: 5 Mask: b'b'
Block: 3 Byte: 4 Mask: b'-'
Block: 3 Byte: 3 Mask: b'}'
Block: 3 Byte: 2 Mask: b'f'
Block: 2 Byte: 16 Mask: b'u'
Block: 2 Byte: 15 Mask: b'r'
Block: 2 Byte: 14 Mask: b'z'
Block: 2 Byte: 13 Mask: b'v'
Block: 2 Byte: 12 Mask: b'f'
Block: 2 Byte: 11 Mask: b'h'
Block: 2 Byte: 10 Mask: b'B'
Block: 2 Byte: 9 Mask: b'%'
Block: 2 Byte: 8 Mask: b'g'
Block: 2 Byte: 7 Mask: b'o'
Block: 2 Byte: 6 Mask: b'c'
Block: 2 Byte: 5 Mask: b'x'
Block: 2 Byte: 4 Mask: b' '
Block: 2 Byte: 3 Mask: b'M'
Block: 2 Byte: 2 Mask: b'N'
Block: 1 Byte: 16 Mask: b'!'
Block: 1 Byte: 15 Mask: b'8'
Block: 1 Byte: 14 Mask: b'f'
Block: 1 Byte: 13 Mask: b'c'
Block: 1 Byte: 12 Mask: b'd'
Block: 1 Byte: 11 Mask: b'u'
Block: 1 Byte: 10 Mask: b't'
Block: 1 Byte: 9 Mask: b'm'
Block: 1 Byte: 8 Mask: b'D'
Block: 1 Byte: 7 Mask: b'*'
Block: 1 Byte: 6 Mask: b'n'
Block: 1 Byte: 5 Mask: b'j'
Block: 1 Byte: 4 Mask: b'l'
Block: 1 Byte: 3 Mask: b'}'
Block: 1 Byte: 2 Mask: b'a'
```

Each mask byte corresponds to the mask value that, when XOR's with the previous ciphertext block which is then XOR'd to the decryption of the current ciphertext block, makes a valid padding byte value 0x01, ..., 0x10. For example, the mask value of block 1 byte 16 is the value that makes byte 16 in the current block turn into 0x01 for a 1 byte pad. The mask value of block 1 byte 3 is the value that makes byte 3 in the current block turn into 0x0E for a 13 byte pad i.e. \x0E\x0E... .
## References
[Al Fardan, Nadhem J., and Kenneth G. Paterson. "Lucky thirteen: Breaking the TLS and DTLS record protocols." 2013 IEEE Symposium on Security and Privacy. IEEE, 2013.](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)

[Albrecht, Martin R., and Kenneth G. Paterson. "Lucky microseconds: a timing attack on Amazon’s s2n implementation of TLS." Annual International Conference on the Theory and Applications of Cryptographic Techniques. Springer, Berlin, Heidelberg, 2016.](https://eprint.iacr.org/2015/1129.pdf)
