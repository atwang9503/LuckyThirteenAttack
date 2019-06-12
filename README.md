# DIFFERENTIAL ATTACK

## Overview
This repository aims to implement a Differential Attack on the FEAL-4 cipher.

## `FEAL4.out`
You can run the attack by entering `make` in the terminal.
This will generate the file `FEAL4.out`.
You can run this file by typing `FEAL4.out` in the terminal.

Warning: Depending on the CPU it is running on the program may time-out

## `Results`
The output should show the randomly generated subkeys at the beginning and the cracked subkeys at the end.
These should be identical to each other.

# BLEICHENBACHER ATTACK

## Overview
This repository aims to implement a more simplified bleichenbacher Attack.
Looks for padded messages that look like :
`\0x00\0x02[3 random bytes]\x00[message of length 3]`

## `bleichAttack.py`
You can run the attack by doing `python bleichAttack.py` in the terminal.
It will then out put attempts at decryption. And after it finds a matching padding
after decryption it should spit out the original message. There will be false positives
but that is the in line with the nature of the attack. I reduced the size of message length and random padding length to reduce the time of finding a prime number and other math operations. This program still portrays the main idea of the attack.

You can change `line 176` to a different message of length 3

## `Intended Output`
The out put should look like the message you typed out at the end:
`GOOD PADDING
256
b'\x02\xc2\xad\x00cab\x00'`

Here cab was put into line 176
There will be false positives which is intended.

# RC4-FMS-Attack

## Overview
This repository aims to implement the stream cipher algorithm RC4,
which was used in TLS protocol until 2015.
The weakness comes from its two core algorithm:
key scheduling algorithm (KSA) and pseudo-random generation algorithm (RSA),
which are implemented in `rc4.py`. This file is also used as my library for the
two files below.

## `WEPOutput.py`
Given a string that contains numbers or letter A-F, this file generates all
possible 24-bit initialization vector along with the first keyStreamByte and put
the reasult in `WEPOutputSim.csv`. The reason we assume that the first
keyStreamByte is available to the eavesdropper is that the first byte plain text
in WEP is always 'aa', which is from SNAP header. The eavesdropper can XOR 'aa'
with the first encrypted cipher to recover the first byte of key stream.

## `keyRecover.py`
This file reads in `WEPOutputSim.csv` and recover the original entered key. It
could be wrong but in most situation the result is always correct.

## Usage
First, use `WEPOutput.py` to generate simulated WEP packets. For example,
in terminal we put:
```
$ python WEPOutput.py AF1423
```
It will output in terminal:
```
WEPOutputSim.csv is generated sucessfully.
```
and also create a file name `WEPOutputSim.csv` to store the packets.
Then, use `keyRecover.py` to analyze this packet files by:
```
$ python keyRecover.py
```
It will output in terminal:
```
keyLength is: 3
AF1423
```

## Reference
https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_1.pdf

https://rickwash.com/papers/stream.pdf

https://en.wikipedia.org/wiki/RC4

# Padding Oracle Attack Demo
The core vulnerability demonstrated in `demo.py` is a padding oracle on a MAC-then-Encrypt AE scheme. Because this design, the decryption algorithm needs to work out how much padding bytes there needs to be, otherwise it cannot operate on the data. In doing so, it will leak information about the message.

One method to prevent this attack is to switch to an Encrypt-then-MAC scheme, which allows the decryption algorithm to not care about how the ciphertext was put together.

## References
[Al Fardan, Nadhem J., and Kenneth G. Paterson. "Lucky thirteen: Breaking the TLS and DTLS record protocols." 2013 IEEE Symposium on Security and Privacy. IEEE, 2013.](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)

[Albrecht, Martin R., and Kenneth G. Paterson. "Lucky microseconds: a timing attack on Amazon’s s2n implementation of TLS." Annual International Conference on the Theory and Applications of Cryptographic Techniques. Springer, Berlin, Heidelberg, 2016.](https://eprint.iacr.org/2015/1129.pdf)
