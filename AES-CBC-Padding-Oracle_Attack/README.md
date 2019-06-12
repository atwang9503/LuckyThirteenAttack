# Padding Oracle Attack Demo
The core vulnerability demonstrated in `demo.py` is a padding oracle on a MAC-then-Encrypt AE scheme. Because this design, the decryption algorithm needs to work out how much padding bytes there needs to be, otherwise it cannot operate on the data. In doing so, it will leak information about the message.

One method to prevent this attack is to switch to an Encrypt-then-MAC scheme, which allows the decryption algorithm to not care about how the ciphertext was put together.

## References
[Al Fardan, Nadhem J., and Kenneth G. Paterson. "Lucky thirteen: Breaking the TLS and DTLS record protocols." 2013 IEEE Symposium on Security and Privacy. IEEE, 2013.](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)

[Albrecht, Martin R., and Kenneth G. Paterson. "Lucky microseconds: a timing attack on Amazon’s s2n implementation of TLS." Annual International Conference on the Theory and Applications of Cryptographic Techniques. Springer, Berlin, Heidelberg, 2016.](https://eprint.iacr.org/2015/1129.pdf)
