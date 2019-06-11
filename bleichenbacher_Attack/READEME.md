# RC4-Attack

## Overview
This repository aims to implement a more simplified bleichenbacher Attack. 
Looks for padded messages that look like : 
`\0x00\0x02[3 random bytes]\x00[message of length 3]`

## `bleichAttack.py`
You can run the attack by doing `python bleichAttack.py` in the terminal.
It will then out put attempts at decryption. And after it finds a matching padding
after decryption it should spit out the original message. There will be false positives
but that is the in line with the nature of the attack. I reduced the size of message length and random padding length to reduce the time of finding a prime number and other math operations. This program still portrays the main idea of the attack.