5-26-19:

Resources I used: 
http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf
https://asecuritysite.com/encryption/c_c3
https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/


So far I have looked  at the Bleichenbacker reaserach paper. In it he 
describes the algorithms needed to implement the attack. So far I have created
some test programs to get a clearer picture of the math behind RSA encryption which
is included in modEncryption.py. I have also created the oracle needed to help the 
attacker verify if padding on a cipher message is correct which is included in the 
pkcsOracle.py. I have began the meat of the attack in the bleichAttack.py . Im
starting out with a simple implementation of the algorithm to better grasp it. I need 
to include my oracle within the bleichAttack file to verify the padding is correct.