# still in progress

import math,binascii
from decimal import *
from subprocess import *

# modulus and encryption exponent
n = 0xa58bfc62abe40a57d287860f395a7705ab0534eeb2bb591131a93d627dd2564b61ebde2a43082a50fbd84d308d1f70b7cd7dc4aca6239abe46ff76d2a7135034c2f8d477d5e1438b57230b157c71c1eb44b62cbf5e2cca14b956979c3b48e7ae4475dd4db8e72ebd5559bde3f281c8ee75c08e23c6960e1e1669fac91a815c67
e = 0x10001

# reads the encrypted message
f = open('enc_message','rb')
data = f.read()
f.close()

print(data)
y = int(binascii.hexlify(data),16)
print(y)

enctwo = (2 ** e) % n # the encryption of 2


def parity(y,n):
    bin_y = binascii.unhexlify('%0128x' % y)  # converts long int into bytes
    print(bin_y)

    #use my oracle here on oracle Return to see if padding is correct
    if oracleReturn == 'OK\n': # if the answer is OK
        return True
    else:
        return False

# do the binary search
def partial(y,n):
    #we do binary search to 
    k = int(math.ceil(math.log(n,2)))  # n. of iterations
    getcontext().prec = k    # allows for 'precise enough' floats
    l=Decimal(0)
    u=Decimal(n)
    for _ in range(k):
        h = (l+u)/2
        if parity(y,n):
            u = h            # we get the left interval
        else:
            l = h            # we get the right interval
        y=(y*enctwo) % n     # multiply y by the encryption of 2
    return int(u)

print('%0256x' % partial((y*enctwo)%n,n)) # print the result in hexadecimal