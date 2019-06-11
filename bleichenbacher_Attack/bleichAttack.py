import math
import random
import base64
import gmpy2

###############################################################################
#### This section is used for helper functions for RSA encryption #############
###############################  CREDIT TO :  #################################
################## https://gist.github.com/JonCooperWorks/5314103 #############

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

'''
Euclid's extended algorithm for finding the multiplicative inverse of two numbers
'''
def multiplicative_inverse(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    # return a , lx, ly  # Return only positive values
    return lx

'''
Tests to see if a number is prime.
'''
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

############################################################################################
################################ Cited Code ends here ######################################
############################################################################################


def encryptMessageNum(myPublicKey, myMessage):
    (publicModulus, publicExponent) = myPublicKey
    if publicModulus < myMessage:
        raise Exception
    return pow(myMessage, publicExponent, publicModulus)

def decryptCipherNum(mySecretKey, myCipher):
    (publicModulus, privateExponent) = mySecretKey
    return pow(myCipher, privateExponent, publicModulus)
    

 #### https://www.delftstack.com/howto/python/how-to-convert-bytes-to-integers/
 #### used this website to help me change bytes to integers and back
def byteToInt(bytes_obj):
    return int.from_bytes(bytes_obj, byteorder='big')

def intToBytes(myInt):
    lengthOfInt= myInt.bit_length()
    lengthInBytes = lengthOfInt//8+(lengthOfInt % 8 > 0)
    bytesConversion = myInt.to_bytes(lengthInBytes, byteorder='big')
    return bytesConversion 

def pkcs1Encode(totalBytes, myMessage):
    lengthOfMessage = len(myMessage)
    lengthOfPadding = totalBytes - 3 - lengthOfMessage
    if lengthOfMessage > totalBytes-4:#changed from 11 to 4
        print("ERROR OCCURRED")
        return("ERROR")
    else:
        # we just pad the message
        # 00 02 [random non zero bytes cant be 0] 00 [message]
        my_padding = ''.join(chr(random.randint(1,255)) for _ in range(lengthOfPadding))
        my_padding_inbytes = str.encode(my_padding)
        pkcsPadding = b'\x00\x02' +my_padding_inbytes+ b'\x00'
        my_Message_as_bytes = str.encode(myMessage)
        pkcsString = pkcsPadding + my_Message_as_bytes
        return(pkcsString)

def pkcs1Decode(encodeMessage):
    #ignore first 2 bytes since its constant
    twoBytesStripped = encodeMessage[2:]
    print(twoBytesStripped)
    messageIndex = 2
    for aByte in twoBytesStripped:
        if aByte == 0:
            messageIndex = messageIndex + 1
            break
        else:
            messageIndex = messageIndex + 1
    
    originalMessage = encodeMessage[messageIndex:]
    return(originalMessage) 

def paddingOracle(Cipher):
    #checking to see if padding is okay or not
    iteration = -1
    got2 = False
    got0 = False
    for b in Cipher:
        iteration = iteration + 1

        if iteration == 0 and b == 2:
            got2 = True
        if iteration == 3 and b == 0:
            got0 = True
        # after checking for 00 and 02 have to look for the second 0
    if got0 == True and got2 == True:
        print("GOOD PADDING")
        # print("Error, never got second 0.")
        return True
    else:
        return False

def createPrime(sizeOFMod):
        x = 0
        while x == 0:
            upperBit = math.pow(2, sizeOFMod) - 1

            lowerBit = math.pow(2, (sizeOFMod - 1))
            
            potentialPrime = random.randint(lowerBit, upperBit)
            if gmpy2.is_prime(potentialPrime):
                return potentialPrime

#def generate_key(modulus_length):
def createRSAKey(publicModulusLength):
    lengthOfPrime = publicModulusLength // 2
    # constant public exponent
    publicExponent = 3

    # createFirst prime number
    firstPrimeP = 4
    while (firstPrimeP - 1) % publicExponent == 0:
        firstPrimeP = createPrime(lengthOfPrime)

    secondPrimeQ = firstPrimeP
    while secondPrimeQ == firstPrimeP or (secondPrimeQ - 1) % publicExponent == 0:
        secondPrimeQ = createPrime(lengthOfPrime)

    publicModulus = firstPrimeP * secondPrimeQ
    publicKey = (publicModulus, publicExponent)
    phi = (firstPrimeP - 1) * (secondPrimeQ - 1)
    privateExponent = multiplicative_inverse(publicExponent, phi)
    secretKey = (publicModulus, privateExponent)

    return publicKey, secretKey


      
def main():
    p = createPrime(40)
    q = createPrime(40)
    
    # YOU CAN CHANGE MESSAGE HERE BUT HAS TO BE LENGTH 3
    myEncodedMessage = pkcs1Encode(7, "cab") # MESSAGE = cab
    print("OG MESSAGE:")
    print(myEncodedMessage)

    i = int.from_bytes(myEncodedMessage, byteorder='big')
    print(i)
    print("\n")

    public,private = createRSAKey(60)
    (n,e) = public
    print("HERE")
    myEncyptedMsg = encryptMessageNum(public,i)
    print("THIS IS MY ENCRYPTED MSG")
    print(myEncyptedMsg)
    
    for myS in range(2,1000000):
        attemptedDecCipher = (myEncyptedMsg*(myS**e)) % n
        decAtttempt = decryptCipherNum(private,attemptedDecCipher)
        print("The decryption attempt")
        print(intToBytes(decAtttempt))
        if paddingOracle(intToBytes(decAtttempt)):
            print(myS)
            print(intToBytes(decAtttempt))
            break

if __name__ == '__main__':
    main()