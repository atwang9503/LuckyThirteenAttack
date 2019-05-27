import binascii
#testing how to directly encypt message using mod equation
def main():
    # obtained by looking at key
    modulus = '''
    00:d3:bb:44:ce:90:4d:52:86:b3:65:47:3e:9d:b8:
    e3:a7:94:8a:2e:7f:43:f7:66:55:00:61:41:da:00:
    fa:e4:7d:46:aa:0a:f4:4f:f0:a6:7d:5a:a3:ab:eb:
    cb:9f:e6:39:c5:99:ab:41:9f:fd:86:c7:8c:cd:fb:
    93:1f:2b:e4:0d:91:81:e2:cc:9e:ab:ae:af:39:80:
    cb:ef:09:54:e0:f6:31:15:75:56:85:54:31:ee:51:
    4a:54:d7:a0:0d:c5:77:63:54:c9:ea:6d:60:cb:0f:
    4a:34:bc:5c:32:5d:76:a9:d6:00:f8:81:39:5a:29:
    00:d1:c6:ec:57:84:28:b7:61 '''

    remove="\n :"    
    table=str.maketrans("","",remove)    
    modulus = modulus.translate(table)  
    n = int(modulus,16)
    hex(n)
    print(hex(n))
    print("\n")
    e = 0x10001 # 65537 in hex
    m = 0x04 # my og message
    enc4 = (m ** e) % n # encrypted version of message using eqn
    hex(enc4)
    print(hex(enc4))

    #try out the multiplicative property of RSA encryption
    enc3 = (0x03 ** e) % n
    print("\n")
    print(hex(enc3))

    enc12 = (0x0C ** e) % n
    print("\n")
    print(hex(enc12))

    # 4 * 3 = 12 or c in hex
    mult = (enc3 * enc4) % n
    

    b =  binascii.unhexlify('%0256x' % mult) # converts to
    f = open("multiplicative.out","wb")
    f.write(b)
    f.close()

if __name__ == '__main__':
    main()