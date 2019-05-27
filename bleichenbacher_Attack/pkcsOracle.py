# this is my padding oracle for the PCKS 1 v1.5
# used as a servers response
def main():
    myMessage = b"\x00\x02\x09\xad\x82\x9f\xfb\x3a\x98\xb9\x1a\x1b\xe5\x3c\x6d\x61'\
    '\x88\x45\x6f\x19\x2e\x85\x0c\x9d\x23\x89\x98\xa3\x95\x58\x74\x21\x86\x97\x04'\
    '\x3f\x5a\x11\xb4\x93\x6e\xfd\x3f\xbe\xc0\x0b\xed\x3c\x10\x03\x19\x99\x13\x9c'\
    '\x04\x4a\x79\xbb\x94\x75\xcb\x50\xc7\x2f\xd5\xd8\x6e\x38\xd3\xc5\x6c\xab\x5d'\
    '\x19\x45\xb9\x31\xd4\x63\xd9\x58\x6c\x05\x29\xa2\xc8\xca\x8b\xb3\x17\x6a\xba'\
    '\x6d\x3e\x32\xde\xeb\xe0\xbc\xa2\x20\x22\x86\x58\x2a\x08\x93\x33\xf7\xca\x7b'\
    '\x40\x70\xf2\x72\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21"
    
    iteration = -1
    pastFirst0 = False
    gotSecond0 = False
    for b in myMessage:
        iteration = iteration + 1

        if b == 0 and pastFirst0 == True:
            print("Got second 0")
            gotSecond0 = True
            print(iteration-2)
            if iteration - 2 < 8:
                print(iteration-2)
                print("ERROR, random padding < 8 bytes.")
                return False
        
        if iteration==0 and b == 0: # check to see if first part of pad is 0x00
            pastFirst0 = True
            print("Got 0x00")
        
        if iteration==1 and b == 2: # check to see if first part of pad is 0x02
            print("Got 0x02")

        # after checking for 00 and 02 have to look for the second 0
        
    
    if pastFirst0 == True and gotSecond0 == False:
        print("Error, never got second 0.")
        return False

    else:
        return True

if __name__ == '__main__':
    main()