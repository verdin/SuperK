#SuperK-server.py

import base64
import socket
import sys
import time
import os
import fractions
import itertools
import hashlib
import select
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES

keyLength = 128    # number of numbers in the key # called n in the assignment

puKey = [0] * keyLength # initiate the public key

class piKeyClass:       #create a class to hold the private key
    perSeq = [0] * keyLength # store permutation 
    M = 0
    W = 0
    supSeq = [0] * keyLength   # store super increasing sequence
    def __str__(self): # used to print the key during testing
        string = "(("
        string += ','.join(str(n) for n in self.perSeq)
        string += ")," + str(self.M)
        string += "," + str(self.W)
        string += ",("
        string += ','.join(str(e) for e in self.supSeq)
        string += "))"
        return string

piKey = piKeyClass() # initiate the private key

def keyGen(): # creates the public and private keys and stores them in puKey and piKey
    reset = 1 # will be used to test if any part of the keygen brakes and start over
    reset2 = 1    
    reset3 = 1
    while reset or reset2 or reset3: # used to prevent errors by regenerating keys if needed. was more useful when collisions were more likely
        
        minSize = 0
        for k in range (0, keyLength): # generate the super increasing sequence
            
            temp = random.randint(minSize,(minSize*2)+100) # the minsize *2 +100 max is to prevent the first int and others from being to big 
            piKey.supSeq[k] = temp
            minSize += temp
            
        piKey.M = random.randint(minSize,(minSize*3))  # create M
        
        # test the super increasing sequence
        hold = 0
        reset = 0
        for L in range(0, keyLength):
            if piKey.supSeq[L] < hold :
                reset = 1
            else:
                hold += piKey.supSeq[L]
        
        reset2 = 1
        for _ in itertools.count(1):          #create W # uses iteratools because number of loops was to big
            piKey.W = random.randint(1, piKey.M+1)
            if fractions.gcd(piKey.M,piKey.W) == 1 :  #test W 
                reset2 = 0
                break;
        reset3 = 1
        if (1 < piKey.W) and (piKey.W < (piKey.M+1) ):
            reset3 = 0
        
        for i in range(0,keyLength): # generate sequence permutation
            piKey.perSeq [i] = i
            
        random.shuffle(piKey.perSeq)        
        
        for j in range(0, keyLength): #generate public key
            puKey[j] = (piKey.W * piKey.supSeq[piKey.perSeq[j]-1]) % piKey.M
        
def multiplicativeInverse(u, v): # calculates the multiplicative inverse
    u0 = u
    v0 = v
    t0 = 0
    t  = 1
    s0 = 1
    s  = 0
    q  = v0 / u0  #{ integer division }
    r  = v0 - q * u0
    while r > 0:
        temp = t0 - q * t
        t0 = t
        t = temp
        temp = s0 - q * s
        s0 = s
        s = temp
        v0 = u0
        u0 = r
        q = v0 / u0 #{ integer division }
        r = v0 - q * u0
    r = u0
    if r == 1 :
        if t > 0:
            return t;
        else:
            return t + v;
    else:
        return 0;
    
def decryptMessage(message, piKeyD): # decrypts the knapsack problem
    
    answer = [0] * keyLength
    plaintext = [0] * keyLength

    w = multiplicativeInverse(piKeyD.W, piKeyD.M) # calc W^-1
    d = (w * message) % piKeyD.M
    for i in reversed(range(0, keyLength)):
        if d >= piKeyD.supSeq[i] :
            d -= piKeyD.supSeq[i]
            answer[i] = 1
        else:
            answer[i] = 0
    
    for j in range(0, keyLength):
        plaintext[j] = answer[piKeyD.perSeq[j]-1]
        
    return plaintext

# not used by server
#def encryptMessage(message, publicKey): # not used by server
    #c = 0
    #for i in range(0, len(publicKey)):
        #c += message[i] * publicKey[i]
    #return c

def AESencryptMessage(plainText, key): #encrypts the message before it is sent out the socket
    plainText = pad(plainText)
    iv = Random.new().read( AES.block_size ) # create random iv of size 128
    cipher = AES.new( key, AES.MODE_CBC, iv )
    cipherText = base64.b64encode( iv + cipher.encrypt( plainText ) )  # puts iv at start of cipherText  
    return cipherText

def AESdecryptMessage(cipherText, key): # decrypts the AES encrypted message
    cipherText = base64.b64decode(cipherText)
    iv = cipherText[:AES.block_size] # gets iv from cipherText
    cipherText = cipherText[AES.block_size:] #removes iv from cipherText
    cipher = AES.new( key, AES.MODE_CBC, iv )
    plainText = unpad(cipher.decrypt( cipherText ))   
    return plainText 

def arrayToKey(arrayKey): # takes in the 128 bit single use key and creates a digest for AES
    string = ''
    for i in range(0, keyLength):  #array to int
        string += str(arrayKey[i])
    key = hashlib.sha256(string).digest() # hash the string to get password
    return key

def pad(s): # adds padding so the message is the same length as the block length
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size) 
     
def unpad(s): # removes padding from the message 
    return s[:-ord(s[len(s)-1:])]


def main():
    
    address = "127.0.0.1"
    port = 4439 #the port
    
    # create public and private key
    keyGen()
    
    # set up server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print "Waiting for client..."
    server.bind((address, port))
    server.listen(5)
    conn, addr = server.accept()
    print "Client connected. Push enter after message to send."
    
    # send public key
    sendPuKey = ",".join(str(e) for e in puKey)
    conn.send(sendPuKey)

    # receive and decrypt single use AES key
    sendCipherTextKey = conn.recv(2048)
    cipherTextKey = long(sendCipherTextKey)
    plainTextKey = decryptMessage(cipherTextKey, piKey)
    AESkey = arrayToKey(plainTextKey)
    
    clientOpen = True # used to exit the loop
    while clientOpen:
        sockets_list = [sys.stdin, conn]
        
        read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])

        for socks in read_sockets: # alternate between reading information from the user and receiving data from the socket.
            if socks == conn:
                messageIn = socks.recv(2048)
                if messageIn: # Test to see if anything was sent. If nothing was the connection is likely dead.
                    AESplainText = AESdecryptMessage(messageIn, AESkey)            
                    print "Client said: ",
                    print AESplainText ,
                else:
                    clientOpen = False # end connection 
                    print "Lost connection to client"
            else:
                messageOut = sys.stdin.readline()
                if messageOut == "exit\n" or messageOut == "quit\n": # test for exit and quit and end program
                    clientOpen = False
                else:
                    if messageOut: # test for empty
                        AEScipherText = AESencryptMessage(messageOut, AESkey)            
                        conn.send(AEScipherText)
    
    conn.close()
    server.close()    
    
main()

