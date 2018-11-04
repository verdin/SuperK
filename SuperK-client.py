#SuperK-client.py

import base64
import socket
import select
import sys
import hashlib
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES

keyLength = 128    # number of numbers in the key #called n in the assignment

puKey = [0] * keyLength # initiate the public key

# message is an array
def encryptMessage(message, publicKey): #  Merkle-Hellman knapsack encryption
    c = 0
    for i in range(0, len(publicKey)):
        c += message[i] * publicKey[i]
    return c # c is a long or ints

def AESencryptMessage(plainText, key): #encrypts the message before it is sent out the socket
    plainText = pad(plainText) 
    iv = Random.new().read( AES.block_size ) # create random iv of size 128
    cipher = AES.new( key, AES.MODE_CBC, iv )
    cipherText = base64.b64encode( iv + cipher.encrypt( plainText ) )  # puts iv at start of cipherText  
    return cipherText

def AESdecryptMessage(cipherText, key): # decrypts the AES encrypted message
    cipherText = base64.b64decode(cipherText)
    iv = cipherText[:AES.block_size] # gets iv from cipherText
    cipherText = cipherText[AES.block_size:] # removes iv from cipherText
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
    
    if len(sys.argv) == 2:
        address = sys.argv[1]
        try: # test argument to see if it is an ip address
            socket.inet_aton(address)
            
        except socket.error:
            print "Incorrect argument" # print error if not an ip address
            return
    else: # default ip address
        address = "127.0.0.1"
    
    plainTextKey = [0] * keyLength # create one use key    
    for i in range(0, keyLength): # create random key
        plainTextKey[i] = random.choice([0, 1]) 
    
    port = 4439 # the port
    
    # connect to server
    print "Connecting to server..."
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((address, port))
    print "Connected to server. Push enter after message to send."
    
    # receive public key
    sentPuKey = server.recv(12048) # you can only send strings
    puKey = sentPuKey.split(",")
    puKey = list(map(int, puKey))

    # encrypt and send single use AES key
    cipherTextKey = encryptMessage(plainTextKey, puKey)
    sendCipherTextKey = str(cipherTextKey)
    server.send(sendCipherTextKey)
    AESkey = arrayToKey(plainTextKey)
    
    serverOpen = True # used to exit the loop
    while serverOpen:
        sockets_list = [sys.stdin, server]
        
        read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])
        
        for socks in read_sockets: # alternate between reading information from the user and receiving data from the socket.
            if socks == server:
                messageIn = socks.recv(2048)
                if messageIn: # Test to see if anything was sent. If nothing was the connection is likely dead.
                    #messageIn should be base64
                    AESplainText = AESdecryptMessage(messageIn, AESkey)            
                    print "Server said: ",
                    print AESplainText ,
                else:
                    serverOpen = False # end connection 
                    print "Lost connection to server" 
                    
            else:
                messageOut = sys.stdin.readline()
                if messageOut == "exit\n" or messageOut == "quit\n": # test for exit and quit and end program
                    serverOpen = False
                else:
                    if messageOut: # test for empty message
                        AEScipherText = AESencryptMessage(messageOut, AESkey)            
                        server.send(AEScipherText)

    server.close() 
    
main()
