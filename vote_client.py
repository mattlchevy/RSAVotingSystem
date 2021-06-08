# Client to implement simplified 'secure' electronic voting algorithm
# and send votes to a server. The client says hello to the server and indicates
# which cryptographic algorithms it can support. The server picks one
# asymmetric key and one symmetric key algorithm and then responds to the
# client with its public key and a nonce. The client generates a symmetric
# key to send to the server, encrypts the symmetric key with the public key,
# and then encrypts the nonce with the symmetric key.
# If the nonce is verified, then the server will send the "107 Polls Open"
# message.

import socket
import math
import random
import sys
import simplified_AES
import NumTheory

# Author: 
# Last modified: 2020-11-13
# Version: 0.1
#!/usr/bin/python3

class RSAClient:
    def __init__(self, address, port):
        # client socket components 
        self.address = address
        self.port = int(port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.vote = None
        self.encvote = None

        #variable storing the latest data recieved
        self.lastRcvdMsg = 0

        #For storing the symmetric key
        self.sessionKey = 0	

        #For storing the server's n in the public key
        self.modulus = 0	
        self.nonce = 0
        #For storing the server's e in the public key
        self.serverExponent = 0 	
        
        # for storing candidate info
        self.candidates = None

    def send(self, message):
        self.socket.send(bytes(message,'utf-8'))

    def read(self):
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Server is unavailable")

    def close(self):
        print("closing connection to", self.address)
        try:
            self.socket.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f"{self.address}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None

    def RSAencrypt(self, msg):
        """Encryption side of RSA"""
        cText = NumTheory.NumTheory.expMod(msg, self.serverExponent, self.modulus)
        return cText

    def RSAdecrypt(self, cText):
        """Decryption side of RSA"""
        """"This function will return (cText^exponent mod modulus) and you must"""
        """ use the expMod() function"""
        msg = NumTheory.NumTheory.expMod(cText, self.serverExponent, self.modulus)
        return msg


    def computeSessionKey(self):
        """Computes this node's session key"""
        self.sessionKey = random.randint(1, 65536)
        return self.sessionKey

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext

    def serverHello(self):
        status = "101 Hello 3DES, AES, RSA16, DH16"
        return status

    def Session_K(self):
        self.computeSessionKey()
        self.EncryptedNonce = self.AESencrypt(self.nonce)
        self.EncryptedKey = self.RSAencrypt(self.sessionKey)
        status = "103 Session Key, "  + str(self.EncryptedKey) + ', '  + str(self.EncryptedNonce)
        return status
   
    def Vote115(self):
        self.encvote = self.AESencrypt(self.vote)
        status = '115 ' + str(self.encvote)
        return status

    def start(self):
        """Main sending and receiving loop for the client"""
        while True:
            self.socket.connect((self.address, self.port))
            self.send(self.serverHello())
            print("101 Hello sent")
            self.read()
            # 102 Hello AES, RSA16, n, e, nonce
            msg = self.lastRcvdMsg.split('6',1)
            info = msg[1].split(' ')
            print(info)
            self.lastRcvdMsg = 0
            # storing values globally for encryption
            self.modulus = (int(info[1]))
            self.serverExponent = (int(info[2]))
            self.nonce = (int(info[3]))
            
            print('The Generated Nonce is: ' + str(self.nonce))
            print ('The Generated Session Key is ' + str(self.sessionKey))
            self.send(str(self.Session_K()))
            print("103 Session was sent!")
            if self.lastRcvdMsg[0:2] == '106':
                self.candidates = self.lastRcvdMsg.split('6')
                print(self.candidates)
        # self.send(self.Vote115())
        
        
        

def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 3:
        print ("PleaseS supply a server address and port.")
        sys.exit()
    serverHost = str(args[1])       # The remote host
    serverPort = int(args[2])       # The same port as used by the server

    client = RSAClient(serverHost, serverPort)
    try:
        client.start()
    except (KeyboardInterrupt, SystemExit):
        exit()

if __name__ == "__main__":
    main()
