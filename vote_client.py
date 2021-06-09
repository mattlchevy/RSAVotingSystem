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
import json


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

        self.can1 = 0
        self.can2 = 0

        self.can1V = 0
        self.can2V = 0


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
        ptext = NumTheory.NumTheory.expMod(cText, self.serverExponent, self.modulus)
        return ptext


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
        msg = "103 Session Key,"  + str(self.EncryptedKey) + ','  + str(self.EncryptedNonce)
        return msg
   
    def Vote115(self):
        self.envote = [{"ID": self.can1["ID"], "Votes": self.AESencrypt(self.can1V)}, {"ID": self.can2["ID"], "Votes": self.AESencrypt(self.can2V)}]
        status = '115 ' + str(self.encvote)
        return status

    def start(self):
        """Main sending and receiving loop for the client"""
        self.socket.connect((self.address, self.port))
        self.send(self.serverHello())
        print("101 Hello sent")
        print("\n")
        status = 1
        while status == 1:
            
            self.read()
            if '102' in self.lastRcvdMsg:
                # 102 Hello AES, RSA16, n, e, nonce
                print("Recievend from server: " + self.lastRcvdMsg)
        
                # storing values globally for encryption
                self.modulus = (int(self.lastRcvdMsg.split(' ')[4]))
                self.serverExponent = (int(self.lastRcvdMsg.split(' ')[5]))
                self.nonce = (int(self.lastRcvdMsg.split(' ')[6]))

                self.send(str(self.Session_K()))
                print("103 Session was sent!")
                print('The Generated Nonce is: ' + str(self.nonce))
                print ('The Generated Session Key is ' + str(self.sessionKey))
                print("\n") 

            if '106' in self.lastRcvdMsg:
                self.read()
                self.candidates = json.loads(self.lastRcvdMsg)
                
                self.can1 = dict(self.candidates[0])
                self.can2 = dict(self.candidates[1])
                print('The list of candidates are: \n')
                print(str(self.can1)+ "\n")
                print(str(self.can2))
            if '107' in self.lastRcvdMsg:
                print("\n")
                print(self.lastRcvdMsg[3:])
                while True:
                    x=input("press (1) to vote for "+ self.can1["Candidate"]+ " and (2) to vote for "+ self.can2["Candidate"]+"\nIf you wish to stop voting press anything else\n")
                    if x == '1':
                        self.can1V += 1
                    elif x == '2':
                        self.can2V += 1
                    else:
                        break

                msg=self.Vote115()
                self.send(msg)
                msg = json.dumps(self.envote)
                self.send(msg)
                print("115 sent")
                
        
        

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
