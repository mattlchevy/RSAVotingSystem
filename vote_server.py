# Server to implement simplified RSA algorithm and tally votes from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.

# Author: 
# Last modified: 
# Version: 0.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES
import NumTheory



class RSAServer(object):
    
    def __init__(self, port, p, q):
        self.p = p 
        self.q = q
        self.socket = socket.socket() 
        # The option below is to permit reuse of a socket in less than an MSL
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", int(port)))
        self.socket.listen(5)	
        self.lastRcvdMsg = 0
        self.sessionKey = 0		#For storing the symmetric key
        self.modulus = 0 #For storing the server's n in the public/private key
        self.pubExponent = 0	#For storing the server's e in the public key
        self.privExponent = 0  #For storing the server's d in the private key
        self.nonce = None
        # Call the methods to compute the public private/key pairs
        # Add code to initialize the candidates and their IDs

    def send(self, conn, message):
        conn.send(bytes(message,'utf-8'))

    def read(self):
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Client is unavailable")

    def close(self, conn):
        print("closing server side of connection")
        try:
            conn.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f" {repr(e)}",
            )
        finally:
            # Delete reference to socket object
            conn = None    

    def RSAencrypt(self, msg): 
        """Encryption side of RSA"""
        """"This function will return (msg^exponent mod modulus) and you must"""
        """ use the expMod() function"""
        cText = NumTheory.expMod(msg, self.pubExponent, self.modulus)
        return cText
    

    def RSAdecrypt(self, cText):
        """Decryption side of RSA"""
        """"This function will return (cText^exponent mod modulus) and you must"""
        """ use the expMod() function"""
        msg = NumTheory.NumTheory.expMod(cText, self.privExponent, self.modulus)
        return msg
        

    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext
    
    def generateNonce(self):
        """This method returns a 16-bit random integer derived from hashing the
            current time. This is used to test for liveness"""
        hash = hashlib.sha1()
        hash.update(str(time.time()).encode('utf-8'))
        self.nonce = int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)


#Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n)) = 1, since lcm(a,b) = |ab|/gcd(a,b).
    def findE(self, phi):
        """Method to randomly choose a good e given phi"""
        self.pubExponent = random.randint(1,self.modulus-1)
        #while e shares a common factor with phi, generate a random e
        while(NumTheory.NumTheory.gcd_iter(self.pubExponent,phi) != 1):
            self.pubExponent = random.randint(1,self.modulus-1)           
        

            
            

#Determine d as d ≡ e−1 (mod λ(n)); that is, d is the modular multiplicative inverse of e modulo λ(n).
    def genKeys(self, p, q):
        """Generates n, phi(n), e, and d"""
        self.modulus = p*q
        phi = (p-1)*(q-1)
        self.findE(phi)
        self.privExponent = NumTheory.NumTheory.ext_Euclid(phi, self.pubExponent)
          



    def clientHelloResp(self):
        """Generates response string to client's hello message"""
        self.generateNonce()
        status = "102 Hello AES, RSA16 " + str(self.modulus) + " " + \
         str(self.pubExponent) + " " + str(self.nonce)
        return status

  


    def start(self):
        """Main sending and receiving loop"""
        """You will need to complete this function"""    
        while True:
            self.connSocket, self.addr = self.socket.accept()
            print("Connection from %s has been established" % str(self.addr))
            msg = self.connSocket.recv(1024).decode('utf-8')   
            self.genKeys(self.p,self.q)         
            print (msg)
            self.send(self.connSocket, self.clientHelloResp())
            msg2 = self.connSocket.recv(1924).decode('utf-8')
            print(msg2)
            self.close(self.connSocket)
            break




def main():
    """Driver function for the project"""
    args = sys.argv 
    if len(args) != 2:
        print ("Please supply a server port.")
        sys.exit()
        
    HOST = ''  # Symbolic name meaning all available interfaces
    PORT = int(args[1])     # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()
    print ("Enter prime numbers. One should be between 211 and 281, and\
 the other between 229 and 307")
    p = int(input('Enter P: '))
    q = int(input('Enter Q: '))


    server = RSAServer(PORT, p, q)
    server.start()


if __name__ == "__main__":
    main()
