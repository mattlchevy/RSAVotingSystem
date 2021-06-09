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
import json




class RSAServer(object):
    
    def __init__(self, port, p, q):
        # two prime numbers for operation and phi (may operate without)
        self.p = p 
        self.q = q
        self.phi = (p-1)*(q-1)

        # initialize socket
        self.socket = socket.socket() 

        # The option below is to permit reuse of a socket in less than an MSL
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
     
        # initialize any available interface with a specified port
        self.socket.bind(("", int(port)))
        
        # listening for incoming connections
        self.socket.listen(5)	

        # variable storing the last stream of bytes recieved
        self.lastRcvdMsg = 0

        #For storing the symmetric key
        self.sessionKey = 0	

        #For storing the server's n in the public/private key
        self.modulus = 0 

        #For storing the server's e in the pu n vco[pblic key
        self.pubExponent = 0	

        #For storing the server's d in the private key
        self.privExponent = 0 
        self.nonce = 0

        # Call the methods to compute the public private/key pairs
        self.genKeys(self.p,self.q)  

        # Add code to initialize the candidates and their IDs
        print("What are the first names of the candidates?")
        self.can1 = str(input("The First Candidates name will be:  "))   
        self.can2 = str(input("The Second Candidates name will be: "))
        self.candidates = [{"Candidate: ": self.can1, "ID: ": 92, 'Votes: ': 0}, {"Candidate: ": self.can2, "ID: ": 37, 'Votes: ': 0}]
        self.winner = None
        #Indicate when to attemp client connection
        print("Now listening for client...") 

    def send(self, conn, message):
        conn.send(bytes(message,'utf-8'))

    def read(self, conn):
        try:
            data = conn.recv(4096).decode('utf-8')
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
        ptext = NumTheory.NumTheory.expMod(cText, self.privExponent, self.modulus)
        return ptext
        

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
    def findE(self):
        """Method to randomly choose a good e given phi"""
        self.pubExponent = random.randint(1,self.modulus-1)
        #while e shares a common factor with phi, generate a random e
        while(NumTheory.NumTheory.gcd_iter(self.pubExponent,self.phi) != 1):
            self.pubExponent = random.randint(1,self.modulus-1)           
        

            
            

#Determine d as d ≡ e−1 (mod λ(n)); that is, d is the modular multiplicative inverse of e modulo λ(n).
    def genKeys(self, p, q):
        """Generates n, phi(n), e, and d"""
        self.modulus = p*q
        self.findE()
        self.privExponent = NumTheory.NumTheory.ext_Euclid(self.phi, self.pubExponent)
          



    def clientHelloResp(self):
        """Generates response string to client's hello message"""
        self.generateNonce()        
        status = "102 Hello AES, RSA16 " + str(self.modulus) + " " + \
         str(self.pubExponent) + " " + str(self.nonce)
        return status

    def nonceVerification(self, recievedNonce):
        """Verifies that the transmitted nonce matches that received
        from the client."""
        return self.nonce == recievedNonce

    def VCandidates(self): 
       status = '106[{Candidate: '  + str(self.candidates[0]['Candidate: ']) + ', ID: '+ str(self.candidates[0]['ID: '])+' }, {Candidates: ' + \
                 str(self.candidates[1]['Candidate: ']) + ', ID: '+ str(self.candidates[1]['ID: '])+' }]'
       return status

    
    def PollOpen(self):
        status = '107 Poll Open'
        return status

    def Error(self):
        status = '400 Error'
        return status

    def WinnerMsg(self):
        status = '220 ' + str(self.winner)
        return status

    def start(self):
        """Main sending and receiving loop"""
        """You will need to complete this function"""    
        self.connSocket, self.addr = self.socket.accept()
        print("Connection from %s has been established" % str(self.addr))
        status = 1
        while status == 1:
            
            self.read(self.connSocket)
            if "101" in self.lastRcvdMsg:
                print ("Recievend from client: "+ self.lastRcvdMsg)

                self.send(self.connSocket, self.clientHelloResp())
                print('Modulus: ' + str(self.modulus))
                print('Phi ' + str(self.phi))
                print('D: ' + str(self.privExponent))
                print('E: ' + str(self.pubExponent))
                print('Nonce: ' + str(self.nonce))
                print("\n")

            
            #self.read(self.connSocket)
            if "103" in self.lastRcvdMsg:
                print ("Received from client: "+ self.lastRcvdMsg)
                print("\n")
                
        
                self.sessionKey = self.RSAdecrypt(int(self.lastRcvdMsg.split(',')[1]))
                print('RSA Decrypted session key: ' + str(self.sessionKey))
                client_nonce = self.AESdecrypt(int(self.lastRcvdMsg.split(',')[2]))
                print('AES Decrypted Nonce: ' + str(client_nonce))
                
                if str(self.nonce) == str(client_nonce):
                    print("Nonce Match, Proceeding Now....")
                    self.send(self.connSocket, self.VCandidates())
                    msg = [{"Candidate": str(self.candidates[0]['Candidate: ']) , "ID": str(self.candidates[0]['ID: '])  }, {"Candidate": \
                            str(self.candidates[1]['Candidate: ']), "ID": str(self.candidates[1]['ID: '])}]
                    tosend = json.dumps(msg)
                    self.send(self.connSocket, tosend )
                    self.send(self.connSocket, self.PollOpen())
                else:
                    self.send(self.connSocket, "400 Error")
                    self.close(self.connSocket)
            
            if "115" in self.lastRcvdMsg:
                self.read(self.connSocket)
                msg = json.loads(self.lastRcvdMsg)
                print('The total amount of votes for the first candidate is: ' +str(self.AESdecrypt(msg[0]["Votes"])))
                print('The total amount of votes for the second candidate is:' +str(self.AESdecrypt(msg[1]["Votes"])))
                print(msg)

            '''  encvote = self.connSocket.recv(2048).decode('utf-8')
                vote = self.AESdecrypt(encvote)
               # FINISH HERE
            else:
                self.send(self.connSocket, self.Error())
                self.close(self.connSocket)
            break'''

def is_prime(n):
    if n % 2 == 0 and n > 2: 
        return False
    return all(n % i for i in range(3, int(math.sqrt(n)) + 1, 2))



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
    if (211 < p < 281) and (229 < q < 307):
        print("Now listening for client...")
        if is_prime(p) and is_prime(q):  
            server = RSAServer(PORT, p, q)
            server.start()
        else:
            print("please ensure p and q are bth prime...")
    else:
        print('Please ensure your numbers fit the criteria...')
if __name__ == "__main__":
    main()
