#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.serialization import *
# instead of importing the following methods and attributes 
# individually we import them all by specifying a *
#from cryptography.hazmat.primitives.serialization import load_pem_parameters
#from cryptography.hazmat.primitives.serialization import load_pem_public_key
#from cryptography.hazmat.primitives.serialization import ParameterFormat
#from cryptography.hazmat.primitives.serialization import PublicFormat 
#from cryptography.hazmat.primitives.serialization import Encoding
#
import binascii as ba
import socketserver
import sys


def load_dh_params():
    '''
    Load DH parameters from a file which is hard coded here for simplicity
    generating DH parameters is a time consuming operation so we rather use 
    generated values in practice several defined primes and generators
    are hard-coded into programs
    '''
    with open('./dh_2048_params.bin', 'rb') as f:
        # the load_pem_parameters is part of serialization which reads binary 
        # input and converts it to proper objects in this case it is
        # DH parameters
        params = load_pem_parameters(f.read(), default_backend())
    print('Parameters have been read from file, Server is ready for requests ...')
    return params

def generate_dh_prvkey(params):
    '''
    Generate a random private key (and a public key) from DH parameters
    '''
    return params.generate_private_key()
    
def check_client_pubkey(pubkey):
    '''
    Check whether the client public key is a valid instance of DH
    shouldn't we check whether the key is valid under the parameters
    sent by the server?
    '''
    if isinstance(pubkey, dh.DHPublicKey):
        return True
    else:
        return False

class Dh_Handler(socketserver.BaseRequestHandler):
    '''
    The request handler class for DH server

    It is instantiated once per connection to the server.
    '''

    def __init__(self, request, client_address, server):
        ''' here we do our service specific initialisation
         in this case we want to load the DH parameters
         that we have generated in advance
        '''

        # the params variable of the class will store the DH parameters
        self.params = load_dh_params()
        # current state, received a request but not handled yet
        # the state variable is made up, it helps us keep track of what is happening
        self.state = 0
        # we just pass the variables we receive to the BaseRequestHandler to do
        # whatever tcp needs to do  
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        '''
        This function handles the requests and sends proper responses
        '''

        # we read the first message sent by the client up to 3072 bytes
        # what if the message is longer?
        # should we check the size of the message?
        self.data = self.request.recv(3072).strip()

        # here we are inventing our own protocol so say the first message sent by the client
        # must be the text Hello, this message will only be valid if we are in state 0, ready 
        # and just received the first request       
        if self.state == 0 and self.data == b'Hello':
            # we have received proper request and the state changes to initiated
            self.state = 1
            # we print the received data and state on the server so we could follow how things
            # work
            print(self.data, self.state)
            # now let's say the proper response in our protocol to the client's Hello message
            # is the text message Hey There!
            response = b'Hey there!'
            # here we send this out to the client
            self.request.sendall(response)
        else:
            # we have received an invalid message since we can only expect a text Hello
            # in state 0, anything else is invalid and we end the communication and return
            response = b'I do not understand you, hanging up'
            self.request.sendall(response)
            return
        
        # so far so good, if we get here it means we have received a proper Hello
        # and have sent a proper Hey There!
        # now is time to read the next client request   
        self.data = self.request.recv(3072).strip()
        # we define the request be the text Params? and if we are in initiated state
        if self.state == 1 and self.data == b'Params?':
            # change the state to parameters requested
            self.state = 2
            print(self.data, self.state)
            dh_params = self.params
            # here we convert the parameter object to binary so we could send it over the network
            response = dh_params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            self.request.sendall(response)
        else:
            # if we get here then something was not right so we end the communication and return
            response = b'I do not understand you, hanging up'
            self.request.sendall(response)
            return

        # Ok we have come a long way, time to read the next client message
        self.data = self.request.recv(3072).strip()
        # now in our protocol we define that when the client wants to send the public key
        # it would start the message with the text "Client public key:", we check if the message
        # starts with that. We convert the received binary data to bytearray and take the first
        # 18-byte slice of it which must be our expected text. Of-course we must be in state 2 
        # (although we will not get here otherwise or would we?)
        if self.state == 2 and bytearray(self.data)[0:18] == b'Client public key:':
            # now we convert the binary message to bytearray so we can choose the public key 
            # part of it and use key serialization method to turn it into an object
            client_pubkey = load_pem_public_key(bytes(bytearray(self.data)[18:]), default_backend())
            # now if the public key is loaded (we might not get to this point otherwise, 
            # something for you to check!)
            if client_pubkey:
                # client key is valid so we generate our own from the parameters
                server_keypair = generate_dh_prvkey(self.params)

                # we will send the public key to the client and we need to convert it to 
                # binary to send over the network
                response = b'Server public key:' + server_keypair.public_key().public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

                # then we will calculate the shared secret
                shared_secret = server_keypair.exchange(client_pubkey)
                
                # and we are done back to waiting
                self.state = 0
                print(self.data, self.state)
                self.request.sendall(response)
                # we print the shared secret on the server and return
                print('Shared Secret:\n{}'.format(ba.hexlify(shared_secret)))
                return
            else:
                # if we get here the client key is not right
                response = b'Invalid client public key, hanging up'
                self.request.sendall(response)
                return  

def main():
    # choosing to listen on any address and port 7777
    host, port = '', 7777
    # create an instance of python's tcp server class, we specify which ip address or 
    # hostname and what request handler
    # the request handler is the one we defined as DH_Handler
    dh_server = socketserver.TCPServer((host, port), Dh_Handler)
    # we don't bother with threading and forking but we want to stop the server and shutdown the socket
    # so we capture the KeyboardInterrupt exception
    try:
        # this will start to listen in an infinite loop
        dh_server.serve_forever()
    except KeyboardInterrupt:
        # we need to be able to stop the service, for now we don't care if our implementation is ugly
        # we just want it to work
        dh_server.shutdown()
        sys.exit(0)
   
if __name__ == '__main__':
    main()
