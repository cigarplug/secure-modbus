#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
import binascii as ba
import socketserver
import socket

def dhclient(host, port):
    # we specify the server's address or hostname and port
    # host, port = 'localhost', 7777
    # create a tcp socket for IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to the tcp socket
    sock.connect((host, port))
    # set the first request according to our protocol
    request = b'Hello'
    # send the request
    sock.sendall(request)
    # read the server's response
    received = sock.recv(3072).strip()
    # print what we have received from the server
    print('Received:\n{}'.format(received))
    # check if the response is valid acording to our protocol
    if received == b'Hey there!':
        # set the next request accordingly
        request = b'Params?'
        sock.sendall(request)
    else:
        # if we get here something is not right
        print('Bad response')
        # close the connection and return
        sock.close()
        return

    # this means we are still in the game and the next server response must be the DH parameters
    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    dh_params = load_pem_parameters(received, default_backend())
    
    # check if the params are valid DH params (do we get here if the response was not valid or 
    # do we get an error before getting here?)
    if isinstance(dh_params, dh.DHParameters):
        # based on received parameters we generate a key pair
        client_keypair = dh_params.generate_private_key()
        # create the next message according to the protocol, get the binary of the public key 
        # to send to the server
        request = b'Client public key:' + client_keypair.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        sock.sendall(request)
    else:
        print('Bad response')
        sock.close()
        return

    # this means we are still in the game
    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    # check the format of the message (or rather the beginning)
    if bytearray(received)[0:18] == b'Server public key:':
        # get the server's public key from the binary and its proper index to the end
        server_pubkey = load_pem_public_key(bytes(bytearray(received)[18:]), default_backend())
        if isinstance(server_pubkey, dh.DHPublicKey):
            # calculate the shared secret
            shared_secret = client_keypair.exchange(server_pubkey)
            # print the shared secret
            print('Shared Secret\n{}'.format(ba.hexlify(shared_secret)))
            # close the connection
            sock.close()
            return
    
    # if we get here it means something went wrong
    print('Failed')
    sock.close()
    return

