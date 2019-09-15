#!/usr/bin/env python
# scripts/examples/simple_tcp_client.py
import socket

import codecs
from umodbus import conf
from umodbus.client import tcp
import binascii as ba
from umodbus.utils import recv_exactly
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

from umodbus.client import dhclient

# key derivation
dh = dhclient.dh_client()

print("dhkeys received!")

salt_key = b'6ea920bb0e8ad58ebf2dbf5634f14f26'
salt_iv = b'4893ed0de93bf86871845c06e2bef676'



backend = default_backend()

hkdf_key = HKDF(
	algorithm=hashes.SHA256(),
	length=16,
	salt=ba.unhexlify(salt_key),
	info=b"keygen",
	backend=backend)

hkdf_iv = HKDF(
	algorithm=hashes.SHA256(),
	length=16,
	salt=ba.unhexlify(salt_iv),
	info=b"ivgen",
	backend=backend)

key = hkdf_key.derive(dh)
iv = hkdf_iv.derive(dh)



# Enable values to be signed (default is False).
conf.SIGNED_VALUES = True

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 502))


# salt_packet = (10001).to_bytes(2, "big") + sk + iv + (10001).to_bytes(2, "big")

# sock.sendall(salt_packet)

# Returns a message or Application Data Unit (ADU) specific for doing
# Modbus TCP/IP.


data = [1,1,1,1]

print("writing data to the server:", data)

message = tcp.write_multiple_coils(slave_id=1, starting_address=1, values=data)


aes = algorithms.AES(key)
mode = modes.CBC(iv)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)





# function to encrypt a plaintext message
def enc_msg(plain):

	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(ba.hexlify(plain))
	padded_data += padder.finalize()

	encryptor = cipher.encryptor()
	ct = encryptor.update(padded_data) + encryptor.finalize()
	return(ct)



# function to decrypt ciphertext
def dec_msg(enc):
	decryptor = cipher.decryptor()
	dec_msg = decryptor.update(enc) + decryptor.finalize()
	unpadder = padding.PKCS7(128).unpadder()
	dec_msg = unpadder.update(dec_msg)
	dt = dec_msg + unpadder.finalize()
	dt = ba.unhexlify(dt)
	return(dt)



sock.sendall(enc_msg(message))
resp = sock.recv(1024)
resp_dec = dec_msg(resp)

# print("message sent. server response:", ba.hexlify(resp))
print("message sent\nparsed server response:", tcp.parse_response_adu(resp_dec, message))



print("...\nreading data pts")
message = tcp.read_coils(slave_id=1,starting_address=1,quantity=len(data))


sock.sendall(enc_msg(message))

recv = sock.recv(1024)
print("message received!")
# print(recv)


print("message data parsed:")
recv_dec = dec_msg(recv)
print(tcp.parse_response_adu(recv_dec, message))

# print(responce)
sock.close()

