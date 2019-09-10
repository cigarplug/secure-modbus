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

# Enable values to be signed (default is False).
conf.SIGNED_VALUES = True

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 502))

# Returns a message or Application Data Unit (ADU) specific for doing
# Modbus TCP/IP.
print("writing data:")
data = [1,1,1,1]
message = tcp.write_multiple_coils(slave_id=1, starting_address=1, values=data)

print("message data", message)
# print("message data og:", message)
print("message data ba", ba.unhexlify(ba.hexlify(message)))

# mbap = ba.hexlify(message[0:7])

# pdu = ba.hexlify(message[7:])
# fnx_code = ba.hexlify(pdu[:1])
# data = ba.hexlify(pdu[1:])

# print("mbap:", mbap)
# print("fnx_code:", fnx_code)
# print("data:", data)
# print("length:", mbap.decode("hex"))





def enc_msg(msg):
	key = b'b311de11706f5ede'
	iv = b'd85f4ed091b8a210'


	backend = default_backend()
	# data = message
	aes = algorithms.AES(key)
	mode = modes.CBC(iv)

	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

	# mbap = msg[0:7]
	# pdu = msg[7:]

	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(ba.hexlify(msg))
	padded_data += padder.finalize()

	encryptor = cipher.encryptor()
	ct = encryptor.update(padded_data) + encryptor.finalize()
	return(ct)

# Response depends on Modbus function code. This particular returns the
# amount of coils written, in this case it is.

# print("encrypted data:", ct)

print("encrypted message:", enc_msg(message))

sock.sendall(enc_msg(message))
resp = sock.recv(1024)

print("message sent. server response:", ba.hexlify(resp))
print("parsed response:", tcp.parse_response_adu(resp, message))

# print("hehe", tcp.parse_response_adu(resp, message))

# mm=sock.recv(1024)

# parse_response_adu(decr, message)

#response = tcp.send_message(message, sock)



# print(response)

print("reading data pts")
message = tcp.read_coils(slave_id=1,starting_address=1,quantity=len(data))
#message=b"".join([message,b'\x64'])
print("read coils msg plain hex:", ba.hexlify(message))
print("read coils msg enc:", enc_msg(message))
# print(ba.b2a_hex(message))

sock.sendall(enc_msg(message))

recv = sock.recv(1024)
print("received:")
print(recv)


print("received parsed:")
print(tcp.parse_response_adu(recv, message))

# print(responce)
sock.close()

