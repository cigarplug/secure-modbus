#!/usr/bin/env python
# scripts/examples/simple_tcp_client.py
import socket

from umodbus import conf
from umodbus.client import tcp
import binascii

# Enable values to be signed (default is False).
conf.SIGNED_VALUES = True

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('10.5.5.10', 502))

# Returns a message or Application Data Unit (ADU) specific for doing
# Modbus TCP/IP.
message = tcp.write_multiple_coils(slave_id=1, starting_address=1, values=[1, 0,1,0])

# Response depends on Modbus function code. This particular returns the
# amount of coils written, in this case it is.

response = tcp.send_message(message, sock)

message =tcp.read_coils(slave_id=1,starting_address=1,quantity=4)
#message=b"".join([message,b'\x64'])
print(binascii.b2a_hex(message))
responce=tcp.send_message(message,sock)
print(responce)
sock.close()

