# secure-modbus

## Securing the modbus protocol message exchange

In this repository, we have modified the uModbus library and implemeneted encryption of messages that are passed over TCP.
Secure keys are generated using Diffie-Helman exchange. These are fed into a KDF to obtain keys for AES encryption

AES mode: CBC-128

Authentication: HMAC  (encrypt and MAC)

## Bugs
The secure variation of modbus server is able to serve once per instance. This should be fixable by moving some code chunks around
