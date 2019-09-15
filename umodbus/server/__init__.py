try:
    from socketserver import BaseRequestHandler
except ImportError:
    from SocketServer import BaseRequestHandler
import binascii
import binascii as ba

from umodbus import log
from umodbus.functions import create_function_from_request_pdu
from umodbus.exceptions import ModbusError, ServerDeviceFailureError
from umodbus.utils import (get_function_code_from_request_pdu,
                           pack_exception_pdu, recv_exactly, recv_exactly_m)


from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF



def route(self, slave_ids=None, function_codes=None, addresses=None):
    """ A decorator that is used to register an endpoint for a given
    rule::

        @server.route(slave_ids=[1], function_codes=[1, 2], addresses=list(range(100, 200)))  # NOQA
        def read_single_bit_values(slave_id, address):
            return random.choise([0, 1])

    :param slave_ids: A list or set with slave id's.
    :param function_codes: A list or set with function codes.
    :param addresses: A list or set with addresses.
    """
    def inner(f):
        self.route_map.add_rule(f, slave_ids, function_codes, addresses)
        return f

    return inner


class AbstractRequestHandler(BaseRequestHandler):
    """ A subclass of :class:`socketserver.BaseRequestHandler` dispatching
    incoming Modbus requests using the server's :attr:`route_map`.

    """
 

    def handle(self):
        try:
            while True:
                try:
                        
                    message=self.request.recv(1024)
                    if not message: break

                    salt_key = b'6ea920bb0e8ad58ebf2dbf5634f14f26'
                    salt_iv = b'4893ed0de93bf86871845c06e2bef676'

                    def readfile ( file ) :
                        with open (file ,'rb') as f:
                            content = f.read ()
                            f.close()
                            return content

                    dh = readfile("umodbus/secrets/my_dh_file")

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

                    aes = algorithms.AES(key)
                    mode = modes.CBC(iv)

                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

                    decryptor = cipher.decryptor()
                    dec_msg = decryptor.update(message) + decryptor.finalize()

                    unpadder = padding.PKCS7(128).unpadder()
                    dec_msg = unpadder.update(dec_msg)
                    dt = dec_msg + unpadder.finalize()

                    dt = ba.unhexlify(dt)

                    #At this Point the message from the client has been received and is ready to be processed 
                    mbap_header = dt[0:7]
                    remaining = self.get_meta_data(mbap_header)['length'] - 1
                    request_pdu = dt[7:8+remaining]

                      
                except ValueError:
                    return

                response_adu = self.process(mbap_header + request_pdu)

                #At this point the responce to the message  has been structured and is ready to be send to the client
                self.respond(response_adu)
        except:
            import traceback
            log.exception('Error while handling request: {0}.'
                          .format(traceback.print_exc()))
        raise



    def process(self, request_adu):
        """ Process request ADU and return response.

        :param request_adu: A bytearray containing the ADU request.
        :return: A bytearray containing the response of the ADU request.
        """
        meta_data = self.get_meta_data(request_adu)
        request_pdu = self.get_request_pdu(request_adu)

        response_pdu = self.execute_route(meta_data, request_pdu)
        response_adu = self.create_response_adu(meta_data, response_pdu)

        return response_adu

    def execute_route(self, meta_data, request_pdu):
        """ Execute configured route based on requests meta data and request
        PDU.

        :param meta_data: A dict with meta data. It must at least contain
            key 'unit_id'.
        :param request_pdu: A bytearray containing request PDU.
        :return: A bytearry containing reponse PDU.
        """
        try:
            function = create_function_from_request_pdu(request_pdu)
            results =\
                function.execute(meta_data['unit_id'], self.server.route_map)

            try:
                # ReadFunction's use results of callbacks to build response
                # PDU...
                return function.create_response_pdu(results)
            except TypeError:
                # ...other functions don't.
                return function.create_response_pdu()
        except ModbusError as e:
            function_code = get_function_code_from_request_pdu(request_pdu)
            return pack_exception_pdu(function_code, e.error_code)
        except Exception as e:
            log.exception('Could not handle request: {0}.'.format(e))
            function_code = get_function_code_from_request_pdu(request_pdu)

            return pack_exception_pdu(function_code,
                                      ServerDeviceFailureError.error_code)

    def respond(self, response_adu):
        """ Send response ADU back to client.
        :param response_adu: A bytearray containing the response of an ADU.
        """
        log.info('--> {0} - {1}.'.format(self.client_address[0],
                 ba.hexlify(response_adu)))

        salt_key = b'6ea920bb0e8ad58ebf2dbf5634f14f26'
        salt_iv = b'4893ed0de93bf86871845c06e2bef676'

        def readfile ( file ) :
            with open (file ,'rb') as f:
                content = f.read ()
                f.close()
                return content

        dh = readfile("umodbus/secrets/my_dh_file")

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

        aes = algorithms.AES(key)
        mode = modes.CBC(iv)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)


        def enc_msg(plain):

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(ba.hexlify(plain))
            padded_data += padder.finalize()

            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            return(ct)



        self.request.sendall(enc_msg(response_adu))