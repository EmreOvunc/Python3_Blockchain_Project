#!/usr/bin/python3

################################################
#                  EMRE OVUNC                  #
################################################
#              info@emreovunc.com              #
################################################
#             AUTHENTICATION SERVER            #
################################################

import ssl
from time        import sleep
from json        import dumps
from json        import JSONEncoder
from uuid        import uuid1
from pickle      import dumps       as d0
from socket      import socket
from socket      import AF_INET
from socket      import SOL_SOCKET
from socket      import SOCK_STREAM
from socket      import SO_REUSEADDR
from threading   import Thread
from subprocess  import PIPE
from subprocess  import Popen
from Crypto.Hash import SHA512
from cryptography.hazmat.backends              import default_backend
from cryptography.hazmat.primitives            import hashes
from cryptography.hazmat.primitives            import serialization
from cryptography.hazmat.primitives.ciphers    import modes
from cryptography.hazmat.primitives.ciphers    import Cipher
from cryptography.hazmat.primitives.ciphers    import algorithms
from cryptography.hazmat.primitives.kdf.hkdf   import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

utf_type = 'utf-8'

number_servers  = 4
blockCodes      = []
binding_address = 'X'
port_number     = 55555

# Values
chainUUID   = ""
key_storage = []


# Generate 2048-bits prime number
def generate_blockcodes():
    if len(blockCodes) == 13:
        return True
    prime_proc     = Popen(['openssl prime -generate -bits 2048'], stdout=PIPE, shell=True)
    (out, err)     = prime_proc.communicate()
    generated_code = out.decode(utf_type)
    for codes in blockCodes:
        if codes   == generated_code:
            generate_blockcodes()
    blockCodes.append(generated_code)
    generate_blockcodes()


# Encoder class for mongodb blocks
class Encoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        else:
            return obj


# Save important informations
def send_others_public(peer_public, peer_ip, shared_pairs):
    global key_storage
    changed = 0
    # Update values
    for keys in key_storage:
        if keys[1] == peer_ip:
            keys = (peer_public, peer_ip, shared_pairs)
            changed = 1
            break

    # Add values
    if changed == 0:
        key_storage.append((peer_public, peer_ip, shared_pairs))

    # Send values
    for keys in key_storage:
        if keys[1] != peer_ip:
            connect(keys[1], aes_encryption_func(derivation_keys(keys[2]),
                                           keys[2],
                                           (peer_public + peer_ip.encode(utf_type))))

            connect(peer_ip, aes_encryption_func(derivation_keys(shared_pairs),
                                           shared_pairs,
                                           (keys[0] + keys[1].encode(utf_type))))


# CLIENT SIDE
# Send any block to others
def connect(HOST, message):
    # Socket informations
    try:
        mySocket = socket(AF_INET, SOCK_STREAM)
        mySocket.settimeout(2)
        context  = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.load_cert_chain('selfsigned.cert', 'selfsigned.key')
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        conn     = context.wrap_socket(mySocket)
        conn.connect((HOST, port_number))

        # Sending bytes data..
        if type(message) == bytes:
            conn.send(message)

        # '.obj' in str(type(message))
        else:
            try:
                msg = dumps(message.__dict__)

            except:
                try:
                    msg = dumps(message.__dict__, cls=Encoder)

                except:
                    msg = message

            try:
                conn.send(d0(msg.encode("ISO-8859-1")))
            except:

                try:
                    conn.send(msg)
                except:
                    return False

        conn.close()
        return True

    except ConnectionRefusedError:
        return False

    except:
        return False


# SERVER SIDE
# Receive data from the socket
class ClientThread(Thread):
    def __init__(self, conn, IP_ADD):
        Thread.__init__(self)
        self.IP_ADD = IP_ADD
        self.conn = conn

    def run(self):
        while True:
            # Receive bytes
            try:
                tempBytes = self.conn.recv(4096)

            except:
                break

            # Block Reloading..
            try:
                # If the public key received
                if str(tempBytes.decode(utf_type)).startswith("-----BEGIN PUBLIC KEY-----") and\
                   "-----END PUBLIC KEY-----" in str(tempBytes.decode(utf_type)):

                        # Get UUID hash
                        if control_uuid(tempBytes.decode(utf_type).split('-----END PUBLIC KEY-----\n')[1]):

                            ecdh_pairs   = elliptic_pair()
                            connect(self.IP_ADD, ecdh_pairs.serialized_public)
                            sleep(1)

                            certificate  = tempBytes.decode(utf_type).split(tempBytes.decode(utf_type)[-128:])[0].encode(utf_type)
                            global chainUUID
                            shared_pairs = ecdh_pairs.findsharedKEY(deserialize_pubkey(certificate))

                            for index in range(0, len(blockCodes)):
                                connect(self.IP_ADD, aes_encryption_func(derivation_keys(shared_pairs),
                                                                   shared_pairs,
                                                                   blockCodes[index]))
                                sleep(0.25)

                            send_others_public(certificate, self.IP_ADD, shared_pairs)
                            chainUUID    = 0

                        break

                else:
                    break

            except:
                break


# UUID controlling..
def control_uuid(peer_uuid):
    global chainUUID
    if peer_uuid == SHA512.new(str(chainUUID).encode(utf_type)).hexdigest():
        return True
    return False


# Listen all connections
def Conn():
    tcpServer = socket(AF_INET, SOCK_STREAM)
    tcpServer.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    tcpServer.bind((binding_address, port_number))
    tcpServer.listen(200)

    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('selfsigned.cert', 'selfsigned.key')
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')

    threads = []

    while True:

        try:
            (conn, (IP_ADD, port_number_ADD)) = tcpServer.accept()
            conn      = context.wrap_socket(conn, server_side=True)
            newthread = ClientThread(conn, IP_ADD)
            newthread.start()
            threads.append(newthread)

        except ssl.SSLError:
            debug('Sender does NOT use SSL..!')

        except:
            pass

        try:
            if not threads[0].is_alive():
                del threads[0]
        except:
            pass

    for t in threads:
        t.join()


# UUID Generator for new comers
def uuid_generator():
    global chainUUID
    chainUUID = uuid1()

    file = open('/var/www/html/code.txt', 'w')
    file.write(str(chainUUID))
    file.close()

    return chainUUID


# Elliptic curve key-pairs
class elliptic_pair:
    def __init__(self):
        # Generate a private key for use in the exchange.
        self.private_key = ec.generate_private_key(ec.SECT571K1, default_backend())
        self.public_key  = self.private_key.public_key()

        # Serialization of Public Key
        self.serialized_public = self.public_key.public_bytes(
                                  encoding = serialization.Encoding.PEM,
                                  format   = serialization.PublicFormat.SubjectPublicKeyInfo)

    # To find shared secret using user's private and other's public
    def findsharedKEY(self, peer_public):
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public)
        return shared_key

    # Serialize and save private key
    def __serialize_private(self):
        __serialized_private = self.private_key.private_bytes(
                                encoding = serialization.Encoding.PEM,
                                format   = serialization.PrivateFormat.PKCS8,
                                encryption_algorithm = serialization.BestAvailableEncryption(bytes(blockCodes[0])))

    # Signing the message
    def sign_message(self, message):
        message = message.encode(utf_type)
        sign    = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return sign

    @staticmethod
    # Verifying the message
    def verify_message(public_key, message, sign):
        message = message.encode(utf_type)
        return public_key.verify(sign, message, ec.ECDSA(hashes.SHA256()))


# De-serialization of Public Key
def deserialize_pubkey(peer_public):
    loaded_public_key = serialization.load_pem_public_key(
                            peer_public,
                            backend = default_backend())
    return loaded_public_key


# HMAC-based Extract and Expand Key Derivation Function
def derivation_keys(shared_key):
    if not type(shared_key) == bytes:
        shared_key = shared_key.encode(utf_type)
    hkdf = HKDF(
                algorithm = hashes.SHA256()   ,
                length    = 32                ,
                salt      = shared_key[16:32] ,
                info      = shared_key[:16]   ,
                backend   = default_backend())

    keyDerived = hkdf.derive(shared_key[16:])
    return keyDerived


# AES Encryption Part
def aes_encryption_func(keyDerived, shared_key, message):
    if not type(message) == bytes:
        message     = message.encode(utf_type)
    if not type(shared_key) == bytes:
        shared_key = shared_key.encode(utf_type)
    if not type(keyDerived) == bytes:
        keyDerived = keyDerived.encode(utf_type)
    length    = 16 - (len(message) % 16)
    message  += bytes([length]) * length
    backend   = default_backend()
    key       = keyDerived
    iv        = shared_key[:16]
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message) + encryptor.finalize()
    return encrypted


# AES Decryption Part
def aes_decryption_func(keyDerived, shared_key, message):
    if not type(message) == bytes:
        message     = message.encode(utf_type)
    if not type(shared_key) == bytes:
        shared_key = shared_key.encode(utf_type)
    if not type(keyDerived) == bytes:
        keyDerived = keyDerived.encode(utf_type)
    backend   = default_backend()
    key       = keyDerived
    iv        = shared_key[:16]
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    dt        = decryptor.update(message) + decryptor.finalize()
    decrypted = dt[:-dt[-1]].decode(utf_type)
    return decrypted


def generate_uuids():
    uuid_generator()
    global chainUUID
    time = 90
    while True:
        if time <= 0:
            generate_uuids()

        if chainUUID == 0:
            generate_uuids()

        sleep(1)
        time -= 1


def main():
    generate_blockcodes()

    # Create a listening server
    listenConn      = Thread(target=Conn,           )
    listenConn.start()
    sleep(0.5)

    generateuuid    = Thread(target=generate_uuids, )
    generateuuid.start()
    sleep(0.5)

main()
