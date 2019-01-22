#!/usr/bin/python3

################################################
#                  EMRE OVUNC                  #
################################################
#              info@emreovunc.com              #
################################################
#                  USERS PART                  #
################################################

from sys              import exit
from time             import sleep
from json             import JSONEncoder
from json             import dumps
from json             import loads
from queue            import Queue
from random           import randint
from socket           import socket
from socket           import AF_INET
from socket           import SOCK_STREAM
from socket           import SOL_SOCKET
from socket           import SO_REUSEADDR
from datetime         import datetime    as dt
from threading        import Thread
from threading        import Lock
from Crypto.Hash      import SHA512
from cryptography.hazmat.backends              import default_backend
from cryptography.hazmat.primitives            import hashes
from cryptography.hazmat.primitives            import serialization
from cryptography.hazmat.primitives.ciphers    import Cipher
from cryptography.hazmat.primitives.ciphers    import algorithms
from cryptography.hazmat.primitives.ciphers    import modes
from cryptography.hazmat.primitives.kdf.hkdf   import HKDF
from cryptography.hazmat.primitives.asymmetric import ec


utf_type     = 'utf-8'
user_ip      = '127.0.0.1'
port         = 31313
user_msg     = 44444

queue_user   = Queue(maxsize = 500)

validBlock   = []
invalidBlock = []
lock_user    = Lock()


# Generate a fake block
class user_block:
    def __init__(self     , id_block  , id_sender        , id_receiver,
                 message  , timestamp , hash             , _id       ,
                 prevHash , who       , digital_signature , verKey    ,
                 totalHash, nonce):

        # Fill values with random hash(s)
        self.id_block    = id_block
        self.id_sender   = id_sender
        self.id_receiver  = id_receiver
        self.message     = message
        self.timestamp   = timestamp
        self.hash        = hash
        self._id         = _id
        self.prevHash    = prevHash
        self.nonce       = nonce
        self.who         = who
        signMSG          = (str(self.id_sender) + str(self.id_receiver) +
                             str(self.message)  + str(self.timestamp)).encode(utf_type)
        self.digital_signature = 0
        self.verKey     = 0

        newid_sender     = SHA512.new(str(self.id_sender).encode(utf_type)).hexdigest()
        newid_receiver   = SHA512.new(str(self.id_receiver).encode(utf_type)).hexdigest()
        newMessage      = SHA512.new(str(self.message).encode(utf_type)).hexdigest()
        newTimestamp    = SHA512.new(str(self.timestamp).encode(utf_type)).hexdigest()

        merkle = ''
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newid_sender).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newid_receiver).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newMessage).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newTimestamp).encode(utf_type)).hexdigest()
        self.hash = merkle
        self.totalHash  = totalHash


# Get current time
def get_current_time():
    now     = dt.now()
    time    = now.isoformat()
    return time


# Signing the message
def sign_message(private_key, message):
    message = message.encode(utf_type)
    sign = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return sign


# Verifying the message
def verify_message(public_key, message, sign):
    message = message.encode(utf_type)
    return public_key.verify(sign, message, ec.ECDSA(hashes.SHA256()))


# Convert dict to object
class obj(object):
    def __init__(self, d):

        for a, b in d.items():

            if isinstance(b, (list, tuple)):
                setattr(self, a, [obj(x) if isinstance(x, dict) else x for x in b])

            else:
                setattr(self, a, obj(b) if isinstance(b, dict) else b)


# Encoder class for mongodb blocks
class Encoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        else:
            return obj


# Decoder func. for receiving mongodb blocks
def decoder(dct):
    for k, v in dct.items():
        if '_id' in dct:
            try:
                dct['_id'] = ObjectId(dct['_id'])
            except:
                pass
        return dct


def loadRecv(object):
    return loads(object)


# USER SERVER CONNECTION
# Receive data from the socket
class ClientUserThread(Thread):
    def __init__(self, conn, IP_ADD):
        Thread.__init__(self)
        self.IP_ADD = IP_ADD
        self.conn = conn

    def run(self):
        while True:
            # Get data from the peer
            try:

                # Receive bytes
                tempBytes = self.conn.recv(4096)


                # Block Reloading..
                try:
                    block = loadRecv(tempBytes.decode("ISO-8859-1"))
                    block = obj(block)

                except:

                    try:
                        block = loads(tempBytes.decode("ISO-8859-1"), object_hook=decoder)
                        block = obj(block)

                    except:

                        try:
                            if b'estimatedtime' in tempBytes:
                                estimatedTime = str(tempBytes[13:]).split('b')[1].split("'")[1]
                                break
                            else:
                                break

                        except:
                            break

            # If Data does NOT load..!
            except ConnectionResetError:
                break

            except AttributeError:
                break

            except:
               break

            # Block has something:
            if block != "":
                queue_user.put(block)

            break


def connect(HOST, message):
    # Byte shifting values..
    try:
        mySocket = socket(AF_INET, SOCK_STREAM)
        mySocket.connect((HOST, port))

        # Sending bytes data..
        if type(message) == bytes:

            mySocket.send(message)

        # '.obj' in str(type(message))
        else:

            try:
                if "'__main__.user_block'" in str(type(message)):
                    try:
                        msg = dumps(message.__dict__)
                    except:
                        msg = dumps(message.__dict__, cls=Encoder)

                else:
                    if len(message) == 128:
                        msg = message

                mySocket.send(msg.encode("ISO-8859-1"))

            except:
                pass

        mySocket.close()
        return True

    except ConnectionRefusedError:
        return False

    except:
        return False


# User block operations..
def user_operations():
    while True:
        if int(queue_user.qsize()) != 0:
            block = queue_user.get()
            break

    lock_user.acquire()
    while True:

        try:
            if hasattr(block, 'process'):
                if block.process == 'ok':
                    prOK = 1
                elif block.process == 'nok':
                    prOK = 0
                else:
                    break

            else:
                break

        except:
            break

        # If the block is added to the blockchain.
        if prOK == 1:

            if len(validBlock) > 10000:
                validBlock.remove(validBlock[0])

            validBlock.append(block.prevHash)

        # If the block is NOT added to the blockchain.
        elif prOK == 0:

            if len(invalidBlock) > 10000:
                invalidBlock.remove(invalidBlock[0])

            invalidBlock.append(block.prevHash)

        # If the process flag is NOT valid.
        else:
            break

        break


# Get estimated message time
def queue_get_time():
    connect(user_ip, b'estimatedtime')


# Check the block.hash is VALID or INVALID
def checking(blockhash):

    if not str(blockhash).startswith('00000'):
        return 0

    # First things first, check the valid one
    try:
        found = 0
        for blocks in validBlock:
            if blocks == str("b'")+blockhash+str("'"):
                validBlock.remove(blocks)
                del blocks
                found = 1
                break
    except:
        found = 0

    # If the blockhash is NOT in the validBlocks
    if found == 0:

        # Check the invalid block
        try:
            foundi = 0
            for blocks in invalidBlock:
                if blocks == str("b'")+blockhash+str("'"):
                    invalidBlock.remove(blocks)
                    del blocks
                    foundi = 1
                    break
        except:
            foundi = 0

        # If the block also is NOT in the invalidBlocks
        if foundi == 0:
            connect(user_ip, blockhash)
            return 2

        # If the block found in the invalidBlocks
        else:
            return 0

    # If the blockhash found in the validBlocks
    else:
        return 1


# Listen all connections from User Server
def listen_all_conns():
    tcpServer3 = socket(AF_INET, SOCK_STREAM)
    tcpServer3.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    tcpServer3.bind((user_ip, user_msg))
    tcpServer3.listen(200)
    threads = []

    while True:
        try:
            (conn, (IP_ADD, port_ADD)) = tcpServer3.accept()
            newthread = ClientUserThread(conn, IP_ADD)
            newthread.start()
            threads.append(newthread)
        except:
            pass

        try:
            if not threads[0].is_alive():
                del threads[0]
        except:
            pass

    for t in threads:
        t.join()

# Elliptic curve key-pairs
def generateECDH():
    # Generate a private key for use in the exchange.
    private_key  = ec.generate_private_key(ec.SECT571K1(), default_backend())
    public_key   = private_key.public_key()
    return private_key, public_key


# To find shared secret using user's private and other's public
def findsharedKEY(private_key, peer_public):
    shared_key = private_key.exchange(ec.ECDH(), peer_public)
    return shared_key


# HMAC-based Extract and Expand Key Derivation Function
def derivation_keys(shared_key):
    hkdf = HKDF(
                algorithm = hashes.SHA256()  ,
                length    = 32               ,
                salt      = shared_key[16:32],
                info      = shared_key[:16]  ,
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
    length      = 16 - (len(message) % 16)
    message     += bytes([length]) * length
    backend     = default_backend()
    key         = keyDerived
    iv          = shared_key[:16]
    cipher      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor   = cipher.encryptor()
    encrypted   = encryptor.update(message) + encryptor.finalize()
    return encrypted


# AES Decryption Part
def aes_decryption_func(keyDerived, shared_key, message):
    if not type(message) == bytes:
        message     = message.encode(utf_type)
    if not type(shared_key) == bytes:
        shared_key = shared_key.encode(utf_type)
    if not type(keyDerived) == bytes:
        keyDerived = keyDerived.encode(utf_type)
    backend    = default_backend()
    key        = keyDerived
    iv         = shared_key[:16]
    cipher     = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor  = cipher.decryptor()
    dt         = decryptor.update(message) + decryptor.finalize()
    decrypted  = dt[:-dt[-1]].decode(utf_type)
    return decrypted


# Serialization of Public Key
def serialize_pubkey(public_key):
    serialized_public = public_key.public_bytes(
                            encoding = serialization.Encoding.PEM,
                            format   = serialization.PublicFormat.SubjectPublicKeyInfo)
    return serialized_public


# De-serialization of Public Key
def deserialize_pubkey(serialized_public):
    loaded_public_key = serialization.load_pem_public_key(
                            serialized_public,
                            backend = default_backend())
    return loaded_public_key


# Send the block
def sending_the_block(id_sender, id_receiver, message, digitalSign, verKey):

    eoBlock = user_block(
        # id_block
        0,

        # id_sender
        id_sender,

        # id_receiver
        id_receiver,

        # message
        message,

        # timestamp
        get_current_time(),

        # hash
        SHA512.new(str(randint(0, 1000000) + randint(0, 99999999)).encode(utf_type)).hexdigest(),

        # _id
        SHA512.new(str(randint(0, 1000000) + randint(0, 99999999)).encode(utf_type)).hexdigest(),

        # prevHash
        0,

        # who
        0,

        # digital_signature
        digitalSign,

        # verifyKey
        verKey,

        # totalHash
        0,

        # nonce
        100)

    connect(user_ip, eoBlock)


# Main func for the user part
def main():

    # Create a listening server for User Server
    listenUser      = Thread(target=listen_all_conns,       )
    listenUser.start()
    sleep(0.5)

    # User Operations...
    userOps         = Thread(target=user_operations,        )
    userOps.start()
    sleep(0.5)


# Return if the hashCheck value is in the blockchain or NOT!
def hash_checking_chain(hashCheck):
    while True:
        result = checking(hashCheck)

        # If the hash was in the blockchain
        if result == 1:
            break

        # Waiting answer...
        elif result == 2:
            sleep(2)

        # If the hash is NOT in the blockchain
        else:
            break

    if result == 1:
        return True

    else:
        return False


if __name__ == '__main__':
    try:
        main()
        sending_the_block(0, 0, 0, 0, 0)

    except KeyboardInterrupt:
        exit()

    except AttributeError:
        exit()

    except:
        exit()
