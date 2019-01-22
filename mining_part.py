#!/usr/bin/python3

################################################
#                  EMRE OVUNC                  #
################################################
#              info@emreovunc.com              #
################################################
#                  MINING PART                 #
################################################

import ssl
from sys             import exit
from time            import sleep
from json            import JSONEncoder
from json            import dumps
from json            import loads
from queue           import Queue
from pickle          import dumps       as d0
from pickle          import loads       as l0
from random          import randint
from random          import choice
from socket          import socket
from socket          import AF_INET
from socket          import SOCK_STREAM
from socket          import SOL_SOCKET
from socket          import SO_REUSEADDR
from base64          import b64encode
from base64          import b64decode
from string          import digits
from string          import ascii_lowercase
from string          import ascii_uppercase
from logging         import warning
from logging         import info
from logging         import debug
from logging         import basicConfig
from logging         import DEBUG
from datetime        import datetime    as dt
from threading       import Thread
from threading       import Lock
from Crypto.Hash     import SHA512
from bson.objectid   import ObjectId
from multiprocessing import Process
from multiprocessing import Manager
from cryptography.hazmat.backends              import default_backend
from cryptography.hazmat.primitives            import hashes
from cryptography.hazmat.primitives            import serialization
from cryptography.hazmat.primitives.ciphers    import modes
from cryptography.hazmat.primitives.ciphers    import Cipher
from cryptography.hazmat.primitives.ciphers    import algorithms
from cryptography.hazmat.primitives.kdf.hkdf   import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

# Logging configuration
basicConfig(filename = 'eo_miningpart.log',
            level    = DEBUG,
            format   = '%(asctime)s : %(levelname)s : %(message)s',
            datefmt  = '%m/%d/%Y %I:%M:%S %p')

# Connection informations
current_address  = "X"
binding_address  = "127.0.0.1"
hosts_of_chains  = ["Y", "Z"]
auth_server      = 'T'
mining_hosts     = []
chain_port       = 55555
user_port        = 31313
user_message     = 44444

# Multi-threading
miner_thread_lock   = Lock()
user_thread_lock    = Lock()

# Multi-processing
manager           = Manager()
queue_block_whom  = manager.Queue(maxsize=500)
queue_user_whom   = manager.Queue(maxsize=500)
queue_proofofwork = manager.Queue(maxsize=2)

# Block headers
header_of_block = 
              [
               'senderID'        , 'receiverID', 'message'  , 'timestamp',
               'digitalSignature', 'verKey'    , 'prevHash' , '_id'      ,
               'hash'            , 'who'       , 'totalHash', 'blockID'  ,
               'nonce'
               ]

# Block.ok and NoK objects
block_ok_obj     = []
block_previd_obj = []

# Encoding & Decoding type
utf_type       = 'utf-8'

# Defaults
blockID     = '0'
prevHash    = '0'
blockid_end = '0'
qF          = 8080
qOUT        = 0

# Queue(s)
queue_chain     = Queue(maxsize=500)
queue_user      = Queue(maxsize=500)
queue_verify    = Queue(maxsize=500)
queue_fakeblock = Queue(maxsize=500)

# Queue timeout 30 seconds for each item
queue_timeout   = 30

# Temp. Queues
temp_hash_q     = Queue(maxsize=500)
temp_hash_q_2   = Queue(maxsize=500)

# Block Communication Codes
codes_of_block = []

# Other's Public
public_storage = []

# 0 for Block is NoK
# 1 for Block is OK
# 2 for Hash is NoK
# 3 for Hash is OK
# 4 for lastBlock is NoK
# 5 for lastBlock is OK
# 6 for lastBlock Request
# 7 for Database add
# 8 for User NoK
# 9 for User OK
# 10 for User Request
# 11 for Block values request
# 12 for  Send your blocks

# Converter flag to check block hash
flag_converter = 0


# Block ok and NoK values calculation
class block_ok_nok_objs:
    def __init__(self, hash, ok, NoK, IP):
        info('block_ok_nok_objs object is created.')
        self.hash = hash
        self.ok   = ok
        self.NoK  = NoK
        self.IP   = []
        self.IP.append(IP)


# prevHash and blockID values
class block_prev_id:
    def __init__(self, hash, prevHash, blockID, counter, IP):
        self.prevHash = []
        self.blockID  = []
        self.IP       = []
        self.counter  = []
        self.hash     = hash
        if prevHash != 0:
            self.prevHash.append(prevHash)
        if blockID  != 0:
            self.blockID.append(blockID)
        if IP != 0:
            self.IP.append(IP)
        if counter != 0:
            self.counter.append(counter)


# Sign the block
def sign_block(Block):
    Block.verKey = b64encode(ecdh_obj.sign_message(Block.totalHash)).decode("ISO-8859-1")


def quitLog():
    warning('----------------------------------------')
    warning('----- Mining Server is stopping... -----')
    warning('----------------------------------------')


def startLog():
    warning('++++++++++++++++++++++++++++++++++++++++')
    warning('+++++ Mining Server is starting... +++++')
    warning('++++++++++++++++++++++++++++++++++++++++')


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


# Get current time
def get_current_time():
    now = dt.now()
    time = now.isoformat()
    return time


def dumpRecv(object):
    return dumps(object)


def loadRecv(object):
    return loads(object)


# Queue Function for putting
def qPut(q, data):
    try:
        q.put(data, timeout=queue_timeout)
    except:
        qGet(q)
        try:
            q.put(data, timeout=queue_timeout)
        except:
            pass


# Queue Function for getting
def qGet(q):
    try:
        if int(q.qsize()) != 0:
            return q.get()
    except:
        return 0


# Queue Function for queue size
def qSize(q):
    return int(q.qsize())


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
                                encryption_algorithm = serialization.BestAvailableEncryption(bytes(codes_of_block[0])))

    # Signing the message
    def sign_message(self, message):
        message = message.encode(utf_type)
        sign    = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return sign

    @staticmethod
    # Verifying the message
    def verify_message(public_key, message, sign):
        try:
            sign = b64decode(sign).encode("ISO-8859-1")
        except:
            sign = b64decode(sign)
        message = message.encode(utf_type)
        return public_key.verify(sign, message, ec.ECDSA(hashes.SHA256()))


# De-serialization of Public Key
def deserialize_pubkey(peer_public):
    loaded_public_key = serialization.load_pem_public_key(
                            peer_public,
                            backend = default_backend())
    return loaded_public_key


# Serialization of Public Keys
def serialize_pubkey(publickey):
    serialized_public = publickey.public_bytes(
                            encoding = serialization.Encoding.PEM,
                            format   = serialization.PublicFormat.SubjectPublicKeyInfo)
    return serialized_public


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
    message    += bytes([length]) * length
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


def engine_starts():
    # Create a listening server for Blockchain Server
    listenConn      = Thread(target=listen_all_chain_conns,      )
    listenConn.start()
    sleep(0.5)

    # Generate blockWho for miner
    blockWhomin     = Process(target=block_who_miner_func,   )
    blockWhomin.start()
    sleep(0.05)

    # Generate blockWho for miner
    blockWhomin2    = Process(target=block_who_miner_func,   )
    blockWhomin2.start()
    sleep(0.05)

    # Generate blockWho for user
    blockWhousr     = Process(target=block_who_user_func,   )
    blockWhousr.start()
    sleep(0.05)

    # Generate blockWho for user
    blockWhousr2    = Process(target=block_who_user_func,   )
    blockWhousr2.start()
    sleep(0.05)

    global shared_pairs
    shared_pairs = 0

    # Generate an elliptic curve object
    global ecdh_obj
    ecdh_obj = elliptic_pair()

    my_uuid   = input('UUID:')
    global hash_uuid
    hash_uuid = SHA512.new(my_uuid.encode(utf_type)).hexdigest().encode(utf_type)

    connect(auth_server, ecdh_obj.serialized_public + hash_uuid)

    while True:
        if len(codes_of_block) == 13:
            break


# When the program starts...
def engine_func():
    global blockCode00, blockCode01, blockCode02, blockCode03
    global blockCode04, blockCode05, blockCode06, blockCode07
    global blockCode08, blockCode09, blockCode10, blockCode11
    global blockCode11, blockCode12

    startLog()
    info('User Binding address is [' + str(current_address)    + ']')
    info('Binding address is ['      + str(binding_address)    + ']')
    info('Chain Port number is ['    + str(chain_port)   	   + ']')
    info('User Port number is ['     + str(user_port)          + ']')
    info('User MSG Port number is [' + str(user_message)       + ']')
    info('Queue for "User" is created.'                      )
    info('Queue for "Verify" is created.'                    )
    info('Queue for "Chain" is created.'                     )
    info('main() function is started.'                       )
    engine_starts()
    main()


def conv_mod_10(hex):
    if hex == 'a':
        return 0

    elif hex == 'b':
        return 1

    elif hex == 'c':
        return 2

    elif hex == 'd':
        return 3

    elif hex == 'e':
        return 4

    elif hex == 'f':
        return 5

    else:
        return hex


def conv_mod_16(nmbr):
    if int(nmbr) == 0:
        return 'a'

    elif int(nmbr) == 1:
        return 'b'

    elif int(nmbr) == 2:
        return 'c'

    elif int(nmbr) == 3:
        return 'd'

    elif int(nmbr) == 4:
        return 'e'

    elif int(nmbr) == 5:
        return 'f'

    else:
        return nmbr


# Convert dict to object
class obj(object):
    def __init__(self, d):

        for a, b in d.items():

            if isinstance(b, (list, tuple)):
                setattr(self, a, [obj(x) if isinstance(x, dict) else x for x in b])

            else:
                setattr(self, a, obj(b) if isinstance(b, dict) else b)


# Dump object before sending
def dumping_object(object):
    info('The object is dumping..')
    return dumps(object)


# Load received object
def loading_object(object):
    info('The object is loading..')
    return loads(object)


# Find and return block_ok_nok_objs object
def found_block_ok_objs(blockHash, IPAdd, type):
    if type == 0:
        for calcs in block_ok_obj:
            if calcs.hash == blockHash:
                info('Calc0bj already created.!')
                return calcs, 1

        info('Calc0bj is appending...')
        block_ok_obj.append(block_ok_nok_objs(blockHash, 0, 0, IPAdd))
        return block_ok_obj[-1], 0

    elif type == 2:
        IPf = 0

        if len(block_previd_obj) > 15:
            block_previd_obj.remove(block_previd_obj[0])

        for objs in block_previd_obj:
            if objs.hash == blockHash:

                for IPs in objs.IP:
                    if IPs == IPAdd:
                        IPf += 1

                if IPf == 0:
                    info('IP is appending..!')
                    objs.IP.append(IPAdd)

                    if len(block_ok_obj) > 10:
                        block_ok_obj.remove(block_ok_obj[0])

                    return objs

                else:
                    return 1

        return 2


# Find and remove block_ok_nok_objs object
def remove_block_ok_objs(blockHash):
    for calcs in block_ok_obj:
        if calcs.hash == blockHash:
            info('Calc0bj is deleted!')
            block_ok_obj.remove(calcs)
            del calcs
            break


# Convert parts to decimal
def conv_10(part):
    # If part has one string
    if len(str(part)) == 1:
        part = conv_mod_10(part)

    # If part has more strings
    elif len(str(part)) == 2:
        try:
            part1 = int(part[0])
        except:
            part1 = conv_mod_10(part[0])

        try:
            part2 = int(part[1])
        except:
            part2 = conv_mod_10(part[1])

        part = str(part1) + str(part2)

    # If part becomes an ERROR
    else:
        debug('conv_10() string ERROR!')

    return int(part)


# Convert parts to hexadecimal
def conv_16(part):
    addPart = []
    for parts in part:
        # If parts have one digit
        if len(str(parts)) == 1:

            chance = randint(0, 1)
            if chance == 1:
                addPart.append('0' + str(conv_mod_16(parts)))

            else:
                addPart.append('0' + str(parts))

        # If parts have two digits.
        elif len(str(parts)) == 2:
            parts  = str(parts)

            chance = randint(0, 1)
            if chance == 1:
                x  = conv_mod_16(parts[0])

            else:
                x  = parts[0]

            chance = randint(0, 1)
            if chance == 1:
                y  = conv_mod_16(parts[1])

            else:
                y  = parts[1]

            addPart.append(str(x) + str(y))

        # If parts have three digits
        else:
            parts  = str(parts)

            chance = randint(0, 1)
            if chance == 1:
                x  = conv_mod_16(parts[0])

            else:
                x  = parts[0]

            chance = randint(0, 1)
            if chance == 1:
                y  = conv_mod_16(parts[1])

            else:
                y  = parts[0]

            chance = randint(0, 1)
            if chance == 1:
                z  = conv_mod_16(parts[2])

            else:
                z  = parts[2]

            addPart.append(str(x) + str(y) + str(z))

    return addPart


# Find blockID from the hash value
def found_blockid_hash(Hash):
    info('Finding blockID ...')
    global blockid_end

    # If blockID is same as lastBlockID + 1
    if Hash == SHA512.new(str(int(blockid_end) + 1).encode(utf_type)).hexdigest():

        # Return new blockID value
        info('blockID is found by using lastBlockID!')
        blockid_end = int(blockid_end) + 1

        return int(blockid_end)

    if 0 < int(blockid_end) - 10:

        for IDs in range(blockid_end - 10 , blockid_end + 10):

            # Controlling..
            if Hash == SHA512.new(str(IDs).encode(utf_type)).hexdigest():

                # Return new blockID value
                info('blockID is found range of lastBlockID!')
                blockid_end = int(IDs)

                return int(IDs)

    # Calculation all values...
    # It takes some time...
    IDs = 100
    while True:

        # If blockID does NOT found, extend the range...
        for IDs in range(IDs - 100, IDs + 100):

            # Controlling..
            if Hash == SHA512.new(str(IDs).encode(utf_type)).hexdigest():

                # Return new blockID value
                info('blockID is found by bruteforcing..!')
                blockid_end = int(IDs)

                return int(IDs)

        # Increase range area
        IDs += 100


# Generate mining side hash..
def generate_mining_hash():
    while True:
        part  = [randint(0, 99), randint(0, 99),
                 randint(0, 99), randint(0, 99),
                 randint(1, 99), randint(1, 99)]

        if part[0] != part[1] and part[1] != part[2] and part[2] != part[3] and\
           part[3] != part[4] and part[4] != part[5] and part[0] != part[2] and\
           part[0] != part[3] and part[0] != part[4] and part[4] != part[5] and\
           part[1] != part[3] and part[1] != part[4] and part[1] != part[5] and\
           part[2] != part[4] and part[2] != part[5] and part[3] != part[5]:
            hexPart = conv_16(part)

            number = randint(0, 128)
            n = ""

            for iteration in range(0, number):
                n = choice(digits) + str(number) + choice(ascii_lowercase) + choice(ascii_uppercase) + n

            myHash = SHA512.new(str(n).encode(utf_type)).hexdigest()
            newHash = ''

            if myHash.startswith('0'):

                try:
                    item1 = int(myHash[part[0]]) % 10
                except ValueError:
                    item1 = conv_mod_10(myHash[part[0]])

                try:
                    item2 = int(myHash[part[1]]) % 10
                except ValueError:
                    item2 = conv_mod_10(myHash[part[1]])

                try:
                    item3 = int(myHash[part[2]]) % 10
                except ValueError:
                    item3 = conv_mod_10(myHash[part[2]])

                if int(item1) != int(item2):

                    if int(item1) != int(item3):

                        if int(item1) + int(item2) % 10 == int(item3):

                            try:
                                item4 = int(myHash[part[3]]) % 10
                            except ValueError:
                                item4 = conv_mod_10(myHash[part[3]])

                            try:
                                item5 = int(myHash[part[4]]) % 10
                            except:
                                item5 = conv_mod_10(myHash[part[4]])

                            if int(item4) == int(item5):

                                if (int(item1) + int(item3)) % 10 == int(item5):

                                    try:
                                        shifting = int(myHash[part[5]]) % 10
                                    except:
                                        shifting = conv_mod_10(myHash[part[5]])

                                    flg = shifting

                                    if int(shifting) != 0:

                                        for times in range(0, int(shifting)):
                                            sftHash = ''
                                            temp = myHash[0]

                                            for item in range(1, int(len(myHash))):

                                                try:
                                                    sftHash += myHash[item]
                                                except IndexError:
                                                    pass

                                            sftHash += temp
                                            myHash = sftHash
                                            newHash = myHash

                                        for hexs in hexPart:
                                            newHash = hexs + newHash

                                        return newHash + str(flg)

                                    else:

                                        for hexs in hexPart:
                                            myHash = hexs + myHash

                                        return myHash + str(flg)


# Generate user side hash..
def generate_user_hash():
    while True:
        part  = [randint(0, 99), randint(0, 99),
                 randint(0, 99), randint(0, 99),
                 randint(0, 99), randint(0, 99)]

        if part[0] != part[1] and part[1] != part[2] and part[2] != part[3] and\
           part[3] != part[4] and part[4] != part[5] and part[0] != part[2] and\
           part[0] != part[3] and part[0] != part[4] and part[4] != part[5] and\
           part[1] != part[3] and part[1] != part[4] and part[1] != part[5] and\
           part[2] != part[4] and part[2] != part[5] and part[3] != part[5]:
             hexPart = conv_16(part)
             break

    while True:

        number = randint(0, 128)
        n = ""

        for iteration in range(0, number):
            n = choice(digits) + str(number) + choice(ascii_lowercase) + choice(ascii_uppercase) + n

        myHash = SHA512.new(str(n).encode(utf_type)).hexdigest()
        newHash = ''

        if myHash.startswith('0'):

            try:
                item1 = int(myHash[part[0]]) % 10
            except ValueError:
                item1 = conv_mod_10(myHash[part[0]])

            try:
                item2 = int(myHash[part[1]]) % 10
            except ValueError:
                item2 = conv_mod_10(myHash[part[1]])

            try:
                item3 = int(myHash[part[2]]) % 10
            except ValueError:
                item3 = conv_mod_10(myHash[part[2]])

            if int(item1) + int(item2) % 10 != int(item3):

                if int(item1) != int(item3):

                    if int(item1) == int(item2):

                        try:
                            item4 = int(myHash[part[3]]) % 10
                        except ValueError:
                            item4 = conv_mod_10(myHash[part[3]])

                        if int(item3) == int(item4):

                            try:
                                item5 = int(myHash[part[4]]) % 10
                            except:
                                item5 = conv_mod_10(myHash[part[4]])

                            if (int(item1) + int(item3)) % 10 == int(item5):

                                try:
                                    shifting = int(myHash[part[5]]) % 10
                                except:
                                    shifting = conv_mod_10(myHash[part[5]])

                                flg = shifting

                                if int(shifting) != 0:

                                    for times in range(0, int(shifting)):
                                        sftHash = ''
                                        temp = myHash[0]

                                        for item in range(1, int(len(myHash))):

                                            try:
                                                sftHash += myHash[item]
                                            except IndexError:
                                                pass

                                        sftHash += temp
                                        myHash = sftHash
                                        newHash = myHash

                                    for hexs in hexPart:
                                        newHash = hexs + newHash

                                    return newHash + str(flg)

                                else:

                                    for hexs in hexPart:
                                        myHash = hexs + myHash

                                    return myHash + str(flg)


# CLIENT SIDE
# Send a block to others
def connect(HOST, message):
    info('Message is sending to [' + str(HOST) + ']')

    # Byte shifting values..
    try:
        mySocket = socket(AF_INET, SOCK_STREAM)
        mySocket.settimeout(2)
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.load_cert_chain('selfsigned.cert', 'selfsigned.key')
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        conn = context.wrap_socket(mySocket)
        conn.connect((HOST, chain_port))

        # Sending bytes data..
        if type(message) == bytes:
            info('Sending bytes format..')
            conn.send(message)

        # '.obj' in str(type(message))
        else:

            info('Sending obj or string format..')

            try:
                msg = dumps(message.__dict__)
            except:

                try:
                    msg = dumps(message.__dict__, cls=Encoder)

                except:

                    try:
                        msg = d0(message)

                    except:
                        conn.close()
                        return False

            try:
                conn.send(d0(msg.encode("ISO-8859-1")))

            except:

                try:
                    conn.send(msg)

                except:
                    return False

        info('Message is sent to [' + str(HOST) + ']')
        conn.close()

        return True

    except ConnectionRefusedError:
        debug('Receiver [' + str(HOST) + '] is OFFLINE!')
        return False

    except:
        debug('Receiver [' + str(HOST) + '] seems like OFFLINE!')
        return False


# USER LOCAL SIDE
# Send some messages
def userConnect(message):
    info('connect() function called.')

    # Byte shifting values..
    try:
        mySocket = socket(AF_INET, SOCK_STREAM)
        mySocket.connect((binding_address, user_message))

        # Sending bytes data..
        if type(message) == bytes:
            info('Sending bytes format..')
            mySocket.send(message)

        # '.obj' in str(type(message))
        else:
            info('Sending obj or string format..')

            try:
                msg = dumps(message.__dict__)
            except:
                try:
                    msg = dumps(message.__dict__, cls=Encoder)
                except:
                    if 'estimatedtime' in message:
                        msg = message
                    else:
                        mySocket.close()
                        return False

            mySocket.send(msg.encode("ISO-8859-1"))

        info('Message is sent to [' + str(binding_address) + ']')
        mySocket.close()

        return True

    except ConnectionRefusedError:
        debug('Receiver [' + str(binding_address) + '] is OFFLINE!')

        return False

    except:
        debug('Receiver [' + str(binding_address) + '] seems like OFFLINE!')

        return False


# Create a merkle hash and return ROOT
def main_block(Block):
    info('Merkle tree created..')
    merkle = ''

    newblockID      = SHA512.new(str(Block.blockID).encode(utf_type)).hexdigest()
    newsenderID     = SHA512.new(str(Block.senderID).encode(utf_type)).hexdigest()
    newreceiverID   = SHA512.new(str(Block.receiverID).encode(utf_type)).hexdigest()
    newMessage      = SHA512.new(str(Block.message).encode(utf_type)).hexdigest()
    newTimestamp    = SHA512.new(str(Block.timestamp).encode(utf_type)).hexdigest()
    newDS           = SHA512.new(str(Block.digitalSignature).encode(utf_type)).hexdigest()
    newVerkey       = SHA512.new(str(Block.verKey).encode(utf_type)).hexdigest()
    newPrevHash     = SHA512.new(str(Block.prevHash).encode(utf_type)).hexdigest()

    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newsenderID).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newreceiverID).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newMessage).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newTimestamp).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newDS).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newVerkey).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newPrevHash).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newblockID).encode(utf_type)).hexdigest()
    root   = SHA512.new(str(merkle).encode(utf_type) + str(Block.nonce).encode(utf_type)).hexdigest()

    return root


# Check block hash re-calculation
def controlling_hash(Block):
    info('Starting block hash controls..')

    try:
        global blockid_end

        # Re-Calculating total hash..
        calcHash = ''
        for heads in header_of_block:
            if heads != 'hash' and heads != 'totalHash' and \
               heads != 'who'  and heads != 'message':

                # Get correct blockID
                if heads == 'blockID':

                    # If block values come
                    if Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type) +
                                                     str(blockCode11).encode(utf_type)).hexdigest():

                        root = main_block(Block)

                        if root == Block.hash and str(root).startswith('00'):

                            if len(Block.__dict__) == 13:
                                info('Blockheader is correct.')
                                return True

                        return False

                    else:
                        item = blockid_end

                else:
                    item = getattr(Block, heads)

                calcHash = SHA512.new((calcHash + str(item)).encode(utf_type)).hexdigest()

                if heads == 'prevHash':
                    lastHash = calcHash

        for blockcode in codes_of_block:
            newCode  = SHA512.new(str(blockcode).encode(utf_type)).hexdigest()
            calcHash = SHA512.new(str(Block.hash).encode(utf_type) +
                                  str(newCode).encode(utf_type)).hexdigest()

            # If calculated hash equals to block hash
            if calcHash == Block.totalHash:
                info('Blockhash is verified.')

                if len(Block.__dict__) == 13:
                    info('Blockheader is correct.')
                    return True

    except:
        debug('Header has something wrong!')
        return False

    lastHash = SHA512.new((lastHash + str(int(blockid_end + 1))).encode(utf_type)).hexdigest()
    lastHash = SHA512.new((lastHash + str(Block.nonce)).encode(utf_type)).hexdigest()

    for blockcode in codes_of_block:
        newCode  = SHA512.new(str(blockcode).encode(utf_type)).hexdigest()
        lastHash = SHA512.new(str(Block.hash).encode(utf_type) +
                              str(newCode).encode(utf_type)).hexdigest()

        # If calculated hash equals to block hash
        if lastHash == Block.totalHash:
            info('Blockhash is verified.')

            if len(Block.__dict__) == 13:
                info('Blockheader is correct.')
                return True

    global blockID

    get_blockid_hash()
    timer = 0
    while True:
        sleep(6)
        if blockID == '0':
            timer += 1
            sleep(2)

        else:
            break

        if timer % 2 == 0:
            get_blockid_hash()

    blockid_end   = blockID
    Block.blockID = blockID

    lastHash      = SHA512.new((lastHash + str(blockid_end)).encode(utf_type)).hexdigest()
    lastHash      = SHA512.new((lastHash + str(Block.nonce)).encode(utf_type)).hexdigest()

    for blockcode in codes_of_block:
        newCode   = SHA512.new(str(blockcode).encode(utf_type)).hexdigest()
        lastHash  = SHA512.new(str(Block.hash).encode(utf_type) +
                               str(newCode).encode(utf_type)).hexdigest()

        # If calculated hash equals to block hash
        if lastHash == Block.totalHash:
            info('Blockhash is verified.')

            if len(Block.__dict__) == 13:
                info('Blockheader is correct.')
                return True

    info('Blockheader is INCORRECT!')
    return False


### Fake Block ###
# Randoms:
#   blockID
#   senderID
#   receiverID
#   message
#   timestamp
#   _id
#   prevHash

# Signature:
#   senderID
#   receiverID
#   message
#   timestamp

# Hash:
#   Proof of Work

# TotalHash:
#   Hash
#   BlockCodes

# Generate a fake block
class generating_fake_block:
    def __init__(self     , blockID   , senderID         , receiverID,
                 message  , timestamp , hash             , _id       ,
                 prevHash , who       , digitalSignature , verKey    ,
                 totalHash, nonce):

        # Fill values with random hash(s)
        self.blockID          = blockID
        self.senderID         = senderID
        self.receiverID       = receiverID
        self.message          = message
        self.timestamp        = timestamp
        self.hash             = hash
        self._id              = _id
        self.prevHash         = prevHash

        while True:
            if queue_block_whom.qsize() != 0:
                self.who = queue_block_whom.get()
                break
            sleep(0.05)

        signMSG               = (str(self.senderID) + str(self.receiverID) + str(self.message) + str(self.timestamp)).encode(utf_type)
        self.verKey           = digitalSignature
        self.digitalSignature = verKey
        self.nonce            = nonce

        newsenderID     = SHA512.new(str(self.senderID).encode(utf_type)).hexdigest()
        newreceiverID   = SHA512.new(str(self.receiverID).encode(utf_type)).hexdigest()
        newMessage      = SHA512.new(str(self.message).encode(utf_type)).hexdigest()
        newTimestamp    = SHA512.new(str(self.timestamp).encode(utf_type)).hexdigest()
        newDS           = SHA512.new(str(self.digitalSignature).encode(utf_type)).hexdigest()
        newVerkey       = SHA512.new(str(self.verKey).encode(utf_type)).hexdigest()

        merkle = ''
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newsenderID).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newreceiverID).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newMessage).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newTimestamp).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newDS).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newVerkey).encode(utf_type)).hexdigest()

        quitF = 0
        self.nonce = 100
        # Calculate and find hash value by using little proof-of-work
        while True:
            for self.nonce in range(self.nonce - 100, self.nonce + 100):

                # If hash startswith '000' , Done!
                if str(SHA512.new(str(merkle).encode(utf_type) + str(self.nonce).encode(utf_type)).hexdigest()).startswith('000'):

                    root  = SHA512.new(str(merkle).encode(utf_type) + str(self.nonce).encode(utf_type)).hexdigest()
                    quitF = 1
                    break

            # If found it, let's exit
            if quitF == 1:
                break

            else:
                self.nonce += 100

        self.hash       = root
        self.totalHash  = SHA512.new(str(root).encode(utf_type) + str(blockCode11).encode(utf_type)).hexdigest()


def gen_fake_block():
    while True:
        if queue_fakeblock.qsize() >= 14:
            reqHash = queue_fakeblock.get()
            for objs in block_previd_obj:
                if reqHash == objs.hash:
                    block_previd_obj.remove(objs)
                    del objs
                    break
            sleep(15)

        else:
            # Create a fake block object
            reqBlock = generating_fake_block(randint(0, 99999999) + randint(0, 99999999),
                                 SHA512.new(str(randint(0, 99999999) + randint(0, 99999999)).encode(utf_type)).hexdigest(),
                                 SHA512.new(str(randint(0, 99999999) + randint(0, 99999999)).encode(utf_type)).hexdigest(),
                                 randint(0, 99999999) + randint(0, 99999999),
                                 get_current_time(),
                                 SHA512.new(str(randint(0, 99999999) + randint(0, 99999999)).encode(utf_type)).hexdigest(),
                                 SHA512.new(str(randint(0, 99999999) + randint(0, 99999999)).encode(utf_type)).hexdigest(),
                                 randint(0, 99999999) + randint(0, 99999999),
                                 randint(0, 99999999) + randint(0, 99999999),
                                 SHA512.new(str(randint(0, 99999999) + randint(0, 99999999)).encode(utf_type)).hexdigest(),
                                 SHA512.new(str(randint(0, 99999999) + randint(0, 99999999)).encode(utf_type)).hexdigest(),
                                 randint(0, 99999999) + randint(0, 99999999),
                                 randint(0, 99999999) + randint(0, 99999999))

            block_previd_obj.append(block_prev_id(reqBlock.hash, 0, 0, 0, 0))
            try:
                queue_fakeblock.put(reqBlock)
            except:
                if queue_fakeblock.qsize() != 0:
                    queue_fakeblock.get()
                try:
                    queue_fakeblock.put(reqBlock)
                except:
                    pass


# Get blockID & prevHash values
def get_blockid_hash():
    info('BlockValues are getting...')
    while True:
        if queue_fakeblock.qsize() != 0:
            reqBlock = queue_fakeblock.get()
            break

    for host in hosts_of_chains:
        sign_block(reqBlock)
        connect(host, reqBlock)


# Get queue time and return seconds
def queue_get_time():
    sizeofQ     = 1
    sizeofQ     += int(qSize(queue_verify)) + int(qSize(queue_user))
    estimated   = int(sizeofQ) * 25
    return int(estimated)


# Mining operations..
def mining_operations():
    while True:

        while True:
            if int(queue_chain.qsize()) != 0:
                infos  = qGet(queue_chain)
                block  = infos[0]
                IP_Add = infos[1]
                break

        miner_thread_lock.acquire()
        while True:
            global blockID
            global prevHash

            try:
                if controlling_hash(block):
                    hashFlag = 1

                else:
                    info('Hash control result is FALSE!')
                    hashFlag = 0

            except:
                info('Hash control result has an ERROR..!')
                hashFlag = 0
                break

            verifyF = 0
            # If the block carries values
            if block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                             str(blockCode11).encode(utf_type)).hexdigest():

                info('The block carries values !!!')
                try:
                    if str(block.prevHash).startswith('000') or \
                       str(block.prevHash) == '0180BC6C2B65E51ECE943BEEF82D702AC273DF262DC2A6EE0F67CC99B4E0F546286C4'\
                                              'D63CD74F5FD8128EE95FE16210A6905BB4A3F6B57CED281410D9FBA8598':

                        info('Value(s) starting point is OK.')
                        objs = found_block_ok_objs(block.hash, IP_Add, 2)

                        if objs == 2:
                            debug('Unknown hash!')
                            break

                        elif objs == 1:
                            debug('Same IP hash!')
                            break

                        else:
                            pF = 1

                            for prevS in objs.prevHash:

                                if prevS == block.prevHash:
                                    pF = 0
                                    info('Block values are already appended!')
                                    break

                                else:
                                    pF = 1

                            if pF == 1:
                                info('Block values are appending..!')
                                objs.prevHash.append(block.prevHash)
                                objs.blockID.append(block.blockID)
                                objs.counter.append(1)

                            else:

                                for index in range(0, len(objs.prevHash)):

                                    if objs.prevHash[index] == block.prevHash:

                                        if objs.blockID[index] == block.blockID:

                                            objs.counter[index] += 1
                                            if len(hosts_of_chains) / 2 < objs.counter[index]:
                                                info('BlockValues are setting..!')
                                                blockID     = found_blockid_hash(block.blockID)
                                                prevHash    = block.prevHash
                                                block_previd_obj.remove(objs)
                                                del objs
                                                break

                except:
                    debug('Block values corrupted!')

                break

            # Check the queue_verify
            elif qSize(queue_verify) != 0 and hashFlag == 1:
                info('VerifyQ is NOT Empty!')

                # Empty queue
                if qSize(temp_hash_q) != 0:
                    for qs in range(0, qSize(temp_hash_q)):
                        qGet(temp_hash_q)

                # Check the block hash and queue_verify hash(es)
                for size in range(0, qSize(queue_verify)):
                    hashTmp = l0(qGet(queue_verify))

                    # Block was in the queue_verify
                    if block.hash == hashTmp.hash:
                        info('The block already exists in the verify Queue..!')

                        # Get object and flag values if exists
                        calcObj, createF = found_block_ok_objs(block.hash, IP_Add, 0)

                        # Already created, check IP
                        if createF == 1:
                            for IPs in calcObj.IP:
                                if IPs == IP_Add:
                                    dupF = 0
                                    debug('Duplicated block has come!')
                                    break
                                else:
                                    dupF = 1

                        elif createF == 0:
                            dupF = 1

                        # If answer is not duplicated one.
                        if dupF == 1:
                            info('Answer is NOT duplicated.')

                            # If it's OK Block
                            if block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                             str(blockCode03).encode(utf_type)).hexdigest():
                                info('It is (+)OK Block.')
                                calcObj.ok  += 1

                            elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                               str(blockCode02).encode(utf_type)).hexdigest():
                                info('It is (-)NoK Block.')
                                calcObj.NoK += 1

                            else:
                                debug('It is (~)NULL Block!')

                            # Control hosts and their answers
                            if len(hosts_of_chains) / 2 < int(calcObj.ok):
                                info('Hosts OK & NoK are verified!')

                                # If the block verified more than 51%
                                if calcObj.ok > calcObj.NoK:

                                    # Delete block_ok_obj object
                                    remove_block_ok_objs(block.hash)

                                    # Re-Calculation of block hash with blockCode[5]
                                    block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                                 str(blockCode05).encode(utf_type)).hexdigest()

                                    # Send a broadcast block ,CHAINS to add.
                                    for hosts in hosts_of_chains:
                                        while True:
                                            if queue_block_whom.qsize() != 0:
                                                block.who = queue_block_whom.get()
                                                break
                                            sleep(0.05)

                                        # Change blockID value for attacks
                                        fakeID_1        = randint(0, 999999999999999999999999)
                                        fakeID_2        = randint(0, 999999999999999999999999)
                                        block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                                        sign_block(block)
                                        connect(hosts, block)

                                    # Send the block to the Django (USER) Side
                                    # To say that the block added to the blockchain
                                    # Is completed successfully
                                    block.process = 'ok'
                                    userConnect(block)

                                    verifyF = 1

                                    break

                            # If the server has more answers then number of chains
                            elif len(hosts_of_chains) < calcObj.ok + calcObj.NoK:

                                # Delete block_ok_obj object
                                remove_block_ok_objs(block.hash)

                                verifyF = 1

                                break

                            else:
                                qPut(queue_verify, d0(hashTmp))

                    else:
                        qPut(queue_verify, d0(hashTmp))

            # If the block is NOT in the queue_verify
            if verifyF == 0 and hashFlag == 1:

                # Check the block is coming for User Side confirmation
                if block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                 str(blockCode09).encode(utf_type)).hexdigest():

                    info('The block is in the blockchain.')

                    # Notify the user for VALID block.hash is getting..
                    block.process = 'ok'
                    userConnect(block)

                # There is NOT any block in the blockchain
                elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                   str(blockCode08).encode(utf_type)).hexdigest():

                    info('The block is NOT in the blockchain!')

                    # Notify the user for INVALID block.hash is getting..
                    block.process = 'nok'
                    userConnect(block)

            break

        miner_thread_lock.release()


# SERVER SIDE
# Receive data from the socket
class ClientThread(Thread):
    def __init__(self, conn, IP_ADD):
        Thread.__init__(self)
        self.IP_ADD = IP_ADD
        self.conn = conn

    def run(self):
        while True:
            # Get data from peers
            try:
                # Receive bytes
                tempBytes = self.conn.recv(4096)

                global shared_pairs
                global tempBlock
                global ecdh_obj
                global certificate

                if str(shared_pairs) == '0' and len(codes_of_block) == 0:
                    # If the public key received
                    try:

                        if len(codes_of_block) == 0:

                            if str(tempBytes.decode(utf_type)).startswith("-----BEGIN PUBLIC KEY-----") and \
                               "-----END PUBLIC KEY-----" in str(tempBytes.decode(utf_type)):
                                    shared_pairs = ecdh_obj.findsharedKEY(deserialize_pubkey(tempBytes))
                                    certificate = tempBytes
                                    tempBlock = []
                                    break

                            else:
                                break

                        break

                    except:
                        pass

                elif str(shared_pairs) != '0' and len(codes_of_block) == 0:
                    try:
                        tempBlock.append(tempBytes)

                        if len(tempBlock) == 13:

                            for blockcodes in tempBlock:
                                codes_of_block.append(aes_decryption_func(derivation_keys(shared_pairs), shared_pairs, blockcodes))

                            global blockCode00, blockCode01, blockCode02, blockCode03
                            global blockCode04, blockCode05, blockCode06, blockCode07
                            global blockCode08, blockCode09, blockCode10, blockCode11
                            global blockCode11, blockCode12

                            blockCode12 = SHA512.new(str(codes_of_block[12]).encode(utf_type)).hexdigest()
                            blockCode11 = SHA512.new(str(codes_of_block[11]).encode(utf_type)).hexdigest()
                            blockCode10 = SHA512.new(str(codes_of_block[10]).encode(utf_type)).hexdigest()
                            blockCode09 = SHA512.new(str(codes_of_block[9]) .encode(utf_type)).hexdigest()
                            blockCode08 = SHA512.new(str(codes_of_block[8]) .encode(utf_type)).hexdigest()
                            blockCode07 = SHA512.new(str(codes_of_block[7]) .encode(utf_type)).hexdigest()
                            blockCode06 = SHA512.new(str(codes_of_block[6]) .encode(utf_type)).hexdigest()
                            blockCode05 = SHA512.new(str(codes_of_block[5]) .encode(utf_type)).hexdigest()
                            blockCode04 = SHA512.new(str(codes_of_block[4]) .encode(utf_type)).hexdigest()
                            blockCode03 = SHA512.new(str(codes_of_block[3]) .encode(utf_type)).hexdigest()
                            blockCode02 = SHA512.new(str(codes_of_block[2]) .encode(utf_type)).hexdigest()
                            blockCode01 = SHA512.new(str(codes_of_block[1]) .encode(utf_type)).hexdigest()
                            blockCode00 = SHA512.new(str(codes_of_block[0]) .encode(utf_type)).hexdigest()

                            for blocks in tempBlock:
                                tempBlock.remove(blocks)
                                del blocks

                        break

                    except:
                        pass

                else:
                    # If others public came..
                    try:
                        changed = 0
                        public  = aes_decryption_func(derivation_keys(shared_pairs), shared_pairs, tempBytes).encode(utf_type)
                        IP      = public.decode('utf-8').split('\n')[-1]

                        for publics in public_storage:
                            if publics[1] == IP:
                                publics = ((deserialize_pubkey(public), IP))
                                changed = 1

                        if changed == 0:
                            public_storage.append((deserialize_pubkey(public), IP))

                    except:
                        pass

                    # Block Reloading..
                    try:
                        block = loadRecv(l0(tempBytes).decode("ISO-8859-1"))
                        block = obj(block)

                    except:

                        try:
                            block = loads(l0(tempBytes).decode("ISO-8859-1"), object_hook=decoder)
                            block = obj(block)

                        except:

                            try:
                                block = l0(tempBytes)

                            except:
                                break

                    # IP address validation for hosts_of_chains
                    for hosts in hosts_of_chains:
                        if hosts == self.IP_ADD:
                            info('IP [' + str(self.IP_ADD) + '] is in the chain list.')
                            connFlag = 1
                            break

                        else:
                            connFlag = 0

                    # The data is coming from the UNKNOWN sender
                    if connFlag == 0:
                        if self.IP_ADD != auth_server:
                            debug('UNKNOWN Sender !!!')
                            break
                        else:
                            info('IP [' + str(self.IP_ADD) + '] is authentication list.')

            # If Data does not LOAD!
            except ConnectionResetError:
                debug('Connection Reset by [' + self.IP_ADD + ']')
                break

            except AttributeError:
                debug('Data is broken !')
                break

            except:
                warning('Connection ERROR !')
                break

            info('[' + self.IP_ADD + '] is connected.')

            try:
                # Block has something:
                if block != "":
                    info('The block is NOT an empty BLOCK.')

                    info('Identifying sender..')
                    try:
                        whoFlag = 4
                        whoHash = block.who
                        # Get the iteration number
                        groups  = [whoHash[-1]]

                        # Split the headers
                        for splitter in range(0, 11):
                            if splitter % 2 == 0:
                                groups.append(whoHash[splitter] + whoHash[splitter + 1])

                        # Get correct hash length
                        whoHash = whoHash[12:-1]

                        # Shifting hash
                        if int(groups[0]) != 0:
                            for times in range(0, int(groups[0])):
                                sftHash = ''
                                temp = whoHash[127]

                                for item in range(0, 128):
                                    sftHash += whoHash[item]

                                sftHash = temp + sftHash
                                whoHash = sftHash
                                newHash = whoHash[:-1]

                        else:
                            newHash = whoHash

                        # Convert groups elements..
                        for gRange in range(1, len(groups)):
                            groups[gRange] = conv_10(groups[gRange])

                        # Check hash ...
                        if str(newHash).startswith('0'):

                            if not int(conv_mod_10(newHash[groups[-1]])) == int(conv_mod_10(newHash[groups[-2]])):

                                # BLOCKCHAIN SERVER PART
                                # Check hash by using groups rules - PART I
                                if int(conv_mod_10(newHash[groups[-1]])) == int(conv_mod_10(newHash[groups[-3]])):

                                    # Check hash by using groups rules - PART II
                                    if (int(conv_mod_10(newHash[groups[-2]])) + int(
                                            conv_mod_10(newHash[groups[-4]]))) % 10 == \
                                            int(conv_mod_10(newHash[groups[-5]])):

                                        # Check hash by using groups rules - PART III
                                        if (int(conv_mod_10(newHash[groups[-1]])) + int(
                                                conv_mod_10(newHash[groups[-3]]))) % 10 == \
                                                int(conv_mod_10(newHash[groups[-5]])):
                                            # Correct Hash
                                            # Comes from blockchain part
                                            whoFlag = 3

                        try:
                            # Check digital signature in the block
                            verifyFlag = 0

                            for publics in public_storage:
                                if str(self.IP_ADD) == str(publics[1]):
                                    if ecdh_obj.verify_message(public_key=publics[0],
                                                               message=block.totalHash,
                                                               sign=block.verKey):
                                        info('Message verifying result is TRUE.')
                                        verifyFlag = 1
                                        break

                            # Message verified..
                            if verifyFlag == 1:

                                if whoFlag == 3:
                                    info('The blockchain sends the block!')
                                    qPut(queue_chain, (block, self.IP_ADD))

                        except:
                            debug('Message verifying result has an ERROR!')


                    except:
                        pass

            except:
                pass

            break


def Calc(merkle, lower, upper):
    # Calculate and find hash value by using hard proof-of-work
    while True:
        for nonce in range(lower, upper):
            # If hash startswith '00000' , Done!
            if str(SHA512.new(str(merkle).encode(utf_type) + str(nonce).encode(utf_type)).hexdigest()).startswith('00000'):
                root = SHA512.new(str(merkle).encode(utf_type) + str(nonce).encode(utf_type)).hexdigest()
                if not queue_proofofwork.qsize() != 0:
                    try:
                        queue_proofofwork.put(root,  timeout=1)
                        queue_proofofwork.put(nonce, timeout=1)
                    except:
                        debug('calc_pow_hash Queue has an ERROR..!')
                break
        break


# Calculate hash value calc_pow_hash
def calc_pow_hash(Block):
    info('calc_pow_hash starting...')
    global prevHash
    global blockID

    while True:
        if queue_proofofwork.qsize() != 0:
            queue_proofofwork.get()
        else:
            break

    # Hash proof of work..
    Block.blockID       = int(blockID)
    Block.prevHash      = prevHash
    blockID             = '0'

    newsenderID         = SHA512.new(str(Block.senderID).encode(utf_type)).hexdigest()
    newreceiverID       = SHA512.new(str(Block.receiverID).encode(utf_type)).hexdigest()
    newMessage          = SHA512.new(str(Block.message).encode(utf_type)).hexdigest()
    newTimestamp        = SHA512.new(str(Block.timestamp).encode(utf_type)).hexdigest()
    newDS               = SHA512.new(str(Block.digitalSignature).encode(utf_type)).hexdigest()
    newPrevHash         = SHA512.new(str(Block.prevHash).encode(utf_type)).hexdigest()
    newblockID          = SHA512.new(str(Block.blockID).encode(utf_type)).hexdigest()

    merkle = ''
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newsenderID).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newreceiverID).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newMessage).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newTimestamp).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newDS).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newPrevHash).encode(utf_type)).hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newblockID).encode(utf_type)).hexdigest()

    # Set lower and upper bounds
    lower = 0
    upper = 500000

    # Create a List to hold all processes
    procs = []

    while True:
        # If the queue_proofofwork is OK, break
        if queue_proofofwork.qsize() == 2:
            root  = queue_proofofwork.get()
            nonce = queue_proofofwork.get()
            break

        # Check if one of the process is NOT alive,
        # Add new one.
        elif len(procs) % 10 == 0 and len(procs) != 0:
            for prN in range(0, len(procs)):
                if not procs[prN].is_alive():
                    procs.remove(procs[prN])
                    procs.append(Process(target=Calc, args=(merkle, lower, upper)))
                    lower += 500000
                    upper += 500000
                    procs[-1].start()
                    break
        else:
            # Create 5 processes
            if len(procs) % 10 != 0 or len(procs) == 0:
                procs.append(Process(target=Calc, args=(merkle, lower, upper)))
                lower += 500000
                upper += 500000
                procs[-1].start()

    # Terminate and remove them
    for proc in procs:
        proc.join()
        proc.terminate()
        procs.remove(proc)

    while True:
        if queue_proofofwork.qsize() != 0:
            queue_proofofwork.get()
        else:
            break

    return root, nonce


# Verify user block(s)
def verifying_user_blocks(Block, Flag):

    # Soft control..
    if Flag == 0:
        info('Soft control..')
        newsenderID    = SHA512.new(str(Block.senderID).encode(utf_type)).hexdigest()
        newreceiverID  = SHA512.new(str(Block.receiverID).encode(utf_type)).hexdigest()
        newMessage     = SHA512.new(str(Block.message).encode(utf_type)).hexdigest()
        newTimestamp   = SHA512.new(str(Block.timestamp).encode(utf_type)).hexdigest()

        # Create a merkle tree
        merkle = ''
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newsenderID).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newreceiverID).encode(utf_type)).hexdigest()
        merkle = SHA512.new(str(merkle).encode(utf_type) + str(newMessage).encode(utf_type)).hexdigest()
        root   = SHA512.new(str(merkle).encode(utf_type) + str(newTimestamp).encode(utf_type)).hexdigest()

        if Block.hash == root:
            info('User hash control is OK')
            return True
        else:
            debug('User hash control is NOT ok!')
            return False

    # Hard control..
    elif Flag == 1:
        info('Hard control..')
        global blockid_end
        get_blockid_hash()

        timer = 0
        while True:
            sleep(6)
            if blockID == '0':
                timer += 1
                sleep(2)

            else:
                break

            if timer % 2 == 0:
                get_blockid_hash()

            debug('User message is waiting...')

        # Fill the block values
        blockid_end     = blockID
        Block.blockID   = blockID
        root            = main_block(Block)

        if Block.totalHash == SHA512.new(str(root).encode(utf_type) +
                                         str(blockCode10).encode(utf_type)).hexdigest():

            info('User hash control is OK [conf.]')
            return True

        else:
            debug('User hash control is NOT ok! [conf]')
            return False

    else:
        warning('Hash control has an ERROR!')
        return False


# User operations..
def user_operations():
    while True:

        while True:
            if int(queue_user.qsize()) != 0:
                infos  = qGet(queue_user)
                block  = infos[0]
                IP_Add = infos[1]
                break

        user_thread_lock.acquire()
        while True:
            global blockID

            try:
                # Check the block type..
                if str(block.totalHash) == '0' and str(block.blockID) == '0' and \
                   str(block.prevHash)  == '0' and str(block.who)     == '0':

                    info('The block comes from the user for calc_pow_hash operations!')

                    if verifying_user_blocks(block, 0):
                        info('User [soft] hash control result is TRUE.')
                        userhashF = 1

                    else:
                        info('User [soft] hash control result is FALSE!')
                        userhashF = 0
                        break

                else:

                    info('The block comes for confirmation operations.')

                    if verifying_user_blocks(block, 1):
                        info('User [hard] hash control result is TRUE.')
                        userhashF = 1

                    else:
                        info('User [hard] hash control result is FALSE!')
                        userhashF = 0
                        break

            except:
                try:
                    # If the blockhash come..!
                    if len(block) == 128:

                        if block.startswith(b'00000'):
                            userhashF = 2

                        else:
                            debug('Blockhash bytes has an ERROR..!')
                            break

                    else:
                        debug('Blockhash size has an ERROR..!')
                        break

                except:
                    debug('Block attributes has an ERROR..!')
                    break

            # If hash is correct
            if userhashF == 1:

                # Control totalHash value
                if str(block.totalHash) == "0":

                    global blockid_end
                    get_blockid_hash()

                    timer = 0
                    while True:
                        sleep(6)
                        if blockID == '0':
                            timer += 1
                            sleep(2)

                        else:
                            break

                        if timer % 2 == 0:
                            get_blockid_hash()

                        debug('User message is waiting...')

                    # Fill the block values
                    global prevHash
                    blockid_end     = blockID

                    while True:
                        if queue_block_whom.qsize() != 0:
                            block.who = queue_block_whom.get()
                            break
                        sleep(0.05)

                    block.prevHash          = prevHash
                    block.hash, block.nonce = calc_pow_hash(block)

                    fakeID_1 = randint(0, 999999999999999999999999)
                    fakeID_2 = randint(0, 999999999999999999999999)
                    block.blockID = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                    # Get random block code and send it
                    randCode = SHA512.new(str(codes_of_block[randint(0, 10)]).encode(utf_type)).hexdigest()

                    block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                 str(randCode).encode(utf_type)).hexdigest()

                    qPut(queue_verify, d0(block))

                # Broadcast the block to all chains
                for host in hosts_of_chains:
                    sign_block(block)
                    connect(host, block)

            # Confirmation blockhash
            elif userhashF == 2:
                while True:
                    if queue_fakeblock.qsize() != 0:
                        reqBlock = queue_fakeblock.get()
                        break
                    sleep(0.05)

                reqBlock.prevHash  = str(block)
                reqBlock.totalHash = SHA512.new(str(reqBlock.hash).encode(utf_type) +
                                                str(blockCode10).encode(utf_type)).hexdigest()

                # userWho set
                while True:
                    if queue_user_whom.qsize() != 0:
                        reqBlock.who = queue_user_whom.get()
                        break
                    sleep(0.05)

                for host in hosts_of_chains:
                    if host == hosts_of_chains[-1]:
                        sign_block(reqBlock)
                        if connect(host, reqBlock):
                            break

                        else:
                            for hosts in hosts_of_chains:
                                sign_block(reqBlock)
                                if connect(hosts, reqBlock):
                                    break

                    # To select random chainHost each request
                    if randint(0, 1):
                        sign_block(reqBlock)
                        if connect(host, reqBlock):
                            break

            break

        user_thread_lock.release()


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

                info('The block is reloading...')

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
                            if len(tempBytes) == 128:
                                block = tempBytes

                            elif tempBytes == b'estimatedtime':
                                userConnect('estimatedtime' + str(queue_get_time()))
                                break

                            else:
                                debug('The block can NOT reload!')
                                break

                        except:
                                block = ""
                                debug('The block can NOT reload!')
                                break

            # If Data does not LOAD!
            except ConnectionResetError:
                debug('Connection Reset by [' + self.IP_ADD + ']')
                break

            except AttributeError:
                debug('Data is broken !')
                break

            except:
                warning('Connection ERROR !')
                break

            # Block has something:
            if block != "":
                qPut(queue_user, (block, self.IP_ADD))

            break


def block_who_miner_func():
    while True:
        if queue_block_whom.qsize() >= 499:
            sleep(15)

        else:
            who = generate_mining_hash()
            try:
                queue_block_whom.put(who)
            except:
                queue_block_whom.get()
                try:
                    queue_block_whom.put(who)
                except:
                    pass


def block_who_user_func():
    while True:
        if queue_user_whom.qsize() >= 499:
            sleep(15)

        else:
            who = generate_user_hash()
            try:
                queue_user_whom.put(who)
            except:
                queue_user_whom.get()
                try:
                    queue_user_whom.put(who)
                except:
                    pass


# Listen all connections from Blockchain Server
def listen_all_chain_conns():
    info('"Blockchain Server" side is preparing..')
    tcpServer   = socket(AF_INET, SOCK_STREAM)
    tcpServer.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    tcpServer.bind((current_address, chain_port))
    tcpServer.listen(200)

    context     = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('selfsigned.cert', 'selfsigned.key')
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')

    threadsX    = []
    info('"Blockchain Server" side is ready to listen.')

    while True:

        try:
            (conn, (IP_ADD, port_number_ADD)) = tcpServer.accept()
            info('[' + str(IP_ADD) + ']:[' + str(port_number_ADD) + '] is connecting...')
            conn        = context.wrap_socket(conn, server_side=True)
            newthread   = ClientThread(conn, IP_ADD)
            newthread.start()
            threadsX.append(newthread)

        except ssl.SSLError:
            debug('Sender does NOT use SSL..!')

        except:
            pass

        try:
            if not threadsX[0].is_alive():
                del threadsX[0]
        except:
            pass

    for th in threadsX:
        th.join()


# Listen all connections from User Server
def listen_all_conns():
    info('"User Server" side is preparing..')
    tcpServer2  = socket(AF_INET, SOCK_STREAM)
    tcpServer2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    tcpServer2.bind((binding_address, user_port))
    tcpServer2.listen(200)
    threads     = []
    info('"User Server" side is ready to listen.')

    while True:
        try:
            (conn, (IP_ADD, port_number_ADD)) = tcpServer2.accept()
            info('[' + str(IP_ADD) + ']:[' + str(port_number_ADD) + '] is connecting...')
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


# Main func for the mining part
def main():
    # Generate fakeblocks
    gengenerating_fake_block    = Thread(target=gen_fake_block,   )
    gengenerating_fake_block.start()
    sleep(0.5)

    # Create a listening server for User Server
    listenUser      = Thread(target=listen_all_conns,       )
    listenUser.start()
    sleep(0.5)

    # Mining Operations...
    minerOps        = Thread(target=mining_operations,       )
    minerOps.start()
    sleep(0.5)

    # User Operations...
    userOps         = Thread(target=user_operations,        )
    userOps.start()
    sleep(0.5)


if __name__ == '__main__':
    try:
        engine_func()

    except KeyboardInterrupt:
        debug('Keyboard Interrupt is occured!')
        quitLog()
        exit()

    except AttributeError:
        debug('Attribute Error: ' + str(AttributeError.__doc__))
        quitLog()
        exit()

    except:
        debug('Something was wrong..!')
        quitLog()
        exit()
