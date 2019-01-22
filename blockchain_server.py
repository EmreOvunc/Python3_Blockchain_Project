#!/usr/bin/python3

################################################
#                  EMRE OVUNC                  #
################################################
#              info@emreovunc.com              #
################################################
#               BLOCKCHAIN SERVER              #
################################################

import ssl
from os              import system
from sys             import exit
from time            import sleep
from json            import dumps
from json            import loads
from json            import JSONEncoder
from queue           import Queue
from pickle          import dumps       as d0
from pickle          import loads       as l0
from random          import choice
from random          import randint
from socket          import socket
from socket          import AF_INET
from socket          import SOL_SOCKET
from socket          import SOCK_STREAM
from socket          import SO_REUSEADDR
from base64          import b64encode
from base64          import b64decode
from string          import digits
from string          import ascii_lowercase
from string          import ascii_uppercase
from os.path         import isfile
from logging         import info
from logging         import debug
from logging         import DEBUG
from logging         import warning
from logging         import basicConfig
from pymongo         import MongoClient
from threading       import Lock
from threading       import Thread
from subprocess      import PIPE
from subprocess      import Popen
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
basicConfig(filename  = 'eo_blockchain.log',
            level     = DEBUG,
            format    = '%(asctime)s : %(levelname)s : %(message)s',
            datefmt   = '%m/%d/%Y %I:%M:%S %p')

# Default(s)
flag_who     = 0

# Confirmation queue
queue_conf        = Queue(maxsize=500)
queue_verify      = Queue(maxsize=500)
queue_miner       = Queue(maxsize=500)
queue_chain       = Queue(maxsize=500)
queue_user        = Queue(maxsize=500)
queue_verifytimer = Queue(maxsize=500)
queue_conftimer   = Queue(maxsize=500)

# Queue timeout 30 seconds for each item
timeout_queue     = 30

# Temp. Queues
queue_temp1       = Queue(maxsize=500)
queue_temp2       = Queue(maxsize=500)

# Connection informations
binding_address   = "X"
chain_hosts       = ["Y"]
miner_hosts       = ['Z']
auth_host         = 'T'
port_number       = 55555

# Multi-threading
lock_miner   = Lock()
lock_user    = Lock()
lock_chain   = Lock()

# blockID & prevHash
blockid_curr  = 0
prevhash_curr = 0
phash_curr    = 0
last_idcurr   = 0

# MongoDB database name
mongodbName  = 'eovunc_Blockchain'

# Encoding & Decoding type
utf_type     = 'utf-8'

# Multi-processing
manager           = Manager()
queue_block_who   = manager.Queue(maxsize=500)

# ECDH Pairs
storage_pub = []

# Values
chainUUID   = ""
uuid_path   = 'uuid.txt'

# Connect MongoDB
try:
    client  = MongoClient('localhost', 27017)
    db      = client.eovunc_Blockchain
except:
    warning('MongoDB is not connected!!!')

# Block Communication Codes
codes_of_block = []

# 0  for  Block is NoK
# 1  for  Block is OK
# 2  for  Hash is NoK
# 3  for  Hash is OK
# 4  for  lastBlock is NoK
# 5  for  lastBlock is OK
# 6  for  lastBlock Request
# 7  for  Database add
# 8  for  User NoK
# 9  for  User OK
# 10 for  User Request
# 11 for  Block values request
# 12 for  Send your blocks

# Block headers
header_of_block = 
              [
               'senderID'        , 'receiverID', 'message'  , 'timestamp',
               'digitalSignature', 'verKey'    , 'prevHash' , '_id'      ,
               'hash'            , 'who'       , 'totalHash', 'blockID'  ,
               'nonce'
               ]

# Block.ok and NoK objects
blockCalc = []


# Block ok and NoK values calculation
class block_calc:
    def __init__(self, hash, ok, NoK, IP):
        info('block_calc object is created.')
        self.hash   = hash
        self.ok     = ok
        self.NoK    = NoK
        self.IP     = []
        self.IP.append(IP)


# Queue Function for putting
def put_queue(q, data):
    if q == queue_conf:
        info('Data is putting in the queue [Confirmation Queue]')

    elif q == queue_verify:
        info('Data is putting in the queue [Verifying Queue]'   )

    elif q == queue_user:
        info('Data is putting in the queue [User Queue]'        )

    elif q == queue_miner:
        info('Data is putting in the queue [Miner Queue]'       )

    elif q == queue_chain:
        info('Data is putting in the queue [Chain Queue]'       )

    else:
        info('Data is putting in the queue [Temp. Queue(s)]'    )

    try:
        q.put(data, timeout=timeout_queue)
    except:
        get_from_queue(q)
        try:
            q.put(data, timeout=timeout_queue)
        except:
            pass


# Queue Function for getting
def get_from_queue(q):
    if q == queue_conf:
        info('Data is getting from the [Confirmation Queue]'    )

    elif q == queue_verify:
        info('Data is getting from the [Verifying Queue]'       )

    elif q == queue_user:
        info('Data is getting in the queue [User Queue]'        )

    elif q == queue_miner:
        info('Data is getting in the queue [Miner Queue]'       )

    elif q == queue_chain:
        info('Data is getting in the queue [Chain Queue]'       )

    else:
        info('Data is getting from the [Temp. Queue(s)]'        )

    try:
        if int(q.qsize()) != 0:
            return q.get()
    except:
        return 0


# Queue Function for queue size
def get_size_queue(q):
    if q == queue_conf:
        info('Get Queue size [Confirmation Queue]'              )

    elif q == queue_verify:
        info('Get Queue size [Verifying Queue]'                 )

    elif q == queue_user:
        info('Data is putting in the queue [User Queue]'        )

    elif q == queue_miner:
        info('Data is putting in the queue [Miner Queue]'       )

    elif q == queue_chain:
        info('Data is putting in the queue [Chain Queue]'       )

    else:
        info('Get Queue size [Temp. Queue(s)]'                  )

    return int(q.qsize())


# Convert hex to decimal
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


# Find and return block_calc object
def find_obj(blockHash, IPAdd):
    for calcs in blockCalc:
        if calcs.hash == blockHash:
            info('Calc0bj already created.!')
            return calcs, 1

    info('Calc0bj is appending...')
    blockCalc.append(block_calc(blockHash, 0, 0, IPAdd))
    return blockCalc[-1], 0


# Find and remove block_calc object
def remove_obj(blockHash):
    info('Calc0bj is deleted!')
    for calcs in blockCalc:
        if calcs.hash == blockHash:
            blockCalc.remove(calcs)
            del calcs
            break


# Identify sender
def detect_block(whoHash):
    info('Identifying sender..')
    # Get the iteration number
    groups = [whoHash[-1]]

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

        # USER PART
        # Check hash by using groups rules - PART I
        if int(conv_mod_10(newHash[groups[-1]])) == int(conv_mod_10(newHash[groups[-2]])):

            # Check hash by using groups rules - PART II
            if int(conv_mod_10(newHash[groups[-3]])) == int(conv_mod_10(newHash[groups[-4]])):

                # Check hash by using groups rules - PART III
                if (int(conv_mod_10(newHash[groups[-1]])) + int(conv_mod_10(newHash[groups[-3]]))) % 10 == \
                        int(conv_mod_10(newHash[groups[-5]])):
                    # Correct Hash
                    # Comes from user part
                    return 1

        else:
            # BLOCKCHAIN SERVER PART
            # Check hash by using groups rules - PART I
            if int(conv_mod_10(newHash[groups[-1]])) == int(conv_mod_10(newHash[groups[-3]])):

                # Check hash by using groups rules - PART II
                if (int(conv_mod_10(newHash[groups[-2]])) + int(conv_mod_10(newHash[groups[-4]]))) % 10 == \
                        int(conv_mod_10(newHash[groups[-5]])):

                    # Check hash by using groups rules - PART III
                    if (int(conv_mod_10(newHash[groups[-1]])) + int(conv_mod_10(newHash[groups[-3]]))) % 10 == \
                            int(conv_mod_10(newHash[groups[-5]])):
                        # Correct Hash
                        # Comes from blockchain part
                        return 3

            # MINING PART
            else:
                # Check hash by using groups rules - PART I
                if (int(conv_mod_10(newHash[groups[-1]])) + int(conv_mod_10(newHash[groups[-2]]))) % 10 == \
                        int(conv_mod_10(newHash[groups[-3]])):

                    # Check hash by using groups rules - PART II
                    if int(conv_mod_10(newHash[groups[-4]])) == int(conv_mod_10(newHash[groups[-5]])):

                        # Check hash by using groups rules - PART III
                        if (int(conv_mod_10(newHash[groups[-1]])) + int(conv_mod_10(newHash[groups[-3]]))) % 10 == \
                                int(conv_mod_10(newHash[groups[-5]])):
                            # Correct Hash
                            # Comes from mining part
                            return 2

    debug('Incorrect Hash ..!')
    return 0


# Create a merkle hash and return ROOT
def main_block(Block, req):
    global blockid_curr

    merkle = ''

    if req == 1:
        newblockID  = SHA512.new(str(Block.blockID).encode(utf_type)).hexdigest()

    elif req == 2:
        newblockID  = SHA512.new(str(int(blockid_curr) + 1).encode(utf_type)).hexdigest()

    elif req == 3:
        newblockID  = SHA512.new(str(int(blockid_curr)).encode(utf_type)).hexdigest()

    else:
        return 0


    newsenderID     = SHA512.new(str(Block.senderID)                    .encode(utf_type)) .hexdigest()
    newreceiverID   = SHA512.new(str(Block.receiverID)                  .encode(utf_type)) .hexdigest()
    newMessage      = SHA512.new(str(Block.message)                     .encode(utf_type)) .hexdigest()
    newTimestamp    = SHA512.new(str(Block.timestamp)                   .encode(utf_type)) .hexdigest()
    newDS           = SHA512.new(str(Block.digitalSignature)            .encode(utf_type)) .hexdigest()
    newPrevHash     = SHA512.new(str(Block.prevHash)                    .encode(utf_type)) .hexdigest()

    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newsenderID)    .encode(utf_type)) .hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newreceiverID)  .encode(utf_type)) .hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newMessage)     .encode(utf_type)) .hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newTimestamp)   .encode(utf_type)) .hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newDS)          .encode(utf_type)) .hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newPrevHash)    .encode(utf_type)) .hexdigest()
    merkle = SHA512.new(str(merkle).encode(utf_type) + str(newblockID)     .encode(utf_type)) .hexdigest()
    root   = SHA512.new(str(merkle).encode(utf_type) + str(Block.nonce)    .encode(utf_type)) .hexdigest()

    info('Merkle tree created..')

    return root


# Check block hash re-calculation
def controlling_hash(Block, blockWho):
    info('Starting block hash controls..')

    # Proof of Work control..
    if Block.hash.startswith('000'):
        info('Block.hash "00000"')

        for blockcode in codes_of_block:
            newCode = SHA512.new(str(blockcode).encode(utf_type)).hexdigest()

            # If calculated hash equals to block hash
            if Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)    +
                                             str(newCode).encode(utf_type)).hexdigest():
                info('Blockhash is verified.')
                return True

        if blockWho == 3:

            if Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)    +
                                             str(code_block_06).encode(utf_type)   +
                                             str(code_block_11).encode(utf_type)).hexdigest():
                return True

            elif Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                               str(code_block_01).encode(utf_type) +
                                               str(code_block_03).encode(utf_type)).hexdigest():
                return True

            elif Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                               str(code_block_04).encode(utf_type) +
                                               str(code_block_00).encode(utf_type)).hexdigest():
                return True

            elif Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                               str(code_block_10).encode(utf_type) +
                                               str(code_block_11).encode(utf_type) +
                                               str(code_block_12).encode(utf_type)).hexdigest():
                return True

            elif Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                               str(code_block_12).encode(utf_type)).hexdigest():
                return True

    debug('Blockhash is NOT verified!')
    return False


# Generate a block_chain hash to set who value
def generate_block_hash():
    while True:
        part = [randint(0, 99), randint(0, 99),
                randint(0, 99), randint(0, 99),
                randint(1, 99), randint(1, 99)]

        if part[0] != part[1] and part[1] != part[2] and part[2] != part[3] and \
           part[3] != part[4] and part[4] != part[5] and part[0] != part[2] and \
           part[0] != part[3] and part[0] != part[4] and part[4] != part[5] and \
           part[1] != part[3] and part[1] != part[4] and part[1] != part[5] and \
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

                    if int(item1) + int(item2) % 10 != int(item3):

                        if int(item1) == int(item3):

                            try:
                                item4 = int(myHash[part[3]]) % 10
                            except ValueError:
                                item4 = conv_mod_10(myHash[part[3]])

                            try:
                                item5 = int(myHash[part[4]]) % 10
                            except:
                                item5 = conv_mod_10(myHash[part[4]])

                            if int(item2) + int(item4) % 10 == int(item5):

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
                                            myHash  = sftHash
                                            newHash = myHash

                                        for hexs in hexPart:
                                            newHash = hexs + newHash

                                        return newHash + str(flg)

                                    else:

                                        for hexs in hexPart:
                                            myHash = hexs + myHash

                                        return myHash + str(flg)


# Controlling blockchain.blockID and received blockID
def checking_block_id(Block):
    info('Starting blockID controls ...')

    try:
        # Get block.blockID
        calcHash = main_block(Block, 2)

        if str(calcHash) == str(Block.hash):
            return True

        elif Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                           str(code_block_06).encode(utf_type)).hexdigest() or \
             Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                           str(code_block_06).encode(utf_type) +
                                           str(code_block_11).encode(utf_type)).hexdigest() or \
             Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                           str(code_block_01).encode(utf_type) +
                                           str(code_block_03).encode(utf_type)).hexdigest() or \
             Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                           str(code_block_07).encode(utf_type)).hexdigest() or \
             Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type)  +
                                           str(code_block_10).encode(utf_type)).hexdigest():

            calcHash = main_block(Block, 3)

            if str(calcHash) == str(Block.hash):
                return True

        if Block.totalHash == SHA512.new(str(Block.hash).encode(utf_type) +
                                         str(code_block_11).encode(utf_type)).hexdigest():
            return True

        return False

    except:
        debug('Control blockID has an ERROR..!')
        return False


# Verify block header
def checking_block_head(Block):
    info('Starting block header controls ...')

    try:
        # Get blockheader items
        for items in Block.__dict__:
            flag = 0

            for heads in header_of_block:
                flag += 1

                # If item was found in the header_of_block
                if items == heads:
                    break

                # If blockheader has more items
                if flag > 15:
                    info('Blockheader is INCORRECT!')
                    return False

        if len(Block.__dict__) == 13:
            info('Blockheader is correct.')
            return True

        else:
            info('Blockheader is INCORRECT!')
            return False

    except:
        debug('Header has something wrong!')
        return False


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
    def found_shared_secret(self, peer_public):
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public)
        return shared_key

    # Serialize and save private key
    def __serialize_private(self):
        __serialized_private = self.private_key.private_bytes(
                                encoding = serialization.Encoding.PEM,
                                format   = serialization.PrivateFormat.PKCS8,
                                encryption_algorithm = serialization.BestAvailableEncryption(bytes(codes_of_block[0])))

    # Signing the message
    def messageSign(self, message):
        message = message.encode(utf_type)
        sign    = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return sign

    @staticmethod
    # Verifying the message
    def verifyMSG(public_key, message, sign):
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
        message = message.encode(utf_type)

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
        message = message.encode(utf_type)

    if not type(shared_key) == bytes:
        shared_key = shared_key.encode(utf_type)

    if not type(keyDerived) == bytes:
        keyDerived = keyDerived.encode(utf_type)

    backend     = default_backend()
    key         = keyDerived
    iv          = shared_key[:16]
    cipher      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor   = cipher.decryptor()
    dt          = decryptor.update(message) + decryptor.finalize()
    decrypted   = dt[:-dt[-1]].decode(utf_type)
    return decrypted


# Controlling prevHash and blockchaindb hash
def check_previous_hash(prevHashs, who):
    info('Controlling prevHash and blockchaindb hash!')
    global prevhash_curr, phash_curr

    if prevHashs == prevhash_curr:
        info('prevHash is verified.')
        return True

    elif detect_block(who) == 3:
        info('Controlling inside of QueueConf...')

        # Check if the block is in the QueueConf
        if get_size_queue(queue_conf) != 0:

            for qs in range(0, get_size_queue(queue_conf)):
                tmpY = loading_object(get_from_queue(queue_conf))

                try:
                    if prevHashs == tmpY.prevHash:
                        info('The block is found inside the QueueConf!')
                        tempF = 1
                    else:
                        tempF = 0

                except AttributeError:
                    tempF = 0
                    break

                put_queue(queue_temp2, dumping_object(tmpY))

            # Get back items in temp_hash_q_2ueue to queue_conf
            for qItems in range(0, get_size_queue(queue_temp2)):
                put_queue(queue_conf, get_from_queue(queue_temp2))

            # Remove all items from the temp_hash_q_2ueue
            for Qitems in range(0, get_size_queue(queue_temp2)):
                get_from_queue(queue_temp2)

            if tempF == 1:
                return True

        # If the block was added to the blockchain
        elif prevHashs == phash_curr:
            info('The block was added to the blockchain')
            return True

    debug('prevHash is NOT verified!')
    return False


def add_block_to_chain(Block):
    global blockid_curr, prevhash_curr, phash_curr, last_idcurr
    Block.blockID = str(int(blockid_curr) + 1)
    blockid_curr   = int(blockid_curr)     + 1
    prevhash_curr  = Block.hash
    phash_curr     = Block.prevHash
    db.blocks.insert({
        "blockID"           : Block.blockID         ,
        "senderID"          : Block.senderID        ,
        "receiverID"        : Block.receiverID      ,
        "message"           : Block.message         ,
        "timestamp"         : Block.timestamp       ,
        "hash"              : Block.hash            ,
        "prevHash"          : Block.prevHash        ,
        "digitalSignature"  : Block.digitalSignature,
        "verKey"            : Block.verKey          ,
        "nonce"             : Block.nonce           ,
        "who"               : Block.who             ,
        "totalHash"         : Block.totalHash
    })
    warning('New block added to the blockchain!')
    Blockcurr     = getlastBlock()
    last_idcurr   = Blockcurr._id


# Compare blockchain hash and received block prevHash
def controlChain(Hash):
    try:
        for docs in db.blocks.find({'hash': str(Hash)[2:-1]}):
            return True
        return False
    except:
        return False


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


# Sign the block
def sign_block(Block):
    global ecdh_obj
    Block.verKey = b64encode(ecdh_obj.messageSign(Block.totalHash)).decode("ISO-8859-1")


# Broadcast the block to all chains and miners
def broadcast(Block):
    info('Broadcasting to all blockchain servers...')
    for hosts in chain_hosts:
        while True:
            if int(queue_block_who.qsize()) != 0:
                Block.who = queue_block_who.get()
                break
            sleep(0.05)
        fakeID_1        = randint(0, 999999999999999999999999)
        fakeID_2        = randint(0, 999999999999999999999999)
        Block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()
        sign_block(Block)
        connect(hosts, Block)


# User Operations...
def user_operations():
    while True:

        while True:
            if int(queue_user.qsize()) != 0:
                infos   = get_from_queue(queue_user)
                block   = infos[0]
                IP_Add  = infos[1]
                break

        lock_user.acquire()
        while True:
            # Block has something:
            if block != "":
                hashFlag = 0
                try:
                    if controlling_hash(block, 1):

                        if block.prevHash[0:7] == "b'00000":
                            hashFlag = 1

                        else:
                            info('Controlling hash is FALSE! 2')
                            hashFlag = 0
                            break

                    else:
                        info('Controlling hash is FALSE! 1')
                        hashFlag = 0
                        break

                except:
                    info('Controlling hash has an ERROR..!')
                    hashFlag = 0
                    break

                if hashFlag == 1:

                    # If the block comes from the user to confirm..
                    if block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                     str(code_block_10).encode(utf_type)).hexdigest():

                        try:
                            if controlChain(block.prevHash):
                                chainF = 1
                                info('Chain control result is TRUE.')

                            else:
                                info('Chain control result is FALSE!')
                                # Re-Send the block with code-8
                                chainF = 0

                        except:
                            debug('Chain controlling ERROR..!')
                            chainF = 0

                        if chainF == 0:
                            block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                         str(code_block_08).encode(utf_type)).hexdigest()

                            while True:
                                if int(queue_block_who.qsize()) != 0:
                                    block.who = queue_block_who.get()
                                    break
                                sleep(0.05)

                            # Change blockID value for attacks
                            fakeID_1        = randint(0, 999999999999999999999999)
                            fakeID_2        = randint(0, 999999999999999999999999)
                            block.blockID   = SHA512.new(str(fakeID_1 +
                                                             fakeID_2).encode(utf_type)).hexdigest()
                            sign_block(block)
                            connect(IP_Add, block)

                        # Chain control result is TRUE
                        elif chainF == 1:
                            info('The block is already in the blockchain.')

                            block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                         str(code_block_09).encode(utf_type)).hexdigest()

                            # Send it with Block.hash is NoK
                            while True:
                                if int(queue_block_who.qsize()) != 0:
                                    block.who = queue_block_who.get()
                                    break
                                sleep(0.05)

                            # Change blockID value for attacks
                            fakeID_1        = randint(0, 999999999999999999999999)
                            fakeID_2        = randint(0, 999999999999999999999999)
                            block.blockID   = SHA512.new(str(fakeID_1 +
                                                             fakeID_2).encode(utf_type)).hexdigest()
                            sign_block(block)
                            connect(IP_Add, block)

                        break

                    break

                break

            break

        lock_user.release()


# Blockchain Operations...
def chain_operations():
    while True:

        while True:
            if int(queue_chain.qsize()) != 0:
                infos   = get_from_queue(queue_chain)
                block   = infos[0]
                IP_Add  = infos[1]
                break

        lock_chain.acquire()
        while True:
            # Block has something:
            if block != "":

                # If block came..
                try:
                    if controlling_hash(block, 3):
                        hashFlag = 1

                    else:
                        info('Controlling hash is FALSE! 3')
                        hashFlag = 0
                        break

                except:
                    info('Controlling hash has an ERROR..!')
                    hashFlag = 0
                    break

                try:
                    if checking_block_id(block):
                        blockIDF = 1
                        info('ID of the block control result is TRUE. [2]')

                    else:
                        blockIDF = 0
                        info('ID of the block control result is FALSE! [2]')

                except:
                    blockIDF = 0
                    debug('ID of the block control ERROR..! [2]')
                    break

                if hashFlag == 1 and blockIDF == 1:

                    debug('The block is coming from the blockchain(s) server!')
                    global blockid_curr, prevhash_curr, last_idcurr

                    # If it is request block
                    if block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                     str(code_block_06).encode(utf_type)).hexdigest():
                        info('It is a request block..')

                        try:
                            if check_previous_hash(block.prevHash, block.who):
                                info('Checking previous hash is TRUE.[1]')
                                prevFlag = 1

                            else:
                                prevFlag = 0
                                info('Checking previous hash is FALSE!')

                        except:
                            prevFlag = 0
                            debug('Checking previous hash has something wrong!')
                            break

                        # Controlling prevHash..
                        if prevFlag == 1:
                            block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                         str(code_block_05).encode(utf_type)).hexdigest()

                            # Send it with OK
                            while True:
                                if int(queue_block_who.qsize()) != 0:
                                    block.who = queue_block_who.get()
                                    break
                                sleep(0.05)

                            # Change blockID value for attacks
                            fakeID_1        = randint(0, 999999999999999999999999)
                            fakeID_2        = randint(0, 999999999999999999999999)
                            block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                        # False prevHash, so send it with NoK
                        else:
                            block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                         str(code_block_04).encode(utf_type)).hexdigest()
                            # Send it with NoK
                            while True:
                                if int(queue_block_who.qsize()) != 0:
                                    block.who = queue_block_who.get()
                                    break
                                sleep(0.05)

                            # Change blockID value for attacks
                            fakeID_1        = randint(0, 999999999999999999999999)
                            fakeID_2        = randint(0, 999999999999999999999999)
                            block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                        sign_block(block)
                        connect(IP_Add, block)

                    # If it is OK Block
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_05).encode(utf_type)).hexdigest():
                        info('It is OK Block')
                        # Get object and flag values if exists
                        calcObj, createF = find_obj(block.hash, IP_Add)

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

                        # If answer is NOT duplicated one.
                        if dupF == 1:
                            info('OK is increased by 1.')
                            calcObj.ok += 1
                            # Empty Queue
                            if get_size_queue(queue_temp1) != 0:
                                for qs in range(0, get_size_queue(queue_temp1)):
                                    get_from_queue(queue_temp1)

                            for qs in range(0, get_size_queue(queue_conf)):
                                tempBlock = loading_object(get_from_queue(queue_conf))

                                if tempBlock.hash == block.hash:
                                    info('queue_conf.hash and block.hash are same!')

                                    if len(chain_hosts) / 2 < int(calcObj.ok):
                                        info('Hosts OK & NoK are verified!')
                                        remove_obj(block.hash)

                                        if int(calcObj.ok) > int(calcObj.NoK):
                                            calcHash = main_block(block, 2)

                                            if str(calcHash) == str(block.hash):
                                                block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                                             str(code_block_07).encode(utf_type)).hexdigest()
                                                block.who = 1
                                                add_block_to_chain(block)

                                                if int(queue_conf.qsize())        != 0:
                                                    get_from_queue(queue_conf)

                                                if int(queue_conftimer.qsize())   != 0:
                                                    get_from_queue(queue_conftimer)

                                                if int(queue_verify.qsize())      != 0:
                                                    get_from_queue(queue_verify)

                                                if int(queue_verifytimer.qsize()) != 0:
                                                    get_from_queue(queue_verifytimer)

                                                broadcast(block)

                                        break
                                else:
                                    debug('queue_conf.hash and block.hash are NOT same!')
                                    put_queue(queue_conf, dumping_object(block))

                    # If it is NoK Block
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_04).encode(utf_type)).hexdigest():
                        info('It is NoK Block')
                        calcObj, createF = find_obj(block.hash, IP_Add)
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

                        if dupF == 1:
                            calcObj.NoK += 1

                    # If lastBlock check request
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_06).encode(utf_type) +
                                                       str(code_block_11).encode(utf_type)).hexdigest():

                        info('It is a lastBlock control request!')

                        if block.hash == prevhash_curr:
                            block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                         str(code_block_01).encode(utf_type) +
                                                         str(code_block_03).encode(utf_type)).hexdigest()
                            while True:
                                if int(queue_block_who.qsize()) != 0:
                                    block.who = queue_block_who.get()
                                    break
                                sleep(0.05)

                            fakeID_1 = randint(0, 999999999999999999999999)
                            fakeID_2 = randint(0, 999999999999999999999999)
                            block.blockID = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                            sign_block(block)
                            connect(IP_Add, block)

                        elif block.prevHash == prevhash_curr:
                            calcHash = main_block(block, 2)

                            if str(calcHash) == str(block.hash):

                                block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                             str(code_block_07).encode(utf_type)).hexdigest()
                                block.who = 1
                                add_block_to_chain(block)

                                if int(queue_conf.qsize())        != 0:
                                    get_from_queue(queue_conf)

                                if int(queue_conftimer.qsize())   != 0:
                                    get_from_queue(queue_conftimer)

                                if int(queue_verify.qsize())      != 0:
                                    get_from_queue(queue_verify)

                                if int(queue_verifytimer.qsize()) != 0:
                                    get_from_queue(queue_verifytimer)

                                broadcast(block)

                    # If lastBlock is NoK
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_04).encode(utf_type) +
                                                       str(code_block_00).encode(utf_type)).hexdigest():
                        info('lastBlock is NoK')

                        block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                     str(code_block_12).encode(utf_type)).hexdigest()
                        while True:
                            if int(queue_block_who.qsize()) != 0:
                                block.who = queue_block_who.get()
                                break
                            sleep(0.05)

                        fakeID_1        = randint(0, 999999999999999999999999)
                        fakeID_2        = randint(0, 999999999999999999999999)
                        block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                        sign_block(block)
                        connect(IP_Add, block)

                    # If lastBlock is OK
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_01).encode(utf_type) +
                                                       str(code_block_03).encode(utf_type)).hexdigest():
                        info('lastBlock is OK..')

                    # Send your blocks request
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_12).encode(utf_type)).hexdigest():
                        info('Send your blocks request...')

                        while True:
                            for docs in db.blocks.find():
                                if str(last_idcurr) == str(obj(docs)._id):
                                    checkF = 1
                                    lastblockID = str(obj(docs).blockID)
                                    break
                                else:
                                    checkF      = 0
                                    lastblockID = 0

                            if checkF == 1 and lastblockID != 0:
                                nowblockID = blockid_curr
                                for IDs in range(int(lastblockID), int(nowblockID)):
                                    for docs in db.blocks.find({'blockID': str(IDs)}):
                                        block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                                     str(code_block_10).encode(utf_type) +
                                                                     str(code_block_11).encode(utf_type) +
                                                                     str(code_block_12).encode(utf_type)).hexdigest()
                                        while True:
                                            if int(queue_block_who.qsize()) != 0:
                                                block.who = queue_block_who.get()
                                                break
                                            sleep(0.05)

                                        fakeID_1        = randint(0, 999999999999999999999999)
                                        fakeID_2        = randint(0, 999999999999999999999999)
                                        block.blockID   = SHA512.new(
                                            str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                                        sign_block(block)
                                        connect(IP_Add, block)
                            break

                    # Add the new block (reply)
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_10).encode(utf_type) +
                                                       str(code_block_11).encode(utf_type) +
                                                       str(code_block_12).encode(utf_type)).hexdigest():
                        info('Add the new block reply..!')
                        calcHash = main_block(block, 2)
                        if str(calcHash) == str(block.hash):
                            if block.prevHash == str(prevhash_curr):
                                block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                             str(code_block_07).encode(utf_type)).hexdigest()
                                block.who = 1
                                add_block_to_chain(block)

                                if int(queue_conf.qsize())        != 0:
                                    get_from_queue(queue_conf)

                                if int(queue_conftimer.qsize())   != 0:
                                    get_from_queue(queue_conftimer)

                                if int(queue_verify.qsize())      != 0:
                                    get_from_queue(queue_verify)

                                if int(queue_verifytimer.qsize()) != 0:
                                    get_from_queue(queue_verifytimer)

                                broadcast(block)

                    # Means other chain server added the block
                    elif block.totalHash == SHA512.new(str(block.hash).encode(utf_type) +
                                                       str(code_block_07).encode(utf_type)).hexdigest():
                        info('Other blockchain server added the block.')

                        calcHash = main_block(block, 2)
                        if str(calcHash) == str(block.hash):
                            if block.prevHash == prevhash_curr:
                                block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                             str(code_block_07).encode(utf_type)).hexdigest()
                                block.who = 1
                                add_block_to_chain(block)

                                if int(queue_conf.qsize())        != 0:
                                    get_from_queue(queue_conf)

                                if int(queue_conftimer.qsize())   != 0:
                                    get_from_queue(queue_conftimer)

                                if int(queue_verify.qsize())      != 0:
                                    get_from_queue(queue_verify)

                                if int(queue_verifytimer.qsize()) != 0:
                                    get_from_queue(queue_verifytimer)

                                broadcast(block)

                    else:
                        info('It is NULL..')

            break

        lock_chain.release()


# Block operations
def miner_operations():
    while True:
        while True:
            if int(queue_miner.qsize()) != 0:
                infos  = get_from_queue(queue_miner)
                block  = infos[0]
                IP_Add = infos[1]
                break

        lock_miner.acquire()
        while True:
            # Block has something:
            if block != "":

                try:
                    if controlling_hash(block, 2):
                        hashFlag = 1

                    else:
                        info('Controlling hash is FALSE 5')
                        hashFlag = 0
                        break

                except:
                    info('Controlling hash has an ERROR.! 6')
                    hashFlag = 0
                    break

                try:
                    if checking_block_id(block):
                        blockIDF = 1
                        info('ID of the block control result is TRUE. [3]')

                    else:
                        blockIDF = 0
                        info('ID of the block control result is FALSE! [3]')

                except:
                    blockIDF = 0
                    debug('ID of the block control ERROR! [3]')
                    break

                if hashFlag == 1 and blockIDF == 1:
                    # Block comes from the miner servers
                    debug('The block is coming from the miner(s) side!')

                    try:
                        if check_previous_hash(block.prevHash, block.who):
                            info('Checking previous hash is TRUE.[2]')
                            prevFlag = 1
                        else:
                            prevFlag = 0
                            info('Checking previous hash is FALSE!')

                    except:
                        prevFlag = 0
                        debug('Checking previous hash has something WRONG!')
                        break

                    if prevFlag == 1:

                        try:
                            # Check digital signature in the block
                            verifyFlag = 0

                            global ecdh_obj
                            for publics in storage_pub:
                                if str(IP_Add) == str(publics[1]):
                                    if ecdh_obj.verifyMSG(public_key = publics[0]     ,
                                                               message    = block.totalHash,
                                                               sign       = block.verKey):
                                        info('Message verifying result is TRUE.')
                                        verifyFlag = 1
                                        break

                        except:
                            info('Message verifying result has an ERROR!')
                            verifyFlag = 0
                            break

                        # Message verified..
                        if verifyFlag == 1:

                            countQverify = get_size_queue(queue_verify)
                            # Check block for verify queue..
                            for qs in range(0, get_size_queue(queue_verify)):
                                tmpBlock = loading_object(get_from_queue(queue_verify))
                                tmpT     = get_from_queue(queue_verifytimer)

                                # Check received block already exists!
                                if block.hash == tmpBlock.hash:
                                    info('Block already exists in the Queue..!')
                                    # Send the block to the miner with code-3 OK
                                    block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                                 str(code_block_03).encode(utf_type)).hexdigest()

                                    while True:
                                        if int(queue_block_who.qsize()) != 0:
                                            block.who = queue_block_who.get()
                                            break
                                        sleep(0.05)

                                    # Change blockID value for attacks
                                    fakeID_1        = randint(0, 999999999999999999999999)
                                    fakeID_2        = randint(0, 999999999999999999999999)
                                    block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                                    # IP address validation for miner_hosts
                                    sign_block(block)
                                    connect(IP_Add, block)

                                    # Calculate hash with requestCode-6
                                    block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                                 str(code_block_06).encode(utf_type)).hexdigest()

                                    # Change blockID value for attacks
                                    fakeID_1        = randint(0, 999999999999999999999999)
                                    fakeID_2        = randint(0, 999999999999999999999999)
                                    block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                                    # Add the block to the queue
                                    put_queue(queue_conf, dumping_object(block))
                                    put_queue(queue_conftimer, 5)

                                    # Broadcast the block to all chain servers
                                    for hosts in chain_hosts:
                                        while True:
                                            if int(queue_block_who.qsize()) != 0:
                                                block.who = queue_block_who.get()
                                                break
                                            sleep(0.05)

                                        sign_block(block)
                                        connect(hosts, block)

                                    break

                                put_queue(queue_verify, dumping_object(tmpBlock))
                                put_queue(queue_verifytimer, tmpT)

                            # If the QVerify size decreases by 1
                            if countQverify == get_size_queue(queue_verify) + 1:
                                pass

                            # If no blocks are in the QVerify
                            else:
                                info('The block is NOT in the QVerify.')

                                put_queue(queue_verify, dumping_object(block))
                                put_queue(queue_verifytimer, 5)

                                block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                                             str(code_block_03).encode(utf_type)).hexdigest()

                                # Change blockID value for attacks
                                fakeID_1        = randint(0, 999999999999999999999999)
                                fakeID_2        = randint(0, 999999999999999999999999)
                                block.blockID   = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                                # Send it with Block is OK
                                while True:
                                    if int(queue_block_who.qsize()) != 0:
                                        block.who = queue_block_who.get()
                                        break
                                    sleep(0.05)

                                sign_block(block)
                                connect(IP_Add, block)

                            break

                # Get values from the last block
                if get_size_queue(queue_conf) != 0 or get_size_queue(queue_verify) != 0:
                    block_id_rndm = '0'
                    fakeHash_1   = randint(0, 999999999999999999999999)
                    fakeHash_2   = randint(0, 999999999999999999999999)
                    prev_hash_rndm  = SHA512.new(str(fakeHash_1 + fakeHash_2).encode(utf_type)).hexdigest()

                else:
                    global blockid_curr, prevhash_curr
                    block_id_rndm  = int(blockid_curr) + 1
                    prev_hash_rndm = prevhash_curr

                    # Add whois information
                    info('ID and prevHash values are getting, added to the block.')

                # Calculate hash of blockID
                hash_block_id   = SHA512.new(str(block_id_rndm).encode(utf_type)).hexdigest()
                block.blockID   = hash_block_id
                block.prevHash  = prev_hash_rndm

                # Re-calculation of block totalHash value
                block.totalHash = SHA512.new(str(block.hash).encode(utf_type) +
                                             str(code_block_11).encode(utf_type)).hexdigest()

                while True:
                    if int(queue_block_who.qsize()) != 0:
                        block.who = queue_block_who.get()
                        break
                    sleep(0.05)

                sign_block(block)
                connect(IP_Add, block)

            break

        lock_miner.release()


# SERVER SIDE
# Receive data from the socket
class ClientThread(Thread):
    def __init__(self, conn, ip_address):
        Thread.__init__(self)
        self.ip_address = ip_address
        self.conn = conn

    def run(self):
        while True:
            # Receive bytes
            connFlag = 1
            conFlag  = 1

            try:
                tempBytes = self.conn.recv(4096)

                #except:
                #    break

                global shared_pairs
                global tempBlock
                global ecdh_obj
                global certificate
                if str(shared_pairs) == '0' and len(codes_of_block) == 0:

                    # If the public key received
                    try:

                        if len(codes_of_block) == 0:

                            if str(tempBytes.decode(utf_type)).startswith("-----BEGIN PUBLIC KEY-----") and\
                               "-----END PUBLIC KEY-----" in str(tempBytes.decode(utf_type)):
                                    shared_pairs = ecdh_obj.found_shared_secret(deserialize_pubkey(tempBytes))
                                    certificate  = tempBytes
                                    tempBlock    = []
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

                            global code_block_00, code_block_01, code_block_02, code_block_03
                            global code_block_04, code_block_05, code_block_06, code_block_07
                            global code_block_08, code_block_09, code_block_10, code_block_11
                            global code_block_11, code_block_12

                            code_block_12 = SHA512.new(str(codes_of_block[12]).encode(utf_type)).hexdigest()
                            code_block_11 = SHA512.new(str(codes_of_block[11]).encode(utf_type)).hexdigest()
                            code_block_10 = SHA512.new(str(codes_of_block[10]).encode(utf_type)).hexdigest()
                            code_block_09 = SHA512.new(str(codes_of_block[9]) .encode(utf_type)).hexdigest()
                            code_block_08 = SHA512.new(str(codes_of_block[8]) .encode(utf_type)).hexdigest()
                            code_block_07 = SHA512.new(str(codes_of_block[7]) .encode(utf_type)).hexdigest()
                            code_block_06 = SHA512.new(str(codes_of_block[6]) .encode(utf_type)).hexdigest()
                            code_block_05 = SHA512.new(str(codes_of_block[5]) .encode(utf_type)).hexdigest()
                            code_block_04 = SHA512.new(str(codes_of_block[4]) .encode(utf_type)).hexdigest()
                            code_block_03 = SHA512.new(str(codes_of_block[3]) .encode(utf_type)).hexdigest()
                            code_block_02 = SHA512.new(str(codes_of_block[2]) .encode(utf_type)).hexdigest()
                            code_block_01 = SHA512.new(str(codes_of_block[1]) .encode(utf_type)).hexdigest()
                            code_block_00 = SHA512.new(str(codes_of_block[0]) .encode(utf_type)).hexdigest()

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
                        public = aes_decryption_func(derivation_keys(shared_pairs), shared_pairs, tempBytes).encode(utf_type)
                        IP = public.decode('utf-8').split('\n')[-1]

                        for publics in storage_pub:
                            if publics[1] == IP:
                                publics = ((deserialize_pubkey(public), IP))
                                changed = 1

                        if changed == 0:
                            storage_pub.append((deserialize_pubkey(public), IP))

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

                # IP address validation for chain_hosts
                for hosts in chain_hosts:
                    if hosts == self.ip_address:
                        info('IP [' + str(self.ip_address) + '] is in the chain list.')
                        connFlag    = 1
                        conFlag     = 0
                        break

                    else:
                        connFlag    = 0
                        conFlag     = 0

                # If the chain list does NOT contains IP address
                if connFlag == 0:
                    # IP address validation for miner_hosts
                    for hosts in miner_hosts:
                        if hosts == self.ip_address:
                            info('IP [' + str(self.ip_address) + '] is in the miner list.')
                            conFlag = 1
                            break

                        else:
                            conFlag = 0

                # The data is coming from the UNKNOWN sender
                if conFlag == 0 and connFlag == 0:
                    if self.ip_address != auth_host:
                        debug('UNKNOWN Sender !!!')
                        break
                    else:
                        info('IP [' + str(self.ip_address) + '] is authentication list.')

            # If Data does NOT LOAD!
            except ConnectionResetError:
                debug('Connection Reset by [' + self.ip_address + ']')
                break

            except AttributeError:
                debug('Data is broken !')
                break

            except:
                warning('Connection ERROR !')
                break

            info('[' + self.ip_address + '] is connected.')

            try:
                blockWho = detect_block(block.who)

            except AttributeError:
                pass

            except UnboundLocalError:
                pass

            except:
                debug('flag_who control result has something wrong!')
                break

            try:
                # If the user sends the block
                if blockWho == 1:
                    info('The user sends the block!')
                    put_queue(queue_user, (block, self.ip_address))

                # If the mining part sends the block
                elif blockWho == 2:
                    info('The miner sends the block!')
                    put_queue(queue_miner, (block, self.ip_address))

                # If the blockchain part sends the block
                elif blockWho == 3:
                    info('The blockchain sends the block!')
                    put_queue(queue_chain, (block, self.ip_address))

                else:
                    debug('Someone sends the block!')

            except:
                pass

            break



# Listen all connections
def Conn():
    info('Server is preparing..')
    tcpServer = socket(AF_INET, SOCK_STREAM)
    tcpServer.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    tcpServer.bind((binding_address, port_number))
    tcpServer.listen(200)

    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('selfsigned.cert', 'selfsigned.key')
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')

    threads = []
    info('Server side is ready to listen.')

    while True:

        try:
            (conn, (ip_address, port_number_ADD)) = tcpServer.accept()
            info('[' + str(ip_address) + ']:[' + str(port_number_ADD) + '] is connecting...')
            conn      = context.wrap_socket(conn, server_side=True)
            newthread = ClientThread(conn, ip_address)
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


def quitLog():
    warning('----------------------------------------')
    warning('--- Blockchain Server is stopping... ---')
    warning('----------------------------------------')


def startLog():
    warning('++++++++++++++++++++++++++++++++++++++++')
    warning('+++ Blockchain Server is starting... +++')
    warning('++++++++++++++++++++++++++++++++++++++++')


# CLIENT SIDE
# Send any block to others
def connect(HOST, message):
    info('Message is sending to [' + str(HOST) + ']')

    # Socket informations
    try:
        mySocket    = socket(AF_INET, SOCK_STREAM)
        mySocket.settimeout(2)
        context     = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.load_cert_chain('selfsigned.cert', 'selfsigned.key')
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        conn        = context.wrap_socket(mySocket)
        conn.connect((HOST, port_number))

        # Sending bytes data..
        if 'bytes' in str(type(message)):
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

    except ConnectionResetError:
        debug('Receiver [' + str(HOST) + '] does NOT use SSL!')
        return False

    except:
        debug('Receiver [' + str(HOST) + '] seems like OFFLINE!')
        return False


# Check if MongoDB is running or not
def mongo_service():
    mongo_Proc = Popen(['ps -A | grep mongod'], stdout=PIPE, shell=True)
    (out, err) = mongo_Proc.communicate()
    info('MongoDB process checking..')

    if out.decode() == "":
        # If MongoDB service is NOT running
        debug("MongoDB process is NOT running!")
        quitLog()
        sleep(0.5)
        system("pkill -9 python")
        exit()

    else:
        info("MongoDB process is running..")
        # If MongoDB service is running
        databaseExists()


# Convert MongoDB dict to object
class obj(object):
    def __init__(self, d):

        for a, b in d.items():

            if isinstance(b, (list, tuple)):
                setattr(self, a, [obj(x) if isinstance(x, dict) else x for x in b])

            else:
                setattr(self, a, obj(b) if isinstance(b, dict) else b)


# Get last block in MongoDB
def getlastBlock():
    lastBlock = db.blocks.find().sort([('_id', -1)]).limit(1)
    info('Lastblock is getting..')
    return obj(lastBlock[0])


def dumpRecv(object):
    return dumps(object)


def loadRecv(object):
    return loads(object)


# Dump object before sending
def dumping_object(object):
    info('The object is dumping..')
    return d0(object)


# Load received object
def loading_object(object):
    info('The object is loading..')
    return l0(object)


def databaseExists():
    dbnames = client.database_names()

    # Check databasename if exists
    if mongodbName in dbnames:
        info('Database name found.')
        collection  = db.blocks
        cursor      = collection.find()
        genZero     = SHA512.new(str(0).encode(utf_type)).hexdigest()
        genMSG      = SHA512.new(str("It's the genesis block.").encode(utf_type)).hexdigest()
        genHash     = genesisHash()

        try:
            genesisBlock = obj(cursor[0])

            # Check genesis block
            if  genesisBlock.blockID          == 0       and \
                genesisBlock.senderID         == genZero and \
                genesisBlock.hash             == genHash and \
                genesisBlock.message          == genMSG  and \
                genesisBlock.prevHash         == genZero and \
                genesisBlock.timestamp        == genZero and \
                genesisBlock.receiverID       == genZero and \
                genesisBlock.digitalSignature == genZero and \
                genesisBlock.verKey           == genZero and \
                genesisBlock.nonce            == genZero and \
                genesisBlock.who              == 1       and \
                genesisBlock.totalHash        == genZero:

                    info('Genesis is verified.')

        except IndexError:
            debug('Genesis block does NOT found in the blockchain.')

            # Create a genesis block
            genesis_creation()

        lastBlock = getlastBlock()

        # If chain has many blocks
        if lastBlock.hash != genHash:
            info('Blockchain has more blocks.')

            # Send and verify last block is correct
            for hosts in chain_hosts:

                lastBlock.totalHash = SHA512.new(str(lastBlock.hash).encode(utf_type) +
                                                 str(code_block_06).encode(utf_type) +
                                                 str(code_block_11).encode(utf_type)).hexdigest()

                # Change blockID value for attacks
                fakeID_1          = randint(0, 999999999999999999999999)
                fakeID_2          = randint(0, 999999999999999999999999)
                lastBlock.blockID = SHA512.new(str(fakeID_1 + fakeID_2).encode(utf_type)).hexdigest()

                while True:
                    if int(queue_block_who.qsize()) != 0:
                        lastBlock.who = queue_block_who.get()
                        break
                    sleep(0.05)

                sign_block(lastBlock)
                connResult = connect(hosts, lastBlock)

                if connResult:
                    info('lastBlock sent [' + hosts + ']')

                else:
                    debug('[' + hosts + '] Connection Error !')

        # If chain has only genesis block
        else:
            info('Blockchain has only genesis block.')

    else:
        debug('Database name does not found!')

        # Create collection and genesis
        genesis_creation()
        collection  = db.blocks
        # noinspection PyUnusedLocal
        cursor      = collection.find()

        # Call it again to get more info
        databaseExists()


# Calculate genesis block hash value
def genesisHash():
    calcHash = ''
    for heads in header_of_block:
        if heads != 'hash' and heads != 'totalHash' and \
           heads != 'who'  and heads != 'message':
            item     = SHA512.new(str(0).encode(utf_type)).hexdigest()
            calcHash = SHA512.new(str(calcHash).encode(utf_type) + str(item).encode(utf_type)).hexdigest()

    newHash = SHA512.new(str(calcHash).encode(utf_type) + str(code_block_07).encode(utf_type)).hexdigest()

    return newHash


# Build a genesis block with 0
def genesis_creation():
    global blockid_curr, prevhash_curr, phash_curr, last_idcurr

    genZero = SHA512.new(str(0).encode(utf_type)).hexdigest()
    genMSG  = SHA512.new(str("It's the genesis block.").encode(utf_type)).hexdigest()
    genHash = genesisHash()

    db.blocks.insert({
        "blockID"           : 0         ,
        "senderID"          : genZero   ,
        "receiverID"        : genZero   ,
        "message"           : genMSG    ,
        "timestamp"         : genZero   ,
        "hash"              : genHash   ,
        "prevHash"          : genZero   ,
        "digitalSignature"  : genZero   ,
        "verKey"            : genZero   ,
        "nonce"             : genZero   ,
        "who"               : genZero   ,
        "totalHash"         : genZero
    })
    info('Genesis block generated.')


# Save UUID..
def save_uuid(peer_uuid):
    if isfile(uuid_path):
        file = open(uuid_path, 'a')
        file.write(str(peer_uuid) + '\n')
        file.close()
    else:
        system('touch ' + str(uuid_path))


# Control Qtimer to detect unused blocks in the Queue
def control_engineueue():
    while True:
        if int(queue_verifytimer.qsize()) != 0:
            for size in range(0, int(queue_verifytimer.qsize())):
                timer  = queue_verifytimer.get()
                timer -= 1

                # Time is OUT
                if timer <= 0:
                    get_from_queue(queue_verify)

                else:
                    try:
                        queue_verifytimer.put(timer)
                    except:
                        queue_verifytimer.get()
                        try:
                            queue_verifytimer.put(timer)
                        except:
                            pass

        if int(queue_conftimer.qsize()) != 0:
            for size in range(0, int(queue_conftimer.qsize())):
                timerC  = queue_conftimer.get()
                timerC -= 1

                # Time is OUT
                if timerC <= 0:
                    get_from_queue(queue_conf)

                else:
                    try:
                        queue_conftimer.put(timerC)
                    except:
                        queue_conftimer.get()
                        try:
                            queue_conftimer.put(timerC)
                        except:
                            pass

        sleep(15)


# Calculate and find blockhash(es)
def calcandfind():
    while True:
        if int(queue_block_who.qsize()) >= 499:
            sleep(15)

        else:
            who = generate_block_hash()
            try:
                queue_block_who.put(who)
            except:
                if int(queue_block_who.qsize()) != 0:
                    queue_block_who.get()
                try:
                    queue_block_who.put(who)
                except:
                    pass


def engine_starts():
    global shared_pairs
    shared_pairs = 0

    # Generate blockWho
    blockWhogen     = Process(target=calcandfind,   )
    blockWhogen.start()
    sleep(0.05)

    # Generate blockWho
    blockWhogen2    = Process(target=calcandfind,   )
    blockWhogen2.start()
    sleep(0.5)

    # Create a listening server
    listenConn      = Thread(target=Conn,           )
    listenConn.start()
    sleep(0.5)

    # Generate an elliptic curve object
    global ecdh_obj
    ecdh_obj = elliptic_pair()

    my_uuid   = input('UUID:')
    global hash_uuid
    hash_uuid = SHA512.new(my_uuid.encode(utf_type)).hexdigest().encode(utf_type)

    connect(auth_host, ecdh_obj.serialized_public + hash_uuid)

    while True:
        if len(codes_of_block) == 13:
            break


def main():
    # MongoDB Process...
    mongodbProc     = Thread(target=mongo_service, )
    mongodbProc.start()
    sleep(1)

    global blockid_curr, prevhash_curr, phash_curr, last_idcurr
    # Get last block informations in MongoDB
    lastB            = getlastBlock()
    blockid_curr     = int(lastB.blockID)
    prevhash_curr    = lastB.hash
    phash_curr       = lastB.prevHash
    last_idcurr      = lastB._id

    # Chain Operations...
    chain_engine        = Thread(target=chain_operations,       )
    chain_engine.start()
    sleep(0.5)

    # User Operations...
    user_engine         = Thread(target=user_operations,        )
    user_engine.start()
    sleep(0.5)

    # Miner Operations...
    miner_engine        = Thread(target=miner_operations,       )
    miner_engine.start()
    sleep(0.5)

    # Control confirmation queue Operations...
    control_engine      = Thread(target=check_queue,            )
    control_engine.start()
    sleep(0.5)


# When the program starts...
def engine():
    global code_block_00, code_block_01, code_block_02, code_block_03
    global code_block_04, code_block_05, code_block_06, code_block_07
    global code_block_08, code_block_09, code_block_10, code_block_11
    global code_block_11, code_block_12

    startLog()
    sleep(0.01)
    info('main() function is called.'              )
    info('Queue for IP is created.'                )
    info('Queue for Conf is created.'              )
    info('Queue for Verifying is created.'         )
    info('Binding address is [' + binding_address + ']'       )
    info('Port number is [' + str(port_number) + ']'      )
    engine_starts()
    main()


if __name__ == '__main__':
    try:
        # engine is activated.
        engine()

    except KeyboardInterrupt:
        debug('Keyboard Interrupt is occured!')
        quitLog()
        system("pkill -9 python")

    except AttributeError:
        debug('Attribute Error: ' + str(AttributeError.__doc__))
        quitLog()
        exit()

    except (KeyboardInterrupt, EOFError):
        debug('KeyboardInterrupt or EOFError !')
        quitLog()
        exit()

    except:
        debug('Something was wrong..!')
        quitLog()
        exit()
