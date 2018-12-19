import socket
import time

from io import BytesIO
from random import randint
from unittest import TestCase

from block import Block
from ecc import PrivateKey
from helper import (
    decode_base58,
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from merkleblock import MerkleBlock
from script import p2pkh_script, Script
from tx import Tx, TxIn, TxOut

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'


class NetworkEnvelope:

    def __init__(self, command, payload, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s, testnet=False):
        '''Takes a stream and creates a NetworkEnvelope'''
        # check the network magic
        magic = s.read(4)
        if magic == b'':
            raise RuntimeError('Connection reset!')
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), expected_magic.hex()))
        # command 12 bytes
        command = s.read(12)
        # strip the trailing 0's
        command = command.strip(b'\x00')
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of hash256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
        # verify checksum
        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')
        # return an instance of the class
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        '''Returns the byte serialization of the entire network message'''
        # add the network magic
        result = self.magic
        # command 12 bytes
        # fill with 0's
        result += self.command + b'\x00' * (12 - len(self.command))
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of hash256 of payload
        result += hash256(self.payload)[:4]
        # payload
        result += self.payload
        return result

    def stream(self):
        '''Returns a stream for parsing the payload'''
        return BytesIO(self.payload)


class NetworkEnvelopeTest(TestCase):

    def test_parse(self):
        msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b'verack')
        self.assertEqual(envelope.payload, b'')
        msg = bytes.fromhex('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b'version')
        self.assertEqual(envelope.payload, msg[24:])

    def test_serialize(self):
        msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)
        msg = bytes.fromhex('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)


class VersionMessage:
    command = b'version'

    def __init__(self, version=70015, services=0, timestamp=None,
                 receiver_services=0,
                 receiver_ip=b'\x00\x00\x00\x00', receiver_port=8333,
                 sender_services=0,
                 sender_ip=b'\x00\x00\x00\x00', sender_port=8333,
                 nonce=None, user_agent=b'/programmingbitcoin:0.1/',
                 latest_block=0, relay=True):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        '''Serialize this message to send over the network'''
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        # receiver services is 8 bytes little endian
        result += int_to_little_endian(self.receiver_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        # receiver port is 2 bytes, little endian should be 0
        result += int_to_little_endian(self.receiver_port, 2)
        # sender services is 8 bytes little endian
        result += int_to_little_endian(self.sender_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        # sender port is 2 bytes, little endian should be 0
        result += int_to_little_endian(self.sender_port, 2)
        # nonce should be 8 bytes
        result += self.nonce
        # useragent is a variable string, so varint first
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result


class VersionMessageTest(TestCase):

    def test_serialize(self):
        v = VersionMessage(timestamp=0, nonce=b'\x00' * 8)
        print(v.serialize().hex())
        self.assertEqual(v.serialize().hex(), '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff000000008d20000000000000000000000000000000000000ffff000000008d200000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000001')


class VerAckMessage:
    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''


class PingMessage:
    command = b'ping'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b'pong'

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class GetHeadersMessage:
    command = b'getheaders'

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError('a start block is required')
        self.start_block = start_block
        if end_block is None:
            self.end_block = b'\x00' * 32
        else:
            self.end_block = end_block

    def serialize(self):
        '''Serialize this message to send over the network'''
        # protocol version is 4 bytes little-endian
        result = int_to_little_endian(self.version, 4)
        # number of hashes is a varint
        result += encode_varint(self.num_hashes)
        # start block is in little-endian
        result += self.start_block[::-1]
        # end block is also in little-endian
        result += self.end_block[::-1]
        return result


class GetHeadersMessageTest(TestCase):

    def test_serialize(self):
        block_hex = '0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3'
        gh = GetHeadersMessage(start_block=bytes.fromhex(block_hex))
        self.assertEqual(gh.serialize().hex(), '7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000')


class HeadersMessage:
    command = b'headers'

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        # number of headers is in a varint
        num_headers = read_varint(stream)
        # initialize the blocks array
        blocks = []
        # loop through number of headers times
        for _ in range(num_headers):
            # add a block to the blocks array by parsing the stream
            blocks.append(Block.parse(stream))
        # return a class instance
        return cls(blocks)


class HeadersMessageTest(TestCase):

    def test_parse(self):
        hex_msg = '0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600'
        stream = BytesIO(bytes.fromhex(hex_msg))
        headers = HeadersMessage.parse(stream)
        self.assertEqual(len(headers.blocks), 2)
        for b in headers.blocks:
            self.assertEqual(b.__class__, Block)


class GetDataMessage:
    command = b'getdata'

    def __init__(self):
        self.data = []

    def add_data(self, data_type, identifier):
        self.data.append((data_type, identifier))

    def serialize(self):
        # start with the number of items as a varint
        result = encode_varint(len(self.data))
        # loop through each tuple (data_type, identifier) in self.data
        for data_type, identifier in self.data:
            # data type is 4 bytes Little-Endian
            result += int_to_little_endian(data_type, 4)
            # identifier needs to be in Little-Endian
            result += identifier[::-1]
        return result


class GetDataMessageTest(TestCase):

    def test_serialize(self):
        hex_msg = '020300000030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000030000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000'
        get_data = GetDataMessage()
        block1 = bytes.fromhex('00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30')
        get_data.add_data(FILTERED_BLOCK_DATA_TYPE, block1)
        block2 = bytes.fromhex('00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910')
        get_data.add_data(FILTERED_BLOCK_DATA_TYPE, block2)
        self.assertEqual(get_data.serialize().hex(), hex_msg)


class GetCFiltersMessage:
    command = b'getcfilters'

    def __init__(self, filter_type=0, start_height=1, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, 'big')
        result += self.start_height.to_bytes(4, 'big')
        result += self.stop_hash
        return result


class CFilterMessage:
    command = b'cfilter'

    def __init__(self, filter_type, block_hash, filter_bytes):
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_bytes = filter_bytes

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        block_hash = s.read(32)[::-1]
        num_bytes = read_varint(s)
        filter_bytes = s.read(num_bytes)
        return cls(filter_type, block_hash, filter_bytes)


class GenericMessage:
    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    def serialize(self):
        return self.payload


class SimpleNode:

    def __init__(self, host, port=None, testnet=False, logging=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        # connect to socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        # create a stream that we can use with the rest of the library
        self.stream = self.socket.makefile('rb', None)

    def handshake(self):
        '''Do a handshake with the other node.
        Handshake is sending a version message and getting a verack back.'''
        # create a version message
        version = VersionMessage()
        # send the command
        self.send(version)
        # wait for a verack message
        self.wait_for(VerAckMessage)

    def send(self, message):
        '''Send a message to the connected node'''
        # create a network envelope
        envelope = NetworkEnvelope(
            message.command, message.serialize(), testnet=self.testnet)
        if self.logging:
            print('sending: {}'.format(envelope))
        # send the serialized envelope over the socket using sendall
        self.socket.sendall(envelope.serialize())

    def read(self):
        '''Read a message from the socket'''
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        if self.logging:
            print('receiving: {}'.format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        '''Wait for one of the messages in the list'''
        # initialize the command we have, which should be None
        command = None
        command_to_class = {m.command: m for m in message_classes}
        # loop until the command is in the commands we want
        while command not in command_to_class.keys():
            # get the next network message
            envelope = self.read()
            # set the command to be evaluated
            command = envelope.command
            # we know how to respond to version and ping, handle that here
            if command == VersionMessage.command:
                # send verack
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                # send pong
                self.send(PongMessage(envelope.payload))
        # return the envelope parsed as a member of the right message class
        return command_to_class[command].parse(envelope.stream())


class SimpleNodeTest(TestCase):

    def test_handshake(self):
        node = SimpleNode('tbtc.programmingblockchain.com', testnet=True)
        node.handshake()


class IntegrationTest(TestCase):

    def test_broadcast(self):
        from bloomfilter import BloomFilter
        last_block_hex = '00000000000000a03f9432ac63813c6710bfe41712ac5ef6faab093fe2917636'
        secret = little_endian_to_int(hash256(b'Jimmy Song'))
        private_key = PrivateKey(secret=secret)
        addr = private_key.point.address(testnet=True)
        h160 = decode_base58(addr)
        target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
        target_h160 = decode_base58(target_address)
        target_script = p2pkh_script(target_h160)
        fee = 5000  # fee in satoshis
        # connect to tbtc.programmingblockchain.com in testnet mode
        node = SimpleNode('tbtc.programmingblockchain.com', testnet=True, logging=\
        False)
        # create a bloom filter of size 30 and 5 functions. Add a tweak.
        bf = BloomFilter(30, 5, 90210)
        # add the h160 to the bloom filter
        bf.add(h160)
        # complete the handshake
        node.handshake()
        # load the bloom filter with the filterload command
        node.send(bf.filterload())
        # set start block to last_block from above
        start_block = bytes.fromhex(last_block_hex)
        # send a getheaders message with the starting block
        getheaders = GetHeadersMessage(start_block=start_block)
        node.send(getheaders)
        # wait for the headers message
        headers = node.wait_for(HeadersMessage)
        # store the last block as None
        last_block = None
        # initialize the GetDataMessage
        getdata = GetDataMessage()
        # loop through the blocks in the headers
        for b in headers.blocks:
            # check that the proof of work on the block is valid
            if not b.check_pow():
                raise RuntimeError('proof of work is invalid')
            # check that this block's prev_block is the last block
            if last_block is not None and b.prev_block != last_block:
                raise RuntimeError('chain broken')
            # add a new item to the getdata message
            # should be FILTERED_BLOCK_DATA_TYPE and block hash
            getdata.add_data(FILTERED_BLOCK_DATA_TYPE, b.hash())
            # set the last block to the current hash
            last_block = b.hash()
        # send the getdata message
        node.send(getdata)
        # initialize prev_tx, prev_index and prev_amount to None
        prev_tx, prev_index, prev_amount = None, None, None
        # loop while prev_tx is None
        while prev_tx is None:
            # wait for the merkleblock or tx commands
            message = node.wait_for(MerkleBlock, Tx)
            # if we have the merkleblock command
            if message.command == b'merkleblock':
                # check that the MerkleBlock is valid
                if not message.is_valid():
                    raise RuntimeError('invalid merkle proof')
            # else we have the tx command
            else:
                # set the tx's testnet to be True
                message.testnet = True
                # loop through the tx outs
                for i, tx_out in enumerate(message.tx_outs):
                    # if our output has the same address as our address we found it
                    if tx_out.script_pubkey.address(testnet=True) == addr:
                        # we found our utxo. set prev_tx, prev_index, and tx
                        prev_tx = message.hash()
                        prev_index = i
                        prev_amount = tx_out.amount
                        self.assertEqual(prev_tx.hex(), 'b2cddd41d18d00910f88c31aa58c6816a190b8fc30fe7c665e1cd2ec60efdf3f')
                        self.assertEqual(prev_index, 7)
        # create the TxIn
        tx_in = TxIn(prev_tx, prev_index)
        # calculate the output amount (previous amount minus the fee)
        output_amount = prev_amount - fee
        # create a new TxOut to the target script with the output amount
        tx_out = TxOut(output_amount, target_script)
        # create a new transaction with the one input and one output
        tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        # sign the only input of the transaction
        self.assertTrue(tx_obj.sign_input_p2pkh(0, private_key))
        # serialize and hex to see what it looks like
        want = '01000000013fdfef60ecd21c5e667cfe30fcb890a116688ca51ac3880f91008dd141ddcdb2070000006b483045022100ff77d2559261df5490ed00d231099c4b8ea867e6ccfe8e3e6d077313ed4f1428022033a1db8d69eb0dc376f89684d1ed1be75719888090388a16f1e8eedeb8067768012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff019334e500000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac00000000'
        self.assertEqual(tx_obj.serialize().hex(), want)
        # send this signed transaction on the network
        node.send(tx_obj)
        # wait a sec so this message goes through with time.sleep(1)
        time.sleep(1)
        # now ask for this transaction from the other node
        # create a GetDataMessage
        getdata = GetDataMessage()
        # ask for our transaction by adding it to the message
        getdata.add_data(TX_DATA_TYPE, tx_obj.hash())
        # send the message
        node.send(getdata)
        # now wait for a Tx response
        received_tx = node.wait_for(Tx)
        # if the received tx has the same id as our tx, we are done!
        self.assertEqual(received_tx.id(), tx_obj.id())
