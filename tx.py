from io import BytesIO
from json import dumps

import random
import requests
import zmq

from ecc import PrivateKey, S256Point, Signature
from helper import (
    decode_base58,
    double_sha256,
    encode_varint,
    hash160,
    int_to_little_endian,
    little_endian_to_int,
    p2pkh_script,
    p2sh_script,
    read_varint,
    SIGHASH_ALL,
)
from script import Script


class LibBitcoinClient:

    context = zmq.Context()
    mainnet_socket = None
    testnet_socket = None
    cache = {}

    @classmethod
    def get_socket(cls, testnet=False):
        if testnet:
            if cls.testnet_socket is None:
                cls.testnet_socket = cls.context.socket(zmq.REQ)
                cls.testnet_socket.connect(
                    'tcp://testnet.libbitcoin.net:19091')
            return cls.testnet_socket
        else:
            if cls.mainnet_socket is None:
                cls.mainnet_socket = cls.context.socket(zmq.REQ)
                cls.mainnet_socket.connect(
                    'tcp://mainnet.libbitcoin.net:9091')
            return cls.mainnet_socket


class Tx(LibBitcoinClient):

    default_version = 1
    default_hash_type = 1
    cache = {}
    p2pkh_prefixes = (b'\x00', b'\x6f')
    p2sh_prefixes = (b'\x05', b'\xc4')
    testnet_prefixes = (b'\x6f', b'\xc4')
    scale = 100000000
    num_bytes = 25
    fee = 2500
    insight = 'https://btc-bitcore6.trezor.io/api'
    seeds = None

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return '{}\nversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n'.format(
            self.hash().hex(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def hash(self):
        return double_sha256(self.serialize())[::-1]

    def id(self):
        return self.hash().hex()

    @classmethod
    def get_address_data(cls, addr):
        b58 = decode_base58(addr, num_bytes=cls.num_bytes)
        prefix = b58[:-20]
        h160 = b58[-20:]
        testnet = prefix in cls.testnet_prefixes
        if prefix in cls.p2pkh_prefixes:
            script_pubkey = Script.parse(p2pkh_script(h160))
        elif prefix in cls.p2sh_prefixes:
            script_pubkey = Script.parse(p2sh_script(h160))
        else:
            raise RuntimeError('unknown type of address {} {}'.format(addr, prefix))
        return {
            'testnet': testnet,
            'h160': h160,
            'script_pubkey': script_pubkey,
        }

    @classmethod
    def fetch_address_utxos(cls, address, at_block_height=None):
        # grab all unspent transaction outputs as of block block_height
        # if block_height is None, we include all utxos
        address_data = cls.get_address_data(address)
        serialized_script_pubkey = address_data['script_pubkey'].serialize()
        socket = cls.get_socket(address_data['testnet'])
        nonce = int_to_little_endian(random.randint(0, 2**32), 4)
        msg = b'blockchain.fetch_history3'
        socket.send(msg, zmq.SNDMORE)
        socket.send(nonce, zmq.SNDMORE)
        socket.send(address_data['h160'] + b'\x00\x00\x00\x00')
        response_msg = socket.recv()
        response_nonce = socket.recv()
        if response_msg != msg or response_nonce != nonce:
            raise RuntimeError('received wrong msg: {}'.format(
                response_msg.decode('ascii')))
        response = socket.recv()
        response_code = little_endian_to_int(response[:4])
        if response_code != 0:
            raise RuntimeError('got code from server: {}'.format(response_code))
        response = response[4:]
        receives = []
        spent = set()
        while len(response) > 0:
            kind = response[0]
            prev_tx = response[1:33]
            prev_index = response[33:37]
            block_height = little_endian_to_int(response[37:41])
            if kind == 0:
                value = little_endian_to_int(response[41:49])
                if at_block_height is None or block_height <= at_block_height:
                    receives.append([prev_tx, prev_index, value])
            else:
                if at_block_height is None or block_height <= at_block_height:
                    spent.add(little_endian_to_int(response[41:49]))
            response = response[49:]
        utxos = []
        tx_mask = 0xffffffffffff8000
        index_mask = 0x7fff
        for prev_tx, prev_index, value in receives:
            tx_upper_49_bits = (little_endian_to_int(prev_tx) >> 12*8) & tx_mask
            index_lower_15_bits = little_endian_to_int(prev_index) & index_mask
            key = tx_upper_49_bits | index_lower_15_bits
            if key not in spent:
                utxos.append([serialized_script_pubkey, prev_tx[::-1], little_endian_to_int(prev_index), value])
        return utxos

    @classmethod
    def get_all_utxos(cls, addrs):
        utxos = []
        for addr in addrs:
            # look up utxos for each address
            utxos.extend(cls.fetch_address_utxos(addr))
        return utxos

    @classmethod
    def spend_tx(cls, wifs, utxos, destination_addr, fee=540, segwit=False):
        destination_address_data = cls.get_address_data(destination_addr)
        testnet = destination_address_data['testnet']
        if testnet:
            prefix = cls.testnet_prefixes[0]
        else:
            prefix = cls.p2pkh_prefixes[0]
        tx_ins = []
        sequence = 0xffffffff
        priv_lookup = {}
        total = 0
        for wif in wifs:
            priv_key = PrivateKey.parse(wif)
            if segwit:
                addr = priv_key.point.segwit_address()
            else:
                addr = priv_key.point.address(priv_key.compressed, prefix=prefix)
            # look up utxos for each address
            address_data = cls.get_address_data(addr)
            script_pubkey = address_data['script_pubkey']
            spk = script_pubkey.serialize()
            priv_lookup[spk] = priv_key
        if not utxos:
            raise RuntimeError('fetch utxos first')
        for serialized_script_pubkey, prev_tx, prev_index, value in utxos:
            tx_ins.append(TxIn(prev_tx, prev_index, b'', sequence, value=value, script_pubkey=serialized_script_pubkey))
            total += value
        num_tx_ins = len(tx_ins)
        if num_tx_ins == 0:
            raise RuntimeError('nothing to spend')
        script_pubkey = destination_address_data['script_pubkey']
        tx_out = TxOut(total - fee, script_pubkey.serialize())
        tx = cls(cls.default_version, tx_ins, [tx_out], 0, testnet=testnet)
        for index, tx_in in enumerate(tx_ins):
            priv_key = priv_lookup[tx_in.script_pubkey().serialize()]
            if segwit:
                sec = priv_key.point.sec(True)
                redeem_script = Script([0, hash160(sec)]).serialize()
            else:
                redeem_script = None
            tx.sign_input(
                index,
                priv_key,
                cls.default_hash_type,
                compressed=priv_key.compressed,
                redeem_script=redeem_script,
            )
        if not tx.verify():
            raise RuntimeError('failed validation')
        return tx

    @classmethod
    def spend_all_tx(cls, private_keys, destination_addr, fee, segwit, utxos):
        destination_address_data = cls.get_address_data(destination_addr)
        testnet = destination_address_data['testnet']
        if testnet:
            if segwit:
                prefix = cls.p2sh_prefixes[1]
            else:
                prefix = cls.p2pkh_prefixes[1]
        else:
            if segwit:
                prefix = cls.p2sh_prefixes[0]
            else:
                prefix = cls.p2pkh_prefixes[0]
        tx_ins = []
        sequence = 0xffffffff
        priv_lookup = {}
        total = 0
        for private_key in private_keys:
            if segwit:
                addr = private_key.point.segwit_address(prefix=prefix)
            else:
                addr = private_key.point.address(private_key.compressed, prefix=prefix)
            address_data = cls.get_address_data(addr)
            script_pubkey = address_data['script_pubkey']
            priv_lookup[script_pubkey.serialize()] = private_key
        for serialized_script_pubkey, prev_tx, prev_index, value in utxos:
            private_key = priv_lookup[serialized_script_pubkey]
            if segwit:
                script_sig = private_key.segwit_redeem_script()
            else:
                script_sig = b''
            tx_in = TxIn(
                prev_tx,
                prev_index,
                script_sig,
                sequence,
                value=value,
                script_pubkey=serialized_script_pubkey,
            )
            tx_ins.append(tx_in)
            total += value
        num_tx_ins = len(tx_ins)
        if num_tx_ins == 0:
            return
        if total - fee < 0:
            return
        script_pubkey = destination_address_data['script_pubkey']
        print('{}: {} to {}'.format(cls, (total - fee) / cls.scale, destination_addr))
        tx_out = TxOut(total - fee, script_pubkey.serialize())
        tx = cls(cls.default_version, tx_ins, [tx_out], 0, testnet=testnet)
        for index, tx_in in enumerate(tx_ins):
            private_key = priv_lookup[tx_in.script_pubkey().serialize()]
            if segwit:
                sec = private_key.point.sec(True)
                redeem_script = Script([0, hash160(sec)]).serialize()
            else:
                redeem_script = None
            if not tx.sign_input(
                index,
                private_key,
                cls.default_hash_type,
                compressed=private_key.compressed,
                redeem_script=redeem_script,
            ):
                raise RuntimeError('sign and verify do different things')
        if not tx.verify():
            raise RuntimeError('failed validation')
        return tx

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # if we have a segwit marker, we need to parse in another way
        if num_inputs == 0:
            return cls.parse_segwit(s, version)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime)

    @classmethod
    def parse_segwit(cls, s, version):
        '''Takes a byte stream and parses the segwit transaction in middle
        return a Tx object
        '''
        marker = s.read(1)
        if marker != b'\x01':
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        tx_ins = []
        for _ in range(num_inputs):
            tx_ins.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        tx_outs = []
        for _ in range(num_outputs):
            tx_outs.append(TxOut.parse(s))
        # now parse the witness program
        for tx_in in tx_ins:
            num_elements = read_varint(s)
            elements = [num_elements]
            for _ in range(num_elements):
                element_len = read_varint(s)
                elements.append(s.read(element_len))
            tx_in.witness_program = Script(elements).serialize()
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, tx_ins, tx_outs, locktime)

    def is_segwit(self):
        for tx_in in self.tx_ins:
            if tx_in.is_segwit():
                return True
        return False

    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        if self.is_segwit():
            return self.serialize_segwit()
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize_segwit(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # segwit marker '0001'
        result += b'\x00\x01'
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # add the witness data
        for tx_in in self.tx_ins:
            result += tx_in.witness_program
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # iterate through inputs
        for tx_in in self.tx_ins:
            # for each input get the value and add to input sum
            input_sum += tx_in.value()
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = double_sha256(all_prevouts)
            self._hash_sequence = double_sha256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = double_sha256(all_outputs)
        return self._hash_outputs

    def sig_hash_preimage_bip143(self, input_index, hash_type, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if tx_in.is_segwit() or redeem_script:
            if redeem_script:
                h160 = redeem_script[-20:]
            else:
                h160 = tx_in.redeem_script()[-20:]
            ser = p2pkh_script(h160)
        else:
            ser = tx_in.script_pubkey().serialize()
        s += bytes([len(ser)]) + ser  # script pubkey
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(hash_type, 4)
        return s

    def sig_hash_bip143(self, input_index, hash_type, redeem_script=None):
        s = self.sig_hash_preimage_bip143(input_index, hash_type, redeem_script=redeem_script)
        return int.from_bytes(double_sha256(s), 'big')

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
                value=tx_in.value(),
                script_pubkey=tx_in.script_pubkey().serialize(),
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        script_pubkey = signing_input.script_pubkey(self.testnet)
        sig_type = script_pubkey.type()
        if sig_type == 'p2pkh':
            signing_input.script_sig = script_pubkey
        elif sig_type == 'p2sh':
            current_input = self.tx_ins[input_index]
            signing_input.script_sig = Script.parse(
                current_input.redeem_script())
        else:
            raise RuntimeError('not a valid sig_type: {}'.format(sig_type))
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime,
        )
        # add the hash_type
        result = alt_tx.serialize()
        result += int_to_little_endian(hash_type, 4)
        return int.from_bytes(double_sha256(result), 'big')

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # get the number of signatures required. This is available in tx_in.script_sig.num_sigs_required()
        sigs_required = tx_in.script_sig.num_sigs_required()
        # iterate over the sigs required and check each signature
        for sig_num in range(sigs_required):
            # get the point from the sec format
            sec = tx_in.sec_pubkey(index=sig_num)
            # get the sec_pubkey at current signature index
            point = S256Point.parse(sec)
            # get the der sig and hash_type from input
            # get the der_signature at current signature index
            der, hash_type = tx_in.der_signature(index=sig_num)
            # get the signature from der format
            signature = Signature.parse(der)
            # get the hash to sign
            if tx_in.is_segwit():
                h160 = hash160(tx_in.script_sig.redeem_script())
                if h160 != tx_in.script_pubkey(self.testnet).elements[1]:
                    return False
                pubkey_h160 = tx_in.script_sig.redeem_script()[-20:]
                if pubkey_h160 != point.h160():
                    return False
                z = self.sig_hash_bip143(input_index, hash_type)
            else:
                z = self.sig_hash(input_index, hash_type)
            # use point.verify on the hash to sign and signature
            if not point.verify(z, signature):
                return False
        return True

    def sign_input(self, input_index, private_key, hash_type, compressed=True, redeem_script=None):
        '''Signs the input using the private key'''
        # get the hash to sign
        tx_in = self.tx_ins[input_index]
        if redeem_script:
            z = self.sig_hash_bip143(input_index, hash_type, redeem_script=redeem_script)
        else:
            z = self.sig_hash(input_index, hash_type)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use bytes([hash_type]))
        sig = der + bytes([hash_type])
        # calculate the sec
        sec = private_key.point.sec(compressed=compressed)
        if redeem_script:
            # witness program 0
            tx_in.script_sig = Script([redeem_script])
            tx_in.witness_program = Script([2, sig, sec]).serialize()
        else:
            # initialize a new script with [sig, sec] as the elements
            # change input's script_sig to new script
            tx_in.script_sig = Script([sig, sec])
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def is_coinbase(self):
        '''Returns whether this transaction is a coinbase transaction or not'''
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        first_input = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if first_input.prev_tx != b'\x00' * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        '''Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        '''
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first input
        first_input = self.tx_ins[0]
        # grab the first element of the script_sig (.script_sig.elements[0])
        first_element = first_input.script_sig.elements[0]
        # convert the first element from little endian to int
        return little_endian_to_int(first_element)

    def verify(self):
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign(self, private_key, compressed=True):
        for i in range(len(self.tx_ins)):
            if not self.sign_input(
                    i,
                    private_key,
                    self.default_hash_type,
                    compressed=compressed,
            ):
                raise RuntimeError('signing failed')

    def send_insight(self):
        if self.insight is None:
            return
        url = '{}/tx/send'.format(self.insight)
        data = dumps({'rawtx': self.serialize().hex()})
        r = requests.post(url, data=data, headers={'Content-Type': 'application/json'})
        return r.text



class BTXTx(Tx):
    fork_block = 492820
    default_version = 2
    fee = 200000
    magic = b'\xf9\xbe\xb4\xd9'
    port = 8555
    seeds = ("37.120.190.76", "37.120.186.85", "185.194.140.60", "188.71.223.206", "185.194.142.122")
    insight = None

    @classmethod
    def fetch_address_utxos(cls, address):
        api_key = 'e86ce04b6888'
        url = 'https://chainz.cryptoid.info/btx/api.dws?q=unspent&active={}&key={}'.format(
            address, api_key)
        result = requests.get(url).json()
        address_data = cls.get_address_data(address)
        serialized_script_pubkey = address_data['script_pubkey'].serialize()
        print(result)
        utxos = []
        for item in result['unspent_outputs']:
            utxos.append([serialized_script_pubkey, bytes.fromhex(item['tx_hash']), item['tx_ouput_n'], int(item['value'])])
        return utxos


class ForkTx(Tx):
    fork_block = 0

    @classmethod
    def fetch_address_utxos(cls, address):
        return super().fetch_address_utxos(address, at_block_height=cls.fork_block)


class BTCPTx(Tx):
    default_hash_type = 0x41
    fork_id = 42 << 8
    p2pkh_prefixes = (b'\x13\x25',)
    p2sh_prefixes = (b'\x13\xaf',)
    num_bytes = 26
    fee = 20000
    insight = 'https://explorer.btcprivate.org/api'

    @classmethod
    def fetch_address_utxos(cls, address):
        url = 'https://explorer.btcprivate.org/api/addr/{}/utxo'.format(
            address)
        result = requests.get(url).json()
        address_data = cls.get_address_data(address)
        serialized_script_pubkey = address_data['script_pubkey'].serialize()
        utxos = []
        for item in result:
            utxos.append([serialized_script_pubkey, bytes.fromhex(item['txid']), item['vout'], int(item['satoshis'])])
        return utxos
        

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
                value=tx_in.value(),
                script_pubkey=tx_in.script_pubkey().serialize(),
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        signing_input.script_sig = signing_input.script_pubkey(self.testnet)
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime,
        )
        # add the hash_type
        result = alt_tx.serialize()
        result += int_to_little_endian(hash_type | self.fork_id, 4)
        return int.from_bytes(double_sha256(result), 'big')

    def sign_input(self, input_index, private_key, hash_type, compressed=True, redeem_script=None):
        '''Signs the input using the private key'''
        # get the hash to sign
        tx_in = self.tx_ins[input_index]
        if redeem_script:
            h160 = Script.parse(redeem_script).elements[1]
            tx_in._script_pubkey = Script.parse(p2pkh_script(h160))
        z = self.sig_hash(input_index, hash_type)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use bytes([hash_type]))
        sig = der + bytes([hash_type])
        # calculate the sec
        sec = private_key.point.sec(compressed=compressed)
        if redeem_script:
            tx_in.script_sig = Script([sig, sec, redeem_script])
        else:
            tx_in.script_sig = Script([sig, sec])
        return self.verify_input(input_index)


class B2XTx(ForkTx):
    fork_block = 501451
    fork_id = 0
    default_hash_type = 0x31
    fee = 20000
    magic = b'\xf4\xb2\xb5\xd8'
    port = 8333
    seeds = ("node1.b2x-segwit.io", "node2.b2x-segwit.io", "node3.b2x-segwit.io")
    insight = None

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
                value=tx_in.value(),
                script_pubkey=tx_in.script_pubkey().serialize(),
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        script_pubkey = signing_input.script_pubkey(self.testnet)
        sig_type = script_pubkey.type()
        if sig_type == 'p2pkh':
            signing_input.script_sig = script_pubkey
        elif sig_type == 'p2sh':
            current_input = self.tx_ins[input_index]
            signing_input.script_sig = Script.parse(
                current_input.redeem_script())
        else:
            raise RuntimeError('not a valid sig_type: {}'.format(sig_type))
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime,
        )
        # add the hash_type
        result = alt_tx.serialize()
        result += int_to_little_endian(hash_type << 1, 4)
        return int.from_bytes(double_sha256(result), 'big')

    def sig_hash_preimage_bip143(self, input_index, hash_type, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if tx_in.is_segwit() or redeem_script:
            if redeem_script:
                h160 = redeem_script[-20:]
            else:
                h160 = tx_in.redeem_script()[-20:]
            ser = p2pkh_script(h160)
        else:
            ser = tx_in.script_pubkey().serialize()
        s += bytes([len(ser)]) + ser  # script pubkey
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(hash_type << 1, 4)
        return s
    

class LBTCTx(ForkTx):
    fork_block = 499999
    fork_id = 0
    magic = b'\xf9\xbe\xb3\xd7'
    port = 9333
    seeds = ("seed9.lbtc.io", "seed8.lbtc.io", "seed10.lbtc.io")
    default_version = 0xff01
    fee = 200000
    insight = None


class BCHTx(ForkTx):
    fork_block = 478558
    fork_id = 0
    default_hash_type = 0x41
    insight = 'https://bch-bitcore2.trezor.io/api'
    fee = 540

    def sig_hash_preimage_bip143(self, input_index, hash_type, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if tx_in.is_segwit() or redeem_script:
            if redeem_script:
                h160 = redeem_script[-20:]
            else:
                h160 = tx_in.redeem_script()[-20:]
            ser = p2pkh_script(h160)
        else:
            ser = tx_in.script_pubkey().serialize()
        s += bytes([len(ser)]) + ser  # script pubkey
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(hash_type | self.fork_id, 4)
        return s

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # get the sec_pubkey at current signature index
        point = S256Point.parse(tx_in.sec_pubkey())
        # get the der sig and hash_type from input
        # get the der_signature at current signature index
        der, hash_type = tx_in.der_signature()
        # get the signature from der format
        signature = Signature.parse(der)
        # get the hash to sign
        z = self.sig_hash_bip143(input_index, hash_type)
        # use point.verify on the hash to sign and signature
        if not point.verify(z, signature):
            return False
        return True

    def sign_input(self, input_index, private_key, hash_type, compressed=True, redeem_script=None):
        '''Signs the input using the private key'''
        # get the hash to sign
        z = self.sig_hash_bip143(input_index, hash_type)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use bytes([hash_type]))
        sig = der + bytes([hash_type])
        # calculate the sec
        sec = private_key.point.sec(compressed=compressed)
        # initialize a new script with [sig, sec] as the elements
        script_sig = Script([sig, sec])
        # change input's script_sig to new script
        self.tx_ins[input_index].script_sig = script_sig
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign(self, private_key, compressed=True):
        hash_type = self.default_hash_type
        for i in range(len(self.tx_ins)):
            if not self.sign_input(
                    i, private_key, hash_type, compressed=compressed):
                raise RuntimeError('signing failed')


class BTGTx(BCHTx):
    fork_block = 491407
    fork_id = 79 << 8
    p2pkh_prefixes = (b'\x26', b'\x6f', b'\x00')
    p2sh_prefixes = (b'\x17', b'\xc4', b'\x05')
    insight = 'https://btg-bitcore2.trezor.io/api'
    fee = 5000

    def sign_input(self, input_index, private_key, hash_type, compressed=True, redeem_script=None):
        '''Signs the input using the private key'''
        # get the hash to sign
        z = self.sig_hash_bip143(input_index, hash_type, redeem_script=redeem_script)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use bytes([hash_type]))
        sig = der + bytes([hash_type])
        # calculate the sec
        sec = private_key.point.sec(compressed=compressed)
        tx_in = self.tx_ins[input_index]
        if redeem_script:
            tx_in.script_sig = Script([redeem_script])
            tx_in.witness_program = Script([2, sig, sec]).serialize()
        else:
            # initialize a new script with [sig, sec] as the elements
            script_sig = Script([sig, sec])
            # change input's script_sig to new script
            tx_in.script_sig = script_sig
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)


class BCITx(BTGTx):
    fork_block = 505083
    fork_id = 79 << 8
    default_hash_type = 0x41
    p2pkh_prefixes = (b'\x66',)
    p2sh_prefixes = (b'\x17',)
    insight = 'https://explorer.bitcoininterest.io/api'
    magic = b'\xed\xe4\xfe\x26'
    port = 8331
    seeds = ("74.208.166.57", "216.250.117.221")
    fee = 20000

class BTPTx(BTGTx):
    fork_block = 499345
    fork_id = 80 << 8
    default_hash_type = 0x41
    p2pkh_prefixes = (b'\x38',)
    p2sh_prefixes = (b'\x05',)
    insight = 'http://exp.btceasypay.com/insight-api'
    fee = 20000
    scale = 10000000

    
class BTVTx(BTGTx):
    fork_block = 505050
    fork_id = 50 << 8
    default_hash_type = 0x41
    fee = 20000
    magic = b'\xf9\x50\x50\x50'
    port = 8333
    seeds = ("seed1.bitvote.one", "seed2.bitvote.one", "seed3.bitvote.one")
    insight = 'https://block.bitvote.one/insight-api'

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
                value=tx_in.value(),
                script_pubkey=tx_in.script_pubkey().serialize(),
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        script_pubkey = signing_input.script_pubkey(self.testnet)
        sig_type = script_pubkey.type()
        if sig_type == 'p2pkh':
            signing_input.script_sig = script_pubkey
        elif sig_type == 'p2sh':
            current_input = self.tx_ins[input_index]
            signing_input.script_sig = Script.parse(
                current_input.redeem_script())
        else:
            raise RuntimeError('not a valid sig_type: {}'.format(sig_type))
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime,
        )
        # add the hash_type
        result = alt_tx.serialize()
        result += int_to_little_endian(hash_type | self.fork_id, 4)
        return int.from_bytes(double_sha256(result), 'big')

    def sign_input(self, input_index, private_key, hash_type, compressed=True, redeem_script=None):
        '''Signs the input using the private key'''
        # get the hash to sign
        tx_in = self.tx_ins[input_index]
        if redeem_script:
            z = self.sig_hash_bip143(input_index, hash_type, redeem_script=redeem_script)
        else:
            z = self.sig_hash(input_index, hash_type)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use bytes([hash_type]))
        sig = der + bytes([hash_type])
        # calculate the sec
        sec = private_key.point.sec(compressed=compressed)
        if redeem_script:
            # witness program 0
            tx_in.script_sig = Script([redeem_script])
            tx_in.witness_program = Script([2, sig, sec]).serialize()
        else:
            # initialize a new script with [sig, sec] as the elements
            # change input's script_sig to new script
            tx_in.script_sig = Script([sig, sec])
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # get the number of signatures required. This is available in tx_in.script_sig.num_sigs_required()
        sigs_required = tx_in.script_sig.num_sigs_required()
        # iterate over the sigs required and check each signature
        for sig_num in range(sigs_required):
            # get the point from the sec format
            sec = tx_in.sec_pubkey(index=sig_num)
            # get the sec_pubkey at current signature index
            point = S256Point.parse(sec)
            # get the der sig and hash_type from input
            # get the der_signature at current signature index
            der, hash_type = tx_in.der_signature(index=sig_num)
            # get the signature from der format
            signature = Signature.parse(der)
            # get the hash to sign
            if tx_in.is_segwit():
                h160 = hash160(tx_in.script_sig.redeem_script())
                if h160 != tx_in.script_pubkey(self.testnet).elements[1]:
                    return False
                pubkey_h160 = tx_in.script_sig.redeem_script()[-20:]
                if pubkey_h160 != point.h160():
                    return False
                z = self.sig_hash_bip143(input_index, hash_type)
            else:
                z = self.sig_hash(input_index, hash_type)
            # use point.verify on the hash to sign and signature
            if not point.verify(z, signature):
                return False
        return True


class BCA(BTGTx):
    fork_block = 505888
    fork_id = 93 << 8
    default_hash_type = 0x41
    fee = 20000
    magic = b'\x4f\xc1\x1d\xe8'
    port = 7333
    seeds = ("seed.bitcoinatom.io", "seed.bitcoin-atom.org", "seed.bitcoinatom.net")
    insight = None

    
class BCXTx(BTGTx):
    fork_block = 498888
    default_version = 2
    default_hash_type = 0x11
    fork_id = 0
    p2pkh_prefixes = (b'\x4b', b'\x41', b'\x00')
    p2sh_prefixes = (b'\x3f', b'\xc4', b'\x05')
    scale = 10000
    magic = b'\x11\x05\xbc\xf9'
    port = 9003
    seeds = ("192.169.227.48", "120.92.119.221", "120.92.89.254", "120.131.5.173", "120.92.117.145", "192.169.153.174", "192.169.154.185", "166.227.117.163")
    fee = 200000
    insight = None


class BTFTx(BTGTx):
    fork_block = 500000
    fork_id = 70 << 8
    p2pkh_prefixes = (b'\x24', b'\x60')
    p2sh_prefixes = (b'\x28', b'\x65')
    fee = 200000
    magic = b'\xfa\xe2\xd4\xe6'
    port = 8346
    seeds = ("a.btf.hjy.cc", "b.btf.hjy.cc", "c.btf.hjy.cc", "d.btf.hjy.cc", "e.btf.hjy.cc", "f.btf.hjy.cc")
    insight = None


class BTWTx(BTGTx):
    fork_block = 499777
    fork_id = 87 << 8
    p2pkh_prefixes = (b'\x49', b'\x87')
    p2sh_prefixes = (b'\x1f', b'\x59')
    scale = 10000
    fee = 200000
    magic = b'\xf8\x62\x74\x77'
    port = 8357
    seeds = ("47.52.250.221", "47.91.237.5")
    insight = None


class BCDTx(ForkTx):
    fork_block = 495866
    default_version = 12
    default_block_hash = bytes.fromhex('c51159637a85160ed5c726fb0df68e14352b495e4c57444d4d427bbc68db0551')
    scale = 10000000
    fee = 20000
    magic = b'\xbd\xde\xb4\xd9'
    port = 7117
    seeds = ("seed1.dns.btcd.io", "seed2.dns.btcd.io", "seed3.dns.btcd.io", "seed4.dns.btcd.io", "seed5.dns.btcd.io", "seed6.dns.btcd.io")
    insight = None

    def __init__(self, version, tx_ins, tx_outs, locktime, prev_block_hash=None, testnet=False):
        super().__init__(version, tx_ins, tx_outs, locktime, testnet=False)
        if prev_block_hash is None:
            self.prev_block_hash = self.default_block_hash
        else:
            self.prev_block_hash = prev_block_hash

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        prev_block_hash = s.read(32)[::-1]
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, prev_block_hash=prev_block_hash)

    def serialize_segwit(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # previous block hash
        result += self.prev_block_hash[::-1]
        # segwit marker '0001'
        result += b'\x00\x01'
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # add the witness data
        for tx_in in self.tx_ins:
            result += tx_in.witness_program
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        if self.is_segwit():
            return self.serialize_segwit()
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # previous block hash
        result += self.prev_block_hash[::-1]
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def sig_hash_preimage_bip143(self, input_index, hash_type, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.prev_block_hash[::-1]
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if tx_in.is_segwit() or redeem_script:
            if redeem_script:
                h160 = redeem_script[-20:]
            else:
                h160 = tx_in.redeem_script()[-20:]
            ser = p2pkh_script(h160)
        else:
            ser = tx_in.script_pubkey().serialize()
        s += bytes([len(ser)]) + ser  # script pubkey
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(hash_type, 4)
        return s

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
                value=tx_in.value(),
                script_pubkey=tx_in.script_pubkey().serialize(),
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        script_pubkey = signing_input.script_pubkey(self.testnet)
        sig_type = script_pubkey.type()
        if sig_type == 'p2pkh':
            signing_input.script_sig = script_pubkey
        elif sig_type == 'p2sh':
            current_input = self.tx_ins[input_index]
            signing_input.script_sig = Script.parse(
                current_input.redeem_script())
        else:
            raise RuntimeError('no valid sig_type')
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime,
            prev_block_hash=self.prev_block_hash,
        )
        # add the hash_type
        result = alt_tx.serialize()
        result += int_to_little_endian(hash_type, 4)
        return int.from_bytes(double_sha256(result), 'big')


class SBTCTx(ForkTx):
    fork_block = 498888
    default_version = 2
    default_hash_type = 0x41
    sighash_append = b'\x04sbtc'
    fee = 20000
    magic = b'\xf9\xbe\xb4\xd9'
    port = 8334
    seeds = ("seed.superbtca.com", "seed.superbtca.info", "seed.superbtc.org")
    insight = None

    def sig_hash_preimage_bip143(self, input_index, hash_type, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if tx_in.is_segwit() or redeem_script:
            if redeem_script:
                h160 = redeem_script[-20:]
            else:
                h160 = tx_in.redeem_script()[-20:]
            ser = p2pkh_script(h160)
        else:
            ser = tx_in.script_pubkey().serialize()
        s += bytes([len(ser)]) + ser  # script pubkey
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(hash_type, 4)
        s += self.sighash_append
        return s

    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a transaction serialization where
        # all the input script_sigs are blanked out
        alt_tx_ins = []
        for tx_in in self.tx_ins:
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
                value=tx_in.value(),
                script_pubkey=tx_in.script_pubkey().serialize(),
            ))
        # replace the input's scriptSig with the scriptPubKey
        signing_input = alt_tx_ins[input_index]
        script_pubkey = signing_input.script_pubkey(self.testnet)
        sig_type = script_pubkey.type()
        if sig_type == 'p2pkh':
            signing_input.script_sig = script_pubkey
        elif sig_type == 'p2sh':
            current_input = self.tx_ins[input_index]
            signing_input.script_sig = Script.parse(
                current_input.redeem_script())
        else:
            raise RuntimeError('no valid sig_type')
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime,
        )
        # add the hash_type
        result = alt_tx.serialize()
        result += int_to_little_endian(hash_type, 4)
        result += self.sighash_append
        return int.from_bytes(double_sha256(result), 'big')

    def sign(self, private_key, compressed=True):
        hash_type = 0x40 | SIGHASH_ALL
        for i in range(len(self.tx_ins)):
            if not self.sign_input(i, private_key, hash_type, compressed=compressed):
                raise RuntimeError('signing failed')


class TxIn(LibBitcoinClient):

    def __init__(self, prev_tx, prev_index, script_sig, sequence, witness_program=b'\x00', value=None, script_pubkey=None):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.script_sig = Script.parse(script_sig)
        self.sequence = sequence
        self.witness_program = witness_program
        self._value = value
        if script_pubkey is None:
            self._script_pubkey = None
        else:
            self._script_pubkey = Script.parse(script_pubkey)

    def __repr__(self):
        return '{}:{}'.format(self.prev_tx.hex(), self.prev_index)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # s.read(n) will return n bytes
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpret as int
        prev_index = little_endian_to_int(s.read(4))
        # script_sig is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_sig_length = read_varint(s)
        script_sig = s.read(script_sig_length)
        # sequence is 4 bytes, little-endian, interpret as int
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # get the scriptSig ready (use self.script_sig.serialize())
        raw_script_sig = self.script_sig.serialize()
        # encode_varint on the length of the scriptSig
        result += encode_varint(len(raw_script_sig))
        # add the scriptSig
        result += raw_script_sig
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        if self.prev_tx not in self.cache:
            socket = self.get_socket(testnet=testnet)
            nonce = int_to_little_endian(random.randint(0, 2**32), 4)
            msg = b'blockchain.fetch_transaction2'
            socket.send(msg, zmq.SNDMORE)
            socket.send(nonce, zmq.SNDMORE)
            socket.send(self.prev_tx[::-1])
            response_msg = socket.recv()
            response_nonce = socket.recv()
            if response_msg != msg or response_nonce != nonce:
                raise RuntimeError('received wrong msg: {}'.format(
                    response_msg.decode('ascii')))
            response_tx = socket.recv()
            response_code = little_endian_to_int(response_tx[:4])
            if response_code != 0:
                raise RuntimeError('got code from server: {}'.format(response_code))
            stream = BytesIO(response_tx[4:])
            self.cache[self.prev_tx] = Tx.parse(stream)
        return self.cache[self.prev_tx]

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash on libbitcoin server
        Returns the amount in satoshi
        '''
        if self._value is None:
            # use self.fetch_tx to get the transaction
            tx = self.fetch_tx(testnet=testnet)
            # get the output at self.prev_index
            # get the amount property
            self._value = tx.tx_outs[self.prev_index].amount
        return self._value

    def script_pubkey(self, testnet=False):
        '''Get the scriptPubKey by looking up the tx hash on libbitcoin server
        Returns the binary scriptpubkey
        '''
        if self._script_pubkey is None:
            # use self.fetch_tx to get the transaction
            tx = self.fetch_tx(testnet=testnet)
            # get the output at self.prev_index
            # get the script_pubkey property
            self._script_pubkey = tx.tx_outs[self.prev_index].script_pubkey
        return self._script_pubkey

    def der_signature(self, index=0):
        '''returns a DER format signature and hash_type if the script_sig
        has a signature'''
        if self.is_segwit():
            signature = self.witness_program[2:-34]
        else:
            signature = self.script_sig.der_signature(index=index)
        # last byte is the hash_type, rest is the signature
        return signature[:-1], signature[-1]

    def sec_pubkey(self, index=0):
        '''returns the SEC format public if the script_sig has one'''
        if self.is_segwit():
            return self.witness_program[-33:]
        else:
            return self.script_sig.sec_pubkey(index=index)

    def redeem_script(self):
        '''return the Redeem Script if there is one'''
        return self.script_sig.redeem_script()

    def is_segwit(self):
        if self.script_sig.type() != 'p2sh sig':
            return False
        redeem_script_raw = self.script_sig.redeem_script()
        if not redeem_script_raw:
            return False
        redeem_script = Script.parse(redeem_script_raw)
        return redeem_script.elements[0] == 0 and \
            type(redeem_script.elements[1]) == bytes and \
            len(redeem_script.elements[1]) == 20


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = Script.parse(script_pubkey)

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey.address())

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # get the length by using read_varint(s)
        script_pubkey_length = read_varint(s)
        script_pubkey = s.read(script_pubkey_length)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # get the scriptPubkey ready (use self.script_pubkey.serialize())
        raw_script_pubkey = self.script_pubkey.serialize()
        # encode_varint on the length of the scriptPubkey
        result += encode_varint(len(raw_script_pubkey))
        # add the scriptPubKey
        result += raw_script_pubkey
        return result
