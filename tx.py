from io import BytesIO
from unittest import TestCase

import json
import requests

from ecc import PrivateKey
from helper import (
    decode_base58,
    double_sha256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    SIGHASH_ALL,
)
from script import p2pkh_script, Script


class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://tbtc.programmingblockchain.com:18332'
        else:
            return 'http://btc.programmingblockchain.com:8332'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/rest/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise RuntimeError(response.text)
            # make sure the tx we got matches to the hash we requested
            computed = double_sha256(raw)[::-1].hex()
            if computed != tx_id:
                raise RuntimeError('server lied: {} vs {}'.format(computed, tx_id))
            cls.cache[tx_id] = Tx.parse(BytesIO(raw), testnet=testnet)
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            cls.cache[k] = Tx.parse(BytesIO(bytes.fromhex(raw_hex)))

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)


class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None
        self.bip65 = True
        self.bip112 = True

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()

    def hash(self):
        '''Binary hash of the legacy serialization'''
        return double_sha256(self.serialize_legacy())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        '''Parses a transaction from stream'''
        # we can determine whether something is segwit or legacy by looking
        # at byte 5
        s.read(4)
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        # reset the seek to the beginning so everything can go through
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s, testnet=False):
        '''Takes a byte stream and parses a legacy transaction'''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
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
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=False)

    @classmethod
    def parse_segwit(cls, s, testnet=False):
        '''Takes a byte stream and parses a segwit transaction'''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # next two bytes need to be 0x00 and 0x01
        marker = s.read(2)
        if marker != b'\x00\x01':
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
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
        # now parse the witness program
        for tx_in in inputs:
            num_items = read_varint(s)
            items = []
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
            tx_in.witness_program = items
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=True)

    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def serialize_legacy(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of outputs
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
            result += int_to_little_endian(len(tx_in.witness_program), 1)
            for item in tx_in.witness_program:
                if type(item) == int:
                    result += int_to_little_endian(item, 1)
                else:
                    result += encode_varint(len(item)) + item
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
            input_sum += tx_in.value(self.testnet)
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def sig_hash(self, input_index, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a new set of tx_ins (alt_tx_ins)
        alt_tx_ins = []
        # iterate over self.tx_ins
        for tx_in in self.tx_ins:
            # create a new TxIn that has no script_sig and add to alt_tx_ins
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                sequence=tx_in.sequence,
            ))
        # grab the input at the input_index
        signing_input = alt_tx_ins[input_index]
        # p2sh would require a redeem_script
        if redeem_script:
            # p2sh replaces the script_sig with the redeem_script
            signing_input.script_sig = redeem_script
        else:
            # the script_sig of the signing_input should be script_pubkey
            signing_input.script_sig = signing_input.script_pubkey(self.testnet)
        # create an alternate transaction with the modified tx_ins
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime)
        # add the hash_type int 4 bytes, little endian
        result = alt_tx.serialize() + int_to_little_endian(SIGHASH_ALL, 4)
        # get the double_sha256 of the tx serialization
        s256 = double_sha256(result)
        # convert this to a big-endian integer using int.from_bytes(x, 'big')
        return int.from_bytes(s256, 'big')

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

    def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.items[1]).serialize()
        else:
            script_code = p2pkh_script(tx_in.script_pubkey(self.testnet).items[1]).serialize()
        s += script_code
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(double_sha256(s), 'big')

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        # check to see if the script_pubkey is a p2sh
        if script_pubkey.is_p2sh_script_pubkey():
            # the last element has to be the redeem script to trigger
            item = tx_in.script_sig.items[-1]
            raw_redeem = int_to_little_endian(len(item), 1) + item
            redeem_script = Script.parse(BytesIO(raw_redeem))
            if redeem_script.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index, redeem_script)
                witness = tx_in.witness_program
            elif redeem_script.is_p2wsh_script_pubkey():
                item = tx_in.witness_program[-1]
                raw_witness = encode_varint(len(item)) + item
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness_program
            else:
                z = self.sig_hash(input_index, redeem_script)
                witness = None
        else:
            if script_pubkey.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index)
                witness = tx_in.witness_program
            elif script_pubkey.is_p2wsh_script_pubkey():
                item = tx_in.witness_program[-1]
                raw_witness = encode_varint(len(item)) + item
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness_program
            else:
                z = self.sig_hash(input_index)
                witness = None
        # combine the current script_sig and the previous script_pubkey
        script = tx_in.script_sig + script_pubkey
        # now evaluate this script and see if it passes
        return script.evaluate(
            z, self.version, self.locktime, tx_in.sequence, witness,
            bip65=self.bip65, bip112=self.bip112,
        )

    def verify(self):
        '''Verify every input of this transaction'''
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                print('failed at input {}'.format(i))
                return False
        return True

    def sign_input_p2pkh(self, input_index, private_key):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash(input_index)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # calculate the sec
        sec = private_key.point.sec()
        # change input's script_sig to a new script with [sig, sec] as the items
        self.tx_ins[input_index].script_sig = Script([sig, sec])
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2sh_multisig(self, input_index, private_keys, redeem_script):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash(input_index, redeem_script=redeem_script)
        # initialize the script_sig items with a 0 (OP_CHECKMULTISIG bug)
        items = [0]
        for private_key in private_keys:
            # get der signature of z from private key
            der = private_key.sign(z).der()
            # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
            sig = der + SIGHASH_ALL.to_bytes(1, 'big')
            # add the signature to the items
            items.append(sig)
        # finally, add the redeem script to the items array
        items.append(redeem_script.raw_serialize())
        # change input's script_sig to the Script consisting of the items array
        self.tx_ins[input_index].script_sig = Script(items)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2wpkh(self, input_index, private_key):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index)
        # calculate the signature
        der = private_key.sign(z).der()
        # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # get the sec
        sec = private_key.point.sec()
        # get the input
        tx_in = self.tx_ins[input_index]
        tx_in.witness_program = [sig, sec]
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2sh_p2wpkh(self, input_index, private_key):
        '''Signs the input using the private key'''
        redeem_script = Script([0, private_key.point.hash160()])
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, redeem_script=redeem_script)
        # calculate the signature
        der = private_key.sign(z).der()
        # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # get the sec
        sec = private_key.point.sec()
        # finally get the redeem script
        redeem = redeem_script.raw_serialize()
        # get the input
        tx_in = self.tx_ins[input_index]
        # change input's script_sig to the Script consisting of the redeem script
        tx_in.script_sig = Script([redeem])
        tx_in.witness_program = [sig, sec]
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2wsh_multisig(self, input_index, private_keys, witness_script):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, witness_script=witness_script)
        # initialize the witness items with a 0 (OP_CHECKMULTISIG bug)
        items = [0]
        for private_key in private_keys:
            # get der signature of z from private key
            der = private_key.sign(z).der()
            # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
            sig = der + SIGHASH_ALL.to_bytes(1, 'big')
            # add the signature to the items
            items.append(sig)
        # finally, add the witness script to the items array
        items.append(witness_script.raw_serialize())
        # change input's script_sig to the Script consisting of the items array
        self.tx_ins[input_index].witness_program = items
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2sh_p2wsh_multisig(self, input_index, private_keys, witness_script):
        '''Signs the input using the private key'''
        tx_in = self.tx_ins[input_index]
        # the redeem_script is the only element in the script_sig
        redeem_script = Script([0, witness_script.sha256()])
        redeem = redeem_script.raw_serialize()
        tx_in.script_sig = Script([redeem])
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, witness_script=witness_script)
        # initialize the witness items with a 0 (OP_CHECKMULTISIG bug)
        items = [0]
        for private_key in private_keys:
            # get der signature of z from private key
            der = private_key.sign(z).der()
            # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
            sig = der + SIGHASH_ALL.to_bytes(1, 'big')
            # add the signature to the items
            items.append(sig)
        # finally, add the witness script to the items array
        items.append(witness_script.raw_serialize())
        # change input's script_sig to the Script consisting of the items array
        tx_in.witness_program = items
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
        # grab the first input's script_sig
        script_sig = self.tx_ins[0].script_sig
        # get the first byte of the scriptsig, which is the length
        length = script_sig.coinbase[0]
        # get the next length bytes
        item = script_sig.coinbase[1:1 + length]
        # convert the first element from little endian to int
        return little_endian_to_int(item)


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script([])
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

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
        # you can use Script.parse to get the actual script
        coinbase_mode = prev_tx == b'\x00' * 32 and prev_index == 0xffffffff
        script_sig = Script.parse(s, coinbase_mode)
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
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the amount property
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        '''Get the scriptPubKey by looking up the tx hash
        Returns a Script object
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the script_pubkey property
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        script_pubkey = Script.parse(s)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


class TxTest(TestCase):
    cache_file = 'tx.cache'

    @classmethod
    def setUpClass(cls):
        # fill with cache so we don't have to be online to run these tests
        TxFetcher.load_cache(cls.cache_file)

    @classmethod
    def tearDownClass(cls):
        # write the cache to disk
        TxFetcher.dump_cache(cls.cache_file)

    def test_parse_version(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(len(tx.tx_ins), 1)
        want = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        self.assertEqual(tx.tx_ins[0].prev_tx.hex(), want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = '6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'
        self.assertEqual(tx.tx_ins[0].script_sig.serialize().hex(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xfffffffe)

    def test_parse_outputs(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = '1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac'
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize().hex(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = '1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac'
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize().hex(), want)

    def test_parse_locktime(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.locktime, 410393)

    def test_parse(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2b69d614f5f69bab704552e66eeaf720d07294ebe80ba37181a5df8c7fdaecac910878060b0a85543de9b224ffffffff0100f2052a01000000232102f3cedb3c71052860e6329e4fd7b1ad51220a21111f2bf4fec3691e6f52664a75ac00000000'
        tx = Tx.parse(BytesIO(bytes.fromhex(raw_tx)))
        self.assertEqual(tx.version, 1)

    def test_serialize(self):
        raw_tx = '0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600'
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.serialize().hex(), raw_tx)

    def test_input_value(self):
        tx_id = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        want = 42505594
        tx_in = TxIn(bytes.fromhex(tx_id), index)
        self.assertEqual(tx_in.value(), want)

    def test_input_pubkey(self):
        tx_id = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        tx_in = TxIn(bytes.fromhex(tx_id), index)
        want = '1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac'
        self.assertEqual(tx_in.script_pubkey().serialize().hex(), want)

    def test_fee(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.fee(), 40000)
        tx = TxFetcher.fetch('ee51510d7bbabe28052038d1deb10c03ec74f06a79e21913c6fcf48d56217c87')
        self.assertEqual(tx.fee(), 140500)

    def test_sig_hash(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        want = int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16)
        self.assertEqual(tx.sig_hash(0), want)

    def test_verify_input_p2pkh(self):
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertTrue(tx.verify())

    def test_verify_input_p2sh(self):
        tx = TxFetcher.fetch('46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b')
        self.assertTrue(tx.verify())

    def test_verify_input_p2wpkh(self):
        tx = TxFetcher.fetch('d869f854e1f8788bcff294cc83b280942a8c728de71eb709a2c29d10bfe21b7c', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_input_p2sh_p2wpkh(self):
        tx = TxFetcher.fetch('c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a')
        self.assertTrue(tx.verify())

    def test_verify_input_p2wsh(self):
        tx = TxFetcher.fetch('78457666f82c28aa37b74b506745a7c7684dc7842a52a457b09f09446721e11c', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_input_p2sh_p2wsh(self):
        tx = TxFetcher.fetch('954f43dbb30ad8024981c07d1f5eb6c9fd461e2cf1760dd1283f052af746fc88', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_input_if(self):
        tx = TxFetcher.fetch('61ba3a8b40706931b72929628cf1a07d604f158c8350055725c664d544d00030', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_input_cltv(self):
        tx = TxFetcher.fetch('ca2c7347aa2fdff68052f026fa9a092448c2451f774ca53f3a2b05d74405addc', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_input_csv(self):
        tx = TxFetcher.fetch('d208b659eaca2640f732b07b11ea9800c1a0bb4ffdc03aaf82af76c1787570ac', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_input_csv_2(self):
        tx = TxFetcher.fetch('807d464fff227ce98cfb5f1292069e2793e99f21b0539a1729cc460af32add77', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_lightning_local_success(self):
        tx = TxFetcher.fetch('0191535bfda21f5dfec1c904775c5e2fbee8a985815c88d77258a0b42dba3526')
        self.assertTrue(tx.verify())

    def test_verify_lightning_local_penalty(self):
        tx = TxFetcher.fetch('0da5e5dba5e793d50820c2275dab74912b121c8b7e34ce32a9dbfd4567a9bf8e')
        self.assertTrue(tx.verify())

    def test_verify_lightning_sender_timeout(self):
        tx = TxFetcher.fetch('a16f6d78a58d31fe7459887adf5bd6b4dd95277ea375d250c700cde9fa908bdb')
        self.assertTrue(tx.verify())

    def test_verify_lightning_sender_preimage(self):
        tx = TxFetcher.fetch('89c744f0806a57a9b4634c320703cc941aaf272f290296373b709499064335e5')
        self.assertTrue(tx.verify())

    def test_verify_lightning_receiver_timeout(self):
        tx = TxFetcher.fetch('f9af9b93d66c7e5ee7dcbe0b53faa3d17aa6b9f4cc5b19f0985917b57d82c59a')
        self.assertTrue(tx.verify())

    def test_verify_lightning_receiver_preimage(self):
        tx = TxFetcher.fetch('36b1aff2ad0076be95b1ee1dc4036374998760c80c6583a6478a699e86658ac0')
        self.assertTrue(tx.verify())

    def test_verify_sha1_pinata(self):
        tx = TxFetcher.fetch('8d31992805518fd62daa3bdd2a5c4fd2cd3054c9b3dca1d78055e9528cff6adc')
        self.assertTrue(tx.verify())

    def test_verify_weird(self):
        tx_ids = (
            'efdf1b981d7bba9c941295c0dfc654c4b5e40d7b9744819dd4f78b8e149898e1',
            '9aa3a5a6d9b7d1ac9555be8e42596d06686cc5f76d259b06c560a207d310d5f5',
            'c5d4b73af6eed28798473b05d2b227edd4f285069629843e899b52c2d1c165b7',
            '74ea059a63c7ebddaee6805e1560b15c937d99a9ee9745412cbc6d2a0a5f5305',
            'e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009',
            'dc3aad51b4b9ea1ef40755a38b0b4d6e08c72d2ac5e95b8bebe9bd319b6aed7e',
        )
        for tx_id in tx_ids:
            tx = TxFetcher.fetch(tx_id, testnet=True, fresh=True)
            tx.bip112 = False
            tx.bip65 = False
            print(tx_id)
            self.assertTrue(tx.verify())

    def test_sign_input_p2pkh(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex('0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8')
        tx_ins.append(TxIn(prev_tx, 0))
        tx_outs = []
        h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        tx_outs.append(TxOut(amount=int(0.99 * 100000000), script_pubkey=p2pkh_script(h160)))
        h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        tx_outs.append(TxOut(amount=int(0.1 * 100000000), script_pubkey=p2pkh_script(h160)))
        tx = Tx(1, tx_ins, tx_outs, 0, True)
        self.assertTrue(tx.sign_input_p2pkh(0, private_key))

    def test_is_coinbase(self):
        tx = TxFetcher.fetch('51bdce0f8a1edd5bc023fd4de42edb63478ca67fc8a37a6e533229c17d794d3f')
        self.assertTrue(tx.is_coinbase())

    def test_coinbase_height(self):
        tx = TxFetcher.fetch('51bdce0f8a1edd5bc023fd4de42edb63478ca67fc8a37a6e533229c17d794d3f')
        self.assertEqual(tx.coinbase_height(), 465879)
        tx = TxFetcher.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertIsNone(tx.coinbase_height())
