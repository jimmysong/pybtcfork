from io import BytesIO
from unittest import TestCase

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


class Tx:

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
        return 'tx: {}\nversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n'.format(
            self.hash().hex(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def hash(self):
        return double_sha256(self.serialize())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        '''Takes a byte stream and parses the transaction to
        return a Tx object
        '''
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
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    @classmethod
    def parse_segwit(cls, s, testnet=False):
        '''Takes a byte stream and parses the segwit transaction to
        return a Tx object
        '''
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
                items.append(s.read(item_len))
            tx_in.witness_program = items
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    def serialize(self):
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
            # create a new TxIn that has a blank script_sig (b'') and add to alt_tx_ins
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=Script([]),
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
        # add some information to tx_in that we'll need for op codes
        tx_in.version = self.version
        tx_in.locktime = self.locktime
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        # check to see if the script_pubkey is a p2sh
        if script_pubkey.is_p2sh_script_pubkey():
            # the last element has to be the redeem script to trigger
            item = tx_in.script_sig.items[-1]
            raw_redeem = int_to_little_endian(len(item), 1) + item
            redeem_script = Script.parse(BytesIO(raw_redeem))
            if redeem_script.is_p2wpkh_script_pubkey():
                tx_in.sig_hash = self.sig_hash_bip143(input_index, redeem_script)
            elif redeem_script.is_p2wsh_script_pubkey():
                item = tx_in.witness_program[-1]
                raw_witness = encode_varint(len(item)) + item
                witness_script = Script.parse(BytesIO(raw_witness))
                tx_in.sig_hash = self.sig_hash_bip143(input_index, witness_script=witness_script)
            else:
                tx_in.sig_hash = self.sig_hash(input_index, redeem_script)
        else:
            if script_pubkey.is_p2wpkh_script_pubkey():
                tx_in.sig_hash = self.sig_hash_bip143(input_index)
            elif script_pubkey.is_p2wsh_script_pubkey():
                item = tx_in.witness_program[-1]
                raw_witness = encode_varint(len(item)) + item
                witness_script = Script.parse(BytesIO(raw_witness))
                tx_in.sig_hash = self.sig_hash_bip143(input_index, witness_script=witness_script)
            else:
                tx_in.sig_hash = self.sig_hash(input_index)
        # combine the current script_sig and the previous script_pubkey
        script = tx_in.script_sig + script_pubkey
        # now evaluate this script and see if it passes
        return script.evaluate(tx_in)

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
        # grab the first input
        first_input = self.tx_ins[0]
        # grab the first element of the script_sig (.script_sig.items[0])
        first_element = first_input.script_sig.items[0]
        # convert the first element from little endian to int
        return little_endian_to_int(first_element)


class TxIn:

    cache = {}

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
        script_sig = Script.parse(s)
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

    @classmethod
    def set_cache(cls, tx_id, raw):
        stream = BytesIO(raw)
        tx = Tx.parse(stream)
        cls.cache[tx_id] = tx

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://tbtc.programmingblockchain.com:18332'
        else:
            return 'http://btc.programmingblockchain.com:8332'

    def fetch_tx(self, testnet=False):
        if self.prev_tx not in self.cache:
            url = '{}/rest/tx/{}.hex'.format(
                self.get_url(testnet), self.prev_tx.hex())
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise RuntimeError(response.text)
            # segwit marker is right after version. If 0 we know it's segwit.
            stream = BytesIO(raw)
            if raw[4] == 0:
                # this is segwit serialization
                tx = Tx.parse_segwit(stream)
            else:
                # normal serialization
                tx = Tx.parse(stream)
                print(raw.hex())
                print(tx.serialize().hex())
            if tx.hash() != self.prev_tx:
                raise RuntimeError('server lied to us {} vs {}'.format(tx.hash().hex(), self.prev_tx.hex()))
            self.cache[self.prev_tx] = tx
        return self.cache[self.prev_tx]

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

    def test_parse_version(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_ins), 1)
        want = bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
        self.assertEqual(tx.tx_ins[0].prev_tx, want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        self.assertEqual(tx.tx_ins[0].script_sig.serialize(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xfffffffe)

    def test_parse_outputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = bytes.fromhex('1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = bytes.fromhex('1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac')
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize(), want)

    def test_parse_locktime(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.locktime, 410393)

    def test_serialize(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.serialize(), raw_tx)

    def test_input_value(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        want = 42505594
        tx_in = TxIn(
            prev_tx=bytes.fromhex(tx_hash),
            prev_index=index,
            script_sig=Script([]),
            sequence=0,
        )
        self.assertEqual(tx_in.value(), want)

    def test_input_pubkey(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        tx_in = TxIn(
            prev_tx=bytes.fromhex(tx_hash),
            prev_index=index,
            script_sig=Script([]),
            sequence=0,
        )
        want = bytes.fromhex('1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac')
        self.assertEqual(tx_in.script_pubkey().serialize(), want)

    def test_fee(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = bytes.fromhex('010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 140500)

    def test_sig_hash(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        want = int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16)
        self.assertEqual(tx.sig_hash(0), want)

    def test_verify_input_p2pkh(self):
        # p2pkh
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_p2sh(self):
        # p2sh
        raw_tx = bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_p2wpkh(self):
        # p2wpkh
        raw_tx = bytes.fromhex('0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse_segwit(stream, testnet=True)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_p2sh_p2wpkh(self):
        # p2sh-p2wpkh
        raw_tx = bytes.fromhex('0200000000010140d43a99926d43eb0e619bf0b3d83b4a31f60c176beecfb9d35bf45e54d0f7420100000017160014a4b4ca48de0b3fffc15404a1acdc8dbaae226955ffffffff0100e1f5050000000017a9144a1154d50b03292b3024370901711946cb7cccc387024830450221008604ef8f6d8afa892dee0f31259b6ce02dd70c545cfcfed8148179971876c54a022076d771d6e91bed212783c9b06e0de600fab2d518fad6f15a2b191d7fbd262a3e0121039d25ab79f41f75ceaf882411fd41fa670a4c672c23ffaf0e361a969cde0692e800000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse_segwit(stream)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_p2wsh(self):
        # p2wsh
        raw_tx = bytes.fromhex('0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560200000000ffffffff0188b3f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100f9d3fe35f5ec8ceb07d3db95adcedac446f3b19a8f3174e7e8f904b1594d5b43022074d995d89a278bd874d45d0aea835d3936140397392698b7b5bbcdef8d08f2fd012321038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990acac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse_segwit(stream, testnet=True)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_p2sh_p2wsh(self):
        # p2sh-p2wsh
        raw_tx = bytes.fromhex('0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f856040000002322002001d5d92effa6ffba3efa379f9830d0f75618b13393827152d26e4309000e88b1ffffffff0188b3f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02473044022038421164c6468c63dc7bf724aa9d48d8e5abe3935564d38182addf733ad4cd81022076362326b22dd7bfaf211d5b17220723659e4fe3359740ced5762d0e497b7dcc012321038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990acac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse_segwit(stream, testnet=True)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_if(self):
        # op_if
        raw_tx = bytes.fromhex('0200000001d4b9e8ec436bdf27164df27c7c3609024500d049037940513c94dac8d3a999ed0100000090041234567800473044022071b0d6894ae2252bd67f8d9882c814a2a59e1c7ae8b8f1117db17a484538833a0220680f44f3150b652c49b6523eff5e750d460f3306ed669835db7c3095596211bf0141049343773d05d5a07f103914d5294ca742db124babd2c2cac5f84e6114f192f07c1e44c956c737a60369fbf4f5e6324dc005ba38d156f61232f9251fec8ee3e262fdffffff01006ebe00000000001976a9144f2465fec27ad88917c9fcb72b09ade39b8911ed88ac6c3c1300')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream, testnet=True)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_cltv(self):
        # op_checklocktimeverify
        raw_tx = bytes.fromhex('0100000001726f90610c79af5f237326855d63355c99628593da6ba96dc0942b256af0aa12000000008b47304402205b1f7ae4145526f33128d92aa74e3b8f6c7369e063506658c4a17119ce9526e00220015df72bed40c5ead4bcd7b732aa36627a8baa6d6b7d38e9de34b9fdb27eac56012102f0141fadbe6757ed04b7a25dad0c78af8b97af09744318cf15c66a4566fa2ec920042d25ec57b17576a914225d81ac31f9c8368033e1d380b8be1860d53c5d88ac0000000001007a3f00000000001976a9146b3a858370ea6ed841633611fcfdeae7bf85f86288ac9125ec57')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream, testnet=True)
        self.assertTrue(tx.verify_input(0))

    def test_verify_input_csv(self):
        # op_checksequenceverify
        raw_tx = bytes.fromhex('0200000001f4db00105cdc7cab7d26ae018154540faa2a20872a1e263c6948c5a4e44d060f00000000f947304402204c7cbcc610ac5ee744dc7de6fc31421217dbd066e41fd377dbe16dbd70372d3d02201e74b66967b44548c007a011d98bb42a9f22651392232b87a640dcf8ad55e1d20100004cad6352210399e3dde1d1853dbd99c81ba4f2c0cca351b3cceecce7cd0bd59acc5789672135210327f017c35a46b759536309e6de256ad44ad609c1c4aed0e2cdb82f62490f75f852ae6763a914a7ec62542b0d393d43442aadf8d55f7da1e303cb88210399e3dde1d1853dbd99c81ba4f2c0cca351b3cceecce7cd0bd59acc5789672135ac6755b275210399e3dde1d1853dbd99c81ba4f2c0cca351b3cceecce7cd0bd59acc5789672135ac68680500000002c28d0000000000001976a914d36d5a91d3f05b2c23cf4fdcac88e4f8b50cec9088ac00000000000000001e6a1cdbb957b39547c4b841700768d623a3f4c849743272bc7783855c9c4d00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream, testnet=True)
        self.assertTrue(tx.verify_input(0))
        self.assertEqual(tx.serialize(), raw_tx)

    def test_verify_input_csv_2(self):
        raw_tx = bytes.fromhex('02000000017110429dbcfdb3d19836bf273766d1b259d8fe09c3a1121594fe3c69110054af00000000bd47304402204705f99c2571936779c8c095e96d066dc9e3ef0b5be5d7967816c1083945015f022059b7a1c3b02c541c8c756424c6b4845120e5e1e9a350d22c15289604ef97b66701004c7263a8202c153075103a7c81c80de8c737f215cdddf46e9028b300e90e57e53189ecd2fa8821027db4b6ad6c26333dfac2864040badb7d7cefb256e4aa01bcd38cd8a53b30ba41ac6703010040b2752103c7fed01e48237da2a2dcf4bc2f21ef56daeae1f8552b41bcaacdbaaa52cfc1beac680100400001d07e0100000000001976a9144657c68523eb9cd215670c8fc0b0b63952626e1588ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream, testnet=True)
        self.assertTrue(tx.verify_input(0))
        self.assertEqual(tx.serialize(), raw_tx)

    def test_sign_input_p2pkh(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex('0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8')
        tx_ins.append(TxIn(
            prev_tx=prev_tx,
            prev_index=0,
            script_sig=Script([]),
            sequence=0xffffffff,
        ))
        tx_outs = []
        h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        tx_outs.append(TxOut(amount=int(0.99 * 100000000), script_pubkey=p2pkh_script(h160)))
        h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        tx_outs.append(TxOut(amount=int(0.1 * 100000000), script_pubkey=p2pkh_script(h160)))

        tx = Tx(
            version=1,
            tx_ins=tx_ins,
            tx_outs=tx_outs,
            locktime=0,
            testnet=True,
        )
        self.assertTrue(tx.sign_input_p2pkh(0, private_key))

    def test_is_coinbase(self):
        raw_tx = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.is_coinbase())

    def test_coinbase_height(self):
        raw_tx = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.coinbase_height(), 465879)
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertIsNone(tx.coinbase_height())
