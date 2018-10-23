from io import BytesIO
from unittest import TestCase

from helper import (
    encode_bech32_checksum,
    encode_varint,
    h160_to_p2pkh_address,
    h160_to_p2sh_address,
    hash160,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    sha256,
)
from op import (
    op_equal,
    op_hash160,
    op_verify,
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


DEBUG = False


def p2pkh_script(h160):
    '''Takes a hash160 and returns the p2pkh scriptPubKey'''
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


def p2sh_script(h160):
    '''Takes a hash160 and returns the p2sh scriptPubKey'''
    return Script([0xa9, h160, 0x87])


def multisig_redeem_script(m, points):
    '''Creates an m-of-n multisig p2sh redeem script'''
    # start the items with m (note OP_1 is 0x51, OP_2 is 0x52 and so on)
    items = [m + 0x50]
    for point in points:
        # add each point's sec format pubkey
        items.append(point.sec())
    # add the n part
    items.append(len(points) + 0x50)
    # add OP_CHECKMULTISIG
    items.append(0xae)
    return Script(items)


def p2wpkh_script(h160):
    '''Takes a hash160 and returns the p2wpkh scriptPubKey'''
    return Script([0x00, h160])


def p2wsh_script(h256):
    '''Takes a hash160 and returns the p2wsh scriptPubKey'''
    return Script([0x00, h256])


def print_state(items, item, stack, altstack):
    print('-' * 78)
    print_altstack = len(altstack) > 0
    if print_altstack:
        column_width = 18
        in_between = 2
    else:
        column_width = 24
        in_between = 3
    format_str = '{0: <' + str(column_width) + '}'
    total_height = max(len(items), 1, len(stack))
    for i in range(total_height):
        to_print = ''
        if len(items) >= total_height - i:
            current = items[len(items) - (total_height - i)]
            if type(current) == int:
                current = OP_CODE_NAMES[current]
            else:
                current = current.hex()[:column_width]
            to_print += format_str.format(current)
        else:
            to_print += ' ' * column_width
        to_print += ' ' * in_between
        if i == total_height - 1:
            current = item
            if type(current) == int:
                current = OP_CODE_NAMES[current]
            else:
                current = current.hex()[:column_width]
            to_print += format_str.format(current)
        else:
            to_print += ' ' * column_width
        to_print += ' ' * in_between
        if len(stack) >= total_height - i:
            current = stack[total_height - i - 1]
            if len(current) == 0:
                current = '0'
            else:
                current = current.hex()[:column_width]
            to_print += format_str.format(current)
        if print_altstack:
            to_print += ' ' * in_between
            if len(stack) >= total_height - i:
                current = stack[total_height - i - 1]
                if len(current) == 0:
                    current = '0'
                else:
                    current = current.hex()[:column_width]
                to_print += format_str.format(current)
        print(to_print)


WEIRD_SET = {98, 101, 102, 107, 108, 109, 111, 112, 113, 114, 115, 116, 119, 120, 121, 122, 123, 125, 139, 140, 143, 144, 146, 147, 148, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 168, 170, 171}


class Script:

    def has_weird_op_code(self):
        for item in self.items:
            if item in WEIRD_SET:
                return True
        return False

    def __init__(self, items, coinbase=None):
        self.items = items
        self.coinbase = coinbase

    def __repr__(self):
        result = ''
        if self.coinbase:
            return self.coinbase.hex()
        for item in self.items:
            if type(item) == int:
                if OP_CODE_NAMES.get(item):
                    name = OP_CODE_NAMES.get(item)
                else:
                    name = 'OP_[{}]'.format(item)
                result += '{} '.format(name)
            else:
                result += '{} '.format(item.hex())
        return result

    @classmethod
    def parse(cls, s, coinbase_mode=False):
        # get the length of the entire field
        length = read_varint(s)
        if coinbase_mode:
            return cls([], coinbase=s.read(length))
        # initialize the items array
        items = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_byte = current[0]
            # if the current byte is between 1 and 75 inclusive
            if current_byte >= 1 and current_byte <= 75:
                # we have an item set n to be the current byte
                n = current_byte
                # add the next n bytes as an item
                items.append(s.read(n))
                # increase the count by n
                count += n
            elif current_byte == 76:
                # op_pushdata1
                data_length = little_endian_to_int(s.read(1))
                items.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                # op_pushdata2
                data_length = little_endian_to_int(s.read(2))
                items.append(s.read(data_length))
                count += data_length + 2
            elif current_byte == 78:
                # op_pushdata4
                data_length = little_endian_to_int(s.read(4))
                items.append(s.read(data_length))
                count += data_length + 4
            else:
                # we have an op code. set the current byte to op_code
                op_code = current_byte
                # add the op_code to the list of items
                items.append(op_code)
        if count != length:
            raise RuntimeError('parsing script failed')
        return cls(items)

    def raw_serialize(self):
        if self.coinbase:
            return self.coinbase
        # initialize what we'll send back
        result = b''
        # go through each item
        for item in self.items:
            # if the item is an integer, it's an op code
            if type(item) == int:
                # turn the item into a single byte integer using int_to_little_endian
                result += int_to_little_endian(item, 1)
            else:
                # otherwise, this is an element
                # get the length in bytes
                length = len(item)
                # for large lengths, we have to use a pushdata op code
                if length < 75:
                    # turn the length into a single byte integer
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    # 76 is pushdata1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length < 0x10000:
                    # 77 is pushdata 2
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                elif length >= 0x10000 and length < 0x100000000:
                    # 78 is pushdata 4
                    result += int_to_little_endian(78, 1)
                    result += int_to_little_endian(length, 4)
                else:
                    raise RuntimeError('too long an item')
                result += item
        return result

    def serialize(self):
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    def hash160(self):
        '''Return the hash160 of the serialized script (without length)'''
        return hash160(self.raw_serialize())

    def sha256(self):
        '''Return the sha256 of the serialized script (without length)'''
        return sha256(self.raw_serialize())

    def __add__(self, other):
        return Script(self.items + other.items)

    def evaluate(self, z, version, locktime, sequence, witness, bip65=True, bip112=True):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        items = self.items[:]
        stack = []
        altstack = []
        if DEBUG:
            print_state(items, b'', stack, altstack)
        while len(items) > 0:
            item = items.pop(0)
            if DEBUG:
                print_state(items, item, stack, altstack)
            if type(item) == int:
                # do what the op code says
                operation = OP_CODE_FUNCTIONS[item]
                if item in (99, 100):
                    # op_if/op_notif require the items array
                    if not operation(stack, items):
                        print('bad op: {}'.format(OP_CODE_NAMES[item]))
                        return False
                elif item in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        print('bad op: {}'.format(OP_CODE_NAMES[item]))
                        return False
                elif item in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        print('bad op: {}'.format(OP_CODE_NAMES[item]))
                        return False
                elif item == 177:
                    # op_checklocktimeverify requires locktime and sequence
                    if bip65 and not operation(stack, locktime, sequence):
                        print('bad cltv')
                        return False
                elif item == 178:
                    # op_checksequenceverify requires version and sequence
                    if bip112 and not operation(stack, version, sequence):
                        print('bad csv')
                        return False
                else:
                    if not operation(stack):
                        print('bad op: {}'.format(OP_CODE_NAMES[item]))
                        return False
            else:
                # add the item to the stack
                stack.append(item)
                # p2sh rule. if the next three items are:
                # OP_HASH160 <20 byte hash> OP_EQUAL this is the RedeemScript
                # OP_HASH160 == 0xa9 and OP_EQUAL == 0x87
                if len(items) == 3 and items[0] == 0xa9 \
                    and type(items[1]) == bytes and len(items[1]) == 20 \
                    and items[2] == 0x87:
                    redeem_script = encode_varint(len(item)) + item
                    # we execute the next three op codes
                    items.pop()
                    h160 = items.pop()
                    items.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    # final result should be a 1
                    if not op_verify(stack):
                        print('bad p2sh h160')
                        return False
                    # hashes match! now add the RedeemScript
                    stream = BytesIO(redeem_script)
                    items.extend(Script.parse(stream).items)
                # witness program version 0 rule. if stack items are:
                # 0 <20 byte hash> this is p2wpkh
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 20:
                    h160 = stack.pop()
                    stack.pop()
                    items.extend(witness)
                    items.extend(p2pkh_script(h160).items)
                # witness program version 0 rule. if stack items are:
                # 0 <32 byte hash> this is p2wsh
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 32:
                    h256 = stack.pop()
                    stack.pop()
                    items.extend(witness[:-1])
                    witness_script = witness[-1]
                    if h256 != sha256(witness_script):
                        print('bad sha256 {} vs {}'.format(h256.hex(), sha256(witness_script).hex()))
                        return False
                    # hashes match! now add the Witness Script
                    stream = BytesIO(encode_varint(len(witness_script)) + witness_script)
                    witness_script_items = Script.parse(stream).items
                    items.extend(witness_script_items)
                    if DEBUG:
                        print_state(items, b'', stack, altstack)
        if len(stack) == 0:
            print('empty stack')
            return False
        if stack.pop() == b'':
            print('bad item left')
            return False
        return True

    def is_p2pkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.'''
        return len(self.items) == 5 and self.items[0] == 0x76 \
            and self.items[1] == 0xa9 \
            and type(self.items[2]) == bytes and len(self.items[2]) == 20 \
            and self.items[3] == 0x88 and self.items[4] == 0xac

    def is_p2sh_script_pubkey(self):
        '''Returns whether this follows the
        OP_HASH160 <20 byte hash> OP_EQUAL pattern.'''
        return len(self.items) == 3 and self.items[0] == 0xa9 \
            and type(self.items[1]) == bytes and len(self.items[1]) == 20 \
            and self.items[2] == 0x87

    def is_p2wpkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_0 <20 byte hash> pattern.'''
        return len(self.items) == 2 and self.items[0] == 0x00 \
            and type(self.items[1]) == bytes and len(self.items[1]) == 20

    def is_p2wsh_script_pubkey(self):
        '''Returns whether this follows the
        OP_0 <20 byte hash> pattern.'''
        return len(self.items) == 2 and self.items[0] == 0x00 \
            and type(self.items[1]) == bytes and len(self.items[1]) == 32

    def address(self, testnet=False):
        '''Returns the address corresponding to the script'''
        if self.is_p2pkh_script_pubkey():  # p2pkh
            # hash160 is the 3rd element
            h160 = self.items[2]
            # convert to p2pkh address using h160_to_p2pkh_address (remember testnet)
            return h160_to_p2pkh_address(h160, testnet)
        elif self.is_p2sh_script_pubkey():  # p2sh
            # hash160 is the 2nd element
            h160 = self.items[1]
            # convert to p2sh address using h160_to_p2sh_address (remember testnet)
            return h160_to_p2sh_address(h160, testnet)
        elif self.is_p2wpkh_script_pubkey():  # p2sh
            # hash160 is the 2nd element
            if testnet:
                prefix = b'tb'
            else:
                prefix = b'bc'
            witness_program = self.raw_serialize()
            # convert to bech32 address using encode_bech32_checksum
            return encode_bech32_checksum(witness_program, prefix=prefix)
        elif self.is_p2wsh_script_pubkey():  # p2sh
            # hash160 is the 2nd element
            if testnet:
                prefix = b'tb'
            else:
                prefix = b'bc'
            witness_program = self.raw_serialize()
            # convert to bech32 address using encode_bech32_checksum
            return encode_bech32_checksum(witness_program, prefix=prefix)


class ScriptTest(TestCase):

    def test_parse(self):
        script_pubkey = BytesIO(bytes.fromhex('6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))
        script = Script.parse(script_pubkey)
        want = bytes.fromhex('304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601')
        self.assertEqual(script.items[0].hex(), want.hex())
        want = bytes.fromhex('035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
        self.assertEqual(script.items[1], want)

    def test_serialize(self):
        want = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.parse(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)

    def test_p2pkh(self):
        script_pubkey_raw = bytes.fromhex('1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
        script_pubkey = Script.parse(BytesIO(script_pubkey_raw))
        self.assertEqual(script_pubkey.serialize(), script_pubkey_raw)
        script_sig_raw = bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        script_sig = Script.parse(BytesIO(script_sig_raw))
        self.assertEqual(script_sig.serialize(), script_sig_raw)

    def test_p2sh(self):
        script_pubkey_raw = bytes.fromhex('17a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687')
        script_pubkey = Script.parse(BytesIO(script_pubkey_raw))
        self.assertEqual(script_pubkey.serialize(), script_pubkey_raw)
        script_sig_raw = bytes.fromhex('db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae')
        script_sig = Script.parse(BytesIO(script_sig_raw))
        self.assertEqual(script_sig.serialize(), script_sig_raw)

    def test_address(self):
        raw_script = bytes.fromhex('1976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac')
        script_pubkey = Script.parse(BytesIO(raw_script))
        want = '15hZo812Lx266Dot6T52krxpnhrNiaqHya'
        self.assertEqual(script_pubkey.address(testnet=False), want)
        want = 'mkDX6B619yTLsLHVp23QanB9ehT5bcf89D'
        self.assertEqual(script_pubkey.address(testnet=True), want)
        script_raw = bytes.fromhex('17a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687')
        script_pubkey = Script.parse(BytesIO(script_raw))
        want = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
        self.assertEqual(script_pubkey.address(testnet=False), want)
        want = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
        self.assertEqual(script_pubkey.address(testnet=True), want)

    def test_coinbase_script_sig(self):
        raw_script = bytes.fromhex('4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73')
        s = Script.parse(BytesIO(raw_script))
        self.assertTrue(s.items[2].find(b'The Times 03/Jan/2009') != -1)
