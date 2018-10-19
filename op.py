import hashlib

from ecc import S256Point, Signature
from helper import little_endian_to_int


def op_0(stack):
    stack.append(0)
    return True


def op_1(stack):
    stack.append(1)
    return True


def op_2(stack):
    stack.append(2)
    return True


def op_3(stack):
    stack.append(3)
    return True


def op_4(stack):
    stack.append(4)
    return True


def op_5(stack):
    stack.append(5)
    return True


def op_6(stack):
    stack.append(6)
    return True


def op_7(stack):
    stack.append(7)
    return True


def op_8(stack):
    stack.append(8)
    return True


def op_9(stack):
    stack.append(9)
    return True


def op_10(stack):
    stack.append(10)
    return True


def op_11(stack):
    stack.append(11)
    return True


def op_12(stack):
    stack.append(12)
    return True


def op_13(stack):
    stack.append(13)
    return True


def op_14(stack):
    stack.append(14)
    return True


def op_15(stack):
    stack.append(15)
    return True


def op_16(stack):
    stack.append(16)
    return True


def op_nop(stack):
    return True


def op_if(stack, items):
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if element == 0:
        items[:0] = false_items
    else:
        items[:0] = true_items
    return True


def op_notif(stack, items):
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if element == 0:
        items[:0] = true_items
    else:
        items[:0] = false_items
    return True


def op_verify(stack):
    if len(stack) < 1:
        return False
    item = stack.pop()
    if item == 0:
        return False
    return True


def op_2dup(stack):
    if len(stack) < 2:
        return False
    stack.extend(stack[-2:])
    return True


def op_drop(stack):
    if len(stack) < 1:
        return False
    stack.pop()
    return True


def op_dup(stack):
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True


def op_equal(stack):
    if len(stack) < 2:
        return False
    item1 = stack.pop()
    item2 = stack.pop()
    if item1 == item2:
        stack.append(1)
    else:
        stack.append(0)
    return True


def op_equalverify(stack):
    return op_equal(stack) and op_verify(stack)


def op_not(stack):
    if len(stack) < 1:
        return False
    item = stack.pop()
    if item == 0:
        stack.append(1)
    else:
        stack.append(0)
    return True


def op_add(stack):
    if len(stack) < 2:
        return False
    item1 = stack.pop()
    item2 = stack.pop()
    stack.append(item1 + item2)
    return True


def op_sub(stack):
    if len(stack) < 2:
        return False
    item1 = stack.pop()
    item2 = stack.pop()
    stack.append(item2 - item1)
    return True


def op_ripemd160(stack):
    if len(stack) < 1:
        return False
    item = stack.pop()
    stack.append(hashlib.new('ripemd160', item).digest())
    return True


def op_sha1(stack):
    if len(stack) < 1:
        return False
    item = stack.pop()
    stack.append(hashlib.sha1(item).digest())
    return True


def op_sha256(stack):
    if len(stack) < 1:
        return False
    item = stack.pop()
    stack.append(hashlib.sha256(item).digest())
    return True


def op_hash160(stack):
    if len(stack) < 1:
        return False
    item = stack.pop()
    h160 = hashlib.new('ripemd160', hashlib.sha256(item).digest()).digest()
    stack.append(h160)
    return True


def op_hash256(stack):
    if len(stack) < 1:
        return False
    item = stack.pop()
    stack.append(hashlib.sha256(hashlib.sha256(item).digest()).digest())
    return True


def op_checksig(stack, z):
    if len(stack) < 2:
        return False
    sec_pubkey = stack.pop()
    # signature is assumed to be using SIGHASH_ALL
    der_signature = stack.pop()[:-1]
    try:
        point = S256Point.parse(sec_pubkey)
        sig = Signature.parse(der_signature)
    except (ValueError, RuntimeError):
        return False
    if point.verify(z, sig):
        stack.append(1)
    else:
        stack.append(0)
    return True


def op_checksigverify(stack, z):
    return op_checksig(stack, z) and op_verify(stack)


def op_checkmultisig(stack, z):
    if len(stack) < 1:
        return False
    n = stack.pop()
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = stack.pop()
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        # signature is assumed to be using SIGHASH_ALL
        der_signatures.append(stack.pop()[:-1])
    # OP_CHECKMULTISIG bug
    stack.pop()
    try:
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        sigs = [Signature.parse(der) for der in der_signatures]
        for sig in sigs:
            # find the point that this was signed by
            signing_point = None
            for point in points:
                if point.verify(z, sig):
                    signing_point = point
                    break
            if signing_point:
                # remove the point since it's been used
                points.remove(signing_point)
            else:
                # did not find a point that signed it
                print('no point found for sig {}'.format(sig.der().hex()))
                return False
        stack.append(1)
    except (ValueError, RuntimeError):
        return False
    return True


def op_checkmultisigverify(stack, z):
    return op_checkmultisig(stack, z) and op_verify(stack)


def op_checklocktimeverify(stack, locktime, sequence):
    if sequence == 0xffffffff:
        return False
    if len(stack) < 1:
        return False
    if type(stack[-1]) == int:
        item = stack[-1]
    else:
        item = little_endian_to_int(stack[-1])
    if item < 0:
        return False
    if item < 500000000 and locktime > 500000000:
        return False
    if locktime < item:
        return False
    return True


def op_checksequenceverify(stack, version, sequence):
    if sequence & (1 << 31) == (1 << 31):
        return False
    if len(stack) < 1:
        return False
    if type(stack[-1]) == int:
        item = stack[-1]
    else:
        item = little_endian_to_int(stack[-1])
    if item < 0:
        return False
    if item & (1 << 31) == (1 << 31):
        if version < 2:
            return False
        elif sequence & (1 << 31) == (1 << 31):
            return False
        elif item & (1 << 22) != sequence & (1 << 22):
            return False
        elif item & 0xffff > sequence & 0xffff:
            return False
    return True


OP_CODE_FUNCTIONS = {
    0: op_0,
    81: op_1,
    82: op_2,
    83: op_3,
    84: op_4,
    85: op_5,
    86: op_6,
    87: op_7,
    88: op_8,
    89: op_9,
    90: op_10,
    91: op_11,
    92: op_12,
    93: op_13,
    94: op_14,
    95: op_15,
    96: op_16,
    97: op_nop,
    #    98: op_ver,
    99: op_if,
    100: op_notif,
    #    101: op_verif,
    #    102: op_vernotif,
    #    103: op_else,
    #    104: op_endif,
    105: op_verify,
    #    106: op_return,
    #    107: op_toaltstack,
    #    108: op_fromaltstack,
    #    109: op_2drop,
    #    110: op_2dup,
    #    111: op_3dup,
    #    112: op_2over,
    #    113: op_2rot,
    #    114: op_2swap,
    #    115: op_ifdup,
    #    116: op_depth,
    117: op_drop,
    118: op_dup,
    #    119: op_nip,
    #    120: op_over,
    #    121: op_pick,
    #    122: op_roll,
    #    123: op_rot,
    #    124: op_swap,
    #    125: op_tuck,
    #    126: op_cat,
    #    127: op_substr,
    #    128: op_left,
    #    129: op_right,
    #    130: op_size,
    #    131: op_invert,
    #    132: op_and,
    #    133: op_or,
    #    134: op_xor,
    135: op_equal,
    136: op_equalverify,
    #    137: op_reserved1,
    #    138: op_reserved2,
    #    139: op_1add,
    #    140: op_1sub,
    #    141: op_2mul,
    #    142: op_2div,
    #    143: op_negate,
    #    144: op_abs,
    145: op_not,
    #    146: op_0notequal,
    147: op_add,
    148: op_sub,
    #    149: op_mul,
    #    150: op_div,
    #    151: op_mod,
    #    152: op_lshift,
    #    153: op_rshift,
    #    154: op_booland,
    #    155: op_boolor,
    #    156: op_numequal,
    #    157: op_numequalverify,
    #    158: op_numnotequal,
    #    159: op_lessthan,
    #    160: op_greaterthan,
    #    161: op_lessthanorequal,
    #    162: op_greaterthanorequal,
    #    163: op_min,
    #    164: op_max,
    #    165: op_within,
    166: op_ripemd160,
    167: op_sha1,
    168: op_sha256,
    169: op_hash160,
    170: op_hash256,
    #    171: op_codeseparator,
    172: op_checksig,
    173: op_checksigverify,
    174: op_checkmultisig,
    175: op_checkmultisigverify,
    #    176: op_nop1,
    177: op_checklocktimeverify,
    178: op_checksequenceverify,
    #    179: op_nop4,
    #    180: op_nop5,
    #    181: op_nop6,
    #    182: op_nop7,
    #    183: op_nop8,
    #    184: op_nop9,
    #    185: op_nop10,
    #    252: op_nulldata,
    #    253: op_pubkeyhash,
    #    254: op_pubkey,
    #    255: op_invalidopcode,
}

OP_CODE_NAMES = {
    0: 'OP_0',
    76: 'OP_PUSHDATA1',
    77: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    80: 'OP_RESERVED',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    98: 'OP_VER',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    101: 'OP_VERIF',
    102: 'OP_VERNOTIF',
    103: 'OP_ELSE',
    104: 'OP_ENDIF',
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    126: 'OP_CAT',
    127: 'OP_SUBSTR',
    128: 'OP_LEFT',
    129: 'OP_RIGHT',
    130: 'OP_SIZE',
    131: 'OP_INVERT',
    132: 'OP_AND',
    133: 'OP_OR',
    134: 'OP_XOR',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    137: 'OP_RESERVED1',
    138: 'OP_RESERVED2',
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    141: 'OP_2MUL',
    142: 'OP_2DIV',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    149: 'OP_MUL',
    150: 'OP_DIV',
    151: 'OP_MOD',
    152: 'OP_LSHIFT',
    153: 'OP_RSHIFT',
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    176: 'OP_NOP1',
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
    252: 'OP_NULLDATA',
    253: 'OP_PUBKEYHASH',
    254: 'OP_PUBKEY',
    255: 'OP_INVALIDOPCODE',
}
