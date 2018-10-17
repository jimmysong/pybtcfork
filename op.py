import hashlib

from ecc import S256Point, Signature


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
    item = stack[-1]
    if item < 0:
        return False
    if item < 500000000 and locktime > 500000000:
        return False
    if locktime < item:
        return False
    return True
