from binascii import hexlify

from helper import (
    double_sha256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_parent,
    merkle_parent_level,
    merkle_path,
    merkle_root,
)


class Proof:

    def __init__(self, merkle_root, tx_hash, index, merkle_proof):
        self.merkle_root = merkle_root
        self.tx_hash = tx_hash
        self.index = index
        self.merkle_proof = merkle_proof

    def __repr__(self):
        s = '{}:{}:{}:['.format(
            hexlify(self.merkle_root).decode('ascii'),
            hexlify(self.tx_hash).decode('ascii'),
            self.index,
        )
        for p in self.merkle_proof:
            s += '{},'.format(hexlify(p).decode('ascii'))
        s += ']'
        return s

    def verify(self):
        '''Returns whether this proof is valid'''
        # current hash starts with self.tx_hash, reversed
        current = self.tx_hash[::-1]
        # Get the Merkle Path for the index and 2**len(merkle_proof)
        path = merkle_path(self.index, 2**len(self.merkle_proof))
        # Loop through Merkle Path and proof hashes
        for proof_hash, index_at_level in zip(self.merkle_proof, path):
            # if index_at_level is odd, proof_hash goes on left
            if index_at_level % 2 == 1:
                # current hash becomes merkle parent of proof_hash and current
                current = merkle_parent(proof_hash, current)
            # if index_at_level is even, proof_hash goes on right
            else:
                # current hash becomes merkle parent of current and proof_hash
                current = merkle_parent(current, proof_hash)
        # if final result reversed is equal to merkle_root, return True
        return current[::-1] == self.merkle_root


class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp,
                 bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes
        self.merkle_tree = None

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses a block. Returns a Block object'''
        # s.read(n) will read n bytes from the stream
        # version - 4 bytes, little endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes, little endian (use [::-1] to reverse)
        prev_block = s.read(32)[::-1]
        # merkle_root - 32 bytes, little endian (use [::-1] to reverse)
        merkle_root = s.read(32)[::-1]
        # timestamp - 4 bytes, little endian, interpret as int
        timestamp = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits = s.read(4)
        # nonce - 4 bytes
        nonce = s.read(4)
        # initialize class
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        '''Returns the 80 byte block header'''
        # version - 4 bytes, little endian
        result = int_to_little_endian(self.version, 4)
        # prev_block - 32 bytes, little endian
        result += self.prev_block[::-1]
        # merkle_root - 32 bytes, little endian
        result += self.merkle_root[::-1]
        # timestamp - 4 bytes, little endian
        result += int_to_little_endian(self.timestamp, 4)
        # bits - 4 bytes
        result += self.bits
        # nonce - 4 bytes
        result += self.nonce
        return result

    def hash(self):
        '''Returns the double-sha256 interpreted little endian of the block'''
        # serialize
        s = self.serialize()
        # double-sha256
        sha = double_sha256(s)
        # reverse
        return sha[::-1]

    def bip9(self):
        '''Returns whether this block is signaling readiness for BIP9'''
        # BIP9 is signalled if the top 3 bits are 001
        # remember version is 32 bytes so right shift 29 (>> 29) and see if
        # that is 001
        return self.version >> 29 == 0b001

    def bip91(self):
        '''Returns whether this block is signaling readiness for BIP91'''
        # BIP91 is signalled if the 5th bit from the right is 1
        # shift 4 bits to the right and see if the last bit is 1
        return self.version >> 4 & 1 == 1

    def bip141(self):
        '''Returns whether this block is signaling readiness for BIP141'''
        # BIP91 is signalled if the 2nd bit from the right is 1
        # shift 1 bit to the right and see if the last bit is 1
        return self.version >> 1 & 1 == 1

    def target(self):
        '''Returns the proof-of-work target based on the bits'''
        # last byte is exponent
        exponent = self.bits[-1]
        # the first three bytes are the coefficient in little endian
        coefficient = little_endian_to_int(self.bits[:-1])
        # the formula is:
        # coefficient * 2**(8*(exponent-3))
        return coefficient * 2**(8*(exponent-3))

    def difficulty(self):
        '''Returns the block difficulty based on the bits'''
        # note difficulty is (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        lowest = 0xffff * 2**(8*(0x1d-3))
        return lowest / self.target()

    def check_pow(self):
        '''Returns whether this block satisfies proof of work'''
        # get the double_sha256 of the serialization of this block
        sha = double_sha256(self.serialize())
        # interpret this hash as an integer using int.from_bytes(sha, 'little')
        proof = int.from_bytes(sha, 'little')
        # return whether this integer is less than the target
        return proof < self.target()

    def validate_merkle_root(self):
        '''Gets the merkle root of the tx_hashes and checks that it's
        the same as the merkle root of this block.
        '''
        # reverse all the transaction hashes (self.tx_hashes)
        hashes = [h[::-1] for h in self.tx_hashes]
        # get the Merkle Root
        root = merkle_root(hashes)
        # reverse the Merkle Root
        # return whether self.merkle root is the same as
        # the reverse of the calculated merkle root
        return root[::-1] == self.merkle_root

    def calculate_merkle_tree(self):
        '''Calculate and store the entire Merkle Tree'''
        # store the result in self.merkle_tree, an array, 0 representing
        # the bottom level and 1 the parent level of level 0 and so on.
        # initialize self.merkle_tree to be an empty list
        self.merkle_tree = []
        # reverse all the transaction hashes (self.tx_hashes)
        # store as current level
        current_level = [h[::-1] for h in self.tx_hashes]
        # if there is more than 1 hash:
        while len(current_level) > 1:
            # store current level in self.merkle_tree
            self.merkle_tree.append(current_level)
            # Make current level Merkle Parent level
            current_level = merkle_parent_level(current_level)
        # store root as the final level
        self.merkle_tree.append(current_level)

    def create_merkle_proof(self, tx_hash):
        # if self.merkle_tree is empty, go and calculate the merkle tree
        if self.merkle_tree is None:
            self.calculate_merkle_tree()
        # find the index of this tx_hash
        index = self.tx_hashes.index(tx_hash)
        # Get the Merkle Path
        path = merkle_path(index, len(self.tx_hashes))
        # initialize merkle_proof list
        proof_hashes = []
        # Loop over the items in the Merkle Path
        for level, index_at_level in enumerate(path):
            # Find the partner index (-1 for odd, +1 for even)
            if index_at_level % 2 == 1:
                partner_index = index_at_level - 1
            else:
                partner_index = index_at_level + 1
            # add partner to merkle_proof list
            proof_hashes.append(self.merkle_tree[level][partner_index])
        # Return a Proof instance
        return Proof(self.merkle_root, tx_hash, index, proof_hashes)
