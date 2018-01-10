from binascii import unhexlify
from io import BytesIO
from unittest import TestCase

from helper import (
    decode_base58,
    encode_base58_checksum,
    encode_varint,
    flip_endian,
    little_endian_to_int,
    int_to_little_endian,
    h160_to_p2pkh_address,
    h160_to_p2sh_address,
    merkle_parent,
    merkle_parent_level,
    merkle_root,
    merkle_path,
    p2pkh_script,
    p2sh_script,
    read_varint,
)


class HelperTest(TestCase):

    def test_base58(self):
        addr = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
        h160 = unhexlify('0074d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        self.assertEqual(decode_base58(addr), h160)
        self.assertRaises(ValueError, decode_base58, addr+'1')
        got = encode_base58_checksum(h160)
        self.assertEqual(got, addr)
        wif = '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'
        want = unhexlify('800000000000000000000000000000000000000000000000000000000000000001')
        self.assertEqual(decode_base58(wif, num_bytes=38, strip_leading_zeros=True), want)

    def test_p2pkh_script(self):
        h160 = unhexlify('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        self.assertEqual(p2pkh_script(h160)[3:-2], h160)

    def test_p2sh_script(self):
        h160 = unhexlify('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        self.assertEqual(p2sh_script(h160)[2:-1], h160)

    def test_varint(self):
        tests = [
            (0x01, unhexlify('01')),
            (0xfd, unhexlify('fdfd00')),
            (0xfe, unhexlify('fdfe00')),
            (0xff, unhexlify('fdff00')),
            (0x1234, unhexlify('fd3412')),
            (0x123456, unhexlify('fe56341200')),
            (0x123456789a01, unhexlify('ff019a785634120000')),
        ]
        for num, encoded in tests:
            self.assertEqual(encode_varint(num), encoded)
            s = BytesIO(encoded)
            self.assertEqual(read_varint(s), num)
        self.assertRaises(ValueError, encode_varint, 2**65)

    def test_flip_endian(self):
        h = '03ee4f7a4e68f802303bc659f8f817964b4b74fe046facc3ae1be4679d622c45'
        w = '452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03'
        self.assertEqual(flip_endian(h), w)
        h = '813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1'
        w = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        self.assertEqual(flip_endian(h), w)

    def test_little_endian_to_int(self):
        h = unhexlify('99c3980000000000')
        want = 10011545
        self.assertEqual(little_endian_to_int(h), want)
        h = unhexlify('a135ef0100000000')
        want = 32454049
        self.assertEqual(little_endian_to_int(h), want)

    def test_int_to_little_endian(self):
        n = 1
        want = b'\x01\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 4), want)
        n = 10011545
        want = b'\x99\xc3\x98\x00\x00\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 8), want)

    def test_p2pkh_address(self):
        h160 = unhexlify('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
        self.assertEqual(h160_to_p2pkh_address(h160), want)
        want = 'mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q'
        self.assertEqual(h160_to_p2pkh_address(h160, prefix=b'\x6f'), want)

    def test_p2sh_address(self):
        h160 = unhexlify('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
        self.assertEqual(h160_to_p2sh_address(h160, prefix=b'\x05'), want)
        want = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
        self.assertEqual(h160_to_p2sh_address(h160, prefix=b'\xc4'), want)

    def test_merkle_parent(self):
        tx_hash0 = unhexlify('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
        tx_hash1 = unhexlify('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
        want = unhexlify('8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')
        self.assertEqual(merkle_parent(tx_hash0, tx_hash1), want)

    def test_merkle_parent_level0(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
            'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
        ]
        tx_hashes = [unhexlify(x) for x in hex_hashes]
        want_hex_hashes = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
            '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
            'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
            '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
            '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
            '4f492e893bf854111c36cb5eff4dccbdd51b576e1cfdc1b84b456cd1c0403ccb',
        ]
        want_tx_hashes = [unhexlify(x) for x in want_hex_hashes]
        self.assertEqual(merkle_parent_level(tx_hashes), want_tx_hashes)

    def test_merkle_parent_level1(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
        ]
        tx_hashes = [unhexlify(x) for x in hex_hashes]
        want_hex_hashes = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
            '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
            'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
            '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
            '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
            '1796cd3ca4fef00236e07b723d3ed88e1ac433acaaa21da64c4b33c946cf3d10',
        ]
        want_tx_hashes = [unhexlify(x) for x in want_hex_hashes]
        self.assertEqual(merkle_parent_level(tx_hashes), want_tx_hashes)

    def test_merkle_root(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
            'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
        ]
        tx_hashes = [unhexlify(x) for x in hex_hashes]
        want_hex_hash = 'acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6'
        want_hash = unhexlify(want_hex_hash)
        self.assertEqual(merkle_root(tx_hashes), want_hash)

    def test_merkle_path(self):
        i = 7
        total = 11
        want = [7, 3, 1, 0]
        self.assertEqual(merkle_path(i, total), want)
