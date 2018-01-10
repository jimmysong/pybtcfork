from binascii import unhexlify
from unittest import TestCase

from script import Script


class ScriptTest(TestCase):

    def test_p2pkh(self):
        script_pubkey_raw = unhexlify('76a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
        script_pubkey = Script.parse(script_pubkey_raw)
        self.assertEqual(script_pubkey.type(), 'p2pkh')
        self.assertEqual(script_pubkey.serialize(), script_pubkey_raw)

        script_sig_raw = unhexlify('483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        script_sig = Script.parse(script_sig_raw)
        self.assertEqual(script_sig.type(), 'p2pkh sig')
        self.assertEqual(script_sig.serialize(), script_sig_raw)
        self.assertEqual(script_sig.der_signature(), unhexlify('3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01'))
        self.assertEqual(script_sig.sec_pubkey(), unhexlify('0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'))

    def test_p2sh(self):
        script_pubkey_raw = unhexlify('a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687')
        script_pubkey = Script.parse(script_pubkey_raw)
        self.assertEqual(script_pubkey.type(), 'p2sh')
        self.assertEqual(script_pubkey.serialize(), script_pubkey_raw)

        script_sig_raw = unhexlify('00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae')
        script_sig = Script.parse(script_sig_raw)
        self.assertEqual(script_sig.type(), 'p2sh sig')
        self.assertEqual(script_sig.serialize(), script_sig_raw)
        self.assertEqual(script_sig.der_signature(index=0), unhexlify('3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701'))
        self.assertEqual(script_sig.der_signature(index=1), unhexlify('3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201'))
        self.assertEqual(script_sig.sec_pubkey(index=0), unhexlify('022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70'))
        self.assertEqual(script_sig.sec_pubkey(index=1), unhexlify('03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71'))

    def test_address(self):
        script_raw = unhexlify('76a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac')
        script_pubkey = Script.parse(script_raw)
        want = '15hZo812Lx266Dot6T52krxpnhrNiaqHya'
        self.assertEqual(script_pubkey.address(), want)
        want = 'mkDX6B619yTLsLHVp23QanB9ehT5bcf89D'
        self.assertEqual(script_pubkey.address(prefix=b'\x6f'), want)
        script_raw = unhexlify('a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687')
        script_pubkey = Script.parse(script_raw)
        want = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
        self.assertEqual(script_pubkey.address(prefix=b'\x05'), want)
        want = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
        self.assertEqual(script_pubkey.address(prefix=b'\xc4'), want)
