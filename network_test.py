from binascii import unhexlify
from io import BytesIO
from unittest import TestCase

from network import NetworkEnvelope


class NetworkEnvelopeTest(TestCase):

    def test_parse(self):
        msg = unhexlify('f9beb4d976657261636b000000000000000000005df6e0e2')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command[:6], b'verack')
        self.assertEqual(envelope.payload, b'')
        msg = unhexlify('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command[:7], b'version')
        self.assertEqual(envelope.payload, msg[24:])

    def test_serialize(self):
        msg = unhexlify('f9beb4d976657261636b000000000000000000005df6e0e2')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)
        msg = unhexlify('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)
