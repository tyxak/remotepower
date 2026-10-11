"""A malformed answer from a device is an SnmpError, not an IndexError or ValueError.

Every caller catches SnmpError. The parser let IndexError (a truncated or empty
datagram, a length that runs off the end) and ValueError (an OID arc too large to
print, past Python's integer-to-string limit) escape, so a faulty or hostile device
turned one failed poll into an exception in the caller: a 500 on the on-demand
walk and deep poll routes, and a failed pass wherever a sweep did not wrap it.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-snmpmal-'))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import snmp  # noqa: E402


def tlv(tag, body):
    n = len(body)
    head = bytes([n]) if n < 128 else bytes([0x82]) + n.to_bytes(2, 'big')
    return bytes([tag]) + head + body


def oid_with_arc(value):
    arcs = []
    while True:
        arcs.append(value & 0x7F)
        value >>= 7
        if not value:
            break
    tail = [a | 0x80 for a in reversed(arcs[1:])] + [arcs[0]]
    return bytes([0x2B]) + bytes(tail)


def response(request_id, oid_body):
    vb = tlv(0x30, tlv(0x06, oid_body) + tlv(0x05, b''))
    pdu = tlv(0xA2, tlv(2, bytes([request_id])) + tlv(2, b'\x00') + tlv(2, b'\x00') + tlv(0x30, vb))
    return tlv(0x30, tlv(2, b'\x01') + tlv(4, b'public') + pdu), pdu


class TestMalformedAnswers(unittest.TestCase):
    def test_a_normal_answer_still_parses(self):
        msg, _ = response(7, oid_with_arc(1234))
        self.assertEqual(list(snmp._parse_response(msg, 7)), ['1.3.1234'])

    def test_an_arc_too_large_to_print_is_an_snmp_error(self):
        msg, pdu = response(7, oid_with_arc(1 << 17000))
        with self.assertRaises(snmp.SnmpError):
            snmp._parse_response(msg, 7)
        with self.assertRaises(snmp.SnmpError):              # the SNMPv3 path parses the PDU alone
            snmp._parse_pdu_body(pdu[2:] if pdu[1] < 128 else pdu[4:], 7)

    def test_empty_truncated_and_garbage_datagrams_are_snmp_errors(self):
        msg, _ = response(7, oid_with_arc(5))
        for name, buf in (('empty', b''), ('one byte', b'\x30'), ('truncated', msg[:10]),
                          ('length runs off the end', b'\x30\x84\xff\xff\xff\xff'),
                          ('not BER', b'GET / HTTP/1.1\r\n\r\n')):
            with self.assertRaises(snmp.SnmpError, msg=name):
                snmp._parse_response(buf, 7)

    def test_the_request_id_check_is_unchanged(self):
        msg, _ = response(7, oid_with_arc(5))
        with self.assertRaises(snmp.SnmpError):
            snmp._parse_response(msg, 8)


if __name__ == '__main__':
    unittest.main()
