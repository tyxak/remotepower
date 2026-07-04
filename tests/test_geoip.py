"""W6-41: pure-python MMDB reader — validated against a hand-built minimal DB."""
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = ROOT / "server" / "cgi-bin"

_spec = importlib.util.spec_from_file_location("geoip", _CGI_BIN / "geoip.py")
geoip = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(geoip)


# ── a tiny MMDB encoder (only the types the reader needs) ────────────────────
def _ctrl(dtype, size):
    assert size < 29
    if dtype <= 7:
        return bytes([(dtype << 5) | size])
    # extended type: control-byte type field = 0, then a byte of (type - 7)
    return bytes([size, dtype - 7])


def enc_str(s):
    b = s.encode()
    return _ctrl(2, len(b)) + b


def enc_uint(n, dtype=6):
    b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big') if n else b''
    return _ctrl(dtype, len(b)) + b


def enc_map(pairs):
    out = _ctrl(7, len(pairs))
    for k, v in pairs:
        out += enc_str(k) + v
    return out


def enc_arr(items):
    out = _ctrl(11, len(items))
    for it in items:
        out += it
    return out


def _build_mmdb():
    """A 1-node IPv4 DB (record_size 24) where every address resolves to one
    country record."""
    node_bytes = 6            # 24-bit records × 2
    node_count = 1
    search_tree_size = node_count * node_bytes
    # data record: {'country': {'iso_code':'US','names':{'en':'United States'}}}
    country = enc_map([
        ('iso_code', enc_str('US')),
        ('names', enc_map([('en', enc_str('United States'))])),
    ])
    data_record = enc_map([('country', country)])
    # data record sits at the start of the data section (abs offset
    # search_tree_size + 16). The tree record value R satisfies
    # R - node_count + search_tree_size == that abs offset → R = node_count + 16.
    R = node_count + 16
    node0 = R.to_bytes(3, 'big') * 2      # both left+right → the data record
    tree = node0
    sep = b'\x00' * 16
    data = data_record
    meta = geoip._METADATA_MARKER + enc_map([
        ('node_count', enc_uint(node_count)),
        ('record_size', enc_uint(24)),
        ('ip_version', enc_uint(4)),
        ('database_type', enc_str('Test')),
        ('binary_format_major_version', enc_uint(2)),
        ('binary_format_minor_version', enc_uint(0)),
        ('build_epoch', enc_uint(0)),
        ('description', enc_map([('en', enc_str('test db'))])),
        ('languages', enc_arr([enc_str('en')])),
    ])
    return tree + sep + data + meta


class TestGeoipReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(tempfile.mkdtemp()) / 'test.mmdb'
        cls.path.write_bytes(_build_mmdb())

    def test_metadata_parsed(self):
        r = geoip.Reader(str(self.path))
        self.assertEqual(r.node_count, 1)
        self.assertEqual(r.record_size, 24)
        self.assertEqual(r.ip_version, 4)

    def test_lookup_returns_country(self):
        r = geoip.Reader(str(self.path))
        rec = r.lookup('1.2.3.4')
        self.assertIsInstance(rec, dict)
        self.assertEqual(rec['country']['iso_code'], 'US')
        self.assertEqual(rec['country']['names']['en'], 'United States')

    def test_geo_of_flattens(self):
        r = geoip.Reader(str(self.path))
        g = geoip.geo_of(r, '1.2.3.4')
        self.assertEqual(g['country_code'], 'US')
        self.assertEqual(g['country'], 'United States')

    def test_bad_input_returns_empty(self):
        r = geoip.Reader(str(self.path))
        self.assertEqual(geoip.geo_of(r, 'not-an-ip'), {})
        self.assertIsNone(r.lookup('not-an-ip'))

    def test_missing_file_open_reader_none(self):
        self.assertIsNone(geoip.open_reader('/nonexistent/geoip.mmdb'))
        self.assertIsNone(geoip.open_reader(''))
        self.assertEqual(geoip.geo_of(None, '1.2.3.4'), {})


if __name__ == '__main__':
    unittest.main()
