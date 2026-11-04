#!/usr/bin/env python3
"""The AI index knows what a host IS: the system maker and model and its memory.

The agent has read the DMI tables since v3.4.0 and the drawer shows the system and
the installed memory modules, and the AI index did not know either. "What servers do
I have", "which hosts run 2133 MT/s memory" and "how much RAM does db01 have
installed" had nothing to find.

Held from the producer to the index: the agent's own DMI parser runs on canned
dmidecode output, its result goes through the real ingest, and the corpus builder
reads what the ingest stored. Serial numbers stay out of the index.
"""
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v750-ragh-'))

import rag_index  # noqa: E402

_SYSTEM = """\
# dmidecode 3.4
Getting SMBIOS data from sysfs.
SMBIOS 3.2.0 present.

Handle 0x0100, DMI type 1, 27 bytes
System Information
\tManufacturer: Dell Inc.
\tProduct Name: PowerEdge R740
\tVersion: Not Specified
\tSerial Number: SN-SYSTEM-7XJ2YZ3
\tUUID: 4c4c4544-0058-4a10-8032-b7c04f5a3233
"""


def _dimm(handle, locator, size, serial):
    if size is None:
        return (f"Handle 0x{handle:04x}, DMI type 17, 84 bytes\nMemory Device\n"
                f"\tSize: No Module Installed\n\tLocator: {locator}\n")
    return (f"Handle 0x{handle:04x}, DMI type 17, 84 bytes\nMemory Device\n"
            f"\tTotal Width: 72 bits\n\tData Width: 64 bits\n\tSize: {size}\n"
            f"\tForm Factor: DIMM\n\tLocator: {locator}\n\tType: DDR4\n"
            f"\tSpeed: 2933 MT/s\n\tManufacturer: Samsung\n\tSerial Number: {serial}\n")


_MEMORY = "# dmidecode 3.4\n" + "\n".join(
    [_dimm(0x1100 + i, f"A{i + 1}", "32 GB", f"SN-DIMM-{i}") for i in range(8)]
    + [_dimm(0x1200, "B1", None, "")])


def _agent_inventory():
    """The agent's own parser, run on canned dmidecode output."""
    spec = importlib.util.spec_from_file_location('rp_agent_v750_ragh',
                                                  _ROOT / 'client' / 'remotepower-agent.py')
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)

    def fake_run(argv, **kw):
        out = ''
        if 'dmidecode' in str(argv[0]):
            out = _SYSTEM if '-t' in argv and argv[argv.index('-t') + 1] == 'system' else _MEMORY
        return types.SimpleNamespace(returncode=0, stdout=out, stderr='')

    agent._which = lambda name: '/usr/sbin/dmidecode' if name == 'dmidecode' else None
    agent.subprocess = types.SimpleNamespace(run=fake_run, TimeoutExpired=Exception,
                                             CalledProcessError=Exception,
                                             DEVNULL=-3, PIPE=-1, STDOUT=-2)
    return agent.get_hardware_inventory()


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v750-ragh-api-')
    spec = importlib.util.spec_from_file_location('api_v750_ragh', _CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestFromTheProducerToTheIndex(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.hw = _agent_inventory()
        cls.api = api = _fresh_api()
        api.save(api.DEVICES_FILE, {'d1': {'name': 'db01', 'last_seen': 1, 'monitored': True,
                                           'sysinfo': {}}})
        api._ingest_hardware('d1', 'db01', {'hardware': cls.hw}, 1000)
        api._LOAD_CACHE.clear()
        cls.stored = api.load(api.HARDWARE_FILE)

    def test_the_premise_the_agent_parser_found_both(self):
        self.assertEqual(self.hw['system']['product'], 'PowerEdge R740')
        self.assertEqual(len(self.hw['memory']), 8)       # the empty slot is not a module

    def test_the_premise_the_ingest_kept_them(self):
        rec = self.stored['d1']['hardware']
        self.assertEqual(rec['system']['manufacturer'], 'Dell Inc.')
        self.assertEqual(len(rec['memory']), 8)

    def test_the_corpus_describes_the_host(self):
        docs = rag_index.build_hardware_corpus(self.stored, {'d1': {'name': 'db01'}}, now=5)
        by_id = {d['id']: d for d in docs}
        self.assertIn('live/d1#inventory', by_id)
        text = by_id['live/d1#inventory']['text']
        self.assertIn('Hardware inventory for db01', text)
        self.assertIn('system: Dell Inc. PowerEdge R740', text)
        self.assertIn('memory: 8 modules, 256 GB installed', text)
        self.assertIn('8 x 32 GB DDR4 2933 MT/s (Samsung)', text)
        self.assertEqual(by_id['live/d1#inventory']['device'], 'd1')

    def test_serial_numbers_stay_out_of_the_index(self):
        docs = rag_index.build_hardware_corpus(self.stored, {'d1': {'name': 'db01'}}, now=5)
        blob = ' '.join(d['text'] for d in docs)
        self.assertNotIn('SN-SYSTEM', blob)
        self.assertNotIn('SN-DIMM', blob)
        self.assertNotIn('4c4c4544', blob)

    def test_it_goes_through_the_real_source_wiring(self):
        api = self.api
        cfg = {'rag': {'sources': {'hardware': True}}}
        docs = api._rag_build_corpus(cfg)
        self.assertIn('live/d1#inventory', {d['id'] for d in docs})
        off = api._rag_build_corpus({'rag': {'sources': {'hardware': False}}})
        self.assertNotIn('live/d1#inventory', {d['id'] for d in off})


class TestTheBuilder(unittest.TestCase):

    def _lines(self, hw):
        return rag_index.hardware_inventory_lines(hw)

    def test_mixed_modules_are_grouped_by_kind_most_common_first(self):
        mem = ([{'size': '16 GB', 'type': 'DDR4', 'speed': '3200 MT/s'}] * 4
               + [{'size': '8 GB', 'type': 'DDR4', 'speed': '2666 MT/s'}] * 2)
        out = self._lines({'memory': mem})
        self.assertEqual(out, ['memory: 6 modules, 80 GB installed - '
                              '4 x 16 GB DDR4 3200 MT/s; 2 x 8 GB DDR4 2666 MT/s'])

    def test_the_most_common_kind_comes_first_even_when_it_sorts_last(self):
        """'16 GB' sorts before '8 GB' as text, so only an ordering by count puts
        the three 8 GB modules first."""
        mem = ([{'size': '16 GB', 'type': 'DDR4'}]
               + [{'size': '8 GB', 'type': 'DDR4'}] * 3)
        out = self._lines({'memory': mem})
        self.assertIn('3 x 8 GB DDR4; 1 x 16 GB DDR4', out[0])

    def test_sizes_in_megabytes_are_added_up(self):
        out = self._lines({'memory': [{'size': '8192 MB'}, {'size': '8192 MB'}]})
        self.assertIn('16 GB installed', out[0])

    def test_one_module_is_singular(self):
        out = self._lines({'memory': [{'size': '4096 MB', 'type': 'LPDDR4'}]})
        self.assertTrue(out[0].startswith('memory: 1 module,'), out)

    def test_a_size_that_is_not_a_size_drops_the_total_not_the_line(self):
        out = self._lines({'memory': [{'size': '8 GB'}, {'size': 'Unknown'}]})
        self.assertIn('2 modules', out[0])
        self.assertNotIn('installed', out[0])

    def test_system_alone_and_memory_alone_both_work(self):
        self.assertEqual(self._lines({'system': {'manufacturer': 'QEMU',
                                                 'product': 'Standard PC'}}),
                         ['system: QEMU Standard PC'])
        self.assertEqual(len(self._lines({'memory': [{'size': '2 GB'}]})), 1)

    def test_a_system_with_only_a_maker_or_only_a_model_still_names_it(self):
        self.assertEqual(self._lines({'system': {'manufacturer': 'QEMU'}}), ['system: QEMU'])
        self.assertEqual(self._lines({'system': {'product': 'Standard PC'}}),
                         ['system: Standard PC'])

    def test_a_system_with_only_a_serial_says_nothing(self):
        self.assertEqual(self._lines({'system': {'serial': 'SN-ONLY'}}), [])

    def test_junk_gives_no_lines(self):
        for junk in (None, 'x', 7, [], {}, {'system': 'x'}, {'memory': 'x'},
                     {'memory': [None, 'x', {}]}, {'memory': [{'size': ''}]}):
            self.assertEqual(self._lines(junk), [], junk)

    def test_many_kinds_are_capped(self):
        mem = [{'size': f'{i + 1} GB', 'type': 'DDR4'} for i in range(20)]
        out = self._lines({'memory': mem})
        self.assertLessEqual(out[0].count(' x '), 6)

    def test_the_notable_signals_chunk_is_unchanged(self):
        """A healthy host still gets no hardware-health chunk, only the inventory
        one; a host with something wrong keeps both."""
        store = {'ok': {'hardware': {'system': {'manufacturer': 'A', 'product': 'B'}}},
                 'bad': {'_smart_failed': True,
                         'hardware': {'system': {'manufacturer': 'A', 'product': 'B'}}}}
        ids = sorted(d['id'] for d in rag_index.build_hardware_corpus(store, {}, now=1))
        self.assertEqual(ids, ['live/bad#hardware', 'live/bad#inventory',
                               'live/ok#inventory'])

    def test_a_record_without_a_hardware_block_adds_nothing(self):
        docs = rag_index.build_hardware_corpus({'d': {'_temp_high': True}}, {}, now=1)
        self.assertEqual([d['id'] for d in docs], ['live/d#hardware'])


if __name__ == '__main__':
    unittest.main()
