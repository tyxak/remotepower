"""One click on "Scan all hosts" starts one scan. The button is wired by data-action-btn; a second listener sent two POSTs and the
second answered 409 "A scan is already running" on every click (8.0.2)."""
import unittest
from pathlib import Path

JS = Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js'
HTML = Path(__file__).resolve().parent.parent / 'server' / 'html' / 'index.html'


class ScanButtonWiredOnce(unittest.TestCase):
    def test_button_uses_the_dispatcher(self):
        self.assertRegex(HTML.read_text(), r'id="btn-trigger-cve-scan"[^>]*data-action-btn="triggerCVEScan"')

    def test_no_second_listener(self):
        for f in JS.glob('app*.js'):
            self.assertNotRegex(f.read_text(), r"getElementById\('btn-trigger-cve-scan'\)[^;\n]*addEventListener", f.name)


if __name__ == '__main__':
    unittest.main()
