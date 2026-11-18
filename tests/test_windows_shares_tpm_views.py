"""What the host drawer and the Fleet Query page say about the shares and the TPM of a Windows host.

The two functions that build the drawer's text run under node, taken out of the real script with the helpers they call; the rendered pages (the pills, the
chips, the criteria) are measured in test_windows_host_e2e. Here:

  * the TPM line for each answer a host can give, and none for a host that never said;
  * the chips of the shares: names, paths and descriptions are escaped, the box says how many are not listed, an encrypted share says so;
  * the new phrases are in the dictionary in all six languages and the real engine translates them;
  * the page has the two pills and the two criteria.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-shares-tpm-views-"))

import i18n_engine  # noqa: E402
import srcpin  # noqa: E402

_APP = (_JS / "app.js").read_text(encoding="utf-8")
_HTML = (ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")


def node(script):
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def preamble():
    return "\n".join([
        re.search(r"^function escHtml\(.*$", _APP, re.M).group(0),
        re.search(r"^function escAttr\(.*$", _APP, re.M).group(0),
        srcpin.js_function(_APP, "_tpmText"),
        srcpin.js_function(_APP, "_sharesChips"),
    ])


def tpm(t):
    return node(preamble() + "\nconsole.log(JSON.stringify({v: _tpmText(%s)}));" % json.dumps(t))["v"]


def chips(sh):
    return node(preamble() + "\nconsole.log(JSON.stringify({v: _sharesChips(%s)}));" % json.dumps(sh))["v"]


class TestTheTpmLine(unittest.TestCase):
    def test_a_ready_tpm(self):
        self.assertEqual(tpm({"present": True, "ready": True, "enabled": True, "spec": "2.0"}), "present · ready · spec 2.0")

    def test_a_tpm_that_is_not_ready(self):
        self.assertEqual(tpm({"present": True, "ready": False, "enabled": True}), "present · not ready")

    def test_a_host_with_no_tpm(self):
        self.assertEqual(tpm({"present": False, "ready": False, "enabled": False}), "none")
        self.assertEqual(tpm({"present": False}), "none")

    def test_a_tpm_that_is_switched_off(self):
        self.assertEqual(tpm({"present": True, "ready": False, "enabled": False, "spec": "1.2"}), "present · not ready · disabled · spec 1.2")

    def test_only_what_the_host_said(self):
        self.assertEqual(tpm({"spec": "2.0"}), "spec 2.0")
        self.assertEqual(tpm({"present": True}), "present")

    def test_a_host_that_never_said_has_no_line(self):
        for t in (None, {}, "x", 5, [], {"spec": ""}, {"present": "True"}, {"spec": 2}):
            self.assertIsNone(tpm(t), t)


class TestTheSharesChips(unittest.TestCase):
    SH = {"count": 2, "admin_count": 3, "items": [
        {"name": "Data", "path": "D:\\Data", "description": "Team data", "encrypted": True},
        {"name": "Public", "path": "C:\\Public", "description": "", "encrypted": False}]}

    def test_each_share_is_a_chip_with_its_name_and_path(self):
        html = chips(self.SH)
        self.assertIn('class="mb-8 scroll-cap-sm"', html)
        self.assertEqual(html.count('class="cmd-badge fs-11"'), 2)
        self.assertIn("Data <code>D:\\Data</code>", html)
        self.assertIn("Public <code>C:\\Public</code>", html)

    def test_the_description_and_the_path_are_in_the_tip(self):
        self.assertIn('title="D:\\Data — Team data"', chips(self.SH))
        self.assertIn('title="C:\\Public"', chips(self.SH))

    def test_an_encrypted_share_says_so_and_another_does_not(self):
        html = chips(self.SH)
        self.assertEqual(html.count('<span class="c-green">encrypted</span>'), 1)
        self.assertLess(html.index("encrypted"), html.index("Public"))

    def test_the_shares_that_are_not_listed_are_counted(self):
        html = chips(dict(self.SH, count=130))
        self.assertIn('<span class="hint">+128</span>', html)
        self.assertNotIn("hint", chips(self.SH))

    def test_nothing_the_host_chose_becomes_markup(self):
        hostile = {"count": 1, "items": [{"name": "<img src=x onerror=alert(1)>", "path": '"><script>x</script>',
                                          "description": '" onmouseover="alert(1)', "encrypted": "yes"}]}
        html = chips(hostile)
        self.assertNotIn("<img", html)
        self.assertNotIn("<script", html)
        self.assertNotRegex(html, r'title="[^"]*"[^>]*onmouseover')
        self.assertNotIn("encrypted", html, "encrypted is a word only for a share that is true")

    def test_a_host_with_no_list_has_no_chips(self):
        for sh in (None, {}, {"items": []}, {"items": "x"}, "x", 5, [], {"count": 4, "admin_count": 3, "items": []}):
            self.assertEqual(chips(sh), "", sh)

    def test_a_count_that_is_not_a_number_adds_no_more(self):
        self.assertNotIn("hint", chips({"count": "many", "items": self.SH["items"]}))


class TestThePage(unittest.TestCase):
    def test_the_drawer_has_the_two_pills_and_the_chips(self):
        fn = srcpin.js_function(_APP, "_loadAuditSection")
        self.assertIn("['Shares', (si.shares && typeof si.shares.count === 'number')", fn)
        self.assertIn("['TPM', _tpmText(si.tpm)],", fn)
        self.assertIn("h += _sharesChips(si.shares);", fn)

    def test_the_criteria_are_in_the_security_posture_group(self):
        group = re.search(r"<summary>Security posture.*?</details>", _HTML, re.S).group(0)
        self.assertIn('id="fq-shares"', group)
        self.assertIn('id="fq-tpm"', group)
        self.assertIn('<option value="missing">no TPM</option><option value="present">TPM present</option><option value="ready">TPM ready</option>'
                      '<option value="notready">not ready</option>', group)


class TestTheWords(unittest.TestCase):
    PHRASES = ["Shares", "Shares >", "TPM", "no TPM", "TPM present", "TPM ready", "not ready", "encrypted"]
    # TPM is the same word in every language
    SAME_IN_LANGUAGE = {lang: {"TPM"} for lang in i18n_engine.LANGS}

    def test_every_phrase_is_a_key_with_all_six_languages(self):
        rows = i18n_engine.dict_rows()
        missing = {p: sorted(set(i18n_engine.LANGS) - rows.get(p, set())) for p in self.PHRASES if set(i18n_engine.LANGS) - rows.get(p, set())}
        self.assertEqual(missing, {})

    def test_the_phrases_are_the_ones_the_page_has(self):
        self.assertIn('<label class="form-label">Shares &gt;</label>', _HTML)
        self.assertIn('<label class="form-label">TPM</label>', _HTML)
        self.assertIn('aria-label="Shares &gt;"', _HTML)
        self.assertIn('aria-label="TPM"', _HTML)
        self.assertIn('<span class="c-green">encrypted</span>', srcpin.js_function(_APP, "_sharesChips"))
        self.assertIn("'Shares'", srcpin.js_function(_APP, "_loadAuditSection"))

    def test_the_real_engine_translates_each(self):
        unchanged = i18n_engine.unchanged_by_engine(self.PHRASES)
        if unchanged is None:
            self.skipTest("node is not installed")
        left = {lang: sorted(set(found) - self.SAME_IN_LANGUAGE.get(lang, set())) for lang, found in unchanged.items()}
        self.assertEqual({lang: found for lang, found in left.items() if found}, {})
        for lang, words in self.SAME_IN_LANGUAGE.items():
            self.assertEqual(sorted(words & set(unchanged[lang])), sorted(words), "an exemption that is not one any more")


if __name__ == "__main__":
    unittest.main()
