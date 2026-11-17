#!/usr/bin/env python3
"""A settings document applied back keeps the credentials of the destinations the export leaves out.

With a config master key armed the destinations of a settings document are importable: the address, the header values and the Pushover user travel as ciphertext, and every
other credential (an HMAC secret, the Pushover, GitHub and Matrix tokens, a ServiceNow or Jira secret) is written as "(redacted)", to be put back from what is stored when the
document is applied. The put-back finds the stored entry by the collection's `id`, and the table of collections gave the destinations none, so nothing was ever put back: an
export applied unchanged replaced each of those credentials by the text "(redacted)". The test module that said the round trip was lossless held a URL, headers and a Pushover
user, and no destination with an `id` and a secret-named field, which is what the Settings page writes.

Held to: every credential comes back, a credential the document really changes is taken, an entry that has no id is not handed the credentials of another, and the export is still
free of every credential.
"""
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-declcred-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_ip_intel import _fresh_api  # noqa: E402

KEY = 'unit-test-master-key-8f2b1c9de4a6'
# One destination of each format that carries a credential, with every credential field set to a value that is easy to find in a document.
DESTS = [
    {'id': 'wh_gen', 'name': 'Generic', 'url': 'https://hook.example.org/in/GENERICPATH', 'format': 'generic', 'enabled': True,
     'hmac_secret': 'HMAC-SECRET-1', 'headers': {'Authorization': 'Bearer HEADER-SECRET-1'}},
    {'id': 'wh_po', 'name': 'Push', 'url': 'https://api.pushover.net/1/messages.json', 'format': 'pushover', 'enabled': True,
     'pushover_token': 'PUSHOVER-TOKEN-1', 'pushover_user': 'PUSHOVER-USER-1'},
    {'id': 'wh_gh', 'name': 'Issues', 'url': 'https://api.github.com/repos/o/r/issues', 'format': 'github', 'enabled': True, 'token': 'GITHUB-TOKEN-1'},
    {'id': 'wh_sn', 'name': 'Service desk', 'url': 'https://x.service-now.com/api/now/table/incident', 'format': 'servicenow', 'enabled': True,
     'itsm_user': 'ITSM-USER-1', 'itsm_secret': 'ITSM-SECRET-1'},
    {'id': 'wh_ji', 'name': 'Jira', 'url': 'https://x.atlassian.net/rest/api/2/issue', 'format': 'jira', 'enabled': True,
     'itsm_user': 'JIRA-USER-1', 'itsm_secret': 'JIRA-SECRET-1', 'jira_project': 'OPS', 'jira_issuetype': 'Task'},
    {'id': 'wh_tg', 'name': 'Telegram', 'url': 'https://api.telegram.org/bot1/sendMessage', 'format': 'telegram', 'enabled': True, 'telegram_chat_id': '111'},
    {'id': 'wh_mx', 'name': 'Matrix', 'url': 'https://hs.example.org/_matrix/client/v3/rooms/r/send/m.room.message', 'format': 'matrix', 'enabled': True,
     'matrix_token': 'MATRIX-TOKEN-1'},
]
# What must not be in the document. The ServiceNow and Jira user names are not here: the Settings form shows them as ordinary text, and the export carries them as it carries a
# Telegram chat id or a Jira project.
CREDENTIALS = ('HMAC-SECRET-1', 'HEADER-SECRET-1', 'PUSHOVER-TOKEN-1', 'PUSHOVER-USER-1', 'GITHUB-TOKEN-1', 'ITSM-SECRET-1', 'JIRA-SECRET-1', 'MATRIX-TOKEN-1')


class _Base(unittest.TestCase):

    def setUp(self):
        saved = os.environ.get('RP_CONFIG_KEY')
        os.environ['RP_CONFIG_KEY'] = KEY

        def back():
            if saved is None:
                os.environ.pop('RP_CONFIG_KEY', None)
            else:
                os.environ['RP_CONFIG_KEY'] = saved
        self.addCleanup(back)
        self.api = _fresh_api()
        self.api.audit_log = lambda *a, **k: None
        self.api.fire_webhook = lambda *a, **k: None
        self.assertTrue(self.api.backup_crypto.available(), 'cryptography is a dependency of the test job: without it this module proves nothing')
        self.put(copy.deepcopy(DESTS))

    def put(self, dests):
        self.api.save(self.api.CONFIG_FILE, {'webhook_urls': dests})
        self.api._LOAD_CACHE.clear()

    def stored(self):
        self.api._LOAD_CACHE.clear()
        return {d['id']: d for d in self.api.load(self.api.CONFIG_FILE)['webhook_urls'] if isinstance(d, dict) and d.get('id')}

    def apply(self, doc, **kw):
        res = self.api._declarative_apply(doc, 'tester', dry_run=False)
        self.assertTrue(res['ok'], res)
        self.assertNotIn('skipped', res['report']['webhook_destinations'], res)
        return res


class TestTheRoundTrip(_Base):

    def test_the_export_holds_no_credential_and_the_destinations_are_importable(self):
        doc = self.api._build_declarative_config()
        self.assertTrue(self.api._declarative_meta()['webhook_destinations']['importable'], 'control: with a key armed the destinations are importable')
        text = json.dumps(doc)
        for secret in CREDENTIALS + ('GENERICPATH',):
            self.assertNotIn(secret, text, secret)
        by_id = {d['id']: d for d in doc['resources']['webhook_destinations']}
        self.assertEqual(by_id['wh_gen']['hmac_secret'], '(redacted)', 'control: the credentials a name rule catches travel as the placeholder')
        self.assertEqual(by_id['wh_po']['pushover_token'], '(redacted)')
        self.assertTrue(by_id['wh_gen']['url'].startswith('enc:v2:'), 'and the address as ciphertext')

    def test_an_export_applied_back_untouched_gives_every_credential_back(self):
        before = self.stored()
        self.apply(self.api._build_declarative_config())
        after = self.stored()
        self.assertEqual(sorted(after), sorted(before), 'control: every destination is there')
        for dest_id, was in before.items():
            now = after[dest_id]
            for field in ('hmac_secret', 'headers', 'pushover_token', 'pushover_user', 'token', 'itsm_user', 'itsm_secret', 'matrix_token', 'url'):
                self.assertEqual(now.get(field), was.get(field), f'{dest_id}.{field} was changed by an import that changed nothing')
        self.assertNotIn('(redacted)', json.dumps(after), 'no placeholder was written into the settings')

    def test_an_export_applied_twice_in_a_row_changes_nothing_either_time(self):
        before = self.stored()
        for _ in range(2):
            self.apply(self.api._build_declarative_config())
            self.assertEqual(self.stored(), before)

    def test_the_credential_an_edited_document_really_changes_is_taken_and_the_others_stay(self):
        doc = self.api._build_declarative_config()
        for d in doc['resources']['webhook_destinations']:
            if d['id'] == 'wh_gen':
                d['hmac_secret'] = 'HMAC-SECRET-2'                      # a value, not the placeholder: the document says this one changed
            if d['id'] == 'wh_mx':
                d['matrix_token'] = '(redacted)'                       # the placeholder: unchanged
        self.apply(doc)
        after = self.stored()
        self.assertEqual(after['wh_gen']['hmac_secret'], 'HMAC-SECRET-2')
        self.assertEqual(after['wh_mx']['matrix_token'], 'MATRIX-TOKEN-1')
        self.assertEqual(after['wh_po']['pushover_token'], 'PUSHOVER-TOKEN-1')

    def test_a_destination_the_store_does_not_have_gets_no_credential_and_keeps_its_placeholder(self):
        doc = self.api._build_declarative_config()
        doc['resources']['webhook_destinations'].append({'id': 'wh_new', 'name': 'New', 'url': self.api._cfg_enc('https://new.example.org/hook'), 'format': 'generic',
                                                           'enabled': True, 'hmac_secret': '(redacted)'})
        self.apply(doc)
        after = self.stored()
        self.assertEqual(after['wh_new']['hmac_secret'], '(redacted)', 'nothing to put back: it stays as written, for the operator to fix')
        self.assertEqual(after['wh_gen']['hmac_secret'], 'HMAC-SECRET-1')

    def test_the_preview_lists_the_destinations_by_id(self):
        doc = self.api._build_declarative_config()
        doc['resources']['webhook_destinations'] = [d for d in doc['resources']['webhook_destinations'] if d['id'] != 'wh_tg']
        res = self.api._declarative_apply(doc, 'tester', dry_run=True)
        rep = res['report']['webhook_destinations']
        self.assertEqual(rep['detail']['removed'], ['wh_tg'], rep)
        self.assertNotIn('replace', rep, 'it is a comparison by id now, and not a replacement of the whole list')


class TestAnEntryWithNoIdIsNotHandedAnotherOnesCredentials(_Base):

    def test_two_entries_without_an_id_keep_their_placeholders_and_take_nothing_from_each_other(self):
        self.put([{'name': 'one', 'url': 'https://one.example.org/h', 'format': 'generic', 'enabled': True, 'hmac_secret': 'ONE-SECRET'},
                  {'name': 'two', 'url': 'https://two.example.org/h', 'format': 'generic', 'enabled': True, 'hmac_secret': 'TWO-SECRET'}])
        doc = self.api._build_declarative_config()
        dests = doc['resources']['webhook_destinations']
        self.assertTrue(all(d['hmac_secret'] == '(redacted)' for d in dests), 'control: both go out as the placeholder')
        self.apply(doc)
        self.api._LOAD_CACHE.clear()
        after = self.api.load(self.api.CONFIG_FILE)['webhook_urls']
        self.assertEqual(sorted(d.get('hmac_secret') for d in after), ['(redacted)', '(redacted)'],
                         'without an id there is nothing to find the entry by: neither gets the credentials of the other, and both are left as written')


if __name__ == '__main__':
    unittest.main()
