"""Log-alert acknowledgements — clear one matched LINE, not the whole rule.

The problem this exists for: a rule like `err|warn|critical|FATAL` matches a
CLASS of lines, so one routine message re-fires its alert forever. Snoozing
brings it back; deleting the rule goes blind.

What has to hold:
  * the same message with a different timestamp/pid is the SAME signature;
  * a genuinely different error is NOT, and still fires;
  * an acknowledged line stops counting toward the rule's threshold;
  * acknowledging also closes the alert that prompted it;
  * the scope of an ack is (device, unit) unless deliberately widened, and
    widening it fleet-wide takes an admin.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import logsig  # noqa: E402


class TestSignature(unittest.TestCase):
    """A signature is the line's *shape*: same message, different run."""

    A = ('2026-07-22T15:46:37+02:00 host php-fpm[137658]: [WARNING] [pool www] '
         'server reached pm.max_children setting (5), consider raising it')
    B = ('2026-07-22T16:02:11+02:00 host php-fpm[9912]: [WARNING] [pool www] '
         'server reached pm.max_children setting (5), consider raising it')
    C = ('2026-07-22T16:02:11+02:00 host php-fpm[9912]: [ERROR] failed to open '
         'stream: Permission denied')

    def test_same_message_different_pid_and_time_is_one_signature(self):
        self.assertEqual(logsig.signature(self.A), logsig.signature(self.B))

    def test_a_different_error_is_a_different_signature(self):
        self.assertNotEqual(logsig.signature(self.A), logsig.signature(self.C))

    def test_normalized_text_is_readable_to_a_human(self):
        """It is shown to the operator as "what you are clearing", so it must
        stay legible — a bare hash would make the feature unusable."""
        n = logsig.normalize(self.A)
        self.assertIn('pm.max_children', n)
        self.assertNotIn('137658', n)

    def test_varying_ids_do_not_split_one_message_into_many(self):
        for a, b in (
            ('conn from 10.0.0.4:5123 failed', 'conn from 192.168.1.9:41 failed'),
            ('req 3f2a91bc77de aborted', 'req aa10ff93b201 aborted'),
            ('job 550e8400-e29b-41d4-a716-446655440000 died',
             'job 6ba7b810-9dad-11d1-80b4-00c04fd430c8 died'),
            ('upload 12.5 MB rejected', 'upload 907 KB rejected'),
        ):
            self.assertEqual(logsig.signature(a), logsig.signature(b), a)

    def test_empty_line_never_produces_a_silencing_signature(self):
        for blank in ('', '   ', None):
            self.assertEqual(logsig.signature(blank), '')

    def test_ack_key_scopes_by_device_and_unit(self):
        self.assertNotEqual(logsig.ack_key('d1', 'u', 'sig'),
                            logsig.ack_key('d2', 'u', 'sig'))
        self.assertNotEqual(logsig.ack_key('d1', 'u1', 'sig'),
                            logsig.ack_key('d1', 'u2', 'sig'))


class _AckBase(unittest.TestCase):
    def setUp(self):
        api.save(api.LOG_ACKS_FILE, {'acks': {}})
        api.save(api.ALERTS_FILE, {'alerts': []})
        for f in (api.LOG_ACKS_FILE, api.ALERTS_FILE):
            api._invalidate_load_cache(f)

    def _ack(self, line, device_id='dev1', unit='php8.3-fpm.service'):
        sig = logsig.signature(line)
        api.save(api.LOG_ACKS_FILE, {'acks': {
            logsig.ack_key(device_id, unit, sig): {
                'device_id': device_id, 'unit': unit, 'sig': sig,
                'sample': line, 'norm': logsig.normalize(line), 'ts': 1}}})
        api._invalidate_load_cache(api.LOG_ACKS_FILE)
        return sig


class TestFiltering(_AckBase):
    NOISE = 'php-fpm[1]: [WARNING] [pool www] server reached pm.max_children setting (5)'
    NOISE2 = 'php-fpm[9]: [WARNING] [pool www] server reached pm.max_children setting (5)'
    REAL = 'php-fpm[1]: [ERROR] failed to open stream: Permission denied'

    def test_acked_line_is_dropped_and_counted(self):
        self._ack(self.NOISE)
        kept, acked = api.filter_acked_lines('dev1', 'php8.3-fpm.service',
                                             [self.NOISE2, self.REAL])
        self.assertEqual(kept, [self.REAL])
        self.assertEqual(acked, 1)

    def test_suppressed_count_is_reported_not_swallowed(self):
        """"2 hits" when 5 matched would look like a broken rule."""
        self._ack(self.NOISE)
        _, acked = api.filter_acked_lines('dev1', 'php8.3-fpm.service',
                                          [self.NOISE, self.NOISE2])
        self.assertEqual(acked, 2)

    def test_no_acks_is_a_cheap_passthrough(self):
        lines = [self.NOISE, self.REAL]
        kept, acked = api.filter_acked_lines('dev1', 'u', lines)
        self.assertEqual((kept, acked), (lines, 0))

    def test_ack_does_not_leak_to_another_host(self):
        """Clearing noise on one host must not blind the same message
        elsewhere — that is a fleet-wide silence nobody asked for."""
        self._ack(self.NOISE, device_id='dev1')
        kept, acked = api.filter_acked_lines('dev2', 'php8.3-fpm.service',
                                             [self.NOISE])
        self.assertEqual(kept, [self.NOISE])
        self.assertEqual(acked, 0)

    def test_ack_does_not_leak_to_another_unit(self):
        self._ack(self.NOISE, unit='php8.3-fpm.service')
        kept, _ = api.filter_acked_lines('dev1', 'nginx.service', [self.NOISE])
        self.assertEqual(kept, [self.NOISE])

    def test_fleet_wide_ack_covers_every_host(self):
        self._ack(self.NOISE, device_id='', unit='')
        kept, acked = api.filter_acked_lines('whatever', 'any.service',
                                             [self.NOISE2])
        self.assertEqual((kept, acked), ([], 1))

    def test_expired_ack_stops_suppressing(self):
        sig = logsig.signature(self.NOISE)
        api.save(api.LOG_ACKS_FILE, {'acks': {
            logsig.ack_key('dev1', 'u', sig): {
                'device_id': 'dev1', 'unit': 'u', 'sig': sig, 'until': 1}}})
        api._invalidate_load_cache(api.LOG_ACKS_FILE)
        kept, _ = api.filter_acked_lines('dev1', 'u', [self.NOISE])
        self.assertEqual(kept, [self.NOISE])


class TestAlertResolution(_AckBase):
    LINE = 'php-fpm[1]: [WARNING] [pool www] server reached pm.max_children setting (5)'

    def _open_alert(self, sample, device_id='dev1', unit='php8.3-fpm.service'):
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a-1', 'event': 'log_alert', 'device_id': device_id, 'ts': 1,
            'payload': {'unit': unit, 'sample': [sample]}}]})
        api._invalidate_load_cache(api.ALERTS_FILE)

    def test_acknowledging_closes_the_alert_that_prompted_it(self):
        """Otherwise the operator acknowledges the same thing twice — which is
        the friction the feature exists to remove."""
        self._open_alert(self.LINE)
        n = api._resolve_log_alerts_for_signature(
            'dev1', 'php8.3-fpm.service', logsig.signature(self.LINE), 'admin')
        self.assertEqual(n, 1)
        a = (api.load(api.ALERTS_FILE) or {})['alerts'][0]
        self.assertTrue(a.get('resolved_at'))
        self.assertEqual(a.get('resolved_by'), 'admin')

    def test_an_unrelated_alert_is_left_open(self):
        self._open_alert('php-fpm[1]: [ERROR] segfault in worker')
        n = api._resolve_log_alerts_for_signature(
            'dev1', 'php8.3-fpm.service', logsig.signature(self.LINE), 'admin')
        self.assertEqual(n, 0)
        self.assertFalse((api.load(api.ALERTS_FILE) or {})['alerts'][0].get('resolved_at'))

    def test_another_hosts_alert_is_left_open(self):
        self._open_alert(self.LINE, device_id='dev2')
        n = api._resolve_log_alerts_for_signature(
            'dev1', 'php8.3-fpm.service', logsig.signature(self.LINE), 'admin')
        self.assertEqual(n, 0)

    def test_a_fleet_wide_ack_closes_every_matching_host(self):
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a-1', 'event': 'log_alert', 'device_id': 'dev1', 'ts': 1,
             'payload': {'unit': 'u', 'sample': [self.LINE]}},
            {'id': 'a-2', 'event': 'log_alert', 'device_id': 'dev2', 'ts': 1,
             'payload': {'unit': 'u', 'sample': [self.LINE]}}]})
        api._invalidate_load_cache(api.ALERTS_FILE)
        self.assertEqual(
            api._resolve_log_alerts_for_signature('', '', logsig.signature(self.LINE), 'admin'), 2)

    def test_an_already_resolved_alert_is_not_touched_again(self):
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a-1', 'event': 'log_alert', 'device_id': 'dev1', 'ts': 1,
            'resolved_at': 99, 'resolved_by': 'someone',
            'payload': {'unit': 'u', 'sample': [self.LINE]}}]})
        api._invalidate_load_cache(api.ALERTS_FILE)
        self.assertEqual(
            api._resolve_log_alerts_for_signature('dev1', '', logsig.signature(self.LINE), 'x'), 0)
        self.assertEqual((api.load(api.ALERTS_FILE) or {})['alerts'][0]['resolved_by'], 'someone')


class TestEvidenceReachesTheFeed(unittest.TestCase):
    """The bug that started this: the Needs-Attention card said only
    "matched pattern 'err|warn|…'" because `sample` was dropped by the
    fleet-event whitelist — the one CLAUDE.md flags as silent."""

    def test_fleet_event_whitelist_carries_a_sample_line(self):
        src = (_CGI / 'api.py').read_text()
        i = src.index("for key in ('device_id', 'device_name', 'name', 'host',")
        block = src[i:i + 6000]
        self.assertIn("'sample'", block)
        self.assertIn("summary['sample']", block)

    def test_only_one_line_is_kept_so_the_feed_stays_compact(self):
        src = (_CGI / 'api.py').read_text()
        i = src.index("summary['sample']")
        self.assertIn('sm[0]', src[i:i + 120])


class TestFirePathIsFiltered(unittest.TestCase):
    """Both log-alert fire sites must filter; one of them missing means acks
    silently do nothing for half the fleet (agent journals vs syslog)."""

    def test_both_fire_sites_filter_matches(self):
        src = (_CGI / 'api.py').read_text()
        # the syslog receiver and the agent-journal ingest
        self.assertEqual(src.count('matches, _acked = filter_acked_lines('), 2)

    def test_filter_runs_before_the_threshold_comparison(self):
        src = (_CGI / 'api.py').read_text()
        for i in [i for i in range(len(src))
                  if src.startswith('matches, _acked = filter_acked_lines(', i)]:
            after = src[i:i + 900]
            self.assertIn('threshold', after)
            self.assertLess(after.index('threshold'), after.index('len(matches) >= threshold'))


class TestRuleLevelAck(_AckBase):
    """The escape hatch for an alert that captured NO line.

    This was the reported failure: `Clear line` only rendered when a sample
    existed, so the alerts actually piling up — older ones, recorded before
    matched lines were kept — were the exact ones with no way to stop them.
    """

    PAT = 'err|warn|critical|Critical|Warning|FATAL'

    def _ack_rule(self, device_id='dev1', unit='remotepower-agent.service'):
        key = logsig.ack_key(device_id, unit, logsig.rule_key(self.PAT))
        api.save(api.LOG_ACKS_FILE, {'acks': {key: {
            'device_id': device_id, 'unit': unit, 'kind': 'rule',
            'sig': logsig.rule_key(self.PAT), 'pattern': self.PAT, 'ts': 1}}})
        api._invalidate_load_cache(api.LOG_ACKS_FILE)

    def test_a_rule_key_is_stable_and_distinct_from_a_line(self):
        self.assertEqual(logsig.rule_key(self.PAT), logsig.rule_key(self.PAT))
        self.assertNotEqual(logsig.rule_key(self.PAT), logsig.signature(self.PAT))
        self.assertTrue(logsig.rule_key(self.PAT).startswith('rule:'))

    def test_an_empty_pattern_never_silences_anything(self):
        for blank in ('', '   ', None):
            self.assertEqual(logsig.rule_key(blank), '')

    def test_the_silenced_rule_stops_firing_on_that_unit(self):
        self._ack_rule()
        self.assertTrue(api.rule_acked('dev1', 'remotepower-agent.service', self.PAT))

    def test_it_does_not_silence_the_rule_on_another_unit(self):
        self._ack_rule(unit='remotepower-agent.service')
        self.assertFalse(api.rule_acked('dev1', 'nginx.service', self.PAT))

    def test_it_does_not_silence_the_rule_on_another_host(self):
        self._ack_rule(device_id='dev1')
        self.assertFalse(api.rule_acked('dev2', 'remotepower-agent.service', self.PAT))

    def test_a_different_rule_still_fires(self):
        self._ack_rule()
        self.assertFalse(api.rule_acked('dev1', 'remotepower-agent.service',
                                        'segfault|OOM'))

    def test_no_acks_means_nothing_is_silenced(self):
        self.assertFalse(api.rule_acked('dev1', 'u', self.PAT))


class TestBothFireSitesHonourRuleAcks(unittest.TestCase):
    def test_the_gate_runs_before_the_rule_is_evaluated(self):
        """A silenced rule must cost nothing and fire nothing — checking after
        the match would still burn the regex and, worse, still fire."""
        src = (_CGI / 'api.py').read_text()
        self.assertEqual(src.count('rule_acked(dev_id'), 2, 'both fire sites')
        for i in [i for i in range(len(src)) if src.startswith('rule_acked(dev_id', i)]:
            after = src[i:i + 2500]
            # the gate short-circuits immediately...
            self.assertIn('continue', after[:220])
            # ...and does so before this rule's matches are ever collected
            self.assertLess(after.index('continue'), after.index('matches ='))


class TestClearIsOfferedWhenThereIsNoLine(unittest.TestCase):
    """The UI half of the same bug: the button has to be present on an alert
    that carries no evidence, or the feature is missing where it is needed."""

    def _js(self, name):
        return (_CGI.parent / 'html' / 'static' / 'js' / name).read_text()

    def test_na_card_offers_it_without_a_sample(self):
        js = self._js('app.js')
        i = js.index('const clearLineBtn')
        blk = js[i:i + 900]
        self.assertIn("i.device_id || i.pattern", blk,
                      'the button must not require i.samples')
        self.assertIn('data-arg4', blk, 'the rule pattern must be passed through')

    def test_alert_row_offers_it_without_a_sample(self):
        js = self._js('app-alerts.js')
        i = js.index("if (a.event === 'log_alert')")
        blk = js[i:i + 900]
        self.assertIn('_logLine || _pat', blk)
        self.assertIn('Silence rule', blk)

    def test_the_coarser_choice_is_labelled_as_such(self):
        js = self._js('app-logs.js')
        self.assertIn('Silence this whole rule here', js)
        html = (_CGI.parent / 'html' / 'index.html').read_text()
        self.assertIn('log-ack-rule-warn', html)
        self.assertIn('not</strong> seen yet are hidden too', html)


class TestEvidenceSurvivesTheREALIngestPath(unittest.TestCase):
    """Drive POST /api/logs end to end, not fire_webhook directly.

    The first version of this feature was verified by calling fire_webhook with
    a hand-built payload, which proves only that the whitelist copies a key —
    it says nothing about whether the ingest path SETS that key. The path that
    matters is: agent submits lines -> rules evaluate -> event recorded ->
    Needs-Attention card renders. That is what is asserted here.
    """

    UNIT = 'apache2.service'
    PAT = 'err|warn|critical|Critical|Warning|FATAL'
    LINE = '[Tue Jul 22 17:55:01 2026] [error] client denied by server configuration'

    def setUp(self):
        import time
        self.dev = 'd-ingest'
        api.save(api.DEVICES_FILE, {self.dev: {
            'name': 'web1', 'ip': '10.0.0.4', 'token': 'tok', 'monitored': True,
            'last_seen': int(time.time()),
            'log_watch': [{'unit': self.UNIT, 'pattern': self.PAT,
                           'threshold': 1, 'severity': 'WARN'}]}})
        api.save(api.FLEET_EVENTS_FILE, {'events': []})
        api.save(api.LOG_ACKS_FILE, {'acks': {}})
        # Reset everything that can SUPPRESS a Needs-Attention row, or a stray
        # ignore/mute left by an earlier test makes this pass for the wrong
        # reason — or fail for one. (Found exactly that: green alone, red in the
        # module.)
        api.save(api.IGNORED_ITEMS_FILE, {})
        api.save(api.CONFIG_FILE, {})
        for f in (api.DEVICES_FILE, api.FLEET_EVENTS_FILE, api.LOG_ACKS_FILE,
                  api.IGNORED_ITEMS_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)
        self._orig = {n: getattr(api, n) for n in
                      ('method', 'get_json_obj', 'get_json_body', '_read_valid',
                       '_device_token_ok')}
        api._device_token_ok = lambda d, t: True
        api.method = lambda: 'POST'

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)

    def _line(self, tag):
        """A line unique to this test.

        The log buffer content-dedupes, so an identical line submitted by an
        earlier test is not "new" and correctly does not re-alert — reusing one
        literal across tests makes them pass or fail by ORDER.
        """
        return f'[Tue Jul 22 17:55:01 2026] [error] client denied by server configuration ({tag})'

    def _submit(self, *lines):
        body = {'device_id': self.dev, 'token': 'tok',
                'units': {self.UNIT: list(lines)}}
        api.get_json_obj = lambda: dict(body)
        api.get_json_body = lambda: dict(body)
        api._read_valid = lambda m: dict(body)
        try:
            api.handle_log_submit()
        except api.HTTPError:
            pass
        # load() memoises per request; this process just WROTE through another
        # code path, so the reader below would otherwise see its own first
        # (empty) snapshot forever — the documented _LOAD_CACHE trap.
        for f in (api.FLEET_EVENTS_FILE, api.DEVICES_FILE, api.ALERTS_FILE):
            api._invalidate_load_cache(f)
        return [e for e in ((api.load(api.FLEET_EVENTS_FILE) or {}).get('events') or [])
                if e.get('event') == 'log_alert']

    def test_the_matched_line_reaches_the_recorded_event(self):
        evs = self._submit(self._line('a'), '[warn] mod_fcgid: read timeout (a)')
        self.assertEqual(len(evs), 1)
        sample = (evs[0].get('payload') or {}).get('sample')
        self.assertTrue(sample, 'the feed event carries NO matched line')
        # Which matched line is kept is not ordered — only that a REAL one is.
        self.assertTrue(any('client denied' in x or 'mod_fcgid' in x for x in sample),
                        f'sample holds no submitted line: {sample}')

    def test_the_needs_attention_card_shows_the_line_not_the_regex(self):
        self._submit(self._line('b'))
        items = api._compute_attention()
        items = items if isinstance(items, list) else (items or {}).get('items') or []
        rows = [i for i in items if isinstance(i, dict) and i.get('kind') == 'log_alert']
        self.assertTrue(rows, 'no log_alert Needs-Attention item')
        summary = rows[0]['summary']
        self.assertIn('client denied', summary,
                      'the card must show the matched LINE, not the rule regex')
        self.assertNotIn('no line captured', summary)
        self.assertNotIn(self.PAT, summary, 'echoing the operator\'s own regex '
                                            'back at them is not evidence')

    def test_a_silenced_rule_produces_no_event_at_all(self):
        api.save(api.LOG_ACKS_FILE, {'acks': {
            logsig.ack_key(self.dev, self.UNIT, logsig.rule_key(self.PAT)): {
                'device_id': self.dev, 'unit': self.UNIT, 'kind': 'rule',
                'sig': logsig.rule_key(self.PAT), 'pattern': self.PAT, 'ts': 1}}})
        api._invalidate_load_cache(api.LOG_ACKS_FILE)
        self.assertEqual(self._submit(self._line('c')), [])

    def test_an_acked_LINE_stops_the_rule_reaching_its_threshold(self):
        api.save(api.LOG_ACKS_FILE, {'acks': {
            logsig.ack_key(self.dev, self.UNIT, logsig.signature(self._line('d'))): {
                'device_id': self.dev, 'unit': self.UNIT, 'kind': 'line',
                'sig': logsig.signature(self._line('d')), 'ts': 1}}})
        api._invalidate_load_cache(api.LOG_ACKS_FILE)
        self.assertEqual(self._submit(self._line('d')), [])


class TestAckAppliesAtTheDigestNotJustAtFireTime(unittest.TestCase):
    """A Needs-Attention card is rendered from the STORED event.

    So an acknowledgement that only gates the firing path leaves the card sitting
    there for the whole 24h window, and the operator reasonably concludes the
    button did nothing. (This is the recurring lesson from alert mutes, which had
    the identical bug.)
    """

    UNIT = 'apache2.service'
    PAT = 'err|warn|critical'
    LINE = '[error] client denied by server configuration'

    def setUp(self):
        import time
        self.dev = 'd-digest'
        api.save(api.DEVICES_FILE, {self.dev: {
            'name': 'web1', 'monitored': True, 'last_seen': int(time.time())}})
        api.save(api.LOG_ACKS_FILE, {'acks': {}})
        api.save(api.IGNORED_ITEMS_FILE, {})
        api.save(api.CONFIG_FILE, {})
        api.save(api.FLEET_EVENTS_FILE, {'events': [{
            'ts': int(time.time()), 'event': 'log_alert',
            'payload': {'device_id': self.dev, 'name': 'web1', 'unit': self.UNIT,
                        'pattern': self.PAT, 'count': 2, 'sample': [self.LINE]}}]})
        for f in (api.DEVICES_FILE, api.LOG_ACKS_FILE, api.FLEET_EVENTS_FILE,
                  api.IGNORED_ITEMS_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)

    def _rows(self):
        items = api._compute_attention()
        items = items if isinstance(items, list) else (items or {}).get('items') or []
        return [i for i in items if isinstance(i, dict) and i.get('kind') == 'log_alert']

    def _ack(self, sig):
        api.save(api.LOG_ACKS_FILE, {'acks': {
            logsig.ack_key(self.dev, self.UNIT, sig): {
                'device_id': self.dev, 'unit': self.UNIT, 'sig': sig, 'ts': 1}}})
        api._invalidate_load_cache(api.LOG_ACKS_FILE)

    def test_the_card_is_there_before_any_acknowledgement(self):
        self.assertEqual(len(self._rows()), 1)

    def test_silencing_the_rule_clears_the_existing_card(self):
        self._ack(logsig.rule_key(self.PAT))
        self.assertEqual(self._rows(), [])

    def test_clearing_the_captured_line_clears_the_existing_card(self):
        self._ack(logsig.signature(self.LINE))
        self.assertEqual(self._rows(), [])

    def test_an_unrelated_acknowledgement_leaves_it_alone(self):
        self._ack(logsig.signature('something else entirely'))
        self.assertEqual(len(self._rows()), 1)

    def test_an_event_with_more_lines_than_were_cleared_still_shows(self):
        """Only every captured line being cleared may hide the card — otherwise
        a still-unexplained message would vanish with it."""
        import time
        api.save(api.FLEET_EVENTS_FILE, {'events': [{
            'ts': int(time.time()), 'event': 'log_alert',
            'payload': {'device_id': self.dev, 'name': 'web1', 'unit': self.UNIT,
                        'pattern': self.PAT, 'count': 2,
                        'sample': [self.LINE, '[crit] disk I/O error']}}]})
        api._invalidate_load_cache(api.FLEET_EVENTS_FILE)
        self._ack(logsig.signature(self.LINE))
        self.assertEqual(len(self._rows()), 1)


class TestNewestOccurrenceWinsTheCard(unittest.TestCase):
    """The reported stuck-card bug.

    Event-derived Needs-Attention cards dedupe on (device, unit, pattern) so a
    rule firing 50x a day is ONE card. The store is append-ordered, so iterating
    forwards kept the OLDEST occurrence in the 24h window — and one stale event
    then shadowed every newer one for a full day. Concretely: cards frozen on a
    pre-v6.3.1 event with no matched line, while every fresh occurrence, which
    did carry the line, was thrown away as a duplicate.
    """

    UNIT = 'apache2.service'
    PAT = 'err|warn|critical'

    def setUp(self):
        import time
        self.now = int(time.time())
        self.dev = 'd-newest'
        api.save(api.DEVICES_FILE, {self.dev: {
            'name': 'web1', 'monitored': True, 'last_seen': self.now}})
        api.save(api.LOG_ACKS_FILE, {'acks': {}})
        api.save(api.IGNORED_ITEMS_FILE, {})
        api.save(api.CONFIG_FILE, {})

    def _events(self, *evs):
        api.save(api.FLEET_EVENTS_FILE, {'events': list(evs)})
        for f in (api.DEVICES_FILE, api.LOG_ACKS_FILE, api.FLEET_EVENTS_FILE,
                  api.IGNORED_ITEMS_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)

    def _ev(self, ts_offset, sample=None, count=1):
        p = {'device_id': self.dev, 'name': 'web1', 'unit': self.UNIT,
             'pattern': self.PAT, 'count': count}
        if sample:
            p['sample'] = [sample]
        return {'ts': self.now + ts_offset, 'event': 'log_alert', 'payload': p}

    def _row(self):
        items = api._compute_attention()
        items = items if isinstance(items, list) else (items or {}).get('items') or []
        rows = [i for i in items if isinstance(i, dict) and i.get('kind') == 'log_alert']
        return rows[0] if rows else None

    def test_the_newer_event_with_a_line_beats_the_older_one_without(self):
        # append order: stale first, fresh second — exactly the reported shape
        self._events(self._ev(-7200, None, count=4),
                     self._ev(-60, '[error] client denied by server config', count=2))
        row = self._row()
        self.assertIsNotNone(row)
        self.assertIn('client denied', row['summary'],
                      'the stale, line-less event is shadowing the fresh one')
        self.assertNotIn('no line captured', row['summary'])

    def test_still_exactly_one_card_for_a_noisy_rule(self):
        self._events(*[self._ev(-i * 60, f'[error] boom {i}') for i in range(30)])
        items = api._compute_attention()
        items = items if isinstance(items, list) else (items or {}).get('items') or []
        self.assertEqual(
            len([i for i in items if isinstance(i, dict) and i.get('kind') == 'log_alert']),
            1, 'dedup must still collapse a noisy rule to one card')

    def test_the_count_shown_is_the_latest_occurrences(self):
        self._events(self._ev(-7200, '[error] old', count=99),
                     self._ev(-60, '[error] new', count=2))
        self.assertIn('2 hits', self._row()['summary'])

    def test_a_lone_stale_event_is_still_shown(self):
        """Preferring the newest must not mean dropping an only occurrence."""
        self._events(self._ev(-7200, None, count=4))
        row = self._row()
        self.assertIsNotNone(row)
        self.assertIn('4 hits', row['summary'])


class TestEvidenceIsRecoveredFromTheBuffer(unittest.TestCase):
    """"no line captured" must be a last resort, not the normal outcome.

    An event should carry its own `sample`, but operators kept seeing cards with
    none — from events recorded before samples were kept, and from any path that
    fails to attach one. Rather than keep asserting the fire sites are correct,
    the digest looks the evidence up where it actually lives: the 6-hour log
    buffer holds the very lines the rule matched.
    """

    UNIT = 'apache2.service'
    PAT = 'err|warn|critical|Critical|Warning|FATAL'

    def setUp(self):
        import time
        self.now = int(time.time())
        self.dev = 'd-eviq'
        api.save(api.DEVICES_FILE, {self.dev: {
            'name': 'web1', 'monitored': True, 'last_seen': self.now}})
        api.save(api.IGNORED_ITEMS_FILE, {})
        api.save(api.CONFIG_FILE, {})
        api.save(api.LOG_ACKS_FILE, {'acks': {}})

    def _setup(self, buf, payload_extra=None):
        api.save(api.LOG_WATCH_FILE, {self.dev: {'units': {self.UNIT: buf}}} if buf else {})
        api.save(api.FLEET_EVENTS_FILE, {'events': [{
            'ts': self.now - 30, 'event': 'log_alert',
            'payload': {'device_id': self.dev, 'name': 'web1', 'unit': self.UNIT,
                        'pattern': self.PAT, 'count': 2, **(payload_extra or {})}}]})
        for f in (api.DEVICES_FILE, api.LOG_WATCH_FILE, api.FLEET_EVENTS_FILE,
                  api.IGNORED_ITEMS_FILE, api.CONFIG_FILE, api.LOG_ACKS_FILE):
            api._invalidate_load_cache(f)
        rows = [i for i in api._compute_attention()
                if isinstance(i, dict) and i.get('kind') == 'log_alert']
        return rows[0] if rows else None

    def test_a_sampleless_event_still_shows_the_matched_line(self):
        row = self._setup([{'ts': self.now - 60, 'line': '[error] AH01071: Got error'}])
        self.assertIn('AH01071', row['summary'])
        self.assertNotIn('no line captured', row['summary'])

    def test_lines_after_the_alert_are_not_passed_off_as_the_cause(self):
        """The buffer keeps filling after the rule fires; a line from ten
        minutes later is not what tripped it."""
        row = self._setup([
            {'ts': self.now - 60, 'line': '[warn] the real one'},
            {'ts': self.now + 600, 'line': '[error] a LATER line'},
        ])
        self.assertIn('the real one', row['summary'])
        self.assertNotIn('LATER', str(row.get('samples')))

    def test_a_clock_skewed_line_is_still_shown(self):
        """THE reason operators kept seeing "aged out" with the lines sitting
        right there. Buffer entries carry the timestamp parsed out of the log
        TEXT, which can sit hours from the server clock — a timezone in the
        line, or an unparseable format stamped at ingest. The time window is an
        ordering preference; it must never be the reason nothing is shown."""
        row = self._setup([{'ts': self.now + 7200, 'line': '[error] two hours ahead'}])
        self.assertIn('two hours ahead', row['summary'])

    def test_a_line_with_no_usable_timestamp_is_still_shown(self):
        row = self._setup([{'ts': 0, 'line': '[error] no timestamp at all'}])
        self.assertIn('no timestamp', row['summary'])

    def test_the_window_still_orders_when_it_can(self):
        """With in-window lines available, a later one must not be preferred."""
        row = self._setup([
            {'ts': self.now - 60, 'line': '[warn] the real one'},
            {'ts': self.now + 600, 'line': '[error] a LATER line'},
        ])
        self.assertIn('the real one', row['summary'])
        self.assertNotIn('LATER', str(row.get('samples')))

    def test_a_line_that_does_not_match_the_rule_is_not_offered(self):
        row = self._setup([{'ts': self.now - 60, 'line': 'a perfectly ordinary line'}])
        self.assertIn('aged out', row['summary'])

    def test_the_events_own_sample_still_wins(self):
        """The buffer is a fallback, never an override — the event recorded what
        actually matched at the time."""
        row = self._setup([{'ts': self.now - 60, 'line': '[error] from the buffer'}],
                          {'sample': ['[error] from the event']})
        self.assertIn('from the event', row['summary'])

    def test_an_empty_buffer_says_so_plainly(self):
        row = self._setup([])
        self.assertIn('aged out of the 6h log buffer', row['summary'])

    def test_a_broken_pattern_cannot_take_down_the_digest(self):
        row = self._setup([{'ts': self.now - 60, 'line': '[error] x'}],
                          {'pattern': '(unclosed'})
        self.assertIsNotNone(row)

    def test_the_buffer_is_read_at_most_once_per_digest(self):
        """It is the whole fleet's log buffer — re-reading it per event would be
        the most expensive thing in the digest."""
        src = (_CGI / 'api.py').read_text()
        i = src.index('def _compute_attention')
        blk = src[i:i + 60000]
        self.assertIn('_log_buf_cache = [None]', blk)
        fn = src[src.index('def _log_alert_evidence('):src.index('def _log_alert_acked(')]
        self.assertIn('if buf_cache[0] is None:', fn)


if __name__ == '__main__':
    unittest.main()
