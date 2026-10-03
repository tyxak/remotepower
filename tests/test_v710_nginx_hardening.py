#!/usr/bin/env python3
"""v7.1.0: what nmap, nikto and nuclei flagged on the shipped nginx config.

Run against nginx 1.24 with the shipped files included unchanged:

  * `Server: nginx/1.24.0 (Ubuntu)` — the version on every response and error
    page. `server_tokens off` in each server block.
  * Every unknown path answered 200 with the dashboard, because `location /`
    fell back to /index.html. The app navigates by #fragment, so nothing needs
    the fallback, and it turned each scanner probe for /WEB-INF/web.xml or
    /phpmyadmin/ into a reported "found" file. Unknown paths are a 404 now.
  * `X-XSS-Protection: 1; mode=block`. The auditor it configures is gone from
    current browsers and, where it survives, the blocking mode can be abused to
    blank a page. `0`, as OWASP and MDN recommend.

The checks read the same five files the installer and the image ship.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_BLOCK_FILES = [ROOT / 'server/conf/remotepower.conf',
                      ROOT / 'docker/nginx-docker.conf',
                      ROOT / 'docker/nginx-docker-tls.conf']
LOCATION_FILES = [ROOT / 'server/conf/remotepower-locations.conf',
                  ROOT / 'docker/nginx-docker-locations.conf']
ALL = SERVER_BLOCK_FILES + LOCATION_FILES


def _live(text):
    """The config with comments removed — a commented-out line configures nothing."""
    return '\n'.join(line.split('#', 1)[0] for line in text.splitlines())


def _server_blocks(text):
    """The bodies of every top-level `server { ... }` block."""
    out, live = [], _live(text)
    for m in re.finditer(r'\bserver\s*\{', live):
        depth, i = 1, m.end()
        while depth and i < len(live):
            depth += {'{': 1, '}': -1}.get(live[i], 0)
            i += 1
        out.append(live[m.end():i - 1])
    return out


def _location_body(text, head):
    live = _live(text)
    m = re.search(re.escape(head) + r'\s*\{', live)
    if not m:
        return None
    depth, i = 1, m.end()
    while depth and i < len(live):
        depth += {'{': 1, '}': -1}.get(live[i], 0)
        i += 1
    return live[m.end():i - 1]


class TestTheFilesParse(unittest.TestCase):
    def test_every_file_has_what_the_checks_look_for(self):
        for f in SERVER_BLOCK_FILES:
            self.assertTrue(_server_blocks(f.read_text()), f'{f.name}: no server block found')
        for f in LOCATION_FILES:
            self.assertIsNotNone(_location_body(f.read_text(), 'location /'),
                                 f'{f.name}: no `location /` found')


class TestNoVersionBanner(unittest.TestCase):
    def test_every_live_server_block_turns_server_tokens_off(self):
        for f in SERVER_BLOCK_FILES:
            for body in _server_blocks(f.read_text()):
                with self.subTest(file=f.name):
                    self.assertRegex(body, r'\bserver_tokens\s+off\s*;')


class TestUnknownPathsAre404(unittest.TestCase):
    def test_the_catch_all_does_not_fall_back_to_the_dashboard(self):
        for f in LOCATION_FILES:
            body = _location_body(f.read_text(), 'location /')
            with self.subTest(file=f.name):
                m = re.search(r'try_files\s+([^;]+);', body)
                self.assertIsNotNone(m)
                self.assertEqual(m.group(1).split()[-1], '=404',
                                 'every unknown path answers 200 with index.html again')

    def test_the_app_still_has_no_path_routes(self):
        """The 404 is only safe while the dashboard routes by #fragment. A
        history.pushState route would need the fallback back."""
        js = '\n'.join(p.read_text(encoding='utf-8')
                       for p in (ROOT / 'server/html/static/js').glob('app*.js'))
        self.assertNotRegex(js, r'history\.pushState\(')


class TestXssProtectionHeader(unittest.TestCase):
    def test_the_legacy_auditor_is_switched_off(self):
        for f in ALL:
            live = _live(f.read_text())
            values = re.findall(r'add_header\s+X-XSS-Protection\s+"([^"]*)"', live)
            with self.subTest(file=f.name):
                self.assertTrue(values, 'header no longer sent at all')
                self.assertEqual(set(values), {'0'})


if __name__ == '__main__':
    unittest.main()
