#!/usr/bin/env python3
"""v4.3.0: golden-file tests for the agent's fragile text parsers.

These functions parse messy real-world tool output (apt/dnf/pacman, systemd,
openssl). They fail SILENTLY — a format drift just yields an empty list / 0 —
so a regression is invisible until a fleet stops reporting upgrades or cert
expiry. Lock the parse against representative fixtures.
"""
import importlib.machinery
import importlib.util
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'client'))
_agent_path = str(Path(__file__).parent.parent / 'client' / 'remotepower-agent')
_loader = importlib.machinery.SourceFileLoader('agent_p', _agent_path)
_spec = importlib.util.spec_from_loader('agent_p', _loader)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class TestParseUpgradableNames(unittest.TestCase):
    # `apt-get -s upgrade` lines: only "Inst <pkg> ..." rows are real upgrades.
    APT = (
        "Reading package lists...\n"
        "Building dependency tree...\n"
        "The following packages will be upgraded:\n"
        "  curl libcurl4 openssl\n"
        "Inst libcurl4 [7.81.0-1] (7.81.0-1ubuntu1.15 Ubuntu:22.04)\n"
        "Inst curl [7.81.0-1] (7.81.0-1ubuntu1.15 Ubuntu:22.04)\n"
        "Conf libcurl4 (7.81.0-1ubuntu1.15 Ubuntu:22.04)\n"
        "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04)\n"
    )
    # `dnf check-update` exit-100 listing: "name.arch  version  repo".
    DNF = (
        "Last metadata expiration check: 0:12:01 ago.\n"
        "\n"
        "kernel.x86_64                 5.14.0-427.el9    baseos\n"
        "openssl.x86_64                3.0.7-25.el9_3    appstream\n"
        "Obsoleting Packages\n"
        "  somepkg.noarch                1.0-1.el9         appstream\n"
    )
    PACMAN = (
        "curl 7.81.0-1 -> 7.82.0-1\n"
        "openssl 3.0.2-1 -> 3.0.3-1\n"
    )

    def test_apt_only_inst_lines(self):
        got = agent._parse_upgradable_names('apt', self.APT)
        self.assertEqual(got, ['curl', 'libcurl4', 'openssl'])

    def test_dnf_strips_arch_and_skips_noise(self):
        got = agent._parse_upgradable_names('dnf', self.DNF)
        # arch suffix stripped; "Last…" + indented "Obsoleting" rows skipped.
        self.assertIn('kernel', got)
        self.assertIn('openssl', got)
        self.assertNotIn('Last', got)
        self.assertNotIn('somepkg', got)   # indented continuation, skipped

    def test_pacman_first_token(self):
        got = agent._parse_upgradable_names('pacman', self.PACMAN)
        self.assertEqual(got, ['curl', 'openssl'])

    def test_empty_and_garbage_are_safe(self):
        self.assertEqual(agent._parse_upgradable_names('apt', ''), [])
        self.assertEqual(agent._parse_upgradable_names('apt', None), [])
        self.assertEqual(agent._parse_upgradable_names('unknown', 'x y z'), [])

    def test_dedup_and_sort(self):
        dup = "Inst curl [a] (b)\nInst curl [a] (b)\nInst abc [a] (b)\n"
        self.assertEqual(agent._parse_upgradable_names('apt', dup), ['abc', 'curl'])


class TestParseSystemdTimestamp(unittest.TestCase):
    def test_utc_roundtrips(self):
        # 2026-04-23 15:30:12 UTC = a fixed epoch.
        ts = agent._parse_systemd_timestamp('Thu 2026-04-23 15:30:12 UTC')
        self.assertEqual(ts, 1776958212)

    def test_missing_or_short_is_zero(self):
        self.assertEqual(agent._parse_systemd_timestamp(''), 0)
        self.assertEqual(agent._parse_systemd_timestamp('n/a'), 0)
        self.assertEqual(agent._parse_systemd_timestamp('Thu 2026-04-23'), 0)

    def test_garbage_date_is_zero(self):
        self.assertEqual(
            agent._parse_systemd_timestamp('Xxx 2026-13-99 99:99:99 UTC'), 0)


class TestParseOpensslDate(unittest.TestCase):
    def test_gmt_date_to_epoch(self):
        # openssl `notAfter` format with the double-space before single-digit day.
        ts = agent._parse_openssl_date('Jun  6 12:00:00 2026 GMT')
        self.assertEqual(ts, 1780747200)   # 2026-06-06 12:00:00 UTC

    def test_notafter_prefix_not_handled_by_this_fn(self):
        # The caller strips "notAfter="; bare junk yields 0, not a crash.
        self.assertEqual(agent._parse_openssl_date('not a date'), 0)

    def test_two_digit_day(self):
        ts = agent._parse_openssl_date('Dec 31 23:59:59 2025 GMT')
        self.assertEqual(ts, 1767225599)


if __name__ == '__main__':
    unittest.main()
