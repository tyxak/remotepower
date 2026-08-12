"""v6.4.3 bug hunt: two recover events closed alerts that were still true.

Found by auditing all 86 recover events against the per-resource contract in
CLAUDE.md rule 3c, then DRIVING the ones whose firing site loops.

A recover event with no ``sub_match`` branch matches on device id alone. For an
event that has no device id at all — these are about the SERVER — that means it
matches every open alert of its kind, so the first resource to recover closes
the alerts of every resource that has not. And because both firing sites are
edge-triggered on a stored mark, the still-broken resource never re-fires: its
alert is gone permanently, and the subsystem it was reporting is silently down.

  * ``sidecar_down`` fires per UNIT (`for unit, what in want:` — syslogd, flowd,
    kmipd). Two down, one comes back, both alerts close. Reproduced: two open
    rows -> zero.
  * ``sweep_failing`` fires per SWEEP LABEL, across ~33 maintenance sweeps. Same
    shape, and worse: `sweep` was in neither `_ALERT_IDENTITY_FIELDS` nor the
    `_record_alert` payload whitelist, so the alert did not even record which
    sweep it was about.

TWO CANDIDATES WERE REJECTED after reading their firing sites, and they are
worth recording because the probe that "found" them was wrong, not the code:

  * ``kmip_cert_expiring`` fires ONE aggregate event for the whole expiring set
    (`'count': len(expiring)`, subject = the soonest) and recovers when the set
    empties. Firing two is a scenario the code cannot produce.
  * ``secret_exposed`` is documented at its call site as "one summary event per
    ingest (first finding + count)" — also an aggregate.

Both were only distinguishable by reading the producer. An invented fixture
shape makes a real-looking bug out of nothing.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_ROOT / "tests"))


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp()
    spec = importlib.util.spec_from_file_location("api_overresolve", str(_CGI / "api.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["api_overresolve"] = mod
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):
    EVENT = ""
    RECOVER = ""
    KEY = ""

    def setUp(self):
        self.api = _fresh_api()
        self.api.save(self.api.ALERTS_FILE, {"alerts": []})
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)

    def _fire(self, value, **extra):
        payload = {"name": "rp-server", self.KEY: value, "detail": f"{value} failed"}
        payload.update(extra)
        self.api._record_alert(self.EVENT, payload)

    def _open(self):
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)
        rows = (self.api.load(self.api.ALERTS_FILE) or {}).get("alerts") or []
        return [
            (a.get("payload") or {}).get(self.KEY)
            for a in rows
            if a.get("event") == self.EVENT and not a.get("resolved_at")
        ]

    def _recover(self, value):
        self.api.fire_webhook(self.RECOVER, {"name": "rp-server", self.KEY: value})


class TestSidecarRecoveryIsPerUnit(_Base):
    EVENT, RECOVER, KEY = "sidecar_down", "sidecar_recovered", "unit"

    def test_two_down_are_two_alerts(self):
        """Positive control: without this the assertion below could pass
        against a single coalesced row."""
        self._fire("remotepower-syslogd")
        self._fire("remotepower-flowd")
        self.assertEqual(2, len(self._open()), f"got {self._open()}")

    def test_one_recovering_leaves_the_other_open(self):
        self._fire("remotepower-syslogd")
        self._fire("remotepower-flowd")
        self._recover("remotepower-syslogd")
        self.assertEqual(
            ["remotepower-flowd"],
            self._open(),
            "syslogd coming back closed the alert for flowd, which is still "
            "down — and sidecar_down is edge-triggered on a stored mark, so it "
            "will never re-fire",
        )

    def test_the_right_one_actually_closes(self):
        """Positive control on the fix: it must still resolve its own alert."""
        self._fire("remotepower-syslogd")
        self._recover("remotepower-syslogd")
        self.assertEqual([], self._open())

    def test_the_unit_is_stored(self):
        self._fire("remotepower-flowd")
        self.assertEqual(["remotepower-flowd"], self._open())


class TestSweepRecoveryIsPerSweep(_Base):
    EVENT, RECOVER, KEY = "sweep_failing", "sweep_recovered", "sweep"

    def test_the_sweep_name_is_stored_on_the_alert(self):
        """Without this the row does not record WHICH sweep failed, and the
        recovery has nothing to match on."""
        self._fire("monitors")
        self.assertEqual(
            ["monitors"],
            self._open(),
            "the failing sweep's name is not in the _record_alert whitelist, "
            "so the alert cannot say which sweep it is about",
        )

    def test_two_failing_sweeps_are_two_alerts(self):
        self._fire("monitors")
        self._fire("integrations")
        self.assertEqual(2, len(self._open()), f"got {self._open()}")

    def test_one_recovering_leaves_the_other_open(self):
        self._fire("monitors")
        self._fire("integrations")
        self._recover("monitors")
        self.assertEqual(
            ["integrations"],
            self._open(),
            "one sweep recovering closed every other failing sweep's alert",
        )

    def test_the_right_one_actually_closes(self):
        self._fire("monitors")
        self._recover("monitors")
        self.assertEqual([], self._open())


class TestTheContractIsWiredNotJustAsserted(unittest.TestCase):
    """All three legs, checked at the source. A sub_match branch alone is a
    false fix: without the identity field the rows coalesce and there is
    nothing to discriminate; without the whitelist entry the key is never
    stored and the match silently never fires."""

    @classmethod
    def setUpClass(cls):
        import apisrc

        cls.src = apisrc.api_source()

    def test_discriminators_are_identity_fields(self):
        block = re.search(r"_ALERT_IDENTITY_FIELDS = \((.*?)\n\)", self.src, re.S)
        self.assertIsNotNone(block)
        for key in ("'unit'", "'sweep'"):
            self.assertIn(key, block.group(1))

    def test_discriminators_are_whitelisted(self):
        import srcpin

        body = srcpin.py_function(self.src, "_record_alert")
        keys = re.search(r"for key in \((.*?)\):", body, re.S)
        self.assertIsNotNone(keys, "the _record_alert whitelist moved")
        for key in ("'unit'", "'sweep'"):
            self.assertIn(key, keys.group(1))

    def test_both_recoveries_have_a_sub_match_branch(self):
        import srcpin

        body = srcpin.py_function(self.src, "_auto_resolve_alerts")
        for ev in ("sidecar_recovered", "sweep_recovered"):
            self.assertIn(ev, body, f"{ev} has no sub_match branch")


class TestTheAggregatesWereCorrectlyLeftAlone(unittest.TestCase):
    """Guards the two rejected candidates. If someone later 'fixes' these the
    same way, they will break a working aggregate — the firing sites emit one
    event for the whole set, so a per-item sub_match would never match."""

    @classmethod
    def setUpClass(cls):
        import apisrc

        cls.src = apisrc.api_source()

    def test_kmip_still_fires_one_event_for_the_whole_set(self):
        self.assertIn("'count': len(expiring)", self.src)

    def test_secret_exposed_is_still_a_per_ingest_summary(self):
        self.assertIn("'count': len(new_fps)", self.src)


if __name__ == "__main__":
    unittest.main()
