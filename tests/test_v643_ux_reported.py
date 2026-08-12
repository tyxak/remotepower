"""v6.4.3: four defects reported from real operator use of the Self page.

Each one is the same shape: the page tells the operator that *something* needs
attention without telling them WHICH thing, WHERE to go, or letting them say
"I know, stop counting it".

  1. "Running — 1 of 3 exporter(s) silent" — but which one? The payload carried
     COUNTS only, so the UI could not name the silent exporter even in principle.
  2. "the daemon is up but its source map is empty" on a receiver the operator
     is not using yet counted toward "needing a look" with no way to silence it.
  3. The Linux LUKS check warned "no encrypted volume found" on every host, by
     default. Unencrypted root is the Linux norm, not a finding.
  4. No path from either receiver row to the inbound tokens that feed it.

The UI assertions EXECUTE `_selfSidecarRows` / `_renderSelfReadiness` in node
against fixture payloads rather than grepping the source, because a grep proves
a line exists and never that it runs.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / "server" / "html" / "static" / "js" / "app-self.js"


def _have_node():
    try:
        subprocess.run(["node", "--version"], capture_output=True, timeout=10)
        return True
    except Exception:
        return False


def _sidecar_rows(subsystems, mutes=None):
    """Run the real row builder in node and return its row descriptors."""
    payload = {"subsystems": subsystems}
    if mutes is not None:
        payload["readiness_mutes"] = mutes
    script = (
        "const fs=require('fs');\n"
        "globalThis.timeAgo=(t,o)=>t?('some time ago'):((o&&o.empty)||'never');\n"
        "globalThis.escHtml=s=>String(s);\n"
        "const src=fs.readFileSync(%s,'utf8');\n"
        "const rows=eval(src+'\\n;_selfSidecarRows('+%s+')');\n"
        "console.log(JSON.stringify(rows));\n"
        % (json.dumps(str(_JS)), json.dumps(json.dumps(payload)))
    )
    p = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise AssertionError("node failed:\n" + (p.stderr or "")[-2000:])
    return json.loads(p.stdout)


def _row(rows, label):
    for r in rows:
        if r.get("label") == label:
            return r
    raise AssertionError(f"no {label!r} row in {[r.get('label') for r in rows]}")


# ── 1 + 4: name the silent exporters, and link to them ─────────────────────
@unittest.skipUnless(_have_node(), "node unavailable")
class TestSilentExportersAreNamed(unittest.TestCase):
    THREE = {
        "flow": {
            "unit": "active",
            "sources": 3,
            "last_ingest": 1_700_000_000,
            "stale_sources": 1,
            "never_seen": 1,
            "stale": [{"label": "edge-rtr2", "last_seen": None}],
        }
    }

    def test_the_silent_exporter_is_named(self):
        r = _row(_sidecar_rows(self.THREE), "Flow receiver")
        self.assertIn(
            "edge-rtr2",
            r["detail"],
            "the row counts the silent exporters but still will not name them — "
            f"detail was {r['detail']!r}",
        )

    def test_a_never_seen_exporter_says_so_per_name(self):
        r = _row(_sidecar_rows(self.THREE), "Flow receiver")
        i = r["detail"].index("edge-rtr2")
        self.assertIn(
            "never",
            r["detail"][i : i + 60],
            "an exporter that has NEVER exported must say so next to its own "
            "name — a bare timestamp-less name reads as merely late",
        )

    def test_the_row_links_to_the_tokens_that_feed_it(self):
        """Item 4. Naming the exporter is only half an answer if the operator
        then has to hunt for where exporters are enrolled."""
        for fx, label in (
            (self.THREE, "Flow receiver"),
            ({"flow": {"unit": "active", "sources": 0}}, "Flow receiver"),
            ({"syslog": {"unit": "active", "sources": 0}}, "Syslog receiver"),
        ):
            r = _row(_sidecar_rows(fx), label)
            self.assertTrue(
                (r.get("link") or {}).get("action"),
                f"{label} in state {r['status']!r} offers no link to its " "inbound tokens",
            )

    def test_a_healthy_receiver_is_not_decorated_with_names(self):
        """Positive control on the negative direction: the naming must appear
        only in the branch that has something to name."""
        r = _row(
            _sidecar_rows({"flow": {"unit": "active", "sources": 2, "last_ingest": 1_700_000_000}}),
            "Flow receiver",
        )
        self.assertEqual("ok", r["state"])
        self.assertNotIn("never", r["detail"])


# ── 2: mute a readiness row ────────────────────────────────────────────────
@unittest.skipUnless(_have_node(), "node unavailable")
class TestReadinessRowsCanBeMuted(unittest.TestCase):
    EMPTY_MAP = {"syslog": {"unit": "active", "sources": 0}}

    def test_unmuted_the_row_needs_a_look(self):
        """Positive control — without this the mute assertion below could pass
        against a row that was never a warning in the first place."""
        r = _row(_sidecar_rows(self.EMPTY_MAP), "Syslog receiver")
        self.assertEqual("warn", r["state"])

    def test_every_row_carries_a_stable_mute_key(self):
        rows = _sidecar_rows(self.EMPTY_MAP)
        for r in rows:
            self.assertTrue(
                r.get("key"),
                f"row {r['label']!r} has no key, so it cannot be muted or "
                "remembered across reloads",
            )
        keys = [r["key"] for r in rows]
        self.assertEqual(len(keys), len(set(keys)), f"duplicate row keys: {keys}")

    def test_a_muted_row_stops_counting_as_needing_a_look(self):
        rows = _sidecar_rows(self.EMPTY_MAP)
        key = _row(rows, "Syslog receiver")["key"]
        muted = _row(_sidecar_rows(self.EMPTY_MAP, mutes=[key]), "Syslog receiver")
        self.assertNotIn(
            muted["state"],
            ("warn", "bad"),
            "the row is still amber after being muted, so it still counts "
            "toward the 'needing a look' tally",
        )

    def test_a_muted_row_says_it_is_muted_and_offers_the_way_back(self):
        rows = _sidecar_rows(self.EMPTY_MAP)
        key = _row(rows, "Syslog receiver")["key"]
        muted = _row(_sidecar_rows(self.EMPTY_MAP, mutes=[key]), "Syslog receiver")
        self.assertIn("mute", json.dumps(muted).lower())

    def test_an_unrelated_mute_does_not_silence_the_row(self):
        r = _row(
            _sidecar_rows(self.EMPTY_MAP, mutes=["not-a-real-row-key"]),
            "Syslog receiver",
        )
        self.assertEqual("warn", r["state"])


try:
    from test_v622_alert_params import _SaveBase
except Exception:  # pragma: no cover - harness unavailable in a stripped tree
    _SaveBase = None


@unittest.skipIf(_SaveBase is None, "config-save harness unavailable")
class TestReadinessMutesPersist(_SaveBase or unittest.TestCase):
    """A mute that does not survive a reload is not a mute. Drives the REAL
    handle_config_save, because the save whitelist is a fixed list of keys and a
    key missing from it is dropped silently — the toast still says success."""

    def test_the_list_persists(self):
        cfg = self._save({"self_readiness_mutes": ["syslog-receiver"]})
        self.assertEqual(
            ["syslog-receiver"],
            cfg.get("self_readiness_mutes"),
            "the mute list did not persist (save-whitelist gotcha)",
        )

    def test_clearing_it_persists_too(self):
        self._save({"self_readiness_mutes": ["syslog-receiver"]})
        cfg = self._save({"self_readiness_mutes": []})
        self.assertEqual([], cfg.get("self_readiness_mutes"))

    def test_junk_keys_are_dropped_not_stored(self):
        cfg = self._save(
            {
                "self_readiness_mutes": [
                    "flow-receiver",
                    "../../etc/passwd",
                    "<script>x</script>",
                    "UPPER",
                    "",
                    42,
                    {"nope": 1},
                ]
            }
        )
        self.assertEqual(["flow-receiver"], cfg.get("self_readiness_mutes"))

    def test_a_non_list_body_does_not_wedge_the_save(self):
        cfg = self._save({"self_readiness_mutes": "flow-receiver"})
        self.assertEqual([], cfg.get("self_readiness_mutes"))

    def test_the_list_is_bounded(self):
        cfg = self._save({"self_readiness_mutes": [f"row-{i}" for i in range(200)]})
        self.assertLessEqual(len(cfg.get("self_readiness_mutes") or []), 64)


class TestSelfStatusDeliversTheMutes(unittest.TestCase):
    def test_the_payload_carries_the_list(self):
        import apisrc

        self.assertIn(
            "out['readiness_mutes'] = list(_config_ro().get('self_readiness_mutes')",
            apisrc.api_source(),
            "the client cannot honour a mute it is never told about",
        )


# ── 3: the LUKS check is opt-in ────────────────────────────────────────────
class TestLuksCheckIsOptIn(unittest.TestCase):
    SI = {"disk_encryption": {"encrypted": False}}

    def _checks(self, **kw):
        import importlib.util
        import sys

        if "checks" not in sys.modules:
            spec = importlib.util.spec_from_file_location(
                "checks", _ROOT / "server" / "cgi-bin" / "checks.py"
            )
            mod = importlib.util.module_from_spec(spec)
            sys.modules["checks"] = mod
            spec.loader.exec_module(mod)
        checks = sys.modules["checks"]
        rows = checks._host_checks("d1", {"sysinfo": self.SI}, now=1_700_000_000, **kw)
        return {r["key"] for r in rows}

    def test_off_by_default(self):
        self.assertNotIn(
            "linux_disk_encryption",
            self._checks(),
            "an unencrypted Linux root is the norm, not a finding — the check "
            "must not warn until the operator asks for it",
        )

    def test_on_when_the_operator_asks(self):
        """Positive control: the row must still be reachable, or the fix above
        is indistinguishable from deleting the feature."""
        self.assertIn("linux_disk_encryption", self._checks(disk_encryption=True))

    def test_an_encrypted_host_is_also_silent_by_default(self):
        """The check is off, not merely downgraded — an opt-in check should not
        emit an OK row either."""
        import sys

        self._checks()
        checks = sys.modules["checks"]
        rows = checks._host_checks(
            "d1",
            {"sysinfo": {"disk_encryption": {"encrypted": True}}},
            now=1_700_000_000,
        )
        self.assertNotIn("linux_disk_encryption", {r["key"] for r in rows})

    def test_the_config_key_reaches_the_engine(self):
        import apisrc

        src = apisrc.api_source()
        self.assertIn("disk_encryption_checks", src)
        self.assertIn("'disk_encryption'", src)

    def test_the_toggle_persists(self):
        import apisrc

        src = apisrc.api_source()
        self.assertIn("'disk_encryption_checks' in body", src)
        html = (_ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")
        self.assertIn("cfg-disk-encryption-checks", html)
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("disk_encryption_checks", js)


class TestAFlowTokenThatCanNeverReceive(unittest.TestCase):
    """The sidecar — not the router — is what POSTs. `remotepower-flowd` builds
    its map as `if ip and tok: m[str(ip)] = tok`, so a flow token whose device
    carries no `ip`, or that is disabled, is dropped from the map and can never
    receive a datagram no matter what the router does. That is a broken
    configuration, not a quiet exporter, and saying "never exported" blames the
    wrong end of the wire.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import sys
        import tempfile as _tf

        os.environ["RP_DATA_DIR"] = _tf.mkdtemp()
        spec = importlib.util.spec_from_file_location(
            "api_flowdiag", str(_ROOT / "server" / "cgi-bin" / "api.py")
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["api_flowdiag"] = mod
        spec.loader.exec_module(mod)
        cls.api = mod

    def _flow(self, tokens, devices):
        api = self.api
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": tokens})
        api.save(api.DEVICES_FILE, devices)
        api._invalidate_load_cache(api.INBOUND_WEBHOOKS_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)
        import time as _t

        return api._subsystems_status(int(_t.time())).get("flow") or {}

    def _entry(self, tokens, devices, label):
        for e in self._flow(tokens, devices).get("stale") or []:
            if e.get("label") == label:
                return e
        raise AssertionError(f"{label!r} not reported stale")

    def test_a_device_with_no_ip_is_reported_as_unmappable(self):
        e = self._entry(
            [{"id": "t1", "kind": "flow", "label": "core-rtr1", "scope_device_id": "d1"}],
            {"d1": {"name": "core-rtr1"}},
            "core-rtr1",
        )
        self.assertTrue(
            e.get("no_ip"),
            "the sidecar maps datagrams by device IP, so a device with none can "
            "never receive flow — the row must say so instead of implying the "
            "router went quiet",
        )

    def test_a_device_with_an_ip_is_not_flagged(self):
        """Positive control: the flag must distinguish, not fire on everything."""
        e = self._entry(
            [{"id": "t1", "kind": "flow", "label": "core-rtr1", "scope_device_id": "d1"}],
            {"d1": {"name": "core-rtr1", "ip": "10.0.0.1"}},
            "core-rtr1",
        )
        self.assertFalse(e.get("no_ip"))
        self.assertFalse(e.get("disabled"))

    def test_a_disabled_token_is_reported_as_disabled(self):
        e = self._entry(
            [
                {
                    "id": "t1",
                    "kind": "flow",
                    "label": "core-rtr1",
                    "scope_device_id": "d1",
                    "enabled": False,
                }
            ],
            {"d1": {"name": "core-rtr1", "ip": "10.0.0.1"}},
            "core-rtr1",
        )
        self.assertTrue(e.get("disabled"))

    def test_a_token_scoped_to_a_missing_device_is_flagged(self):
        e = self._entry(
            [{"id": "t1", "kind": "flow", "label": "ghost", "scope_device_id": "gone"}],
            {"d1": {"name": "core-rtr1", "ip": "10.0.0.1"}},
            "ghost",
        )
        self.assertTrue(e.get("no_ip") or e.get("no_device"))

    def test_syslog_reports_the_same_defect(self):
        """remotepower-syslogd maps by device ip with the identical
        `if not ip: continue`, so a syslog source is dead in exactly the same
        way — and until now the card said "N source(s)" and nothing else."""
        api = self.api
        api.save(
            api.INBOUND_WEBHOOKS_FILE,
            {
                "tokens": [
                    {"id": "s1", "kind": "syslog", "label": "fw01", "scope_device_id": "d1"},
                    {"id": "s2", "kind": "syslog", "label": "sw02", "scope_device_id": "d2"},
                ]
            },
        )
        api.save(
            api.DEVICES_FILE,
            {"d1": {"name": "fw01"}, "d2": {"name": "sw02", "ip": "10.0.0.2"}},
        )
        api._invalidate_load_cache(api.INBOUND_WEBHOOKS_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)
        import time as _t

        sy = api._subsystems_status(int(_t.time())).get("syslog") or {}
        bad = sy.get("unmappable") or []
        self.assertEqual(
            ["fw01"],
            [e.get("label") for e in bad],
            "the source with no device IP can never receive a line, and the "
            "one with an IP must not be flagged alongside it",
        )


@unittest.skipUnless(_have_node(), "node unavailable")
class TestTheRowExplainsTheUnmappableCase(unittest.TestCase):
    def _detail(self, entry):
        return _row(
            _sidecar_rows(
                {
                    "flow": {
                        "unit": "active",
                        "sources": 2,
                        "last_ingest": 1_700_000_000,
                        "stale_sources": 1,
                        "never_seen": 1,
                        "stale": [entry],
                    }
                }
            ),
            "Flow receiver",
        )["detail"]

    def test_it_names_the_cause_it_can_actually_see(self):
        d = self._detail({"label": "core-rtr1", "last_seen": None, "no_ip": True})
        self.assertIn("core-rtr1", d)
        self.assertIn("no IP", d)

    def test_a_disabled_token_says_disabled(self):
        d = self._detail({"label": "core-rtr1", "last_seen": None, "disabled": True})
        self.assertIn("disabled", d.lower())

    def test_an_ordinary_silent_exporter_is_unchanged(self):
        """Positive control on the negative direction — the new wording must
        not leak onto a plain quiet exporter."""
        d = self._detail({"label": "core-rtr1", "last_seen": None})
        self.assertIn("core-rtr1", d)
        self.assertNotIn("no IP", d)
        self.assertNotIn("disabled", d.lower())

    def _syslog(self, sy):
        return _row(_sidecar_rows({"syslog": sy}), "Syslog receiver")

    def test_a_dead_syslog_source_is_named_on_the_row(self):
        r = self._syslog(
            {
                "unit": "active",
                "sources": 2,
                "last_ingest": 1_700_000_000,
                "unmappable": [{"label": "fw01", "no_ip": True}],
            }
        )
        self.assertIn("fw01", r["detail"])
        self.assertEqual(
            "warn",
            r["state"],
            "a source that can never receive a line is not a healthy receiver",
        )

    def test_a_healthy_syslog_receiver_is_untouched(self):
        """Positive control: the branch must still reach 'ok'."""
        r = self._syslog({"unit": "active", "sources": 2, "last_ingest": 1_700_000_000})
        self.assertEqual("ok", r["state"])
        self.assertNotIn("cannot receive", r["detail"])


class TestFlowPayloadNamesTheStaleExporters(unittest.TestCase):
    """Server side of item 1: `_subsystems_status` has to put the names in the
    payload at all. Until it does, no UI can render them."""

    def test_the_payload_carries_names_not_only_counts(self):
        import apisrc

        src = apisrc.api_source()
        self.assertIn("'stale': _fstale_named", src)

    def test_the_name_list_is_bounded(self):
        """A fleet with 400 exporters must not put 400 names in a status card."""
        import apisrc
        import re

        src = apisrc.api_source()
        self.assertTrue(
            re.search(r"_fstale_named\[:\d+\]", src),
            "the stale-exporter name list is unbounded",
        )


if __name__ == "__main__":
    unittest.main()
