"""v6.1.2 — batch B: six container improvements.

1. **`docker system df`.** The 40 GB build-cache surprise is a homelab rite of
   passage: the box fills up and nothing says WHY, because "disk 94%" doesn't
   distinguish your data from layers of images whose containers you deleted
   months ago.
2. **Per-volume sizes** — "which volume is eating 200 GB" without SSHing in.
3. **Limits vs usage.** "Using 3 GB" means something entirely different capped at
   4 GB versus uncapped — and an uncapped container can OOM the whole host.
4. **Scheduled container restart** — "restart Home Assistant nightly at 04:00" is
   THE recurring homelab chore, and the restart action existed with no way to
   schedule it.
5. **Scheduled/on-demand prune.** Volumes are NEVER pruned: that deletes data.
6. **Compose-file drift auto-watch.** The drift engine can watch any file and the
   agent already discovers every compose file — the two halves simply were never
   connected, so a hand-edited docker-compose.yml drifted unwatched.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v612-cnt-"))
_spec = importlib.util.spec_from_file_location("api_v612_cnt", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import containers as cmod  # noqa: E402

_AGENT = (_ROOT / "client/remotepower-agent.py").read_text()
_JS = (_ROOT / "server/html/static/js/app-containers.js").read_text()


class TestContainerLimits(unittest.TestCase):
    def test_limits_ride_the_existing_batched_inspect(self):
        # No extra subprocess per container.
        self.assertIn("{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}", _AGENT)

    def test_limits_survive_normalization(self):
        # containers.py's normaliser is a whitelist — an unlisted key is dropped
        # and never reaches the UI.
        out = cmod.normalize_listing([{
            "id": "a", "name": "ha", "image": "ha", "status": "Up",
            "runtime": "docker", "mem_limit_bytes": 2147483648,
            "cpu_limit_cores": 1.5,
        }])
        self.assertEqual(out[0]["mem_limit_bytes"], 2147483648)
        self.assertEqual(out[0]["cpu_limit_cores"], 1.5)

    def test_absent_limits_mean_unlimited_not_missing(self):
        # 0 is docker's own encoding of "no limit"; a garbage value must degrade
        # to the truthful 'unlimited' rather than inventing a cap.
        out = cmod.normalize_listing([{
            "id": "b", "name": "x", "image": "y", "status": "Up",
            "runtime": "docker", "cpu_limit_cores": "nonsense",
        }])
        self.assertEqual(out[0]["mem_limit_bytes"], 0)
        self.assertEqual(out[0]["cpu_limit_cores"], 0.0)

    def test_the_ui_calls_out_an_unlimited_container(self):
        self.assertIn("unlimited", _JS)


class TestDockerDiskUsage(unittest.TestCase):
    def test_sanitizer_keeps_known_buckets_and_drops_the_rest(self):
        df = api._sanitize_docker_df({
            "images": {"size": "12.3GB", "reclaimable": "8.1GB (65%)"},
            "build_cache": {"size": "40GB", "reclaimable": "40GB (100%)"},
            "evil": {"size": "x"},
        })
        self.assertEqual(sorted(df), ["build_cache", "images"])

    def test_volumes_are_bounded_and_carry_link_counts(self):
        df = api._sanitize_docker_df({
            "volumes": [{"name": "nextcloud", "size": "210GB", "links": 1},
                        {"name": "orphan", "size": "2GB", "links": 0}],
        })
        self.assertEqual(len(df["volumes"]), 2)
        self.assertEqual(df["volumes"][1]["links"], 0)

    def test_junk_is_rejected(self):
        self.assertIsNone(api._sanitize_docker_df(None))
        self.assertIsNone(api._sanitize_docker_df("nope"))
        self.assertIsNone(api._sanitize_docker_df({}))

    def test_it_rides_a_slow_cadence_not_every_heartbeat(self):
        # docker walks the whole layer store; this is not worth paying for on
        # every beat.
        self.assertIn("DOCKER_DF_EVERY", _AGENT)
        self.assertIn("poll_count % DOCKER_DF_EVERY == 0", _AGENT)

    def test_the_previous_value_is_carried_forward_between_samples(self):
        # df arrives on ~1 in 60 container reports; blanking it in between would
        # make the panel flicker empty almost all the time.
        src = (_CGI / "api.py").read_text()
        i = src.index("if 'containers' in body:")
        block = src[i : i + 1400]
        self.assertIn("_prev.get('df')", block)

    def test_sizes_sort_by_bytes_not_lexicographically(self):
        # "9MB" sorts above "10GB" as a string — exactly backwards from what
        # someone hunting the fat host wants.
        self.assertIn("_parseSize", _JS)
        self.assertIn("_dfTotalBytes", _JS)

    def test_the_disk_column_has_a_matching_sort_key(self):
        # A data-col with no sortRows key shows an arrow that does nothing
        # (the Restore-drill bug fixed earlier this release).
        html = (_ROOT / "server/html/index.html").read_text()
        thead = html[html.index('id="containers-thead"'):]
        thead = thead[: thead.index("</thead>")]
        import re
        cols = set(re.findall(r'data-col="(\w+)"', thead))
        block = _JS[_JS.index("name: 'containers',"):]
        block = block[: block.index("match:")]
        keys = set(re.findall(r"^\s+(\w+):", block, re.M))
        self.assertEqual(cols - keys, set(), "every data-col needs a sort key")


class TestDockerPrune(unittest.TestCase):
    def test_volumes_are_NEVER_pruned(self):
        # `docker volume prune` deletes DATA. Someone clearing "disk space"
        # must not be one mis-click from wiping their Nextcloud volume.
        for cmd in api._DOCKER_PRUNE_CMDS.values():
            self.assertNotIn("volume", cmd)
        self.assertEqual(sorted(api._DOCKER_PRUNE_CMDS), ["all", "cache", "images"])

    def test_the_command_is_a_fixed_server_side_template(self):
        # No operator input reaches the shell.
        self.assertIn("docker image prune -f", api._DOCKER_PRUNE_CMDS["images"])
        self.assertIn("docker builder prune -f", api._DOCKER_PRUNE_CMDS["cache"])

    def test_the_route_is_registered(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("handle_device_docker_prune", src)
        self.assertIn("'/docker/prune'", src)


class TestScheduledContainerActions(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}})
        api.save(api.CONTAINERS_FILE,
                 {"d1": {"items": [{"name": "homeassistant", "runtime": "docker"}]}})
        api._LOAD_CACHE.clear()

    def _check(self, command):
        try:
            api._validate_scheduled_command(command, "d1")
            return None
        except api.HTTPError as e:
            return e.status

    def test_one_whitelist_shared_by_create_update_and_dispatch(self):
        # This used to be THREE copies (two _SCHED_STATIC tuples + a private
        # _ALLOWED_SCHED in process_schedule) that had to agree and could drift.
        src = (_CGI / "api.py").read_text()
        self.assertEqual(src.count("SCHED_STATIC_COMMANDS = ("), 1)
        self.assertNotIn("_ALLOWED_SCHED = (", src)
        self.assertIn("docker_prune", api.SCHED_STATIC_COMMANDS)

    def test_a_reported_container_can_be_scheduled(self):
        self.assertIsNone(self._check("container_restart:homeassistant"))
        self.assertIsNone(self._check("docker_prune"))

    def test_an_unreported_container_is_refused(self):
        # The name is validated against what the DEVICE reported — a stolen
        # token can't schedule an action against an arbitrary target.
        self.assertEqual(self._check("container_restart:not-there"), 400)
        self.assertEqual(self._check("container_restart:"), 400)

    def test_arbitrary_commands_are_still_refused(self):
        self.assertEqual(self._check("exec:rm -rf /"), 400)
        self.assertEqual(self._check("anything"), 400)

    def test_dispatch_emits_the_four_part_wire_format(self):
        # The agent parses container:<runtime>:<action>:<id> — a three-part
        # string is rejected as malformed, so the runtime must be looked up.
        src = (_CGI / "api.py").read_text()
        i = src.index("elif is_creq:")
        block = src[i : i + 1400]
        self.assertIn("f'container:{_rt}:restart:{cname}'", block)
        self.assertIn("('docker', 'podman')", block)


class TestComposeDriftAutoWatch(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {"drift_watch_compose": True})
        api._LOAD_CACHE.clear()
        self.dev = {"name": "h", "compose_projects": [
            {"path": "/opt/stack/docker-compose.yml"},
            {"path": "/srv/media/compose.yml"},
        ]}

    def test_discovered_compose_files_are_folded_in(self):
        out = api._with_compose_watch("d1", self.dev, {}, ["/etc/ssh/sshd_config"])
        self.assertIn("/opt/stack/docker-compose.yml", out)
        self.assertIn("/srv/media/compose.yml", out)

    def test_it_appends_and_never_displaces_a_curated_entry(self):
        out = api._with_compose_watch("d1", self.dev, {}, ["/etc/ssh/sshd_config"])
        self.assertEqual(out[0], "/etc/ssh/sshd_config")

    def test_off_by_default(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        out = api._with_compose_watch("d1", self.dev, {}, ["/etc/hosts"])
        self.assertEqual(out, ["/etc/hosts"])

    def test_paths_are_validated_like_the_manual_list(self):
        dev = {"compose_projects": [
            {"path": "relative/compose.yml"},          # not absolute
            {"path": "/opt/../../etc/shadow"},         # traversal
            {"path": "/good/docker-compose.yml"},
        ]}
        out = api._with_compose_watch("d1", dev, {}, [])
        self.assertEqual(out, ["/good/docker-compose.yml"])

    def test_the_list_stays_bounded(self):
        dev = {"compose_projects": [{"path": f"/s/{i}/compose.yml"} for i in range(300)]}
        out = api._with_compose_watch("d1", dev, {}, [])
        self.assertLessEqual(len(out), 80)


class TestAgentStaysInSync(unittest.TestCase):
    def test_extensionless_copy_matches(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
