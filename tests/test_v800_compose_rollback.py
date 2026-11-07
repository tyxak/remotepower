#!/usr/bin/env python3
"""8.0.0: the agent notes the images a compose update replaces, and can put them back (`compose:rollback:<dir>`).

The agent's own functions are driven here (client/remotepower-agent.py, imported and called as the dispatcher calls them) against a stand-in for
the docker command line (tests/fake_docker.py). The stand-in is not Docker: it models images, tags, the containers of a project and the one rule
the rollback depends on, that `up -d` recreates a container whose image is not the one its reference now points at. No real daemon was used (the
docker client is installed on the development machine, its daemon is not running and the compose plugin is not installed).

What must hold, each with a test that fails when it does not:
  * `compose:update` leaves a private note of the images before and after it, only when it changed something, and a failure to write the note never
    blocks the update;
  * `compose:rollback` puts the changed references back on the images they had and runs `up -d --pull never`, never `pull`;
  * it changes nothing, and says why, when there is no note, when the project runs something else than the note says it ran after the update,
    when a previous image is gone, or when only digest-pinned images moved;
  * nothing in a note or a container's reference can become an option of `docker tag`;
  * the whole round: the server queues the rollback for an unhealthy update, the agent runs that exact command, the host reports, the server says
    rolled back.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from importlib import machinery, util
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_docker  # noqa: E402
from fake_docker import FakeDocker  # noqa: E402
from test_v742_container_recovery import api  # noqa: E402
from test_v800_image_autoupdate import POLICY_ON, REG, box, _seed  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "client" / "remotepower-agent.py"
OLD = "sha256:" + "a" * 64
NEW = REG                               # the image the registry ships, as the report names it: the digest and the id are the same text here
DB = "sha256:" + "c" * 64
OTHER = "sha256:" + "d" * 64
WEB = "ghcr.io/acme/web:1"
DBREF = "docker.io/other/db:2"
_AGENT = {}


def setUpModule():
    loader = machinery.SourceFileLoader("rp_agent_compose_rollback", str(AGENT))
    spec = util.spec_from_loader("rp_agent_compose_rollback", loader)
    mod = util.module_from_spec(spec)                       # type: ignore[arg-type]
    loader.exec_module(mod)                                  # type: ignore[union-attr]
    _AGENT["m"] = mod


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="rp-rollback-")))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.agent = _AGENT["m"]
        self.fake = FakeDocker(self.tmp / "fake")
        self.project = self.tmp / "srv-web"
        self.project.mkdir()
        (self.project / "docker-compose.yml").write_text("services: {}\n")
        self.state_dir = self.tmp / "state"
        self.state_dir.mkdir()
        self.use_env(self.fake.env())
        patch = mock.patch.object(self.agent, "STATE_DIR", self.state_dir)
        patch.start()
        self.addCleanup(patch.stop)
        self.plant()

    def use_env(self, env):
        patch = mock.patch.dict(os.environ, env)
        patch.start()
        self.addCleanup(patch.stop)
        cache = self.agent._which.__defaults__[0]
        cache.clear()
        self.addCleanup(cache.clear)

    def plant(self, **changes):
        """web (on the old image, the registry has a newer one) and db (current) in the project directory."""
        state = {
            "images": {OLD: {}, DB: {}},
            "tags": {WEB: OLD, DBREF: DB},
            "registry": {WEB: NEW},
            "projects": {str(self.project): {"web": WEB, "db": DBREF}},
            "containers": {
                "1" * 64: {"image": OLD, "ref": WEB, "service": "web", "dir": str(self.project), "oneoff": False},
                "2" * 64: {"image": DB, "ref": DBREF, "service": "db", "dir": str(self.project), "oneoff": False}},
            "fail": {},
        }
        state.update(changes)
        self.fake.write(state)

    def run_compose(self, action, directory=None):
        return self.agent._run_compose("compose:%s:%s" % (action, directory or self.project))

    def image_of(self, service):
        return [c["image"] for c in self.fake.read()["containers"].values() if c["service"] == service]

    def note_path(self):
        return self.agent._compose_record_path(self.project)

    def update(self):
        res = self.run_compose("update")
        self.assertEqual(res["rc"], 0, res)
        return res

    def calls_since(self, mark):
        return self.fake.calls()[mark:]


class TestTheNoteOfAnUpdate(_Base):

    def test_an_update_that_moves_an_image_leaves_a_note_of_the_images_before_and_after(self):
        self.update()
        self.assertEqual(self.image_of("web"), [NEW])
        self.assertEqual(self.image_of("db"), [DB], "the service that did not move was not recreated")
        rec = self.agent._compose_record_read(self.project)
        self.assertEqual(rec["before"], [{"service": "db", "ref": DBREF, "id": DB}, {"service": "web", "ref": WEB, "id": OLD}])
        self.assertEqual(rec["after"], [{"service": "db", "ref": DBREF, "id": DB}, {"service": "web", "ref": WEB, "id": NEW}])

    def test_the_note_is_private_and_lives_in_the_state_directory_under_a_name_that_is_not_the_path(self):
        self.update()
        path = self.note_path()
        self.assertEqual(path.parent, self.state_dir / "compose-previous")
        self.assertRegex(path.name, r"^[0-9a-f]{24}\.json$")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(json.loads(path.read_text())["dir"], str(self.project))

    def test_an_update_that_changed_nothing_leaves_the_earlier_note_alone(self):
        self.update()
        first = self.note_path().read_bytes()
        state = self.fake.read()
        state["registry"][WEB] = NEW                      # nothing newer than what runs now
        self.fake.write(state)
        self.update()
        self.assertEqual(self.note_path().read_bytes(), first, "the note that still describes a change is the one to keep")

    def test_a_second_update_that_moves_something_replaces_the_note(self):
        self.update()
        state = self.fake.read()
        state["images"][OTHER] = {}
        state["registry"][WEB] = OTHER
        self.fake.write(state)
        self.update()
        rec = self.agent._compose_record_read(self.project)
        self.assertEqual([r["id"] for r in rec["before"] if r["service"] == "web"], [NEW])
        self.assertEqual([r["id"] for r in rec["after"] if r["service"] == "web"], [OTHER])

    def test_a_project_with_nothing_running_before_has_a_note_with_nothing_to_go_back_to(self):
        state = self.fake.read()
        state["containers"] = {}
        self.fake.write(state)
        self.update()
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 1)
        self.assertIn("nothing to roll back to", res["output"])

    def test_a_failed_update_leaves_no_note_and_keeps_the_one_before(self):
        self.update()
        first = self.note_path().read_bytes()
        state = self.fake.read()
        state["fail"] = {"up": True}
        state["registry"][WEB] = DB
        state["images"][DB] = {}
        self.fake.write(state)
        res = self.run_compose("update")
        self.assertNotEqual(res["rc"], 0)
        self.assertEqual(self.note_path().read_bytes(), first)

    def test_an_update_that_changed_containers_and_then_failed_does_not_replace_the_note(self):
        self.update()
        first = self.note_path().read_bytes()
        state = self.fake.read()
        state["images"][OTHER] = {}
        state["registry"][WEB] = OTHER
        state["fail"] = {"up_after": True}
        self.fake.write(state)
        res = self.run_compose("update")
        self.assertNotEqual(res["rc"], 0)
        self.assertEqual(self.image_of("web"), [OTHER], "the containers did move")
        self.assertEqual(self.note_path().read_bytes(), first, "a failed update is not noted as one that went through")

    def test_docker_that_cannot_inspect_the_containers_leaves_no_note_and_is_not_a_reason_to_guess(self):
        state = self.fake.read()
        state["fail"] = {"inspect": True}
        self.fake.write(state)
        self.update()
        self.assertFalse(self.note_path().exists())
        self.agent._compose_record_write(self.project, [{"service": "web", "ref": WEB, "id": OLD}], [{"service": "web", "ref": WEB, "id": NEW}])
        mark = len(self.fake.calls())
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 1)
        self.assertIn("could not say which containers", res["output"])
        self.assertNotIn("tag", [c["argv"][0] for c in self.calls_since(mark)])

    def test_what_docker_lists_that_is_not_a_container_id_is_never_passed_to_inspect(self):
        state = self.fake.read()
        state["ps_extra"] = ["--help", "-1", "x y", "G" * 64, "abc"]
        self.fake.write(state)
        mark = len(self.fake.calls())
        rows = self.agent._compose_images([str(self.project)])
        self.assertEqual([r["service"] for r in rows], ["db", "web"])
        inspected = [a for c in self.calls_since(mark) if c["argv"][0] == "inspect" for a in c["argv"][3:]]
        self.assertEqual(sorted(inspected), sorted(self.fake.read()["containers"]))

    def test_an_image_id_that_is_not_an_id_leaves_the_row_out_of_what_is_known(self):
        state = self.fake.read()
        state["containers"]["3" * 64] = {"image": "not-an-id", "ref": "x:1", "service": "odd", "dir": str(self.project), "oneoff": False}
        state["containers"]["4" * 64] = {"image": "sha256:abc", "ref": "x:2", "service": "short", "dir": str(self.project), "oneoff": False}
        self.fake.write(state)
        self.assertEqual([r["service"] for r in self.agent._compose_images([str(self.project)])], ["db", "web"])

    def test_not_being_able_to_note_the_images_does_not_stop_the_update(self):
        state = self.fake.read()
        state["fail"] = {"ps": True}
        self.fake.write(state)
        res = self.update()
        self.assertIn("$ docker compose pull", res["output"])
        self.assertEqual(self.image_of("web"), [NEW], "the update itself went through")
        self.assertFalse(self.note_path().exists())

    def test_a_note_that_cannot_be_written_does_not_turn_a_good_update_into_a_failure(self):
        blocker = self.state_dir / "compose-previous"
        blocker.write_text("a file where the directory should be")
        res = self.update()
        self.assertEqual(self.image_of("web"), [NEW])
        self.assertIn("$ docker compose up -d", res["output"])

    def test_the_containers_are_found_by_the_directory_as_reported_and_by_the_resolved_one(self):
        link = self.tmp / "link-to-web"
        link.symlink_to(self.project)
        mark = len(self.fake.calls())
        self.update_via(link)
        asked = [c["argv"][5] for c in self.calls_since(mark) if c["argv"][:1] == ["ps"]]
        self.assertIn("label=com.docker.compose.project.working_dir=" + str(link), asked)
        self.assertIn("label=com.docker.compose.project.working_dir=" + str(self.project), asked)
        self.assertEqual(self.run_compose("rollback", link)["rc"], 0, "the note is kept under the resolved directory, so either name finds it")

    def update_via(self, directory):
        res = self.run_compose("update", directory)
        self.assertEqual(res["rc"], 0, res)


class TestRollingBack(_Base):

    def test_the_references_that_moved_are_put_back_and_the_project_is_started_without_pulling(self):
        self.update()
        mark = len(self.fake.calls())
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 0, res)
        state = self.fake.read()
        self.assertEqual(state["tags"][WEB], OLD)
        self.assertEqual(self.image_of("web"), [OLD], "the container runs the image it ran before")
        self.assertEqual(self.image_of("db"), [DB])
        later = self.calls_since(mark)
        self.assertEqual([c["argv"][0] for c in later if c["argv"][0] != "compose"], ["ps", "inspect", "image", "tag"])
        self.assertEqual(later[-1]["argv"], ["compose", "up", "-d", "--pull", "never"])
        self.assertEqual(later[-1]["cwd"], str(self.project))
        self.assertNotIn(["compose", "pull"], [c["argv"] for c in later], "a rollback never reaches for the registry")
        self.assertIn("$ docker tag sha256:aaaaaaaaaaaa " + WEB, res["output"])
        self.assertNotIn(OLD, res["output"], "the id is shown short")

    def test_the_note_is_used_up_and_a_second_rollback_has_nothing_to_go_back_to(self):
        self.update()
        self.assertEqual(self.run_compose("rollback")["rc"], 0)
        self.assertFalse(self.note_path().exists())
        again = self.run_compose("rollback")
        self.assertEqual(again["rc"], 1)
        self.assertIn("no note", again["output"])

    def test_without_a_note_there_is_nothing_to_roll_back_to(self):
        mark = len(self.fake.calls())
        res = self.run_compose("rollback")
        self.assertEqual((res["rc"], "no note of the images" in res["output"]), (1, True))
        self.assertEqual(self.calls_since(mark), [], "nothing was asked of docker")

    def test_a_project_that_was_changed_after_the_update_is_not_rolled_back_over_that_change(self):
        self.update()
        state = self.fake.read()
        state["images"][OTHER] = {}
        for c in state["containers"].values():
            if c["service"] == "web":
                c["image"] = OTHER                      # someone updated it again, by hand
        self.fake.write(state)
        mark = len(self.fake.calls())
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 1)
        self.assertIn("something changed it since", res["output"])
        self.assertNotIn("tag", [c["argv"][0] for c in self.calls_since(mark)])
        self.assertEqual(self.image_of("web"), [OTHER])
        self.assertTrue(self.note_path().exists(), "the note stays, it describes the update it was made for")

    def test_a_previous_image_that_was_removed_stops_the_rollback_before_anything_moves(self):
        self.update()
        state = self.fake.read()
        del state["images"][OLD]
        self.fake.write(state)
        mark = len(self.fake.calls())
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 1)
        self.assertIn("previous image of " + WEB + " is no longer on this host", res["output"])
        self.assertIn("nothing was rolled back", res["output"])
        self.assertNotIn("tag", [c["argv"][0] for c in self.calls_since(mark)])
        self.assertEqual(self.fake.read()["tags"][WEB], NEW)
        self.assertEqual(self.image_of("web"), [NEW])

    def test_all_the_previous_images_are_checked_before_the_first_one_is_moved_whichever_of_them_is_gone(self):
        for gone, ref in ((OTHER, "docker.io/other/cache:3"), (OLD, WEB)):
            with self.subTest(gone=ref):
                self.plant()
                shutil.rmtree(str(self.state_dir / "compose-previous"), ignore_errors=True)
                self.two_images_moved()
                state = self.fake.read()
                del state["images"][gone]
                self.fake.write(state)
                mark = len(self.fake.calls())
                res = self.run_compose("rollback")
                self.assertEqual(res["rc"], 1, res)
                self.assertIn(ref, res["output"])
                self.assertNotIn("tag", [c["argv"][0] for c in self.calls_since(mark)], "nothing was moved, whichever image was the missing one")
                self.assertEqual(self.fake.read()["tags"][WEB], NEW)

    def test_an_image_pinned_by_digest_is_not_moved_and_a_project_where_only_such_images_moved_has_nothing_to_roll_back(self):
        pinned = "ghcr.io/acme/web@sha256:" + "f" * 64
        db = {"service": "db", "ref": DBREF, "id": DB}
        self.agent._compose_record_write(self.project, [db, {"service": "web", "ref": pinned, "id": OLD}], [db, {"service": "web", "ref": pinned, "id": NEW}])
        state = self.fake.read()
        state["images"][NEW] = {}
        for c in state["containers"].values():
            if c["service"] == "web":
                c.update(image=NEW, ref=pinned)
        self.fake.write(state)
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 1)
        self.assertIn("pinned by digest or id", res["output"])

    def test_a_pinned_image_beside_one_that_moved_is_left_and_said_so(self):
        pinned = "docker.io/other/db@sha256:" + "f" * 64
        self.agent._compose_record_write(
            self.project,
            [{"service": "db", "ref": pinned, "id": DB}, {"service": "web", "ref": WEB, "id": OLD}],
            [{"service": "db", "ref": pinned, "id": OTHER}, {"service": "web", "ref": WEB, "id": NEW}])
        state = self.fake.read()
        state["images"].update({NEW: {}, OTHER: {}})
        state["tags"][WEB] = NEW
        for c in state["containers"].values():
            if c["service"] == "web":
                c.update(image=NEW)
            else:
                c.update(image=OTHER, ref=pinned)
        self.fake.write(state)
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 0, res)
        self.assertEqual(self.image_of("web"), [OLD])
        self.assertIn("left as they are (pinned by digest or id): " + pinned, res["output"])
        self.assertNotIn(pinned, [c["argv"][2] for c in self.fake.calls() if c["argv"][0] == "tag"])

    def test_nothing_in_a_note_or_a_reference_can_become_an_option_of_docker_tag(self):
        hostile = ["--rm", "-x", "a b", "a\nb", "", "sha256:" + "a" * 64, "a" * 12, "a" * 64, "x;y", "$(id)", "a" * 300, "../x"]
        for ref in hostile:
            self.agent._compose_record_write(self.project, [{"service": "web", "ref": ref, "id": OLD}], [{"service": "web", "ref": WEB, "id": NEW}])
            state = self.fake.read()
            state["images"][NEW] = {}
            for c in state["containers"].values():
                if c["service"] == "web":
                    c.update(image=NEW, ref=WEB)
            state["containers"] = {k: v for k, v in state["containers"].items() if v["service"] == "web"}
            self.fake.write(state)
            mark = len(self.fake.calls())
            res = self.run_compose("rollback")
            self.assertEqual(res["rc"], 1, (ref, res))
            self.assertNotIn("tag", [c["argv"][0] for c in self.calls_since(mark)], "reference %r reached docker tag" % ref)

    def test_an_image_id_that_is_not_an_id_is_never_passed_on(self):
        for bad in ("sha256:abc", "sha256:" + "G" * 64, "latest", "-x", ""):
            self.agent._compose_record_write(self.project, [{"service": "web", "ref": WEB, "id": bad}], [{"service": "web", "ref": WEB, "id": NEW}])
            state = self.fake.read()
            state["images"][NEW] = {}
            state["containers"] = {k: dict(v, image=NEW) for k, v in state["containers"].items() if v["service"] == "web"}
            self.fake.write(state)
            mark = len(self.fake.calls())
            res = self.run_compose("rollback")
            self.assertEqual(res["rc"], 1, (bad, res))
            self.assertNotIn("tag", [c["argv"][0] for c in self.calls_since(mark)], bad)
            if bad:
                self.assertFalse([c["argv"] for c in self.calls_since(mark) if bad in c["argv"]], "the id %r reached a docker call, as an option or an argument" % bad)

    def test_a_note_that_is_damaged_or_belongs_to_another_directory_is_no_note(self):
        self.update()
        path = self.note_path()
        good = path.read_text()
        foreign = dict(json.loads(good), dir="/elsewhere")                    # a note that would work, copied from another project
        for text in ("{not json", "[]", "null", json.dumps(foreign), json.dumps({"dir": str(self.project), "before": "x", "after": 5}),
                     json.dumps({"dir": str(self.project), "before": [{"service": 1, "ref": None, "id": []}], "after": []})):
            path.write_text(text)
            res = self.run_compose("rollback")
            self.assertEqual(res["rc"], 1, text)
            self.assertIn("no note", res["output"], text)
        path.write_text(good)
        self.assertEqual(self.run_compose("rollback")["rc"], 0, "the control: the untouched note is used")

    def test_the_order_of_the_rows_in_a_note_does_not_matter(self):
        self.update()
        rec = self.agent._compose_record_read(self.project)
        self.agent._compose_record_write(self.project, rec["before"][::-1], rec["after"][::-1])
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 0, res)
        self.assertEqual(self.image_of("web"), [OLD])

    def test_a_tag_that_fails_stops_the_rollback_before_the_rest_and_keeps_the_note(self):
        self.two_images_moved()
        state = self.fake.read()
        state["fail"] = {"tag": True}
        self.fake.write(state)
        mark = len(self.fake.calls())
        res = self.run_compose("rollback")
        self.assertNotEqual(res["rc"], 0)
        later = [c["argv"][0] if c["argv"][0] != "compose" else "compose " + c["argv"][1] for c in self.calls_since(mark)]
        self.assertEqual(later.count("tag"), 1, "the first failure ended it")
        self.assertNotIn("compose up", later)
        self.assertTrue(self.note_path().exists())

    def two_images_moved(self):
        """web and cache both moved in the update, so the rollback has two images to put back; db did not."""
        state = self.fake.read()
        state["images"][OTHER] = {}
        state["tags"]["docker.io/other/cache:3"] = OTHER
        state["projects"][str(self.project)]["cache"] = "docker.io/other/cache:3"
        state["containers"]["3" * 64] = {"image": OTHER, "ref": "docker.io/other/cache:3", "service": "cache", "dir": str(self.project), "oneoff": False}
        state["registry"]["docker.io/other/cache:3"] = "sha256:" + "e" * 64
        self.fake.write(state)
        self.update()

    def test_a_docker_that_fails_part_way_leaves_the_note_for_another_try(self):
        self.update()
        state = self.fake.read()
        state["fail"] = {"up": True}
        self.fake.write(state)
        res = self.run_compose("rollback")
        self.assertNotEqual(res["rc"], 0)
        self.assertTrue(self.note_path().exists())
        state = self.fake.read()
        state["fail"] = {}
        self.fake.write(state)
        self.assertEqual(self.run_compose("rollback")["rc"], 0, "the project still runs what the note says it ran after the update, so a second try goes through")
        self.assertEqual(self.image_of("web"), [OLD])

    def test_docker_that_cannot_say_which_containers_run_is_not_a_reason_to_guess(self):
        self.update()
        state = self.fake.read()
        state["fail"] = {"ps": True}
        self.fake.write(state)
        mark = len(self.fake.calls())
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 1)
        self.assertIn("could not say which containers", res["output"])
        self.assertNotIn("tag", [c["argv"][0] for c in self.calls_since(mark)])

    def test_docker_that_does_not_answer_about_an_image_is_not_read_as_an_image_that_is_gone(self):
        self.update()
        state = self.fake.read()
        state["fail"] = {"image_inspect": True}
        self.fake.write(state)
        res = self.run_compose("rollback")
        self.assertEqual(res["rc"], 1)
        self.assertIn("no longer on this host", res["output"], "a failed lookup refuses; the words say what could be told")
        self.assertEqual(self.fake.read()["tags"][WEB], NEW)

    def test_without_docker_the_verb_says_so_as_the_others_do(self):
        self.update()
        patch = mock.patch.object(self.agent, "_which", lambda prog: None)       # it also searches /usr/bin, where this machine has a real docker client
        patch.start()
        self.addCleanup(patch.stop)
        res = self.run_compose("rollback")
        self.assertEqual((res["rc"], res["output"]), (-1, "docker not installed on this host"))

    def test_the_verb_is_known_and_a_directory_that_is_not_there_is_refused_as_for_every_other_action(self):
        self.assertIn("rollback", self.agent.COMPOSE_ALLOWED_ACTIONS)
        res = self.agent._run_compose("compose:rollback:" + str(self.tmp / "nowhere"))
        self.assertEqual(res["rc"], -1)
        self.assertIn("directory not found", res["output"])
        self.assertIn("not allowed", self.agent._run_compose("compose:explode:" + str(self.project))["output"])


class TestTheStandInCanSayNo(unittest.TestCase):
    """The tests above are only as good as the stand-in: it must refuse what the agent does not send, and fail where docker fails."""

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="rp-fake-docker-")))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.fake = FakeDocker(self.tmp)
        self.fake.write({"images": {OLD: {}}, "tags": {}, "registry": {}, "projects": {}, "containers": {}, "fail": {}})

    def docker(self, *argv, cwd=None):
        env = dict(os.environ, **self.fake.env())
        return subprocess.run(["docker", *argv], capture_output=True, text=True, env=env, cwd=cwd or str(self.tmp), timeout=60)

    def test_it_refuses_an_argument_list_the_agent_does_not_send(self):
        for argv in (("ps",), ("ps", "-a"), ("inspect", "x"), ("inspect", "--format", "{{.Id}}", "x"), ("image", "inspect", OLD), ("tag", "a", "b", "c"), ("rm", "x"),
                     ("compose", "down"), ("compose", "up"), ("compose", "up", "-d", "--build")):
            self.assertEqual(self.docker(*argv).returncode, 2, argv)

    def test_a_tag_of_an_image_that_is_not_there_and_an_option_in_the_place_of_a_reference_fail(self):
        self.assertEqual(self.docker("tag", "sha256:" + "9" * 64, "x:1").returncode, 1)
        self.assertEqual(self.docker("tag", OLD, "--rm").returncode, 2)
        self.assertEqual(self.docker("tag", "-x", "x:1").returncode, 2)
        self.assertEqual(self.docker("tag", OLD, "x:1").returncode, 0)
        self.assertEqual(self.fake.read()["tags"], {"x:1": OLD})

    def test_up_without_pulling_fails_for_a_reference_that_points_at_nothing_and_with_pulling_fetches_it(self):
        project = self.tmp / "p"
        project.mkdir()
        state = self.fake.read()
        state["projects"][str(project)] = {"web": "x:1"}
        state["registry"]["x:1"] = OLD
        self.fake.write(state)
        self.assertEqual(self.docker("compose", "up", "-d", "--pull", "never", cwd=str(project)).returncode, 1)
        self.assertEqual(self.docker("compose", "up", "-d", cwd=str(project)).returncode, 0)
        self.assertEqual([c["image"] for c in self.fake.read()["containers"].values()], [OLD])

    def test_up_recreates_only_a_container_whose_image_is_not_the_one_its_reference_points_at(self):
        project = self.tmp / "p"
        project.mkdir()
        state = self.fake.read()
        state["images"][DB] = {}
        state["tags"] = {"x:1": OLD}
        state["projects"][str(project)] = {"web": "x:1"}
        state["containers"]["7" * 64] = {"image": OLD, "ref": "x:1", "service": "web", "dir": str(project), "oneoff": False}
        self.fake.write(state)
        self.assertIn("Running", self.docker("compose", "up", "-d", cwd=str(project)).stdout)
        self.assertEqual(list(self.fake.read()["containers"]), ["7" * 64], "nothing changed, nothing was recreated")
        state = self.fake.read()
        state["tags"]["x:1"] = DB
        self.fake.write(state)
        self.assertIn("Recreated", self.docker("compose", "up", "-d", cwd=str(project)).stdout)
        self.assertEqual([c["image"] for c in self.fake.read()["containers"].values()], [DB])

    def test_it_lists_only_the_service_containers_of_the_directory_asked_for(self):
        state = self.fake.read()
        state["containers"] = {"1" * 64: {"image": OLD, "ref": "x:1", "service": "a", "dir": "/p", "oneoff": False},
                               "2" * 64: {"image": OLD, "ref": "x:1", "service": "a", "dir": "/p", "oneoff": True},
                               "3" * 64: {"image": OLD, "ref": "x:1", "service": "b", "dir": "/q", "oneoff": False}}
        self.fake.write(state)
        out = self.docker("ps", "-a", "-q", "--no-trunc", "--filter", fake_docker.DIR_LABEL + "/p", "--filter", fake_docker.ONEOFF_LABEL).stdout.split()
        self.assertEqual(out, ["1" * 64])


class TestWhatTheAgentSays(unittest.TestCase):

    def test_the_agent_says_it_in_its_heartbeat(self):
        import ast
        tree = ast.parse(AGENT.read_text())
        hits = [n for n in ast.walk(tree) if isinstance(n, ast.Dict)
                and any(isinstance(k, ast.Constant) and k.value == "compose_rollback" and isinstance(v, ast.Constant) and v.value is True for k, v in zip(n.keys, n.values))]
        self.assertEqual(len(hits), 1, "one sysinfo dict says compose_rollback: True")
        keys = {k.value for k in hits[0].keys if isinstance(k, ast.Constant)}
        self.assertIn("probe_types", keys, "it is the heartbeat's sysinfo, beside the key it was added next to")

    def test_a_host_with_no_word_from_its_agent_is_not_taken_to_roll_back(self):
        import image_autoupdate as IA
        self.assertFalse(IA.can_roll_back({"sysinfo": {}}))
        self.assertFalse(IA.can_roll_back({}))
        self.assertFalse(IA.can_roll_back(None))
        self.assertTrue(IA.can_roll_back({"sysinfo": {"compose_rollback": True}}))
        for said in (False, "true", 1, [True]):
            self.assertFalse(IA.can_roll_back({"sysinfo": {"compose_rollback": said}}), said)


class TestTheWholeRound(unittest.TestCase):
    """The server decides, the agent acts on the exact command the server queued, the host reports, the server judges: the real server code, the real
    agent functions and the stand-in for docker."""

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="rp-round-")))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.agent = _AGENT["m"]
        self.fake = FakeDocker(self.tmp / "fake")
        self.project = self.tmp / "srv-web"
        self.project.mkdir()
        (self.project / "docker-compose.yml").write_text("services: {}\n")
        (self.tmp / "state").mkdir()
        for patch in (mock.patch.dict(os.environ, self.fake.env()), mock.patch.object(self.agent, "STATE_DIR", self.tmp / "state")):
            patch.start()
            self.addCleanup(patch.stop)
        self.agent._which.__defaults__[0].clear()
        self.addCleanup(self.agent._which.__defaults__[0].clear)
        self.fake.write({"images": {OLD: {}}, "tags": {WEB: OLD}, "registry": {WEB: NEW}, "projects": {str(self.project): {"web": WEB}},
                         "containers": {"1" * 64: {"image": OLD, "ref": WEB, "service": "web", "dir": str(self.project), "oneoff": False}}, "fail": {}})
        now = int(time.time())
        self.devices = {"d1": {"id": "d1", "name": "web01", "last_seen": now, "token": "t1", "sysinfo": {"compose_rollback": True}}}
        _seed(config={"image_autoupdate": dict(POLICY_ON, rollback=True)}, devices=self.devices,
              containers={"d1": {"reported_at": now, "items": [box(digest=OLD, cdir=str(self.project))]}})
        self.fired, self.audits = [], []

        def fire(event, payload=None, *_args, **_kw):
            self.fired.append((event, dict(payload or {})))

        def audit(*args, **_kw):
            self.audits.append(args)
        for name, fn in (("fire_webhook", fire), ("audit_log", audit)):
            patch = mock.patch.object(api, name, fn)
            patch.start()
            self.addCleanup(patch.stop)

    def sweep(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["last_image_autoupdate"] = 0
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.run_image_autoupdate_if_due()
        api._LOAD_CACHE.clear()

    def receipt(self):
        api._LOAD_CACHE.clear()
        rows = ((api.load(api.IMAGE_UPDATES_FILE) or {}).get("autoupdate") or {}).get("receipts") or []
        self.assertEqual(len(rows), 1, rows)
        return rows[0]

    def due(self, key_at, key_queued):
        store = api.load(api.IMAGE_UPDATES_FILE)
        r = store["autoupdate"]["receipts"][0]
        r[key_at], r[key_queued] = int(time.time()) - 1, int(time.time()) - 400
        api.save(api.IMAGE_UPDATES_FILE, store)
        api._LOAD_CACHE.clear()

    def queued(self):
        api._LOAD_CACHE.clear()
        return list((api.load(api.CMDS_FILE) or {}).get("d1") or [])

    def host_reports(self, health, status="Up 2 minutes"):
        """What the host's next container report says, taken from what the stand-in's containers run now."""
        items = [box(digest=c["image"], status=status, health=health, cdir=str(self.project)) for c in self.fake.read()["containers"].values()]
        store = api.load(api.CONTAINERS_FILE)
        store["d1"] = {"reported_at": int(time.time()) + 5, "items": items}
        api.save(api.CONTAINERS_FILE, store)
        api._LOAD_CACHE.clear()

    def test_an_unhealthy_update_is_rolled_back_by_the_agent_from_the_command_the_server_queued_and_the_host_is_judged_rolled_back(self):
        self.sweep()
        self.assertEqual(self.receipt()["state"], "queued")
        update = self.queued()[0]
        self.assertEqual(update, "compose:update:" + str(self.project))
        self.assertEqual(self.agent._run_compose(update)["rc"], 0)
        self.assertEqual([c["image"] for c in self.fake.read()["containers"].values()], [NEW])
        self.host_reports("unhealthy")
        self.due("verify_at", "queued_at")
        self.sweep()
        r = self.receipt()
        self.assertEqual(r["state"], "rolling_back", r)
        self.assertIn("failing its health check", r["unhealthy_detail"])
        rollback = [c for c in self.queued() if c.startswith("compose:rollback:")]
        self.assertEqual(rollback, ["compose:rollback:" + str(self.project)])
        self.assertEqual([e for e, _ in self.fired if e == "image_autoupdate_failed"].__len__(), 1, "the failed update is one alert, which says a rollback follows")
        self.assertIn("rolling back", self.fired[-1][1]["detail"])
        res = self.agent._run_compose(rollback[0])
        self.assertEqual(res["rc"], 0, res)
        self.assertEqual([c["image"] for c in self.fake.read()["containers"].values()], [OLD])
        self.host_reports("healthy")
        self.due("rollback_verify_at", "rollback_queued_at")
        self.sweep()
        r = self.receipt()
        self.assertEqual(r["state"], "rolled_back", r)
        self.assertIn("rolled back to the previous image", r["detail"])
        self.assertEqual(len([1 for e, _ in self.fired if e == "image_autoupdate_failed"]), 1, "good news is not an alert")
        self.assertTrue(any(a[1] == "image_autoupdate_rolled_back" for a in self.audits))

    def test_a_rollback_that_the_host_does_not_take_is_an_alert_of_its_own(self):
        self.sweep()
        self.agent._run_compose(self.queued()[0])
        self.host_reports("unhealthy")
        self.due("verify_at", "queued_at")
        self.sweep()
        self.assertEqual(self.receipt()["state"], "rolling_back")
        state = self.fake.read()
        state["images"].pop(OLD)                                # the previous image was pruned meanwhile: the agent refuses
        self.fake.write(state)
        res = self.agent._run_compose([c for c in self.queued() if c.startswith("compose:rollback:")][0])
        self.assertEqual(res["rc"], 1)
        self.host_reports("unhealthy")                          # still the new image, still failing
        self.due("rollback_verify_at", "rollback_queued_at")
        self.sweep()
        r = self.receipt()
        self.assertEqual(r["state"], "rollback_failed", r)
        self.assertIn("still runs the new image", r["detail"])
        self.assertEqual([e for e, _ in self.fired if e == "image_autoupdate_failed"].__len__(), 2, "the update failed, and then the rollback did")


if __name__ == "__main__":
    unittest.main()
