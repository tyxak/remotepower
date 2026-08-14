"""v6.4.2 — Azure and GCP get the bulk inventory import AWS already had.

`cloud_import.py` implemented three providers: EC2 (hand-rolled SigV4), Hetzner
Cloud and DigitalOcean. Azure and GCP were not implemented — the module's own
docstring said it was "structured so Azure/GCP (OAuth2 bearer flows) can slot
in later".

So an operator on those clouds had no bulk-inventory path at all: every VM
added by hand as an agentless device, or enrolled one at a time. A shop running
60 Azure VMs across three subscriptions either kept a spreadsheet or wrote their
own script against `POST /api/devices` and re-ran it on cron — re-implementing
the decommission-not-delete logic the built-in scheduled re-sync already has.

Found while wiring it: `handle_config_save`'s cloud-account loop was
`if prov != 'aws': continue`, commented "v1: AWS only" — so Hetzner and
DigitalOcean accounts could not be SAVED either, and the importer branches that
had handled them since W6-44 could never be reached. A dispatch branch with no
way to get to it.
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-cloud-"))

_spec = importlib.util.spec_from_file_location("api_cloud", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import cloud_import  # noqa: E402


class _Resp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_transport(responses):
    """A urlopen stand-in. `responses` maps a URL substring to a payload; the
    calls are recorded so the test can assert what was actually requested."""
    seen = []

    def _open(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        seen.append({"url": url, "method": getattr(req, "method", "GET"),
                     "body": (req.data or b"").decode() if getattr(req, "data", None) else "",
                     "headers": dict(getattr(req, "headers", {}) or {})})
        for frag, payload in responses.items():
            if frag in url:
                return _Resp(payload)
        raise AssertionError(f"unexpected request: {url}")
    _open.seen = seen
    return _open


_TOKEN = {"access_token": "tok-123", "expires_in": 3600}


class TestAzure(unittest.TestCase):
    VMS = {
        "value": [
            {"name": "vm-web-01", "location": "westeurope",
             "properties": {"provisioningState": "Succeeded",
                            "hardwareProfile": {"vmSize": "Standard_D2s_v5"}}},
            {"name": "vm-db-01", "location": "northeurope",
             "properties": {"provisioningState": "Succeeded",
                            "hardwareProfile": {"vmSize": "Standard_E4s_v5"}}},
        ]
    }

    def _run(self, vms=None):
        op = _fake_transport({"login.microsoftonline.com": _TOKEN,
                              "management.azure.com": vms or self.VMS})
        out = cloud_import.import_azure("tenant-1", "cid", "csecret", "sub-9",
                                        _opener=op)
        return out, op.seen

    def test_it_lists_the_subscription(self):
        out, _ = self._run()
        self.assertEqual([i["name"] for i in out], ["vm-web-01", "vm-db-01"])
        self.assertEqual(out[0]["type"], "Standard_D2s_v5")
        self.assertEqual(out[0]["az"], "westeurope")

    def test_it_exchanges_a_token_first(self):
        _out, seen = self._run()
        self.assertIn("login.microsoftonline.com", seen[0]["url"])
        self.assertEqual(seen[0]["method"], "POST")
        self.assertIn("client_credentials", seen[0]["body"])

    def test_the_token_url_is_built_from_a_fixed_host(self):
        """The tenant is operator input; the HOST is not. A free-form token URL
        would be an SSRF hole in a credential-bearing POST."""
        _out, seen = self._run()
        self.assertTrue(seen[0]["url"].startswith("https://login.microsoftonline.com/"))

    def test_it_uses_the_list_all_endpoint(self):
        """One call covers every resource group — an operator with VMs spread
        across a dozen groups should not have to enumerate them."""
        _out, seen = self._run()
        self.assertIn("/providers/Microsoft.Compute/virtualMachines", seen[1]["url"])
        self.assertNotIn("resourceGroups", seen[1]["url"])

    def test_it_sends_the_bearer_token(self):
        _out, seen = self._run()
        self.assertIn("tok-123", json.dumps(seen[1]["headers"]))

    def test_it_follows_paging_but_is_bounded(self):
        """A paging loop that trusts the server's nextLink must terminate."""
        op = _fake_transport({
            "login.microsoftonline.com": _TOKEN,
            "management.azure.com": {
                "value": [{"name": "vm", "location": "we", "properties": {}}],
                # points at itself — a broken or hostile API
                "nextLink": "https://management.azure.com/next"}})
        out = cloud_import.import_azure("t", "c", "s", "sub", _opener=op)
        self.assertLessEqual(len(out), 20)
        self.assertGreater(len(out), 1)

    def test_it_leaves_the_ip_blank_rather_than_inventing_one(self):
        """ARM's VM list does not carry NIC addresses — they live on a separate
        resource. Claiming an IP we did not fetch would be worse than blank."""
        out, _ = self._run()
        self.assertEqual(out[0]["public_ip"], "")
        self.assertEqual(out[0]["private_ip"], "")

    def test_missing_credentials_say_which(self):
        with self.assertRaises(RuntimeError) as e:
            cloud_import.import_azure("", "c", "s", "")
        for w in ("tenant_id", "subscription_id"):
            self.assertIn(w, str(e.exception))

    def test_a_token_failure_carries_the_providers_own_error(self):
        """"AADSTS7000215: Invalid client secret" IS the diagnosis. Swallowing
        it leaves the operator guessing between a wrong secret, a wrong tenant
        and a missing role assignment."""
        import urllib.error

        def _open(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 401, "Unauthorized", {},
                __import__("io").BytesIO(b'{"error":"AADSTS7000215"}'))
        with self.assertRaises(RuntimeError) as e:
            cloud_import.import_azure("t", "c", "s", "sub", _opener=_open)
        self.assertIn("AADSTS7000215", str(e.exception))

    def test_a_response_without_a_token_is_an_error_not_a_silent_empty_list(self):
        op = _fake_transport({"login.microsoftonline.com": {"expires_in": 1}})
        with self.assertRaises(RuntimeError) as e:
            cloud_import.import_azure("t", "c", "s", "sub", _opener=op)
        self.assertIn("access_token", str(e.exception))


class TestGcp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.PEM = k.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()

    INSTANCES = {
        "items": {
            "zones/europe-west1-b": {"instances": [{
                "id": "77", "name": "gce-web-1", "status": "RUNNING",
                "machineType": "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west1-b/machineTypes/e2-medium",
                "networkInterfaces": [{"networkIP": "10.0.0.5",
                                       "accessConfigs": [{"natIP": "34.1.2.3"}]}],
            }]},
            "zones/us-east1-c": {"instances": []},
        }
    }

    def _run(self, payload=None):
        op = _fake_transport({"oauth2.googleapis.com": _TOKEN,
                              "compute.googleapis.com": payload or self.INSTANCES})
        out = cloud_import.import_gcp("svc@p.iam.gserviceaccount.com", self.PEM,
                                      "proj-1", _opener=op)
        return out, op.seen

    def test_it_lists_instances_across_zones(self):
        out, _ = self._run()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["name"], "gce-web-1")
        self.assertEqual(out[0]["az"], "europe-west1-b")

    def test_the_machine_type_is_the_name_not_the_resource_url(self):
        """The operator wants "e2-medium", not the path it lives at."""
        out, _ = self._run()
        self.assertEqual(out[0]["type"], "e2-medium")

    def test_it_reads_both_addresses(self):
        out, _ = self._run()
        self.assertEqual(out[0]["private_ip"], "10.0.0.5")
        self.assertEqual(out[0]["public_ip"], "34.1.2.3")

    def test_an_instance_with_no_external_ip_is_not_a_crash(self):
        p = json.loads(json.dumps(self.INSTANCES))
        p["items"]["zones/europe-west1-b"]["instances"][0]["networkInterfaces"] = [
            {"networkIP": "10.0.0.9"}]
        out, _ = self._run(p)
        self.assertEqual(out[0]["public_ip"], "")
        self.assertEqual(out[0]["private_ip"], "10.0.0.9")

    def test_an_instance_with_no_nic_at_all_is_not_a_crash(self):
        p = json.loads(json.dumps(self.INSTANCES))
        del p["items"]["zones/europe-west1-b"]["instances"][0]["networkInterfaces"]
        out, _ = self._run(p)
        self.assertEqual(out[0]["public_ip"], "")

    def test_it_uses_aggregated_list(self):
        """One call covers every zone."""
        _out, seen = self._run()
        self.assertIn("/aggregatedList/instances", seen[1]["url"])

    def test_it_signs_a_jwt_assertion(self):
        _out, seen = self._run()
        self.assertIn("jwt-bearer", seen[0]["body"])
        self.assertIn("assertion=", seen[0]["body"])

    def test_the_assertion_is_a_real_rs256_jwt(self):
        import base64
        a = cloud_import._gcp_assertion("svc@p.iam.gserviceaccount.com", self.PEM)
        head, claim, sig = a.split(".")
        self.assertEqual(json.loads(base64.urlsafe_b64decode(head + "=="))["alg"],
                         "RS256")
        body = json.loads(base64.urlsafe_b64decode(claim + "=="))
        self.assertEqual(body["aud"], "https://oauth2.googleapis.com/token")
        self.assertGreater(body["exp"], body["iat"])
        self.assertEqual(len(base64.urlsafe_b64decode(sig + "==")), 256)

    def test_it_asks_for_read_only_scope(self):
        """An inventory import has no reason to hold a write scope on a whole
        GCP project."""
        import base64
        a = cloud_import._gcp_assertion("svc@p.iam.gserviceaccount.com", self.PEM)
        claim = json.loads(base64.urlsafe_b64decode(a.split(".")[1] + "=="))
        self.assertIn("compute.readonly", claim["scope"])

    def test_an_unreadable_key_says_so(self):
        with self.assertRaises(RuntimeError) as e:
            cloud_import._gcp_assertion("svc@p", "not a pem")
        self.assertIn("private key", str(e.exception))

    def test_missing_fields_say_which(self):
        with self.assertRaises(RuntimeError) as e:
            cloud_import.import_gcp("", "k", "")
        self.assertIn("client_email", str(e.exception))

    def test_paging_is_bounded(self):
        p = json.loads(json.dumps(self.INSTANCES))
        p["nextPageToken"] = "again"
        op = _fake_transport({"oauth2.googleapis.com": _TOKEN,
                              "compute.googleapis.com": p})
        out = cloud_import.import_gcp("svc@p", self.PEM, "proj", _opener=op)
        self.assertLessEqual(len(out), 20)


class TestBothMapOntoDevices(unittest.TestCase):
    def test_the_device_fragment_shape_is_the_same_as_every_other_provider(self):
        """The importers return the EC2 shape on purpose, so instance_to_device
        and the whole upsert/decommission path need no per-provider branch."""
        for provider, inst in (
                ("azure", {"instance_id": "vm-1", "name": "vm-1", "state": "Succeeded",
                           "type": "Standard_D2s_v5", "public_ip": "",
                           "private_ip": "", "az": "westeurope"}),
                ("gcp", {"instance_id": "77", "name": "gce-1", "state": "RUNNING",
                         "type": "e2-medium", "public_ip": "34.1.2.3",
                         "private_ip": "10.0.0.5", "az": "europe-west1-b"})):
            with self.subTest(provider=provider):
                did, frag = cloud_import.instance_to_device(provider, "eu", inst)
                self.assertTrue(did.startswith(provider + "-"))
                self.assertTrue(frag["agentless"])
                self.assertEqual(frag["source"], f"cloud:{provider}")
                self.assertEqual(frag["cloud"]["provider"], provider)
                self.assertIn(provider, frag["tags"])


class TestTheSavePathReachesEveryImporter(unittest.TestCase):
    """The bug found while wiring this: the save loop was `if prov != 'aws':
    continue`, so two providers with shipped importers could never be
    configured — a dispatch branch with no way to reach it."""

    def test_every_savable_provider_has_an_importer(self):
        fetch = (_CGI / "api.py").read_text()
        i = fetch.index("def _cloud_fetch_instances(")
        block = fetch[i:fetch.index("\ndef ", i + 10)]
        for prov in api._CLOUD_PROVIDER_FIELDS:
            with self.subTest(provider=prov):
                self.assertIn(f"'{prov}'", block)

    def test_every_dispatched_provider_can_be_saved(self):
        """The direction that actually bit."""
        for prov in ("aws", "hetzner", "digitalocean", "azure", "gcp"):
            with self.subTest(provider=prov):
                self.assertIn(prov, api._CLOUD_PROVIDER_FIELDS)

    def test_the_aws_only_guard_is_gone(self):
        # Comments stripped first: the fix's own explanatory comment QUOTES the
        # line it replaced, so a raw substring search finds the string it is
        # asserting the absence of. This trap has bitten repeatedly.
        import re
        src = (_CGI / "api.py").read_text()
        code = re.sub(r"^\s*#.*$", "", src, flags=re.M)
        self.assertNotIn("if prov != 'aws':", code)

    def test_the_account_identity_separates_two_subscriptions(self):
        """Keying on provider+region alone would merge two Azure subscriptions
        in the same region into one account, and a secret-less edit of either
        would inherit the other's secret."""
        a = {"provider": "azure", "region": "we", "subscription_id": "s1"}
        b = {"provider": "azure", "region": "we", "subscription_id": "s2"}
        self.assertNotEqual(api._cloud_account_key(a), api._cloud_account_key(b))

    def test_the_secret_is_always_named_secret_key(self):
        """Five parallel secret field names would each need adding to the GET
        scrub, the backup redaction and the config-secret walker — and one
        would be forgotten."""
        for spec in api._CLOUD_PROVIDER_FIELDS.values():
            for field, _req in spec:
                with self.subTest(field=field):
                    self.assertNotIn("secret", field)
                    self.assertNotIn("password", field)


class TestSecretsStayHidden(unittest.TestCase):
    def test_the_get_scrub_surfaces_identifiers_but_never_the_secret(self):
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        body = py_function(src, "handle_config_get")
        i = body.index("safe['cloud_accounts']")
        seg = body[i:i + 900]
        self.assertIn("secret_key_set", seg)
        self.assertNotIn("'secret_key':", seg)
        # …and the new providers' identifiers ARE surfaced, or an Azure account
        # renders as a blank row the operator cannot tell apart from another.
        for f in ("tenant_id", "subscription_id", "project_id", "client_email"):
            with self.subTest(field=f):
                self.assertIn(f, seg)

    def test_the_secret_walker_still_covers_cloud_accounts(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_hit(_ca, 'secret_key')", src)


if __name__ == "__main__":
    unittest.main()
