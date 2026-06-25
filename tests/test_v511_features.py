"""v5.1.1 "ClusterMatters" — regression tests for the Proxmox cluster listing (#9).

The feature interpolates node names from a (potentially hostile) `/cluster/resources`
response into `/nodes/<node>/…` request paths, so the load-bearing tests are:
  * the node-name validator drops path-separator / traversal / newline injection,
  * the listing falls back to the single configured node on a permission error or
    an empty/ambiguous cluster response (existing single-node setups unaffected),
  * owning-node resolution matches on (vmid, type) and falls back to the configured
    node — and never returns an unvalidated node,
  * the cluster member listing degrades to [] rather than raising.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("proxmox_client_v511", _CGI / "proxmox_client.py")
pcmod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pcmod)

PC = {"node": "pve1"}   # minimal config; _request is fully mocked below


class TestSafeNode(unittest.TestCase):
    """The single guard between a cluster/resources `node` string and a request path."""

    def test_drops_path_injection_and_junk(self):
        for bad in ("a/b", "../../etc", "pve/../x", "pve\n", "localhost:8006/x",
                    "a b", "node\t", "", None, "//evil", "n/../../"):
            self.assertEqual(pcmod._safe_node(bad), "", f"must drop {bad!r}")

    def test_keeps_legit_hostnames(self):
        for ok in ("pve1", "pve-node.dc1", "node01", "a"):
            self.assertEqual(pcmod._safe_node(ok), ok)


class _MockRequest:
    """Routes proxmox_client._request by path to canned data (or raises)."""
    def __init__(self):
        self.cluster = []          # /cluster/resources?type=vm
        self.cluster_error = False
        self.single = []           # /nodes/<node>/<type>
        self.nodes = []            # /nodes
        self.nodes_error = False
        self.seen_paths = []

    def __call__(self, pc, path, method="GET", **kw):
        self.seen_paths.append(path)
        if "cluster/resources" in path:
            if self.cluster_error:
                raise pcmod.ProxmoxError("no cluster perm")
            return self.cluster
        if path == "/nodes":
            if self.nodes_error:
                raise pcmod.ProxmoxError("no /nodes perm")
            return self.nodes
        if path.endswith("/qemu") or path.endswith("/lxc"):
            return self.single
        return []


class _Patched(unittest.TestCase):
    def setUp(self):
        self.mock = _MockRequest()
        self._orig = pcmod._request
        pcmod._request = self.mock
    def tearDown(self):
        pcmod._request = self._orig


class TestClusterListing(_Patched):
    def test_cluster_path_filters_type_and_stamps_node(self):
        self.mock.cluster = [
            {"type": "qemu", "vmid": 100, "name": "web", "node": "pve1", "status": "running"},
            {"type": "lxc",  "vmid": 200, "name": "ct",  "node": "pve2", "status": "running"},
            {"type": "qemu", "vmid": 101, "name": "db",  "node": "pve2", "status": "stopped"},
        ]
        qemu = pcmod.list_guests(PC, "qemu")
        self.assertEqual([g["vmid"] for g in qemu], [100, 101])      # only qemu, sorted
        self.assertEqual({g["node"] for g in qemu}, {"pve1", "pve2"})  # owning node carried
        lxc = pcmod.list_guests(PC, "lxc")
        self.assertEqual([g["vmid"] for g in lxc], [200])

    def test_hostile_node_in_cluster_row_is_dropped_to_empty(self):
        self.mock.cluster = [
            {"type": "qemu", "vmid": 100, "name": "evil", "node": "pve/../x", "status": "running"},
        ]
        g = pcmod.list_guests(PC, "qemu")[0]
        self.assertEqual(g["node"], "", "injected node must not survive into the guest record")

    def test_falls_back_to_single_node_on_permission_error(self):
        self.mock.cluster_error = True
        self.mock.single = [{"vmid": 100, "name": "web", "status": "running"}]
        guests = pcmod.list_guests(PC, "qemu")
        self.assertEqual([g["vmid"] for g in guests], [100])
        self.assertEqual(guests[0]["node"], "pve1")   # stamped with configured node
        self.assertTrue(any("/nodes/pve1/qemu" in p for p in self.mock.seen_paths))

    def test_empty_cluster_response_falls_through_to_single_node(self):
        self.mock.cluster = []     # ambiguous → must not assert "zero guests"
        self.mock.single = [{"vmid": 7, "name": "x", "status": "running"}]
        self.assertEqual([g["vmid"] for g in pcmod.list_guests(PC, "qemu")], [7])

    def test_non_numeric_uptime_in_hostile_row_does_not_raise(self):
        self.mock.cluster = [
            {"type": "qemu", "vmid": 100, "name": "x", "node": "pve1",
             "status": "running", "uptime": "not-a-number", "mem": 3.5},
        ]
        g = pcmod.list_guests(PC, "qemu")[0]   # _int0 must absorb it
        self.assertEqual(g["uptime"], 0)


class TestFindGuestNode(_Patched):
    def setUp(self):
        super().setUp()
        self.mock.cluster = [
            {"type": "qemu", "vmid": 100, "node": "pve1"},
            {"type": "lxc",  "vmid": 100, "node": "pve3"},   # same vmid, different type
            {"type": "qemu", "vmid": 101, "node": "pve/../x"},  # hostile node
        ]

    def test_resolves_by_vmid_and_type(self):
        self.assertEqual(pcmod.find_guest_node(PC, 100, "qemu"), "pve1")
        self.assertEqual(pcmod.find_guest_node(PC, 100, "lxc"), "pve3")

    def test_hostile_node_falls_back_to_configured(self):
        self.assertEqual(pcmod.find_guest_node(PC, 101, "qemu"), "pve1")  # not 'pve/../x'

    def test_absent_vmid_falls_back_to_configured(self):
        self.assertEqual(pcmod.find_guest_node(PC, 999, "qemu"), "pve1")

    def test_cluster_error_falls_back_to_configured(self):
        self.mock.cluster_error = True
        self.assertEqual(pcmod.find_guest_node(PC, 100, "qemu"), "pve1")


class TestListNodes(_Patched):
    def test_drops_bad_node_and_normalises(self):
        self.mock.nodes = [
            {"node": "pve1", "status": "online", "cpu": 0.25, "mem": 50, "maxmem": 100},
            {"node": "bad/node", "status": "online"},     # invalid name → dropped
            {"node": "pve2", "status": "offline"},
        ]
        out = pcmod.list_nodes(PC)
        self.assertEqual([n["node"] for n in out], ["pve1", "pve2"])
        self.assertEqual(out[0]["cpu_percent"], 25.0)
        self.assertEqual(out[0]["mem_percent"], 50.0)

    def test_never_raises_on_permission_error(self):
        self.mock.nodes_error = True
        self.assertEqual(pcmod.list_nodes(PC), [])


if __name__ == "__main__":
    unittest.main()
