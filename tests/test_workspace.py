"""The live workspace behind `unitas <folder> -H`.

The workspace owns a scan folder: it parses what is in it, folds the triage
from state.md over the top, and writes state.md back. These tests drive it
without a browser -- files in, files out.
"""

# pylint: skip-file
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from unitas.convert import MarkdownConvert, load_markdown_state
from unitas.workspace import STATE_FILENAME, Workspace


def nmap_scan(*hosts) -> str:
    """A minimal nmap XML for (ip, hostname, [(port, protocol, service)])."""
    blocks = []
    for ip, hostname, ports in hosts:
        entries = "".join(
            f'<port protocol="{protocol}" portid="{port}">'
            f'<state state="open"/><service name="{service}" method="probed"/>'
            f"</port>"
            for port, protocol, service in ports
        )
        names = (
            f'<hostnames><hostname name="{hostname}" type="user"/></hostnames>'
            if hostname
            else ""
        )
        blocks.append(
            f'<host><status state="up" reason="syn-ack"/>'
            f'<address addr="{ip}" addrtype="ipv4"/>{names}'
            f"<ports>{entries}</ports></host>"
        )
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000">'
        + "".join(blocks)
        + "</nmaprun>"
    )


SWEEP = (
    '<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000">'
    '<host><status state="up" reason="echo-reply"/>'
    '<address addr="10.0.0.9" addrtype="ipv4"/></host>'
    "</nmaprun>"
)


class WorkspaceTestCase(unittest.TestCase):
    """A temporary scan folder with a workspace that is never left running."""

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, ignore_errors=True)
        self.workspace = None

    def tearDown(self):
        if self.workspace is not None:
            self.workspace.stop()

    def write(self, name: str, content: str) -> str:
        path = os.path.join(self.folder, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def open_workspace(self, **kwargs) -> Workspace:
        kwargs.setdefault("poll_interval", 0.05)
        self.workspace = Workspace(self.folder, **kwargs)
        self.workspace.refresh()
        return self.workspace

    @property
    def state_file(self) -> str:
        return os.path.join(self.folder, STATE_FILENAME)

    def state_from_disk(self):
        return load_markdown_state(self.state_file)

    def port_of(self, state, ip, port):
        host = state[ip]
        return next(p for p in host.ports if p.port == str(port))


class TestWorkspaceState(WorkspaceTestCase):
    def test_parses_the_folder_and_writes_state_md(self):
        self.write(
            "scan.xml",
            nmap_scan(("10.0.0.1", "alpha", [("80", "tcp", "http")])),
        )
        workspace = self.open_workspace()

        self.assertEqual(workspace.version, 1)
        self.assertTrue(os.path.exists(self.state_file))

        state = self.state_from_disk()
        self.assertEqual(list(state), ["10.0.0.1"])
        self.assertEqual(state["10.0.0.1"].hostname, "alpha")
        self.assertEqual(self.port_of(state, "10.0.0.1", 80).state, "TBD")

    def test_empty_folder_is_a_valid_workspace(self):
        workspace = self.open_workspace()

        self.assertEqual(workspace.summary()["hosts"], 0)
        version, snapshot = workspace.snapshot()
        self.assertEqual(version, workspace.version)
        self.assertIn("hosts", snapshot)

    def test_a_host_with_nothing_open_is_only_reported_as_up(self):
        self.write("sweep.xml", SWEEP)
        workspace = self.open_workspace()

        self.assertEqual(workspace.summary()["hosts"], 0)
        self.assertIn("10.0.0.9", workspace._hostup)

    def test_a_host_that_answers_on_a_port_is_not_listed_as_only_up(self):
        self.write("sweep.xml", SWEEP)
        self.write(
            "ports.xml",
            nmap_scan(("10.0.0.9", "", [("22", "tcp", "ssh")])),
        )
        workspace = self.open_workspace()

        self.assertIn("10.0.0.9", workspace._state)
        self.assertNotIn("10.0.0.9", workspace._hostup)

    def test_unreadable_scan_does_not_take_the_workspace_down(self):
        self.write("broken.xml", "<nmaprun><host>")
        self.write("good.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        workspace = self.open_workspace()

        self.assertEqual(list(workspace._state), ["10.0.0.1"])

    def test_snapshot_is_rebuilt_only_when_the_version_moves(self):
        self.write("scan.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        workspace = self.open_workspace()

        first = workspace.snapshot()
        self.assertIs(workspace.snapshot()[1], first[1])

        workspace.apply_edits([{"ip": "10.0.0.1", "port": "80", "state": "Done"}])
        self.assertIsNot(workspace.snapshot()[1], first[1])


class TestWorkspaceEdits(WorkspaceTestCase):
    def setUp(self):
        super().setUp()
        self.write(
            "scan.xml",
            nmap_scan(
                (
                    "10.0.0.1",
                    "alpha",
                    [("80", "tcp", "http"), ("445", "tcp", "microsoft-ds")],
                ),
                ("10.0.0.2", "beta", [("22", "tcp", "ssh")]),
            ),
        )

    def test_a_port_edit_lands_in_state_md(self):
        workspace = self.open_workspace()
        before = workspace.version

        result = workspace.apply_edits(
            [
                {
                    "ip": "10.0.0.1",
                    "port": "80",
                    "protocol": "tcp",
                    "state": "Done",
                    "comment": "default creds",
                }
            ]
        )

        self.assertEqual(result["applied"], 1)
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["version"], before + 1)

        port = self.port_of(self.state_from_disk(), "10.0.0.1", 80)
        self.assertEqual(port.state, "Done")
        self.assertEqual(port.comment, "default creds")
        # the other ports are untouched
        self.assertEqual(
            self.port_of(self.state_from_disk(), "10.0.0.1", 445).state, "TBD"
        )

    def test_a_host_edit_covers_every_port_of_that_host(self):
        workspace = self.open_workspace()

        result = workspace.apply_edits([], [{"ip": "10.0.0.1", "state": "In progress"}])

        self.assertEqual(result["applied"], 2)
        state = self.state_from_disk()
        self.assertEqual({p.state for p in state["10.0.0.1"].ports}, {"In progress"})
        self.assertEqual(self.port_of(state, "10.0.0.2", 22).state, "TBD")

    def test_unknown_targets_are_reported_not_invented(self):
        workspace = self.open_workspace()

        result = workspace.apply_edits(
            [{"ip": "10.0.0.1", "port": "9999", "state": "Done"}],
            [{"ip": "10.9.9.9", "state": "Done"}],
        )

        self.assertEqual(result["applied"], 0)
        self.assertEqual(len(result["missing"]), 2)
        self.assertEqual(result["version"], workspace.version)

    def test_an_edit_that_changes_nothing_does_not_bump_the_version(self):
        workspace = self.open_workspace()
        before = workspace.version

        result = workspace.apply_edits(
            [{"ip": "10.0.0.1", "port": "80", "state": "TBD"}]
        )

        self.assertEqual(result["applied"], 0)
        self.assertEqual(workspace.version, before)

    def test_a_pipe_in_a_comment_survives_the_round_trip(self):
        workspace = self.open_workspace()

        workspace.apply_edits(
            [{"ip": "10.0.0.1", "port": "80", "comment": "banner: a|b"}]
        )

        port = self.port_of(self.state_from_disk(), "10.0.0.1", 80)
        self.assertEqual(port.comment, "banner: a|b")

    def test_triage_survives_a_rescan(self):
        workspace = self.open_workspace()
        workspace.apply_edits(
            [{"ip": "10.0.0.1", "port": "80", "state": "Done", "comment": "owned"}]
        )

        # a second scan of the same host, this time with a better service name
        self.write(
            "later.xml",
            nmap_scan(("10.0.0.1", "alpha", [("80", "tcp", "http-proxy")])),
        )
        self.assertTrue(workspace.refresh())

        port = self.port_of(self.state_from_disk(), "10.0.0.1", 80)
        self.assertEqual(port.state, "Done")
        self.assertEqual(port.comment, "owned")
        self.assertEqual(port.service, "http-proxy")

    def test_edits_are_kept_when_a_scan_file_is_removed(self):
        workspace = self.open_workspace()
        workspace.apply_edits([{"ip": "10.0.0.1", "port": "80", "state": "Done"}])

        os.remove(os.path.join(self.folder, "scan.xml"))
        workspace.refresh()

        # the triage in state.md is the record, deleting a scan does not erase it
        self.assertEqual(
            self.port_of(self.state_from_disk(), "10.0.0.1", 80).state, "Done"
        )

    def test_summary_counts_what_is_done(self):
        workspace = self.open_workspace()
        workspace.apply_edits([{"ip": "10.0.0.1", "port": "80", "state": "Done"}])

        summary = workspace.summary()
        self.assertEqual(summary["hosts"], 2)
        self.assertEqual(summary["ports"], 3)
        self.assertEqual(summary["done"], 1)
        self.assertEqual(summary["scan_files"], 1)
        self.assertFalse(summary["read_only"])


class TestWorkspaceWatching(WorkspaceTestCase):
    def test_a_new_scan_file_is_picked_up(self):
        self.write("first.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        workspace = self.open_workspace()
        before = workspace.version

        self.write("second.xml", nmap_scan(("10.0.0.2", "", [("22", "tcp", "ssh")])))

        self.assertTrue(workspace.refresh())
        self.assertGreater(workspace.version, before)
        self.assertEqual(sorted(workspace._state), ["10.0.0.1", "10.0.0.2"])

    def test_a_scan_in_a_subfolder_counts(self):
        os.makedirs(os.path.join(self.folder, "nessus"))
        self.write(
            os.path.join("nessus", "deep.xml"),
            nmap_scan(("10.0.0.3", "", [("443", "tcp", "https")])),
        )
        workspace = self.open_workspace()

        self.assertIn("10.0.0.3", workspace._state)

    def test_nothing_new_means_no_version_bump(self):
        self.write("scan.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        workspace = self.open_workspace()
        before = workspace.version

        self.assertFalse(workspace.refresh())
        self.assertEqual(workspace.version, before)

    def test_an_external_edit_of_state_md_is_read_back(self):
        self.write("scan.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        workspace = self.open_workspace()

        # what `unitas -u` or a text editor would leave behind
        state = self.state_from_disk()
        self.port_of(state, "10.0.0.1", 80).state = "In progress"
        markdown = MarkdownConvert(state).convert(True)
        time.sleep(0.01)
        self.write(STATE_FILENAME, markdown)

        self.assertTrue(workspace.refresh())
        self.assertEqual(
            self.port_of(workspace._state, "10.0.0.1", 80).state, "In progress"
        )

    def test_a_deleted_state_file_is_rewritten(self):
        self.write("scan.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        workspace = self.open_workspace()
        workspace.apply_edits([{"ip": "10.0.0.1", "port": "80", "state": "Done"}])

        os.remove(self.state_file)
        workspace.refresh()

        self.assertTrue(os.path.exists(self.state_file))
        # the state we hold is the truth once the file is gone
        self.assertEqual(
            self.port_of(self.state_from_disk(), "10.0.0.1", 80).state, "Done"
        )

    def test_the_watcher_thread_notices_a_dropped_scan(self):
        workspace = self.open_workspace()
        arrived = []
        workspace.add_listener(arrived.append)
        workspace.start()

        self.write(
            "late.xml", nmap_scan(("10.0.0.7", "", [("3389", "tcp", "ms-wbt-server")]))
        )

        deadline = time.time() + 5
        while time.time() < deadline and not arrived:
            time.sleep(0.05)

        self.assertTrue(arrived, "the watcher never reported the new scan")
        self.assertIn("10.0.0.7", workspace._state)

    def test_stop_joins_the_watcher(self):
        workspace = self.open_workspace()
        workspace.start()
        workspace.stop()

        self.assertIsNone(workspace._watcher)


class TestWorkspaceReadOnly(WorkspaceTestCase):
    def test_a_read_only_workspace_never_writes(self):
        self.write("scan.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        workspace = self.open_workspace(read_only=True)

        self.assertTrue(workspace.read_only)
        self.assertFalse(os.path.exists(self.state_file))
        # edits still apply in memory, they just do not reach the disk
        self.assertEqual(
            workspace.apply_edits([{"ip": "10.0.0.1", "port": "80", "state": "Done"}])[
                "applied"
            ],
            1,
        )
        self.assertFalse(os.path.exists(self.state_file))

    def test_an_unwritable_folder_starts_read_only(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the write bit")
        self.write("scan.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        os.chmod(self.folder, 0o500)
        self.addCleanup(os.chmod, self.folder, 0o700)

        workspace = self.open_workspace()

        self.assertTrue(workspace.read_only)

    def test_a_state_file_outside_the_scan_folder_is_honoured(self):
        self.write("scan.xml", nmap_scan(("10.0.0.1", "", [("80", "tcp", "http")])))
        elsewhere = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, elsewhere, ignore_errors=True)
        target = os.path.join(elsewhere, "triage.md")

        workspace = self.open_workspace(state_file=target)

        self.assertTrue(os.path.exists(target))
        self.assertFalse(os.path.exists(self.state_file))


if __name__ == "__main__":
    unittest.main()
