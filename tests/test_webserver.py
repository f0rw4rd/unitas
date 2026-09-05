"""The workspace API behind `unitas <folder> -H`.

Real HTTP against a server on an ephemeral port, no browser: the routes, what
they refuse, and that an edit posted over the wire ends up in state.md.
"""

# pylint: skip-file
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from unitas.convert import load_markdown_state
from unitas.webserver import TOKEN_HEADER, create_server
from unitas.workspace import STATE_FILENAME, Workspace

from test_workspace import nmap_scan


class ServedWorkspace:
    """A workspace served on a port the OS picks."""

    def __init__(self, folder, **kwargs):
        self.workspace = Workspace(folder, poll_interval=0.05, **kwargs)
        self.workspace.refresh()
        self.httpd = create_server(self.workspace, port=0)
        self.token = self.httpd.unitas_token
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path, headers=None):
        return self._open(urllib.request.Request(self.url(path), headers=headers or {}))

    def post(self, path, payload=None, token=True, headers=None):
        head = {"Content-Type": "application/json"}
        if token:
            head[TOKEN_HEADER] = self.token if token is True else token
        head.update(headers or {})
        request = urllib.request.Request(
            self.url(path),
            data=json.dumps(payload or {}).encode("utf-8"),
            headers=head,
            method="POST",
        )
        return self._open(request)

    @staticmethod
    def _open(request):
        """(status, parsed body or text)."""
        try:
            response = urllib.request.urlopen(request, timeout=10)
            status, raw = response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read().decode("utf-8")
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, raw

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        self.workspace.stop()


class WebserverTestCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, ignore_errors=True)
        self.write(
            "scan.xml",
            nmap_scan(
                (
                    "10.0.0.1",
                    "alpha",
                    [("80", "tcp", "http"), ("445", "tcp", "netbios-ssn")],
                ),
                ("10.0.0.2", "beta", [("22", "tcp", "ssh")]),
            ),
        )
        self.server = self.serve()

    def serve(self, **kwargs):
        server = ServedWorkspace(self.folder, **kwargs)
        self.addCleanup(server.close)
        return server

    def write(self, name, content):
        path = os.path.join(self.folder, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def state_from_disk(self):
        return load_markdown_state(os.path.join(self.folder, STATE_FILENAME))


class TestStateRoute(WebserverTestCase):
    def test_state_carries_the_scan_and_a_version(self):
        status, body = self.server.get("/api/state")

        self.assertEqual(status, 200)
        self.assertFalse(body["unchanged"])
        self.assertEqual(body["version"], self.server.workspace.version)
        self.assertEqual(
            sorted(host["ip"] for host in body["data"]["hosts"]),
            ["10.0.0.1", "10.0.0.2"],
        )
        self.assertEqual(body["summary"]["ports"], 3)

    def test_a_poll_at_the_current_version_sends_no_data(self):
        _, first = self.server.get("/api/state")

        status, body = self.server.get(f"/api/state?version={first['version']}")

        self.assertEqual(status, 200)
        self.assertTrue(body["unchanged"])
        self.assertNotIn("data", body)
        # the counters still come along, they are what the header shows
        self.assertEqual(body["summary"]["hosts"], 2)

    def test_a_stale_version_gets_the_new_state(self):
        _, first = self.server.get("/api/state")
        self.server.post(
            "/api/edits", {"ports": [{"ip": "10.0.0.1", "port": "80", "state": "Done"}]}
        )

        status, body = self.server.get(f"/api/state?version={first['version']}")

        self.assertFalse(body["unchanged"])
        self.assertGreater(body["version"], first["version"])

    def test_a_junk_version_is_not_a_500(self):
        status, body = self.server.get("/api/state?version=yesterday")

        self.assertEqual(status, 200)
        self.assertFalse(body["unchanged"])

    def test_unknown_endpoints_are_404(self):
        self.assertEqual(self.server.get("/api/nope")[0], 404)
        self.assertEqual(self.server.post("/api/nope")[0], 404)
        self.assertEqual(self.server.post("/nope")[0], 404)


class TestEditsRoute(WebserverTestCase):
    def test_an_edit_reaches_state_md(self):
        status, body = self.server.post(
            "/api/edits",
            {
                "ports": [
                    {
                        "ip": "10.0.0.1",
                        "port": "445",
                        "protocol": "tcp",
                        "state": "In progress",
                        "comment": "null session",
                    }
                ]
            },
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["applied"], 1)

        port = next(
            p for p in self.state_from_disk()["10.0.0.1"].ports if p.port == "445"
        )
        self.assertEqual(port.state, "In progress")
        self.assertEqual(port.comment, "null session")

    def test_a_host_edit_marks_every_port(self):
        status, body = self.server.post(
            "/api/edits", {"hosts": [{"ip": "10.0.0.1", "state": "Done"}]}
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["applied"], 2)
        self.assertEqual(
            {p.state for p in self.state_from_disk()["10.0.0.1"].ports}, {"Done"}
        )

    def test_edits_without_the_token_are_refused(self):
        status, body = self.server.post(
            "/api/edits",
            {"ports": [{"ip": "10.0.0.1", "port": "80", "state": "Done"}]},
            token=False,
        )

        self.assertEqual(status, 403)
        self.assertIn("token", body["error"])
        self.assertEqual(
            next(
                p for p in self.state_from_disk()["10.0.0.1"].ports if p.port == "80"
            ).state,
            "TBD",
        )

    def test_a_wrong_token_is_refused(self):
        self.assertEqual(
            self.server.post("/api/edits", {}, token="not-the-token")[0], 403
        )

    def test_another_page_cannot_drive_the_api(self):
        """A token leak still should not let evil.example POST here."""
        status, body = self.server.post(
            "/api/edits",
            {"hosts": [{"ip": "10.0.0.1", "state": "Done"}]},
            headers={"Origin": "http://evil.example"},
        )

        self.assertEqual(status, 403)
        self.assertIn("cross origin", body["error"])

    def test_our_own_origin_is_accepted(self):
        status, _ = self.server.post(
            "/api/edits",
            {"hosts": [{"ip": "10.0.0.2", "state": "Done"}]},
            headers={"Origin": f"http://127.0.0.1:{self.server.port}"},
        )

        self.assertEqual(status, 200)

    def test_malformed_bodies_are_rejected_not_crashed(self):
        request = urllib.request.Request(
            self.server.url("/api/edits"),
            data=b"{not json",
            headers={TOKEN_HEADER: self.server.token},
            method="POST",
        )
        self.assertEqual(ServedWorkspace._open(request)[0], 400)

        self.assertEqual(self.server.post("/api/edits", {"ports": "all"})[0], 400)
        # a JSON array is valid JSON and still not an edit
        request = urllib.request.Request(
            self.server.url("/api/edits"),
            data=b"[]",
            headers={TOKEN_HEADER: self.server.token},
            method="POST",
        )
        self.assertEqual(ServedWorkspace._open(request)[0], 400)

    def test_junk_entries_are_skipped_not_fatal(self):
        status, body = self.server.post(
            "/api/edits",
            {
                "ports": [
                    "nope",
                    None,
                    {"ip": "10.0.0.1", "port": "80", "state": "Done"},
                ]
            },
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["applied"], 1)

    def test_a_read_only_workspace_refuses_writes(self):
        server = ServedWorkspace(self.folder, read_only=True)
        self.addCleanup(server.close)

        status, body = server.post(
            "/api/edits", {"hosts": [{"ip": "10.0.0.1", "state": "Done"}]}
        )

        self.assertEqual(status, 409)
        self.assertIn("read only", body["error"])


class TestRescanRoute(WebserverTestCase):
    def test_rescan_picks_up_a_new_file(self):
        self.write(
            "later.xml", nmap_scan(("10.0.0.3", "", [("3389", "tcp", "ms-wbt-server")]))
        )

        status, body = self.server.post("/api/rescan")

        self.assertEqual(status, 200)
        self.assertTrue(body["changed"])
        _, state = self.server.get("/api/state")
        self.assertIn("10.0.0.3", [host["ip"] for host in state["data"]["hosts"]])

    def test_rescan_needs_the_token_too(self):
        self.assertEqual(self.server.post("/api/rescan", token=False)[0], 403)


class TestPageAndAssets(WebserverTestCase):
    def test_the_page_carries_the_bootstrap(self):
        status, html = self.server.get("/")

        self.assertEqual(status, 200)
        self.assertIn("window.UNITAS", html)
        self.assertIn(self.server.token, html)
        self.assertIn('"live": true', html)
        # the bootstrap has to come before the scripts that read it
        self.assertLess(html.index("window.UNITAS"), html.index("workspace.js"))
        # workspace.js drives the API; the data.json loader would race it
        self.assertNotIn("auto-loader.js", html)

    def test_the_token_cannot_break_out_of_the_script(self):
        status, html = self.server.get("/index.html")

        self.assertNotIn("\\u003c/script", html.split("window.UNITAS")[1][:400].lower())
        self.assertIn("window.UNITAS", html)

    def test_assets_are_served_from_the_package(self):
        status, body = self.server.get("/static/js/app.js")

        self.assertEqual(status, 200)
        self.assertGreater(len(body), 100)

    def test_data_json_is_the_current_snapshot(self):
        status, body = self.server.get("/data.json")

        self.assertEqual(status, 200)
        self.assertEqual(len(body["hosts"]), 2)

    def test_summary_reports_the_state_file(self):
        status, body = self.server.get("/api/summary")

        self.assertEqual(status, 200)
        self.assertEqual(body["state_file"], self.server.workspace.state_file)
        self.assertFalse(body["read_only"])


class TestNessusRoutes(WebserverTestCase):
    """The counter the panel shows and the export behind its button.

    Everything is driven against a patched exporter: these routes are about
    what the server does with the answers, not about talking to Nessus.
    """

    SCANS = {
        "scans": [
            {"id": 1, "name": "external", "status": "completed"},
            {"id": 2, "name": "internal", "status": "completed"},
            {"id": 3, "name": "still going", "status": "running"},
            {"id": 4, "name": "merged", "status": "completed"},
        ]
    }

    def exporter(self):
        """A NessusExporter whose session answers with SCANS."""
        from unitas.exporter import NessusExporter

        exporter = NessusExporter.__new__(NessusExporter)
        exporter.url = "https://nessus:8834"
        exporter.ses = MagicMock()
        exporter.ses.get.return_value.json.return_value = self.SCANS
        return exporter

    def test_an_unconfigured_server_says_so_rather_than_failing(self):
        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = False
            status, body = self.server.get("/api/nessus")

        self.assertEqual(status, 200)
        self.assertFalse(body["configured"])
        self.assertEqual(body["total"], 0)

    def test_the_counter_reports_what_is_still_missing(self):
        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.return_value = self.exporter()
            status, body = self.server.get("/api/nessus")

        self.assertEqual(status, 200)
        self.assertTrue(body["configured"])
        self.assertEqual(body["total"], 4)
        # a running scan and "merged" are never exported
        self.assertEqual(body["skipped"], 2)
        self.assertEqual(body["exported"], 0)
        self.assertEqual(body["missing"], 2)

    def test_a_scan_already_on_disk_counts_as_exported(self):
        self.write("external_1.nessus", "<NessusClientData_v2/>")

        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.return_value = self.exporter()
            _, body = self.server.get("/api/nessus")

        self.assertEqual(body["exported"], 1)
        self.assertEqual(body["missing"], 1)
        landed = next(s for s in body["scans"] if s["name"] == "external")
        self.assertTrue(landed["exported"])

    def test_an_unreachable_nessus_is_a_message_not_a_500(self):
        exporter = self.exporter()
        exporter.ses.get.side_effect = OSError("connection refused")

        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.return_value = exporter
            status, body = self.server.get("/api/nessus")

        self.assertEqual(status, 200)
        self.assertIn("connection refused", body["error"])

    def test_the_export_runs_in_the_background(self):
        started = threading.Event()
        release = threading.Event()

        def slow_export(target_dir):
            started.set()
            release.wait(10)

        exporter = self.exporter()
        exporter.export = slow_export

        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.return_value = exporter

            status, body = self.server.post("/api/nessus/export")
            self.assertEqual(status, 200)
            self.assertTrue(body["started"])
            self.assertTrue(started.wait(10), "the export never started")

            # the request came back while it is still going
            _, running = self.server.get("/api/nessus")
            self.assertTrue(running["running"])

            # and a second one is refused rather than queued
            again = self.server.post("/api/nessus/export")
            self.assertEqual(again[0], 409)
            self.assertIn("already running", again[1]["reason"])

            release.set()

    def test_a_failed_export_is_reported_on_the_next_status(self):
        exporter = self.exporter()
        exporter.export = MagicMock(side_effect=RuntimeError("403 from Nessus"))

        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.return_value = exporter

            self.server.post("/api/nessus/export")

            deadline = time.time() + 10
            body = {}
            while time.time() < deadline:
                _, body = self.server.get("/api/nessus")
                if body.get("last_error"):
                    break
                time.sleep(0.05)

        self.assertIn("403 from Nessus", body["last_error"])

    def test_the_export_needs_the_token(self):
        self.assertEqual(self.server.post("/api/nessus/export", token=False)[0], 403)

    def test_an_unconfigured_export_is_refused_with_a_reason(self):
        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = False
            status, body = self.server.post("/api/nessus/export")

        self.assertEqual(status, 409)
        self.assertIn("credentials", body["reason"])

    def test_a_read_only_workspace_does_not_download_into_the_folder(self):
        server = ServedWorkspace(self.folder, read_only=True)
        self.addCleanup(server.close)

        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            status, body = server.post("/api/nessus/export")

        self.assertEqual(status, 409)
        self.assertIn("read only", body["error"])


class TestServerWithoutWorkspace(unittest.TestCase):
    """`-H` can still serve a single snapshot, the way it always did."""

    def setUp(self):
        payload = json.dumps({"metadata": {}, "hosts": [{"ip": "10.0.0.1"}]})
        self.httpd = create_server(None, port=0, json_content=payload)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()
        self.addCleanup(self._close)

    def _close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

    def get(self, path):
        return ServedWorkspace._open(
            urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        )

    def test_the_snapshot_is_served(self):
        status, body = self.get("/data.json")

        self.assertEqual(status, 200)
        self.assertEqual(body["hosts"][0]["ip"], "10.0.0.1")

    def test_the_api_says_there_is_nothing_live(self):
        self.assertEqual(self.get("/api/state")[0], 404)

    def test_the_page_says_it_is_not_live(self):
        html = self.get("/index.html")[1]

        self.assertIn('"live": false', html)
        # without a workspace the page still needs something to fetch data.json
        self.assertIn("auto-loader.js", html)


if __name__ == "__main__":
    unittest.main()
