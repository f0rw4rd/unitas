"""The browser against a live `unitas <folder> -H`.

Everything below the browser is covered by test_workspace and test_webserver;
what needs a real page is the loop itself -- a click reaching state.md on disk,
and a scan dropped into the folder appearing in the table without a reload.

Skips itself without playwright and a chromium build.
"""

# pylint: skip-file
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from unitas.convert import MarkdownConvert, load_markdown_state
from unitas.webserver import create_server
from unitas.workspace import STATE_FILENAME, Workspace

from test_viewer_xss import CHROMIUM, PLAYWRIGHT_AVAILABLE, ViewerServer
from test_workspace import nmap_scan

if PLAYWRIGHT_AVAILABLE:
    from playwright.sync_api import sync_playwright


@unittest.skipUnless(
    PLAYWRIGHT_AVAILABLE and CHROMIUM is not None,
    "playwright with a chromium build is required",
)
class LiveWorkspaceCase(unittest.TestCase):
    """A served scan folder, a browser on it, and the helpers to poke both."""

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

        self.workspace = Workspace(self.folder, poll_interval=0.2)
        self.workspace.refresh()
        self.addCleanup(self.workspace.stop)

        self.httpd = create_server(self.workspace, port=0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()
        self.addCleanup(self._close)

        self.workspace.start()

        self.playwright = sync_playwright().start()
        self.addCleanup(self.playwright.stop)
        launch = {"executable_path": CHROMIUM} if CHROMIUM else {}
        self.browser = self.playwright.chromium.launch(**launch)
        self.addCleanup(self.browser.close)

        self.errors = []
        self.page = self.browser.new_page()
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.goto(f"http://127.0.0.1:{self.port}/index.html")
        self.open_ports_view(self.page)

    @staticmethod
    def open_ports_view(page):
        """The Ports table is the triage view, and it is not the default tab."""
        page.wait_for_function(
            "document.querySelectorAll('#ports-table tbody tr').length > 0"
        )
        page.click('.nav-item[data-view="ports-view"]')
        page.wait_for_selector("#ports-table tbody tr")

    def _close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

    def write(self, name, content):
        path = os.path.join(self.folder, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def state_from_disk(self):
        return load_markdown_state(os.path.join(self.folder, STATE_FILENAME))

    def wait_for(self, predicate, message, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if predicate():
                    return
            except Exception:  # pylint: disable=broad-except
                pass
            self.page.wait_for_timeout(100)
        self.fail(message)

    def row(self, ip, port):
        return self.page.locator(
            f'#ports-table tbody tr[data-ip="{ip}"][data-port="{port}"]'
        )

    def mark(self, ip, port, state):
        """Set one port to a state through the batch bar."""
        self.row(ip, port).locator("[data-select-row]").check()
        self.page.click(f'#ports-batch .batch-btn[data-mark="{state}"]')

    def state_of(self, ip, port):
        parsed = self.state_from_disk()
        if ip not in parsed:
            return None
        match = next((p for p in parsed[ip].ports if p.port == str(port)), None)
        return match.state if match else None


class TestLiveWorkspaceInTheBrowser(LiveWorkspaceCase):
    def test_the_page_comes_up_from_the_api(self):
        self.assertTrue(self.page.evaluate("window.UNITAS.live"))
        self.assertEqual(self.page.locator("#ports-table tbody tr").count(), 3)
        self.assertEqual(self.page.locator("#total-hosts").inner_text(), "2")
        self.assertEqual(self.errors, [])

    def test_the_indicator_reports_progress_not_a_local_edit_count(self):
        self.wait_for(
            lambda: "0/3 done" in self.page.locator("#edit-count").inner_text(),
            "the indicator never showed the server's progress",
        )
        # there is nothing local to reset, and nothing else to load
        self.assertTrue(self.page.locator("#reset-edits-btn").is_hidden())
        self.assertTrue(self.page.locator("#reload-btn").is_hidden())
        self.assertTrue(self.page.locator("#rescan-btn").is_visible())

    def test_a_status_click_reaches_state_md(self):
        toggle = self.row("10.0.0.1", "80").locator("[data-state-toggle]")

        toggle.click()

        self.wait_for(
            lambda: self.state_of("10.0.0.1", "80") == "In progress",
            "the click never reached state.md",
        )
        # and the other ports were not swept along
        self.assertEqual(self.state_of("10.0.0.1", "445"), "TBD")

        toggle.click()
        self.wait_for(
            lambda: self.state_of("10.0.0.1", "80") == "Done",
            "the second click never reached state.md",
        )

    def test_a_comment_reaches_state_md(self):
        comment = self.row("10.0.0.2", "22").locator(".comment-input")
        comment.fill("weak host key")
        comment.press("Enter")

        self.wait_for(
            lambda: next(
                p for p in self.state_from_disk()["10.0.0.2"].ports if p.port == "22"
            ).comment
            == "weak host key",
            "the comment never reached state.md",
        )

    def test_the_progress_counter_follows_the_triage(self):
        self.mark("10.0.0.1", "80", "Done")

        self.wait_for(
            lambda: "1/3 done" in self.page.locator("#edit-count").inner_text(),
            "the progress counter did not move",
        )

    def test_a_scan_dropped_in_appears_without_a_reload(self):
        self.write(
            "later.xml",
            nmap_scan(("10.0.0.3", "gamma", [("3389", "tcp", "ms-wbt-server")])),
        )

        self.wait_for(
            lambda: self.page.locator("#ports-table tbody tr").count() == 4,
            "the new scan never reached the table",
        )
        self.assertEqual(self.row("10.0.0.3", "3389").count(), 1)
        self.assertEqual(self.page.locator("#total-hosts").inner_text(), "3")

    def test_triage_survives_a_new_scan_of_the_same_host(self):
        self.mark("10.0.0.1", "80", "Done")
        self.wait_for(
            lambda: self.state_of("10.0.0.1", "80") == "Done",
            "the click never reached state.md",
        )

        self.write(
            "rescan.xml",
            nmap_scan(
                (
                    "10.0.0.1",
                    "alpha",
                    [("80", "tcp", "http"), ("8080", "tcp", "http-proxy")],
                )
            ),
        )

        self.wait_for(
            lambda: self.page.locator("#ports-table tbody tr").count() == 4,
            "the re-scan never reached the table",
        )
        self.assertEqual(
            self.row("10.0.0.1", "80").locator("[data-state-toggle]").inner_text(),
            "Done",
        )

    def test_an_external_state_md_edit_shows_up(self):
        path = os.path.join(self.folder, STATE_FILENAME)
        with open(path, "r", encoding="utf-8") as f:
            markdown = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write(markdown.replace("|TBD||", "|Done|from the CLI|", 1))

        self.wait_for(
            lambda: self.page.locator(
                '#ports-table tbody tr [data-state-toggle]:text-is("Done")'
            ).count()
            == 1,
            "the hand edit never reached the page",
        )

    def test_rescan_button_pulls_the_folder(self):
        self.write("manual.xml", nmap_scan(("10.0.0.4", "", [("21", "tcp", "ftp")])))

        self.page.locator("#rescan-btn").click()

        self.wait_for(
            lambda: self.row("10.0.0.4", "21").count() == 1,
            "the rescan button did not pull the new scan",
        )

    def test_a_read_only_workspace_says_so_and_does_not_write(self):
        workspace = Workspace(self.folder, read_only=True, poll_interval=0.2)
        workspace.refresh()
        self.addCleanup(workspace.stop)
        httpd = create_server(workspace, port=0)
        thread = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        thread.start()

        try:
            page = self.browser.new_page()
            page.goto(f"http://127.0.0.1:{httpd.server_address[1]}/index.html")
            self.open_ports_view(page)

            self.assertIn("read only", page.locator("#edit-count").inner_text())

            page.locator(
                '#ports-table tbody tr[data-ip="10.0.0.1"][data-port="80"] [data-state-toggle]'
            ).click()
            page.wait_for_timeout(500)

            self.assertEqual(self.state_of("10.0.0.1", "80"), "TBD")
            page.close()
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join()

    def test_the_page_survives_the_server_going_away(self):
        self._close()  # the teardown calls it again, which is a no-op

        self.row("10.0.0.1", "80").locator("[data-state-toggle]").click()

        self.wait_for(
            lambda: "not saved" in self.page.locator("#edit-count").inner_text(),
            "the page never noticed the server was gone",
        )
        # the click is still shown, so the tester does not silently lose it
        self.assertEqual(
            self.row("10.0.0.1", "80").locator("[data-state-toggle]").inner_text(),
            "In progress",
        )


@unittest.skipUnless(
    PLAYWRIGHT_AVAILABLE and CHROMIUM is not None,
    "playwright with a chromium build is required",
)
class TestBatchTriage(LiveWorkspaceCase):
    """Marking a run of ports or a set of hosts in one gesture."""

    def setUp(self):
        super().setUp()
        # a second host with a run of ports, so a shift-range has something to
        # cover
        self.write(
            "block.xml",
            nmap_scan(
                (
                    "10.0.0.5",
                    "delta",
                    [(str(port), "tcp", "http") for port in range(8000, 8006)],
                )
            ),
        )
        self.wait_for(
            lambda: self.page.locator("#ports-table tbody tr").count() == 9,
            "the extra scan never reached the table",
        )

    def selected_count(self):
        return self.page.locator("#ports-batch-count").inner_text()

    def test_the_bar_appears_only_with_a_selection(self):
        self.assertTrue(self.page.locator("#ports-batch").is_hidden())

        self.row("10.0.0.5", "8000").locator("[data-select-row]").check()

        self.assertTrue(self.page.locator("#ports-batch").is_visible())
        self.assertEqual(self.selected_count(), "1 port selected")

    def test_shift_click_selects_the_run_between(self):
        self.row("10.0.0.5", "8000").locator("[data-select-row]").check()
        self.row("10.0.0.5", "8004").locator("[data-select-row]").click(
            modifiers=["Shift"]
        )

        self.assertEqual(self.selected_count(), "5 ports selected")

        self.page.click('#ports-batch .batch-btn[data-mark="Done"]')

        self.wait_for(
            lambda: [self.state_of("10.0.0.5", port) for port in range(8000, 8006)]
            == ["Done"] * 5 + ["TBD"],
            "the range did not reach state.md",
        )

    def test_marking_clears_the_selection(self):
        self.row("10.0.0.5", "8000").locator("[data-select-row]").check()
        self.page.click('#ports-batch .batch-btn[data-mark="In progress"]')

        self.assertTrue(self.page.locator("#ports-batch").is_hidden())
        self.assertEqual(
            self.row("10.0.0.5", "8000").locator("[data-state-toggle]").inner_text(),
            "In progress",
        )

    def test_select_all_covers_what_the_filter_left(self):
        self.page.fill("#search", "8000")
        self.wait_for(
            lambda: self.page.locator(
                "#ports-table tbody tr:not([style*='display: none'])"
            ).count()
            == 1,
            "the search never narrowed the table",
        )

        self.page.check("#ports-table thead [data-select-all]")
        self.assertEqual(self.selected_count(), "1 port selected")

        self.page.click('#ports-batch .batch-btn[data-mark="Done"]')

        self.wait_for(
            lambda: self.state_of("10.0.0.5", "8000") == "Done",
            "the filtered selection was not marked",
        )
        # nothing outside the filter was touched
        self.assertEqual(self.state_of("10.0.0.5", "8001"), "TBD")

    def test_a_row_the_filter_hides_leaves_the_selection(self):
        self.row("10.0.0.5", "8000").locator("[data-select-row]").check()
        self.row("10.0.0.5", "8001").locator("[data-select-row]").check()

        self.page.fill("#search", "8000")
        self.wait_for(
            lambda: self.selected_count() == "1 port selected",
            "the hidden row stayed in the selection",
        )

        # and it does not come back checked
        self.page.fill("#search", "")
        self.page.wait_for_timeout(300)
        self.assertEqual(self.selected_count(), "1 port selected")

    def test_a_host_batch_marks_every_port_of_it(self):
        self.page.click('.nav-item[data-view="hosts-view"]')
        self.page.wait_for_selector("#hosts-table tbody tr")

        self.page.check('#hosts-table tbody tr[data-ip="10.0.0.1"] [data-select-row]')
        self.assertEqual(
            self.page.locator("#hosts-batch-count").inner_text(), "1 host selected"
        )

        self.page.click('#hosts-batch .batch-btn[data-mark="Done"]')

        self.wait_for(
            lambda: self.state_of("10.0.0.1", "80") == "Done"
            and self.state_of("10.0.0.1", "445") == "Done",
            "the host batch never reached state.md",
        )
        # and only that host
        self.assertEqual(self.state_of("10.0.0.2", "22"), "TBD")

    def test_the_in_progress_filter_works(self):
        self.row("10.0.0.5", "8000").locator("[data-select-row]").check()
        self.page.click('#ports-batch .batch-btn[data-mark="In progress"]')

        self.page.click('.status-btn[data-status="in progress"]')

        self.wait_for(
            lambda: self.page.locator(
                "#ports-table tbody tr:not([style*='display: none'])"
            ).count()
            == 1,
            "the In progress filter did not narrow the table",
        )


@unittest.skipUnless(
    PLAYWRIGHT_AVAILABLE and CHROMIUM is not None,
    "playwright with a chromium build is required",
)
class TestSearchOperatorsAndKeyboard(LiveWorkspaceCase):
    """Narrowing the list and marking it without touching the mouse."""

    def setUp(self):
        super().setUp()
        self.write(
            "more.xml",
            nmap_scan(
                ("10.31.112.5", "smb-a", [("445", "tcp", "microsoft-ds")]),
                ("10.31.112.6", "smb-b", [("445", "tcp", "microsoft-ds"), ("8445", "tcp", "https")]),
                ("192.168.1.9", "printer", [("445", "tcp", "microsoft-ds")]),
            ),
        )
        self.wait_for(
            lambda: self.page.locator("#ports-table tbody tr").count() == 7,
            "the extra scan never reached the table",
        )

    def visible(self):
        # the "no rows match" placeholder carries no data, it is not a result
        return self.page.locator(
            "#ports-table tbody tr[data-ip]:not([style*='display: none'])"
        )

    def search(self, text, expected):
        self.page.fill("#search", text)
        self.wait_for(
            lambda: self.visible().count() == expected,
            f'"{text}" left {self.visible().count()} rows, expected {expected}',
        )

    def test_a_bare_word_still_matches_anything(self):
        # four ports named smb plus the host called smb-b's https port
        self.search("smb", 5)

    def test_service_and_port_narrow_to_the_field(self):
        # a bare 445 also matches 8445; the operator does not
        self.search("445", 5)
        self.search("port:445", 4)
        self.search("service:smb", 4)
        self.search("service:https", 1)

    def test_net_anchors_at_the_start_of_the_address(self):
        self.search("net:10.31.112.", 3)
        # a substring match would also take 192.168.1.9 on "1."
        self.search("net:192.168.", 1)

    def test_clauses_combine_and_negate(self):
        self.search("net:10.31.112. port:445", 2)
        self.search("port:445 -printer", 3)
        self.search("port:445 -net:10.", 1)

    def test_state_follows_the_triage(self):
        self.mark("10.31.112.5", "445", "Done")
        self.wait_for(
            lambda: self.state_of("10.31.112.5", "445") == "Done",
            "the mark never landed",
        )

        self.search("state:done", 1)
        self.search("port:445 -state:done", 3)

    def test_an_unknown_operator_is_just_text(self):
        # "foo:" is not a field, so it must not silently match everything
        self.search("foo:bar", 0)

    def test_j_and_d_triage_from_the_keyboard(self):
        self.page.click("#ports-table")
        self.page.keyboard.press("j")
        self.assertEqual(self.page.locator("tr.row-cursor").count(), 1)

        first = self.page.locator("tr.row-cursor")
        ip = first.get_attribute("data-ip")
        port = first.get_attribute("data-port")

        self.page.keyboard.press("d")

        self.wait_for(
            lambda: self.state_of(ip, port) == "Done",
            "the keyboard mark never reached state.md",
        )

    def test_x_selects_and_the_state_key_covers_the_selection(self):
        self.search("net:10.31.112. port:445", 2)
        self.page.click("#ports-table")

        for _ in range(2):
            self.page.keyboard.press("j")
            self.page.keyboard.press("x")

        self.assertEqual(
            self.page.locator("#ports-batch-count").inner_text(), "2 ports selected"
        )

        self.page.keyboard.press("p")

        self.wait_for(
            lambda: [
                self.state_of("10.31.112.5", "445"),
                self.state_of("10.31.112.6", "445"),
            ]
            == ["In progress"] * 2,
            "the keyboard did not mark the selection",
        )
        # and nothing the filter had hidden
        self.assertEqual(self.state_of("10.0.0.1", "445"), "TBD")

    def test_n_opens_the_note_and_typing_does_not_trigger_shortcuts(self):
        self.page.click("#ports-table")
        self.page.keyboard.press("j")
        self.page.keyboard.press("n")

        self.assertEqual(
            self.page.evaluate("document.activeElement.dataset.commentInput"), ""
        )

        row = self.page.locator("tr.row-cursor")
        ip = row.get_attribute("data-ip")
        port = row.get_attribute("data-port")

        self.page.keyboard.type("dpu jk x")
        self.page.keyboard.press("Enter")

        self.wait_for(
            lambda: next(
                p for p in self.state_from_disk()[ip].ports if p.port == port
            ).comment
            == "dpu jk x",
            "the typed note never reached state.md",
        )
        # and none of those letters marked anything
        self.assertEqual(self.page.locator("#edit-count").inner_text().count("done"), 1)
        self.assertIn("0/7 done", self.page.locator("#edit-count").inner_text())


@unittest.skipUnless(
    PLAYWRIGHT_AVAILABLE and CHROMIUM is not None,
    "playwright with a chromium build is required",
)
class TestGroupedWorklist(LiveWorkspaceCase):
    """The Ports view as a worklist rather than a flat list."""

    def setUp(self):
        super().setUp()
        self.write(
            "block.xml",
            nmap_scan(
                ("10.31.112.5", "smb-a", [("445", "tcp", "microsoft-ds")]),
                ("10.31.112.6", "smb-b", [("445", "tcp", "microsoft-ds")]),
                ("10.31.112.7", "smb-c", [("445", "tcp", "microsoft-ds")]),
            ),
        )
        self.wait_for(
            lambda: self.page.locator("#ports-table tbody tr[data-ip]").count() == 6,
            "the extra scan never reached the table",
        )

    def group_by(self, mode):
        self.page.select_option("#group-by", mode)
        self.page.wait_for_timeout(200)

    def header(self, key):
        return self.page.locator(f'tr.group-row[data-group-header="{key}"]')

    def visible_headers(self):
        return self.page.eval_on_selector_all(
            "tr.group-row",
            "rows => rows.filter(r => r.style.display !== 'none')"
            ".map(r => r.dataset.groupHeader)",
        )

    def test_no_grouping_by_default(self):
        self.assertEqual(self.page.locator("tr.group-row").count(), 0)

    def test_grouping_by_service_counts_each_group(self):
        self.group_by("service")

        # smb is the biggest group, so it leads
        self.assertEqual(self.visible_headers()[0], "smb")
        self.assertIn(
            "4 ports, 4 hosts, 0 done",
            self.header("smb").inner_text(),
        )
        self.assertIn("1 port, 1 host, 0 done", self.header("ssh").inner_text())

    def test_the_counts_follow_a_mark(self):
        self.group_by("service")
        self.mark("10.31.112.5", "445", "Done")

        self.wait_for(
            lambda: "4 ports, 4 hosts, 1 done" in self.header("smb").inner_text(),
            "the group count did not follow the mark",
        )

    def test_grouping_by_subnet(self):
        self.group_by("subnet")

        self.assertEqual(
            sorted(self.visible_headers()), ["10.0.0", "10.31.112"]
        )
        self.assertIn("3 ports, 3 hosts", self.header("10.31.112").inner_text())

    def test_collapsing_hides_the_rows_but_keeps_the_count(self):
        self.group_by("service")

        self.page.click('[data-group-toggle="smb"]')

        self.assertEqual(
            self.page.locator(
                "#ports-table tbody tr[data-ip]:not([style*='display: none'])"
            ).count(),
            2,
        )
        # the header still reports the whole group
        self.assertIn("4 ports, 4 hosts", self.header("smb").inner_text())
        self.assertTrue(self.header("smb").is_visible())

        self.page.click('[data-group-toggle="smb"]')
        self.assertEqual(
            self.page.locator(
                "#ports-table tbody tr[data-ip]:not([style*='display: none'])"
            ).count(),
            6,
        )

    def test_a_group_the_filter_empties_disappears(self):
        self.group_by("service")

        self.page.fill("#search", "service:smb")

        self.wait_for(
            lambda: self.visible_headers() == ["smb"],
            "the emptied groups stayed on screen",
        )
        self.assertIn("4 ports, 4 hosts", self.header("smb").inner_text())

    def test_sorting_stays_inside_the_groups(self):
        self.group_by("service")

        self.page.click('#ports-table th[data-sort="ip"]')

        order = self.page.eval_on_selector_all(
            "#ports-table tbody tr",
            "rows => rows.map(r => r.dataset.groupHeader || r.dataset.ip)",
        )
        # every row still sits under its own header
        self.assertEqual(order[0], "smb")
        self.assertEqual(order[1:5], ["10.0.0.1", "10.31.112.5", "10.31.112.6", "10.31.112.7"])
        self.assertIn("ssh", order[5:])

    def test_g_cycles_the_grouping(self):
        self.page.click("#ports-table")

        self.page.keyboard.press("g")
        self.assertEqual(self.page.input_value("#group-by"), "service")

        self.page.keyboard.press("g")
        self.assertEqual(self.page.input_value("#group-by"), "subnet")

        self.page.keyboard.press("g")
        self.assertEqual(self.page.input_value("#group-by"), "none")
        self.assertEqual(self.page.locator("tr.group-row").count(), 0)

    def test_grouping_survives_a_new_scan(self):
        self.group_by("service")

        self.write("late.xml", nmap_scan(("10.31.112.8", "", [("445", "tcp", "microsoft-ds")])))

        self.wait_for(
            lambda: "5 ports, 5 hosts" in self.header("smb").inner_text(),
            "the group did not take the new scan",
        )


@unittest.skipUnless(
    PLAYWRIGHT_AVAILABLE and CHROMIUM is not None,
    "playwright with a chromium build is required",
)
class TestNessusPanel(LiveWorkspaceCase):
    """The "N of M exported" counter and its button.

    The exporter is patched: what is under test is the panel, not Nessus.
    """

    SCANS = {
        "scans": [
            {"id": 1, "name": "external", "status": "completed"},
            {"id": 2, "name": "internal", "status": "completed"},
            {"id": 3, "name": "merged", "status": "completed"},
        ]
    }

    def fake_exporter(self, export=None):
        from unitas.exporter import NessusExporter

        exporter = NessusExporter.__new__(NessusExporter)
        exporter.url = "https://nessus:8834"
        exporter.ses = MagicMock()
        exporter.ses.get.return_value.json.return_value = self.SCANS
        if export is not None:
            exporter.export = export
        return exporter

    def counter(self):
        return self.page.locator("#nessus-count").inner_text()

    def test_no_panel_without_credentials(self):
        # setUp loaded the page with the real (unconfigured) exporter
        self.assertTrue(self.page.locator("#nessus-panel").is_hidden())

    def test_the_counter_names_what_is_missing(self):
        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.return_value = self.fake_exporter()

            self.page.reload()
            self.open_ports_view(self.page)

            self.wait_for(
                lambda: "2 missing" in self.counter(),
                f"the counter said {self.counter()!r}",
            )
            self.assertIn("0 of 2 exported", self.counter())
            self.assertTrue(
                self.page.locator("#nessus-export-btn").is_enabled()
            )

    def test_the_button_starts_an_export_and_the_files_land(self):
        started = threading.Event()

        def export(target_dir):
            started.set()
            with open(
                os.path.join(target_dir, "external_1.nessus"), "w", encoding="utf-8"
            ) as f:
                f.write(
                    '<NessusClientData_v2><Report><ReportHost name="10.0.0.9">'
                    '<HostProperties><tag name="host-ip">10.0.0.9</tag></HostProperties>'
                    '<ReportItem port="3306" svc_name="mysql" protocol="tcp"'
                    ' pluginID="1" pluginName="MySQL" pluginFamily="Databases"/>'
                    "</ReportHost></Report></NessusClientData_v2>"
                )

        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.side_effect = lambda: self.fake_exporter(export=export)

            self.page.reload()
            self.open_ports_view(self.page)
            self.wait_for(
                lambda: "missing" in self.counter(), "the panel never appeared"
            )

            self.page.click("#nessus-export-btn")
            self.assertTrue(started.wait(10), "the export never started")

            # the folder watcher picks the download up with no further clicking
            self.wait_for(
                lambda: self.row("10.0.0.9", "3306").count() == 1,
                "the exported scan never reached the table",
            )
            # and the counter follows
            self.wait_for(
                lambda: "1 of 2 exported" in self.counter(),
                f"the counter said {self.counter()!r}",
            )

    def test_a_failing_export_says_why(self):
        def export(target_dir):
            raise RuntimeError("403 from Nessus")

        with patch("unitas.webserver.NessusExporter") as mock:
            mock.is_configured.return_value = True
            mock.side_effect = lambda: self.fake_exporter(export=export)

            self.page.reload()
            self.open_ports_view(self.page)
            self.wait_for(
                lambda: "missing" in self.counter(), "the panel never appeared"
            )

            self.page.click("#nessus-export-btn")

            self.wait_for(
                lambda: "403 from Nessus" in self.counter(),
                f"the counter said {self.counter()!r}",
            )


@unittest.skipUnless(
    PLAYWRIGHT_AVAILABLE and CHROMIUM is not None,
    "playwright with a chromium build is required",
)
class TestBatchTriageWithoutAServer(unittest.TestCase):
    """The same batch bar with no API behind it.

    A single file report and a dropped JSON keep the localStorage overlay, and
    the batch actions have to go through it rather than assuming a workspace.
    """

    SCAN = {
        "metadata": {"generated": "2026-01-01 00:00:00", "version": "1.0"},
        "hosts": [
            {
                "ip": "10.0.0.1",
                "hostname": "alpha",
                "mac_address": "",
                "vendor": "",
                "hasOpenPorts": True,
                "ports": [
                    {
                        "port": str(port),
                        "protocol": "tcp",
                        "service": "http",
                        "state": "TBD",
                        "comment": "",
                        "uncertain": False,
                        "tls": False,
                    }
                    for port in (80, 443, 8080)
                ],
            }
        ],
        "hostsUp": [],
    }

    @classmethod
    def setUpClass(cls):
        cls.server = ViewerServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def setUp(self):
        self.playwright = sync_playwright().start()
        self.addCleanup(self.playwright.stop)
        launch = {"executable_path": CHROMIUM} if CHROMIUM else {}
        self.browser = self.playwright.chromium.launch(**launch)
        self.addCleanup(self.browser.close)

        self.errors = []
        self.page = self.browser.new_page()
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.goto(self.server.url)
        self.page.wait_for_function("typeof validateAndDisplayData === 'function'")
        self.page.evaluate(
            "data => { window.scanData = data; validateAndDisplayData(data); }",
            self.SCAN,
        )
        self.page.click('.nav-item[data-view="ports-view"]')
        self.page.wait_for_selector("#ports-table tbody tr")

    def test_a_batch_mark_lands_in_the_local_overlay(self):
        self.page.check(
            '#ports-table tbody tr[data-port="80"] [data-select-row]'
        )
        self.page.locator('#ports-table tbody tr[data-port="8080"] [data-select-row]').click(
            modifiers=["Shift"]
        )
        self.assertEqual(
            self.page.locator("#ports-batch-count").inner_text(), "3 ports selected"
        )

        self.page.click('#ports-batch .batch-btn[data-mark="Done"]')

        self.assertEqual(self.page.evaluate("editCount()"), 3)
        self.assertEqual(
            self.page.evaluate(
                "Array.from(document.querySelectorAll('#ports-table tbody tr"
                " [data-state-toggle]')).map(b => b.textContent)"
            ),
            ["Done", "Done", "Done"],
        )
        self.assertEqual(self.errors, [])

    def test_a_backslash_survives_the_round_trip_into_the_parser(self):
        """The exported markdown has to parse back the way it was written.

        The browser escapes the cells itself, and the CLI is what reads them:
        an unescaped backslash makes `unitas -u` drop it ("DOMAIN\\user" comes
        back as "DOMAINuser"), and one at the end of a comment escapes the cell
        separator and corrupts the whole row.
        """
        awkward = "DOMAIN\\user share\\"
        self.page.evaluate(
            """value => {
                const port = window.scanData.hosts[0].ports[0];
                setPortEdit(window.scanData.hosts[0].ip, port, {comment: value});
            }""",
            awkward,
        )

        markdown = self.page.evaluate(
            """() => {
                let written = null;
                const original = downloadTextFile;
                window.downloadTextFile = content => { written = content; };
                exportStateMarkdown();
                window.downloadTextFile = original;
                return written;
            }"""
        )

        parsed = MarkdownConvert().parse(markdown)
        port = next(p for p in parsed["10.0.0.1"].ports if p.port == "80")
        self.assertEqual(port.comment, awkward)
        # the row after it still parses, so the separator was not eaten
        self.assertEqual(len(parsed["10.0.0.1"].ports), 3)

    def test_the_export_carries_the_batch(self):
        self.page.check('#ports-table tbody tr[data-port="443"] [data-select-row]')
        self.page.click('#ports-batch .batch-btn[data-mark="In progress"]')

        markdown = self.page.evaluate(
            """() => {
                let written = null;
                const original = downloadTextFile;
                window.downloadTextFile = content => { written = content; };
                exportStateMarkdown();
                window.downloadTextFile = original;
                return written;
            }"""
        )

        self.assertIn("|443/tcp(http)|In progress||", markdown)
        self.assertIn("|80/tcp(http)|TBD||", markdown)


if __name__ == "__main__":
    unittest.main()
