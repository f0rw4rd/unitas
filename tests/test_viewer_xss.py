"""Browser regression test for the viewer's handling of hostile scan data.

Every string in a scan is written by the scanned host, so a host can answer with
an HTML banner. This drives a real browser to prove none of it becomes markup.

The test needs playwright and a chromium build; it skips itself when they are
not available, so the normal `python -m unittest discover -s tests` run is
unaffected.
"""

# pylint: skip-file
import http.server
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from unitas.report import find_resources_dir

try:
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    PLAYWRIGHT_AVAILABLE = False


def find_chromium():
    """A chromium playwright can launch, or None."""
    if not PLAYWRIGHT_AVAILABLE:
        return None

    browsers = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    if os.path.isdir(browsers):
        for entry in sorted(os.listdir(browsers), reverse=True):
            candidate = os.path.join(browsers, entry, "chrome-linux", "chrome")
            if os.path.exists(candidate):
                return candidate

    # let playwright use whatever it has installed itself
    return ""


CHROMIUM = find_chromium()

PAYLOAD = '<img src=x onerror="window.__xss.push(1)">'

SCAN = {
    "metadata": {"generated": PAYLOAD, "version": PAYLOAD, "includesOrigin": True},
    "hosts": [
        {
            "ip": "10.0.0.1",
            "hostname": PAYLOAD,
            "mac_address": PAYLOAD,
            "vendor": PAYLOAD,
            "hasOpenPorts": True,
            "ports": [
                {
                    "port": "80",
                    "protocol": "tcp",
                    "service": PAYLOAD,
                    "state": PAYLOAD,
                    "comment": PAYLOAD,
                    "uncertain": False,
                    "tls": False,
                    "sources": [{"type": PAYLOAD, "file": PAYLOAD, "date": ""}],
                },
                {
                    "port": "8443",
                    "protocol": "tcp",
                    "service": "https",
                    "state": "TBD",
                    "comment": PAYLOAD,
                    "uncertain": True,
                    "tls": True,
                },
            ],
        },
        {
            "ip": "10.0.0.2",
            "hostname": "ordinary",
            "mac_address": "",
            "vendor": "",
            "hasOpenPorts": True,
            "ports": [
                {
                    "port": "22",
                    "protocol": "tcp",
                    "service": "ssh",
                    "state": "TBD",
                    "comment": "",
                    "uncertain": False,
                    "tls": False,
                }
            ],
        },
    ],
    "hostsUp": [{"ip": "10.0.0.9", "reason": PAYLOAD}],
}

# Renders every view, both graph tooltips, the node details panel for each node
# type and all four analyses, then reports what the scan data managed to create.
PROBE = """
() => {
  window.__xss = [];
  window.scanData = SCAN_DATA;
  loadEdits(); updateStats(); populateTables(); renderGraph();

  const seen = {};
  const nodes = nodesDataset.get();
  ['host', 'service', 'up-host'].forEach(type => {
    const node = nodes.find(n => n.type === type);
    if (node) {
      showNodeDetails(node);
      seen['details_' + type] = document.getElementById('node-details-content').innerHTML;
      showTooltip(node.id, {x: 10, y: 10});
      seen['tooltip_' + type] = document.getElementById('graph-tooltip').innerHTML;
    }
  });

  ['common-services', 'segments', 'unusual', 'connectivity'].forEach(analysis => {
    document.getElementById('analysis-type').value = analysis;
    runAnalysis();
    seen['analysis_' + analysis] = document.getElementById('analysis-content').innerHTML;
  });

  return {
    markup: Object.entries(seen)
        .filter(([, html]) => html.includes('<img'))
        .map(([where]) => where),
    images: document.querySelectorAll('img').length,
    // the legitimate markup has to survive the escaping
    tooltip_formatted: (seen['tooltip_host'] || '').includes('<strong>'),
    rows: document.querySelectorAll('#ports-table tbody tr').length
  };
}
"""


class ViewerServer:
    """Serves a copy of the resources the way `unitas -H` does."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        shutil.copytree(find_resources_dir(), self.dir, dirs_exist_ok=True)
        handler = self._handler(self.dir)
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @staticmethod
    def _handler(directory):
        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=directory, **kwargs)

            def log_message(self, *args):
                pass

        return Handler

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/index.html"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        shutil.rmtree(self.dir, ignore_errors=True)


@unittest.skipUnless(
    PLAYWRIGHT_AVAILABLE and CHROMIUM is not None,
    "playwright with a chromium build is required",
)
class TestViewerHandlesHostileScanData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ViewerServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def test_scan_data_never_becomes_markup(self):
        probe = PROBE.replace("SCAN_DATA", json.dumps(SCAN))
        errors = []

        with sync_playwright() as playwright:
            launch = {"executable_path": CHROMIUM} if CHROMIUM else {}
            browser = playwright.chromium.launch(**launch)
            page = browser.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(self.server.url)
            page.wait_for_timeout(1000)
            result = page.evaluate(probe)
            # an onerror handler fires on the next task, give it one
            page.wait_for_timeout(1000)
            result["executed"] = page.evaluate("window.__xss.length")
            browser.close()

        self.assertEqual(result["markup"], [], "scan data reached the DOM as markup")
        self.assertEqual(result["images"], 0, "the scan created an element")
        self.assertEqual(result["executed"], 0, "the scan executed script")
        self.assertEqual(errors, [])

        # and the viewer still works
        self.assertTrue(result["tooltip_formatted"], "tooltips lost their formatting")
        self.assertEqual(result["rows"], 3)


if __name__ == "__main__":
    unittest.main()
