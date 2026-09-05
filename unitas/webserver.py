"""The web interface, backed by a live workspace.

`unitas <folder> -H` used to serialise the state once, copy the viewer into a
temp directory with a data.json beside it, and serve that. The server now keeps
the folder open through a `Workspace`: the same page can ask what changed, push
triage back, and force a rescan.

Everything is stdlib; this tool gets copied onto assessment boxes and a
dependency for a local viewer is not worth it.
"""

import http.server
import json
import logging
import os
import secrets
import socketserver
import threading
import time
import urllib.parse
import webbrowser
from typing import Optional

from unitas.report import find_resources_dir
from unitas.workspace import Workspace

# The write routes must not be reachable from another page in the same browser.
TOKEN_HEADER = "X-Unitas-Token"
MAX_BODY = 8 * 1024 * 1024


class UnitasHandler(http.server.SimpleHTTPRequestHandler):
    """The viewer's assets plus the workspace API."""

    workspace: Optional[Workspace] = None
    token: str = ""
    static_json: Optional[str] = None
    server_version = "unitas"
    sys_version = ""

    def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
        logging.debug("%s - %s", self.address_string(), fmt % args)

    # ------------------------------------------------------------------ helpers

    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json_text(self, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        # the state changes under the page, nothing here may be cached
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def _origin_is_ours(self) -> bool:
        """Reject a request another page made on our behalf.

        The API writes files, so it may only be driven by the page we serve.
        Browsers set Origin on every cross-site POST; a request without one did
        not come from a page.
        """
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return origin in (f"http://{host}", f"https://{host}")

    def _authorised(self) -> bool:
        if not self._origin_is_ours():
            self._send({"error": "cross origin request refused"}, 403)
            return False
        if not secrets.compare_digest(
            self.headers.get(TOKEN_HEADER, ""), self.token or ""
        ):
            self._send({"error": "missing or wrong token"}, 403)
            return False
        return True

    def _body(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._send({"error": "bad content length"}, 413)
            return None
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError as e:
            self._send({"error": f"invalid JSON: {e}"}, 400)
            return None
        if not isinstance(payload, dict):
            self._send({"error": "expected a JSON object"}, 400)
            return None
        return payload

    # -------------------------------------------------------------------- GET

    def do_GET(self):  # pylint: disable=invalid-name
        path = urllib.parse.urlsplit(self.path).path

        if path.startswith("/api/"):
            self._api_get(path)
            return

        if path in ("/", "/index.html"):
            self._send_index()
            return

        if path == "/data.json":
            self._send_json_text(self._snapshot_json())
            return

        super().do_GET()

    def _snapshot_json(self) -> str:
        if self.workspace is not None:
            return self.workspace.snapshot()[1]
        return self.static_json or "{}"

    def _api_get(self, path: str) -> None:
        if path == "/api/state":
            self._api_state()
        elif path == "/api/summary":
            self._send(
                self.workspace.summary()
                if self.workspace
                else {"error": "no workspace"}
            )
        else:
            self._send({"error": "unknown endpoint"}, 404)

    def _api_state(self) -> None:
        if self.workspace is None:
            self._send({"error": "the server has no workspace"}, 404)
            return

        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        try:
            known = int(query.get("version", ["0"])[0])
        except ValueError:
            known = 0

        version, snapshot = self.workspace.snapshot()
        summary = self.workspace.summary()

        if known == version:
            # the common case for a poll: an integer compare, no serialisation
            self._send({"version": version, "unchanged": True, "summary": summary})
            return

        # the snapshot is already JSON, splice it in rather than parsing it back
        self._send_json_text(
            '{"version": %d, "unchanged": false, "summary": %s, "data": %s}'
            % (version, json.dumps(summary), snapshot)
        )

    def _send_index(self) -> None:
        """The page, with the API bootstrap injected.

        The same rewrite the auto loader injection has always used; inline
        script is allowed by the page's CSP.
        """
        index = os.path.join(self.directory, "index.html")
        try:
            with open(index, "r", encoding="utf-8") as f:
                html = f.read()
        except OSError as e:
            self.send_error(500, f"could not read index.html: {e}")
            return

        bootstrap = (
            "<script>window.UNITAS = "
            + json.dumps(
                {
                    "token": self.token,
                    "live": self.workspace is not None,
                    "stateFile": (
                        self.workspace.state_file if self.workspace else None
                    ),
                    "readOnly": bool(self.workspace and self.workspace.read_only),
                }
            ).replace("<", "\\u003c")
            + ";</script>"
        )
        # into the head: workspace.js reads window.UNITAS as it loads, and the
        # page's own scripts sit at the end of the body
        html = html.replace("</head>", bootstrap + "\n</head>", 1)

        if self.workspace is None:
            # the static case still needs something to fetch data.json; with a
            # workspace the page's own workspace.js drives the API instead
            html = html.replace(
                "</body>", '<script src="static/js/auto-loader.js"></script></body>'
            )

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------- POST

    def do_POST(self):  # pylint: disable=invalid-name
        path = urllib.parse.urlsplit(self.path).path

        if not path.startswith("/api/"):
            self._send({"error": "unknown endpoint"}, 404)
            return
        if self.workspace is None:
            self._send({"error": "the server has no workspace"}, 404)
            return
        if not self._authorised():
            return

        if path == "/api/edits":
            self._api_edits()
        elif path == "/api/rescan":
            self._api_rescan()
        else:
            self._send({"error": "unknown endpoint"}, 404)

    def _api_edits(self) -> None:
        payload = self._body()
        if payload is None:
            return

        ports = payload.get("ports") or []
        hosts = payload.get("hosts") or []
        if not isinstance(ports, list) or not isinstance(hosts, list):
            self._send({"error": "ports and hosts must be lists"}, 400)
            return
        ports = [edit for edit in ports if isinstance(edit, dict)]
        hosts = [edit for edit in hosts if isinstance(edit, dict)]

        if self.workspace.read_only:
            self._send({"error": "the workspace is read only"}, 409)
            return

        self._send(self.workspace.apply_edits(ports, hosts))

    def _api_rescan(self) -> None:
        changed = self.workspace.refresh(force=True)
        self._send({"version": self.workspace.version, "changed": changed})


def create_server(
    workspace: Workspace = None,
    port: int = 8000,
    json_content: str = None,
    resources_dir: str = None,
    token: str = None,
):
    """A threading HTTP server bound to loopback, and the token it expects.

    Threading, because a rescan that takes a second used to block every asset
    request behind it.
    """
    resources_dir = resources_dir or find_resources_dir()
    if not resources_dir or not os.path.exists(resources_dir):
        raise FileNotFoundError("Could not find the viewer resources directory")

    token = token or secrets.token_urlsafe(24)

    class Handler(UnitasHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=resources_dir, **kwargs)

    Handler.workspace = workspace
    Handler.token = token
    Handler.static_json = json_content

    socketserver.TCPServer.allow_reuse_address = True
    # loopback only, scan results have no business on the network
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    httpd.unitas_token = token
    return httpd


def start_http_server(
    json_content=None, port=8000, scan_folder=None, show_origin=False, read_only=False
):
    """Serve the viewer until interrupted.

    With a scan folder the server is live: the folder is watched, state.md is
    kept up to date and the page can write back. Without one it serves the
    single snapshot it was handed, which is what the old server did.
    """
    workspace = None
    try:
        if scan_folder:
            workspace = Workspace(
                scan_folder, show_origin=show_origin, read_only=read_only
            )
            workspace.start()
            logging.info(
                "Watching %s, triage in %s%s",
                workspace.scan_folder,
                workspace.state_file,
                " (read only)" if workspace.read_only else "",
            )

        httpd = create_server(workspace, port, json_content)
    except Exception as e:  # pylint: disable=broad-except
        logging.error(f"Error starting HTTP server: {e}")
        if workspace:
            workspace.stop()
        return False

    port = httpd.server_address[1]
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    logging.info(f"Started HTTP server at http://localhost:{port}")
    logging.info("The web interface is now available")
    logging.info("Press Ctrl+C to stop the server")

    try:
        webbrowser.open(f"http://localhost:{port}/index.html")
    except Exception as e:  # pylint: disable=broad-except
        logging.debug(f"Could not open a browser: {e}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("\nStopping HTTP server")
    finally:
        httpd.shutdown()
        server_thread.join()
        httpd.server_close()
        if workspace:
            workspace.stop()

    return True
