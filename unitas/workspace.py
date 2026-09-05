"""Live state behind the web interface.

`unitas <folder> -H` used to serialise the scans once and serve a static copy.
The workspace keeps the folder open instead: it re-reads scans as they appear,
folds them into one state, and keeps the triage in a state.md that it owns, so
the browser and the CLI work on the same file.

The merge is the one the CLI already does for `-u`: merge_states(triage, scans)
keeps a non-empty state and comment from the triage side while still letting a
better service name from a newer scan win.
"""

import glob
import hashlib
import logging
import os
import tempfile
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from unitas.convert import JsonConverter, MarkdownConvert, load_markdown_state
from unitas.model import HostScanData, merge_states
from unitas.parser import NessusParser, NmapParser, parse_file
from unitas.utils import hostup_dict

SCAN_PARSERS = (NessusParser, NmapParser)
STATE_FILENAME = "state.md"


class Workspace:
    """The scan folder, its parsed state and the triage written beside it."""

    def __init__(
        self,
        scan_folder: str,
        state_file: str = None,
        show_origin: bool = False,
        read_only: bool = False,
        poll_interval: float = 2.0,
    ):
        self.scan_folder = os.path.abspath(scan_folder)
        self.state_file = os.path.abspath(
            state_file or os.path.join(self.scan_folder, STATE_FILENAME)
        )
        self.show_origin = show_origin
        self.poll_interval = poll_interval
        self.read_only = read_only or not self._folder_is_writable()

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._watcher: Optional[threading.Thread] = None

        # path -> (mtime, size, {ip: host dict}), so an unchanged file is never
        # parsed twice and the cached results cannot be mutated by a merge
        self._files: Dict[str, Tuple[float, int, Dict[str, dict]]] = {}
        self._file_hostup: Dict[str, Dict[str, str]] = {}

        self._state: Dict[str, HostScanData] = {}
        self._hostup: Dict[str, str] = {}
        self._version = 0
        self._fingerprint = ""
        self._snapshot: Optional[str] = None
        self._state_file_mtime: Optional[float] = None
        self._listeners: List[Callable[[int], None]] = []

    # ---------------------------------------------------------------- lifecycle

    def start(self) -> int:
        """Read everything once, then watch the folder."""
        self.refresh()
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()
        return self._version

    def stop(self) -> None:
        self._stop.set()
        if self._watcher:
            self._watcher.join(timeout=self.poll_interval * 2)
            self._watcher = None

    def _watch(self) -> None:
        while not self._stop.wait(self.poll_interval):
            try:
                self.refresh()
            except Exception as e:  # pylint: disable=broad-except
                logging.error("Workspace refresh failed: %s", e, exc_info=True)

    # ------------------------------------------------------------------- state

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def snapshot(self) -> Tuple[int, str]:
        """The version and the JSON the viewer consumes."""
        with self._lock:
            if self._snapshot is None:
                self._snapshot = JsonConverter(
                    self._state, self._hostup, self.show_origin
                ).convert()
            return self._version, self._snapshot

    def state_markdown(self) -> str:
        with self._lock:
            return MarkdownConvert(self._state, self.show_origin).convert(True)

    def add_listener(self, callback: Callable[[int], None]) -> None:
        self._listeners.append(callback)

    # ----------------------------------------------------------------- reading

    def _folder_is_writable(self) -> bool:
        return os.access(self.scan_folder, os.W_OK)

    def _scan_files(self) -> List[str]:
        """Every scan file in the folder, minus the ones we wrote ourselves."""
        found = []
        for parser_class in SCAN_PARSERS:
            for extension in parser_class.get_extensions():
                pattern = os.path.join(self.scan_folder, "**", f"*.{extension}")
                found.extend(glob.glob(pattern, recursive=True))
        return sorted(set(found))

    def _read_file(self, path: str) -> Tuple[Dict[str, dict], Dict[str, str]]:
        """Parse one scan, isolating what it contributed to the host-up list."""
        parser_class = NessusParser if path.endswith(".nessus") else NmapParser
        try:
            parser = parser_class(path)
        except Exception as e:  # pylint: disable=broad-except
            logging.error("Could not load %s: %s", path, e)
            return {}, {}

        # hostup_dict is a module global that is never reset; take only what
        # this file adds to it
        before = dict(hostup_dict)
        hostup_dict.clear()
        try:
            _, data = parse_file(parser)
            contributed = dict(hostup_dict)
        finally:
            hostup_dict.clear()
            hostup_dict.update(before)
            hostup_dict.update(contributed)

        return {ip: host.to_dict() for ip, host in data.items()}, contributed

    def _collect(self) -> bool:
        """Refresh the per-file cache. True when anything changed on disk."""
        changed = False
        seen = set()

        for path in self._scan_files():
            seen.add(path)
            try:
                stat = os.stat(path)
            except OSError:
                continue

            cached = self._files.get(path)
            if cached and cached[0] == stat.st_mtime and cached[1] == stat.st_size:
                continue

            logging.info("Reading %s", os.path.relpath(path, self.scan_folder))
            data, contributed = self._read_file(path)
            self._files[path] = (stat.st_mtime, stat.st_size, data)
            self._file_hostup[path] = contributed
            changed = True

        for path in list(self._files):
            if path not in seen:
                del self._files[path]
                self._file_hostup.pop(path, None)
                changed = True

        return changed

    def _state_file_changed(self) -> bool:
        """True when state.md was touched by something other than us."""
        try:
            mtime = os.path.getmtime(self.state_file)
        except OSError:
            # gone (or never existed); only interesting if we had read one
            return self._state_file_mtime is not None
        return mtime != self._state_file_mtime

    def _load_triage(self) -> Dict[str, HostScanData]:
        """The triage to merge the scans into: the file when it changed under
        us or on the first pass, otherwise what we already hold."""
        if self._state and not self._state_file_changed():
            return self._state

        if not os.path.exists(self.state_file):
            # a state.md that vanished is not an empty state.md; the triage we
            # hold is the record and the next write puts the file back
            self._state_file_mtime = None
            return self._state

        triage = load_markdown_state(self.state_file)
        try:
            self._state_file_mtime = os.path.getmtime(self.state_file)
        except OSError:
            self._state_file_mtime = None
        return triage

    def refresh(self, force: bool = False) -> bool:
        """Re-read what changed and rebuild. True when the version moved."""
        with self._lock:
            scans_changed = self._collect()
            triage_changed = self._state_file_changed()

            if not (scans_changed or triage_changed or force or not self._state):
                return False

            # the triage side wins for state and comment, the scans for
            # everything they know better
            triage = self._load_triage()

            parsed: Dict[str, HostScanData] = {}
            for _, _, data in self._files.values():
                parsed = merge_states(
                    parsed, {ip: HostScanData.from_dict(d) for ip, d in data.items()}
                )

            state = merge_states(triage, parsed)

            hostup = {}
            for contributed in self._file_hostup.values():
                hostup.update(contributed)
            # a host with an open port is not "up with nothing open"
            for ip in state:
                hostup.pop(ip, None)

            markdown = MarkdownConvert(state, self.show_origin).convert(True)
            fingerprint = hashlib.sha1(markdown.encode("utf-8")).hexdigest()
            if fingerprint == self._fingerprint and not force:
                self._state, self._hostup = state, hostup
                if not os.path.exists(self.state_file):
                    self._write_state(markdown)
                return False

            self._state = state
            self._hostup = hostup
            self._fingerprint = fingerprint
            self._snapshot = None
            self._version += 1

            self._write_state(markdown)
            version = self._version

        for listener in list(self._listeners):
            try:
                listener(version)
            except Exception:  # pylint: disable=broad-except
                logging.debug("Workspace listener failed", exc_info=True)
        return True

    # ------------------------------------------------------------------ writing

    def _write_state(self, markdown: str = None) -> None:
        """Replace state.md atomically, so a reader never sees half a file."""
        if self.read_only:
            return

        markdown = markdown or MarkdownConvert(self._state, self.show_origin).convert(
            True
        )
        directory = os.path.dirname(self.state_file) or "."

        try:
            os.makedirs(directory, exist_ok=True)
            handle, temporary = tempfile.mkstemp(
                dir=directory, prefix=".state-", suffix=".md"
            )
            with os.fdopen(handle, "w", encoding="utf-8") as f:
                f.write(markdown)
            os.replace(temporary, self.state_file)
            self._state_file_mtime = os.path.getmtime(self.state_file)
        except OSError as e:
            logging.error("Could not write %s: %s", self.state_file, e)
            self.read_only = True

    # ------------------------------------------------------------------- edits

    def apply_edits(
        self, port_edits: List[dict], host_edits: List[dict] = None
    ) -> dict:
        """Set the state or comment of ports, or of every port of a host.

        Returns {"version": int, "applied": int, "missing": [...]}.
        """
        applied = 0
        missing = []

        with self._lock:
            for edit in host_edits or []:
                host = self._state.get(str(edit.get("ip", "")))
                if host is None:
                    missing.append(edit)
                    continue
                for port in host.ports:
                    applied += self._apply_to_port(port, edit)

            for edit in port_edits or []:
                host = self._state.get(str(edit.get("ip", "")))
                port = self._find_port(host, edit) if host else None
                if port is None:
                    missing.append(edit)
                    continue
                applied += self._apply_to_port(port, edit)

            if applied:
                markdown = MarkdownConvert(self._state, self.show_origin).convert(True)
                self._fingerprint = hashlib.sha1(markdown.encode("utf-8")).hexdigest()
                self._snapshot = None
                self._version += 1
                self._write_state(markdown)

            version = self._version

        if applied:
            for listener in list(self._listeners):
                try:
                    listener(version)
                except Exception:  # pylint: disable=broad-except
                    logging.debug("Workspace listener failed", exc_info=True)

        return {"version": version, "applied": applied, "missing": missing}

    @staticmethod
    def _find_port(host: HostScanData, edit: dict):
        wanted_port = str(edit.get("port", ""))
        wanted_protocol = str(edit.get("protocol", "tcp"))
        for port in host.ports:
            if port.port == wanted_port and port.protocol == wanted_protocol:
                return port
        return None

    @staticmethod
    def _apply_to_port(port, edit: dict) -> int:
        changed = 0
        if "state" in edit and edit["state"] is not None:
            value = str(edit["state"]).strip() or "TBD"
            if port.state != value:
                port.state = value
                changed = 1
        if "comment" in edit and edit["comment"] is not None:
            value = str(edit["comment"]).strip()
            if port.comment != value:
                port.comment = value
                changed = 1
        return changed

    # -------------------------------------------------------------------- stats

    def summary(self) -> dict:
        with self._lock:
            ports = [port for host in self._state.values() for port in host.ports]
            done = sum(1 for port in ports if port.state.lower() == "done")
            return {
                "version": self._version,
                "hosts": len(self._state),
                "ports": len(ports),
                "done": done,
                "scan_files": len(self._files),
                "state_file": self.state_file,
                "read_only": self.read_only,
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
