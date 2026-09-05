import functools
import logging
import os
import time
from typing import Dict, List

import requests
import urllib3
from unitas.utils import config


class NessusExporter:

    report_name = "Merged Report"

    # A request that never answers used to hang the CLI forever; the web
    # interface runs the same code on a background thread, where it would pin
    # the thread instead. Neither is acceptable, so everything is bounded.
    REQUEST_TIMEOUT = 30
    DOWNLOAD_TIMEOUT = 300
    EXPORT_DEADLINE = 900
    POLL_INTERVAL = 5

    def __init__(self):
        access_key, secret_key, url = (
            config.get_access_key(),
            config.get_secret_key(),
            config.get_url(),
        )
        if not access_key or not secret_key:
            raise ValueError("Secret or access key was empty!")
        self.access_key = access_key
        self.secret_key = secret_key
        self.url = url

        self.ses = requests.Session()
        self.ses.headers.update(
            {"X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}"}
        )
        self.ses.verify = False  # yeah i know :D

        def error_handler(r, *args, **kwargs):
            if not r.ok:
                logging.error(f"Problem with nessus API: {r.text}")
            r.raise_for_status()

        self.ses.hooks = {"response": error_handler}
        self.ses.request = functools.partial(
            self.ses.request, timeout=self.REQUEST_TIMEOUT
        )
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def is_configured() -> bool:
        """Whether a key pair is on file, without raising to find out."""
        return bool(config.get_access_key() and config.get_secret_key())

    def _initiate_export(self, scan_id):
        logging.info(f"Initiating export for scan ID: {scan_id}")
        return self.ses.post(
            f"{self.url}/scans/{scan_id}/export",
            json={"format": "nessus", "chapters": ""},
        ).json()["file"]

    def _check_export_status(self, scan_id, file_id):
        logging.debug(
            f"Checking export status for scan ID: {scan_id}, file ID: {file_id}"
        )
        deadline = time.monotonic() + self.EXPORT_DEADLINE
        while True:
            status = self.ses.get(
                f"{self.url}/scans/{scan_id}/export/{file_id}/status"
            ).json()["status"]
            if status == "ready":
                logging.debug(f"Export is ready for download for scan ID: {scan_id}")
                break
            if time.monotonic() >= deadline:
                # an export that is still not ready after this is stuck; give
                # the thread back rather than polling until the process dies
                raise TimeoutError(
                    f"Export of scan {scan_id} was not ready after "
                    f"{self.EXPORT_DEADLINE}s (last status: {status})"
                )
            logging.debug("Export is not ready yet, waiting 5 seconds...")
            time.sleep(self.POLL_INTERVAL)

    def _list_scans(self) -> List[Dict]:
        logging.debug("Listing nessus scans")
        scans = self.ses.get(f"{self.url}/scans").json()["scans"]
        if not scans:
            return []
        export_scans = []
        for x in scans:
            if x["status"] in ["cancled", "running"]:
                logging.warning(
                    f"Skipping scan \"{x['name']}\" because status is {x['status']}"
                )
            else:
                export_scans.append(x)
        return export_scans

    def list_scans_status(self, target_dir: str) -> dict:
        """What the server has against what is already on disk.

        This is the "9 of 12 exported, 3 missing" the web interface shows; it
        touches nothing, so it is safe to call on every page load.
        """
        scans = []
        exported = 0
        skipped = 0

        for scan in self.ses.get(f"{self.url}/scans").json().get("scans") or []:
            status = scan.get("status", "")
            name = scan.get("name", "")
            # "merged" and the running scans are the ones export() will not take
            exportable = status not in ("canceled", "cancled", "running") and (
                name.lower() != "merged"
            )
            on_disk = exportable and os.path.exists(
                self._generate_file_name(target_dir, scan)
            )

            if on_disk:
                exported += 1
            elif not exportable:
                skipped += 1

            scans.append(
                {
                    "id": scan.get("id"),
                    "name": name,
                    "status": status,
                    "exportable": exportable,
                    "exported": on_disk,
                }
            )

        return {
            "scans": scans,
            "total": len(scans),
            "exported": exported,
            "skipped": skipped,
            "missing": len(scans) - exported - skipped,
        }

    def _sanitize_name(self, scan: dict) -> str:
        return scan["name"].replace(" ", "_").replace("/", "_").replace("\\", "_")

    def _generate_file_name(self, target_dir: str, scan: dict) -> str:
        scan_id = scan["id"]
        scan_name = self._sanitize_name(scan)
        filename = os.path.join(target_dir, f"{scan_name}_{scan_id}.nessus")
        return filename

    def _download_export(self, scan: dict, file_id: str, target_dir: str):
        scan_id = scan["id"]
        filename = self._generate_file_name(target_dir, scan)
        if os.path.exists(filename):
            logging.error(f"Export file {filename} already exists. Skipping download.")
            return
        logging.info(f"Downloading export for scan ID: {scan_id} to {filename}")
        response = self.ses.get(
            f"{self.url}/scans/{scan_id}/export/{file_id}/download",
            stream=True,
            timeout=self.DOWNLOAD_TIMEOUT,
        )
        response.raise_for_status()
        with open(filename, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Download completed successfully for {filename}")

    def export(self, target_dir: str):
        scans = self._list_scans()

        if not scans:
            logging.error("No scans found!")
            return

        for scan in scans:
            scan_id = scan["id"]
            scan_name = scan["name"]
            if scan_name.lower() == "merged":
                logging.info("Skipping export for scan named 'merged'")
                continue

            nessus_filename = self._generate_file_name(target_dir, scan)
            if os.path.exists(nessus_filename):
                logging.info(
                    f"Skipping export for {nessus_filename} as it already exists."
                )
                continue

            try:
                nessus_file_id = self._initiate_export(scan_id)
                self._check_export_status(scan_id, nessus_file_id)
                self._download_export(scan, nessus_file_id, target_dir)
            except Exception as e:  # pylint: disable=broad-except
                # one stuck or forbidden scan must not cost the other eleven
                logging.error(f'Could not export scan "{scan_name}": {e}')
