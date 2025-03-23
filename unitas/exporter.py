import logging

import requests
from unitas.utils import config


class NessusExporter:

    report_name = "Merged Report"

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
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        while True:
            status = self.ses.get(
                f"{self.url}/scans/{scan_id}/export/{file_id}/status"
            ).json()["status"]
            if status == "ready":
                logging.debug(f"Export is ready for download for scan ID: {scan_id}")
                break
            logging.debug("Export is not ready yet, waiting 5 seconds...")
            time.sleep(5)

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
            f"{self.url}/scans/{scan_id}/export/{file_id}/download", stream=True
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
            if not os.path.exists(nessus_filename):
                nessus_file_id = self._initiate_export(scan_id)
                self._check_export_status(scan_id, nessus_file_id)
                self._download_export(scan, nessus_file_id, target_dir)
            else:
                logging.info(
                    f"Skipping export for {nessus_filename} as it already exists."
                )
