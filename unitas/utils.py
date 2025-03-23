from collections import defaultdict
import configparser
import logging
import os
import socket
import threading
from typing import Dict, List

from unitas.model import HostScanData, PortDetails

try:
    from importlib.metadata import version, PackageNotFoundError

    try:
        __version__ = version("unitas")
    except PackageNotFoundError:
        __version__ = "dev-version"
except ImportError:
    __version__ = "dev-version"  # Fallback for older Python versions


def get_version() -> str:
    return __version__


class UnitasConfig:
    def __init__(self, config_file: str = "~/.unitas"):
        self.config_file = os.path.expanduser(config_file)
        self.config = configparser.ConfigParser()

        if not os.path.exists(self.config_file):
            logging.error(f"Config file {config_file} was not found creating default")
            self.create_template_config()
        else:
            self.config.read(self.config_file)

    def create_template_config(self):
        self.config["nessus"] = {
            "secret_key": "",
            "access_key": "",
            "url": "https://127.0.0.1:8834",
        }
        with open(self.config_file, "w") as file:
            self.config.write(file)
        logging.info(
            f"Template config file created at {self.config_file}. Please update the settings."
        )

    def get_secret_key(self):
        return self.config.get("nessus", "secret_key")

    def get_access_key(self):
        return self.config.get("nessus", "access_key")

    def get_url(self):
        return self.config.get("nessus", "url")


class ThreadSafeServiceLookup:
    def __init__(self):
        self._lock = threading.Lock()
        self._cache: Dict[str, str] = {}

    def get_service_name_for_port(
        self, port: str, protocol: str = "tcp", default_service: str = "unknown?"
    ):
        if PortDetails.is_valid_port(port):
            cache_id = port + protocol
            if cache_id in self._cache:
                return self._cache[cache_id]
            with self._lock:
                if cache_id in self._cache:
                    return self._cache[cache_id]
                try:
                    service = socket.getservbyport(int(port), protocol)
                    if service is None:
                        service = default_service
                except (socket.error, ValueError, TypeError):
                    logging.debug(f"Lookup for {port} and {protocol} failed!")
                    service = default_service
                service = PortDetails.get_service_name(service, port)
                self._cache[cache_id] = service
                return service
        else:
            raise ValueError(f'Port "{port}" is not valid!')


service_lookup = ThreadSafeServiceLookup()
hostup_dict = defaultdict(dict)
config = UnitasConfig()


def search_port_or_service(
    global_state: Dict[str, HostScanData],
    search_terms: List[str],
    with_url: bool,
    hide_ports: bool,
) -> List[str]:
    matching_ips = set()
    for ip, host_data in global_state.items():
        for port in host_data.ports:
            for term in search_terms:
                if term.lower().strip() == port.port.lower() or (
                    term.lower().strip() == port.service.lower()
                    or term.lower().strip() + "?" == port.service.lower()
                ):
                    port_nr = port.port
                    service = port.service.replace("?", "")
                    url: str = ip
                    if with_url:
                        url = service + "://" + url

                    if port == 139:
                        pass

                    # show ports if the port is not the default port for the service
                    # if multiple terms are used, do not do this e.g. http and https, which leads to the same host without any context which is which
                    if hide_ports:
                        pass  # no need to do anything

                    elif (
                        not service_lookup.get_service_name_for_port(port_nr) == service
                        or len(search_terms) > 1
                    ):
                        url += ":" + port_nr

                    matching_ips.add(url)

    return sorted(list(matching_ips))
