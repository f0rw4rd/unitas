from collections import defaultdict
import configparser
import logging
import os
import socket
import threading
from ipaddress import ip_address
from typing import Dict, List, Optional
from manuf2 import manuf

from unitas.model import HostScanData, PortDetails

try:
    from importlib.metadata import version, PackageNotFoundError

    try:
        __version__ = version("unitas")
    except PackageNotFoundError:
        __version__ = "dev-version"
except ImportError:
    __version__ = "dev-version"  # Fallback for older Python versions


class MacVendorLookup:
    def __init__(self):
        self._parser = manuf.MacParser()
        self._cache = {}

    def lookup(self, mac_address: str) -> str:
        if not mac_address:
            return ""

        if mac_address in self._cache:
            return self._cache[mac_address]

        try:
            result = self._parser.get_all(mac_address)
            if result and result.manuf:
                vendor = result.manuf
                if result.manuf_long and result.manuf_long != result.manuf:
                    vendor = result.manuf_long
                self._cache[mac_address] = vendor
                return vendor
        except Exception as e:
            logging.debug(f"Error looking up MAC vendor for {mac_address}: {e}")

        self._cache[mac_address] = ""
        return ""


def find_nmap_ip_address(host_or_addresses) -> str:
    """Return the IP of a nmap <host>, ignoring the MAC address entry.

    Takes either the <host> element or its already collected <address>
    children, so a caller that needs the addresses anyway does not pay for a
    second lookup.
    """
    addresses = host_or_addresses
    if hasattr(host_or_addresses, "findall"):
        addresses = host_or_addresses.findall("address") or host_or_addresses.findall(
            ".//address"
        )

    fallback = ""
    for address in addresses:
        addr = address.attrib.get("addr", "")
        if not addr:
            continue
        addr_type = address.attrib.get("addrtype", "")
        if addr_type == "ipv4":
            return addr
        if addr_type == "ipv6" and not fallback:
            fallback = addr
        elif not addr_type and not fallback:
            # older/odd scans might not set the addrtype
            fallback = addr

    return fallback


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
        return self.config.get("nessus", "secret_key", fallback="")

    def get_access_key(self):
        return self.config.get("nessus", "access_key", fallback="")

    def get_url(self):
        return self.config.get("nessus", "url", fallback="https://127.0.0.1:8834")


class ThreadSafeServiceLookup:
    SERVICES_FILE = "/etc/services"

    def __init__(self):
        self._lock = threading.Lock()
        self._cache: Dict[str, str] = {}
        self._known: Optional[Dict[str, str]] = None

    def _load_known_services(self) -> Dict[str, str]:
        """Read /etc/services once.

        socket.getservbyport() re-reads the file per call (~54us here), which a
        wide port range pays thousands of times over: 8000 distinct ports cost
        350ms of syscalls, versus 0.7ms of dict lookups once the file is known.
        """
        known: Dict[str, str] = {}
        try:
            with open(self.SERVICES_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].split()
                    if len(line) < 2 or "/" not in line[1]:
                        continue
                    name = line[0]
                    number, _, proto = line[1].partition("/")
                    if number.isdigit():
                        known.setdefault(number + proto, name)
        except OSError as e:
            logging.debug("Could not read %s: %s", self.SERVICES_FILE, e)
        return known

    def get_service_name_for_port(
        self, port: str, protocol: str = "tcp", default_service: str = "unknown?"
    ):
        if not PortDetails.is_valid_port(port):
            raise ValueError(f'Port "{port}" is not valid!')

        cache_id = port + protocol
        if cache_id in self._cache:
            return self._cache[cache_id]

        with self._lock:
            if cache_id in self._cache:
                return self._cache[cache_id]

            if self._known is None:
                self._known = self._load_known_services()

            service = self._known.get(cache_id)
            if service is None:
                if self._known:
                    # the file is the same database getservbyport reads, so a
                    # miss here is a miss there: no syscall for unknown ports
                    service = default_service
                else:
                    # the file could not be read, ask the resolver instead
                    try:
                        service = socket.getservbyport(int(port), protocol)
                    except (socket.error, ValueError, TypeError):
                        logging.debug("Lookup for %s and %s failed!", port, protocol)
                        service = default_service

            service = PortDetails.get_service_name(service, port)
            self._cache[cache_id] = service
            return service


service_lookup = ThreadSafeServiceLookup()
hostup_dict = defaultdict(dict)
config = UnitasConfig()
mac_vendor_lookup = MacVendorLookup()


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

                    # show ports if the port is not the default port for the service
                    # if multiple terms are used, do not do this e.g. http and https, which leads to the same host without any context which is which
                    if hide_ports:
                        pass  # no need to do anything

                    elif (
                        not service_lookup.get_service_name_for_port(
                            port_nr, port.protocol
                        )
                        == service
                        or len(search_terms) > 1
                    ):
                        url += ":" + port_nr

                    matching_ips.add(url)

    return sorted(list(matching_ips))


# Ports that are commonly web services even when the scan could not identify
# the service (e.g. a plain SYN scan).
WEB_PORT_HINTS = {
    "80",
    "81",
    "88",
    "591",
    "3000",
    "5000",
    "7001",
    "8000",
    "8008",
    "8080",
    "8081",
    "8082",
    "8088",
    "8888",
    "9080",
    "10000",
}
TLS_PORT_HINTS = {
    "443",
    "832",
    "981",
    "1311",
    "4443",
    "7002",
    "8443",
    "8834",
    "9443",
    "10443",
}


def _is_web_service(port: PortDetails) -> bool:
    service = port.service.lower()
    if "http" in service or "www" in service:
        return True
    # a scan that only knows the port number still gets a guess from the
    # well known web ports
    if "?" in service or "unknown" in service:
        return port.port in WEB_PORT_HINTS or port.port in TLS_PORT_HINTS
    return False


def _uses_tls(port: PortDetails) -> bool:
    service = port.service.lower()
    if "https" in service or "ssl" in service or "tls" in service:
        return True
    if "tls" in port.comment.lower() or "ssl" in port.comment.lower():
        return True
    return port.port in TLS_PORT_HINTS


def sort_key_for_ip(ip: str):
    """Sort key that keeps IPv4 and IPv6 addresses comparable."""
    address = ip_address(ip)
    return (address.version, address)


def _format_host(ip: str) -> str:
    # IPv6 literals need brackets to be a valid URL authority
    try:
        if ip_address(ip).version == 6:
            return f"[{ip}]"
    except ValueError:
        pass
    return ip


def generate_service_urls(
    global_state: Dict[str, HostScanData], mode: str = "web"
) -> List[str]:
    """Render the open ports as URLs, one per host/port.

    mode "web" only returns http(s) URLs, which is what tools like EyeWitness,
    httpx or nuclei expect. mode "all" uses the service name as the scheme for
    every port that has one (e.g. ssh://10.0.0.1:22).
    """
    urls: List[str] = []
    seen = set()

    for ip, host_data in global_state.items():
        for port in host_data.ports:
            if mode == "web":
                if port.protocol != "tcp" or not _is_web_service(port):
                    continue
                scheme = "https" if _uses_tls(port) else "http"
            else:
                scheme = port.service.lower().replace("?", "").strip()
                # nothing sensible to build a URL from
                if not scheme or "unknown" in scheme:
                    continue
                scheme = scheme.replace("/", "-")

            url = f"{scheme}://{_format_host(ip)}:{port.port}"
            if url in seen:
                continue
            seen.add(url)
            urls.append((ip, int(port.port), url))

    urls.sort(key=lambda entry: (sort_key_for_ip(entry[0]), entry[1], entry[2]))
    return [entry[2] for entry in urls]
