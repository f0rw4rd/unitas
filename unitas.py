import glob
import threading
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
from typing import Dict, List, Optional, Tuple, Any, Type
import os
import concurrent.futures
import argparse
import re
import socket
from ipaddress import ip_address
import logging
from abc import ABC, abstractmethod
from functools import lru_cache


__version__ = "1.0.0"


class PortDetails:
    def __init__(
        self,
        port: str,
        protocol: str,
        state: str,
        service: str = "unknown?",
        comment: str = "",
    ):
        if not PortDetails.is_valid_port(port):
            raise ValueError(f'Port "{port}" is not valid!')
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.comment = comment

    def __str__(self) -> str:
        return f"{self.port}/{self.protocol}({self.service})"

    def to_dict(self) -> Dict[str, str]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "comment": self.comment,
        }

    def __eq__(self, other):
        if not isinstance(other, PortDetails):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __repr__(self) -> str:
        return f"PortDetails({self.port}/{self.protocol} {self.state} {self.service} {self.comment})"

    def update(self, other: "PortDetails"):
        # check if service should be overwritten
        update_service = False
        if other.service != "unknown?" and self.service == "unknown?":
            update_service = True
        if (
            not "unknown" in other.service and not "?" in other.service
        ) and self.service == "unknown":
            update_service = True
        # without the question mark, it was a service scan
        elif "?" not in other.service and "?" in self.service:
            update_service = True
        # if the tag is longer e.g. http/tls instead of http, take it
        elif "?" not in other.service and len(other.service) > len(self.service):
            update_service = True

        if update_service:
            logging.debug(f"Updating service from {self.service} -> {other.service}")
            self.service = other.service
        # update the comments if comment is set
        if not self.comment and other.comment:
            logging.debug(f"Updating comment from {self.comment} -> {other.comment}")
            self.comment = other.comment

        if not self.state and other.state:
            logging.debug(f"Updating state from {self.state} -> {other.state}")
            self.state = other.state

    @staticmethod
    def is_valid_port(port: str) -> bool:
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False

    SERVICE_MAPPING: Dict[str, str] = {
        "www": "http",
        "microsoft-ds": "smb",
        # "netbios-ssn": "smb",
        "cifs": "smb",
        "ms-wbt-server": "rdp",
    }

    @staticmethod
    def get_service_name(service: str):
        if service in PortDetails.SERVICE_MAPPING:
            return PortDetails.SERVICE_MAPPING[service]
        return service

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "PortDetails":
        return cls(data["port"], data["protocol"], data["state"], data["service"])


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
                except socket.error:
                    service = default_service
                service = PortDetails.get_service_name(service)
                self._cache[cache_id] = service
                return service
        else:
            raise ValueError(f'Port "{port}" is not valid!')


service_lookup = ThreadSafeServiceLookup()


class HostScanData:
    def __init__(self, ip: str):
        if not HostScanData.is_valid_ip(ip):
            raise ValueError(f"'{ip}' is not a valid ip!")
        self.ip = ip
        self.hostname: str = ""
        self.ports: List[PortDetails] = []

    @staticmethod
    def is_valid_ip(address: str) -> bool:
        try:
            ip_address(address)
            return True
        except ValueError:
            return False

    def add_port_details(self, new_port: PortDetails):
        if new_port is None:  # skip if new_port is None
            return

        for p in self.ports:
            if p.port == new_port.port and p.protocol == new_port.protocol:
                p.update(new_port)
                return
        # if the port did not exist, just add it
        self.ports.append(new_port)

    def add_port(
        self,
        port: str,
        protocol: str,
        state: str,
        service: str = "unknown?",
        comment: str = "",
    ) -> None:
        new_port = PortDetails(port, protocol, state, service, comment)
        self.add_port_details(new_port)

    def set_hostname(self, hostname: str) -> None:
        self.hostname = hostname

    def get_sorted_ports(self) -> List[PortDetails]:
        return sorted(self.ports, key=lambda p: (p.protocol, int(p.port)))

    def merge(self, other: "HostScanData") -> List[PortDetails]:
        if self.ip != other.ip:
            raise ValueError("Cannot merge hosts with different IPs")
        self.hostname = self.hostname or other.hostname
        existing_ports = {(port.port, port.protocol): port for port in self.ports}
        new_ports = []
        for port in other.ports:
            key = (port.port, port.protocol)
            if key not in existing_ports:
                self.ports.append(port)
                new_ports.append(port)
            elif not existing_ports[key].service and port.service:
                existing_ports[key].service = port.service
            elif self.overwrite_service(existing_ports[key].service, port.service):
                existing_ports[key].service = port.service
        return new_ports

    def __str__(self) -> str:
        ports_str = ", ".join(str(port) for port in self.ports)
        return f"{self.ip} ({self.hostname}): {ports_str}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "ports": [port.to_dict() for port in self.ports],
        }

    def to_markdown_rows(self) -> List[str]:
        return [
            f"|{self.ip}|{str(x)}|       |       |" for x in self.get_sorted_ports()
        ]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HostScanData":
        host = cls(data["ip"])
        host.hostname = data["hostname"]
        for port_data in data["ports"]:
            host.ports.append(PortDetails.from_dict(port_data))
        return host


class Convert(ABC):
    def __init__(self, global_state: Dict[str, HostScanData] = None):
        self.global_state = Convert.sort_global_state_by_ip(global_state or {})

    @abstractmethod
    def convert(self) -> str:
        pass

    @abstractmethod
    def parse(self, content: str) -> Dict[str, HostScanData]:
        pass

    @staticmethod
    def sort_global_state_by_ip(
        global_state: Dict[str, HostScanData]
    ) -> Dict[str, HostScanData]:
        sorted_ips = sorted(global_state.keys(), key=lambda ip: ip_address(ip))
        return {ip: global_state[ip] for ip in sorted_ips}


class MarkdownConvert(Convert):
    def convert(self) -> str:
        output = ["|IP|Hostname|Port|Status|Comment|"]
        output.append("|--|--|--|--|---|")
        for host in self.global_state.values():
            for port in host.get_sorted_ports():
                output.append(
                    f"|{host.ip}|{host.hostname}|{port.port}/{port.protocol}({port.service})|{port.state}|{port.comment}|"
                )
        return "\n".join(output) + "\n"

    def parse(self, content: str) -> Dict[str, HostScanData]:
        lines = content.strip().split("\n")
        if len(lines) < 2:
            logging.error(
                f"Could not load markdown, markdown was only {len(lines)} lines. are you missing the two line header?"
            )
            return {}
        lines = lines[2:]  # Skip header and separator
        result = {}
        counter = 1
        for line in lines:
            counter += 1
            match = re.match(
                r"\s*\|([^|]+)\|\s*([^|]*)\s*\|\s*([^|/]+)/([^|(]+)\(([^)]+)\)\s*\|\s*([^|]*)\s*\|\s*([^|]*)\s*\|",
                line.strip(),
            )
            if match:
                ip, hostname, port, protocol, service, status, comment = match.groups()
                ip = ip.strip()
                if ip not in result:
                    result[ip] = HostScanData(ip)
                    if hostname.strip():
                        result[ip].set_hostname(hostname.strip())
                result[ip].add_port(
                    port.strip(),
                    protocol.strip(),
                    status.strip() or "TBD",
                    service.strip(),
                    comment.strip(),
                )
            else:
                logging.error(
                    f"Markdown error: Failed to parse line nr {counter}: {line}"
                )

        return result


class ScanParser(ABC):
    def __init__(self, file_path: str):
        self.file_path: str = file_path
        self.tree: ET.ElementTree = ET.parse(file_path)
        self.root: ET.Element = self.tree.getroot()
        self.data: Dict[str, HostScanData] = {}

    @abstractmethod
    def parse(self) -> Dict[str, HostScanData]:
        pass

    @staticmethod
    @abstractmethod
    def get_extensions() -> List[str]:
        pass

    @classmethod
    def load_file(cls, dir: str) -> List["ScanParser"]:
        files = []
        for ext in cls.get_extensions():
            logging.debug(
                f'Looking in folder "{dir}" for "{ext}" files for parser {cls.__name__}'
            )
            for f in glob.glob(f"{dir}/**/*.{ext}", recursive=True):
                logging.debug(f"Adding file {f} for parser {cls.__name__}")
                try:
                    files.append(cls(f))
                except ParseError as e:
                    logging.error(f"Could not load XML from file {f}")
        return files


class NessusParser(ScanParser):

    @staticmethod
    def get_extensions() -> List[str]:
        return ["nessus"]

    def parse(self) -> Dict[str, HostScanData]:
        for block in self.root.findall(".//ReportHost"):
            name: str = block.attrib.get("name", "")
            hostname: Optional[str] = None

            if HostScanData.is_valid_ip(name):
                ip = name
                host_blk = block.find(".//tag[@name='host-fqdn']")
                if host_blk is not None and host_blk.text:
                    hostname = host_blk.text
            else:
                ip_blk = block.find(".//tag[@name='host-ip']")
                hostname = name
                if ip_blk is not None and ip_blk.text:
                    ip = ip_blk.text
                else:
                    raise ValueError(f"Could not find IP for host {hostname}")

            host = HostScanData(ip)
            if hostname:
                host.set_hostname(hostname)
            self._parse_service_detection(block, host)
            self._parse_port_scanners(block, host)

            self.data[ip] = host
        return self.data

    def _parse_service_item(self, item: ET.Element) -> PortDetails:
        if not all(
            attr in item.attrib
            for attr in ["port", "protocol", "svc_name", "pluginName"]
        ):
            logging.error(f"Failed to parse nessus service scan: {ET.tostring(item)}")
            return None
        port: str = item.attrib.get("port")
        protocol: str = item.attrib.get("protocol")
        service: str = item.attrib.get("svc_name")
        service = PortDetails.get_service_name(service)
        comment: str = ""
        if "TLS" in item.attrib.get("pluginName") or "SSL" in item.attrib.get(
            "pluginName", ""
        ):
            if service == "http":
                service = "https"
            comment = "Has TLS"
        state: str = "TBD"
        return PortDetails(
            port=port, service=service, comment=comment, state=state, protocol=protocol
        )

    def _parse_service_detection(self, block: ET.Element, host: HostScanData) -> None:
        for item in block.findall(".//ReportItem[@pluginFamily='Service detection']"):
            host.add_port_details(self._parse_service_item(item))

    def _parse_port_item(self, item: ET.Element) -> PortDetails:
        if not all(attr in item.attrib for attr in ["port", "protocol", "svc_name"]):
            logging.error(f"Failed to parse nessus port scan: {ET.tostring(item)}")
            return None
        port: str = item.attrib.get("port")
        if port == "0":  # host scans return port zero, skip
            return None
        protocol: str = item.attrib.get("protocol")
        service: str = item.attrib.get("svc_name")
        if "?" not in service:  # append a ? for just port scans
            service = service_lookup.get_service_name_for_port(port, protocol, service)
            service += "?"
        else:
            service = PortDetails.get_service_name(service)
        state: str = "TBD"
        return PortDetails(port=port, service=service, state=state, protocol=protocol)

    def _parse_port_scanners(self, block: ET.Element, host: HostScanData) -> None:
        for item in block.findall(".//ReportItem[@pluginFamily='Port scanners']"):
            host.add_port_details(self._parse_port_item(item))


class NmapParser(ScanParser):

    @staticmethod
    def get_extensions() -> List[str]:
        return ["xml"]

    def parse(self) -> Dict[str, HostScanData]:
        for host in self.root.findall(".//host"):
            status = host.find(".//status")
            if status is not None and status.attrib.get("state") == "up":
                address = host.find(".//address")
                if address is not None:  # explicit None check is needed
                    host_ip: str = address.attrib.get("addr", "")
                    h = HostScanData(ip=host_ip)

                    self._parse_ports(host, h)
                    self.data[host_ip] = h

                    hostnames = host.find(".//hostnames")
                    if hostnames is not None:
                        for x in hostnames:
                            if "name" in x.attrib:
                                h.set_hostname(x.attrib.get("name"))
        return self.data

    def _parse_port_item(self, port: ET.Element) -> PortDetails:
        if not all(attr in port.attrib for attr in ["portid", "protocol"]):
            logging.error(f"Failed to parse nmap scan: {ET.tostring(port)}")
            return None
        protocol: str = port.attrib.get("protocol")
        portid: str = port.attrib.get("portid")
        service_element = port.find(".//service")
        comment: str = ""

        if service_element is not None:
            service: str = service_element.attrib.get("name")
            # need or service will not be overwritten by other services
            if service == "tcpwrapped":
                service = "unknown?"
            elif service_element.attrib.get("method") == "table":
                service = service_lookup.get_service_name_for_port(
                    portid, protocol, service
                )
                service += "?"
            else:
                service = PortDetails.get_service_name(service)

            if service_element.attrib.get("tunnel", "none") == "ssl":
                # nmap is not is not consistent with http/tls and https
                if service == "http":
                    service = "https"

                comment += "Has TLS"
        else:
            service = service_lookup.get_service_name_for_port(
                portid, protocol, "unknown"
            )
            service += "?"

        return PortDetails(
            port=portid,
            protocol=protocol,
            state="TBD",
            comment=comment,
            service=service,
        )

    def _parse_ports(self, host: ET.Element, h: HostScanData) -> None:
        for port in host.findall(".//port[state]"):
            # for some reason, doing a single xpath query fails with invalid attribute#
            # only allow open ports
            if port.find("state[@state='open']") is not None:
                h.add_port_details(self._parse_port_item(port))


class CustomFormatter(logging.Formatter):
    """
    Custom logging formatter to add tags for different log levels.
    """

    def format(self, record):
        level_tags = {
            logging.DEBUG: "[d]",
            logging.INFO: "[+]",
            logging.WARNING: "[!]",
            logging.ERROR: "[e]",
            logging.CRITICAL: "[c]",
        }
        record.leveltag = level_tags.get(record.levelno, "[?]")
        return super().format(record)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    formatter = CustomFormatter("%(leveltag)s %(message)s")

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.addHandler(handler)


def save_markdown_state(state: Dict[str, HostScanData], filename: str):
    converter = MarkdownConvert(state)
    content = converter.convert()
    with open(filename, "w") as f:
        f.write(content)


def load_markdown_state(filename: str) -> Dict[str, HostScanData]:
    try:
        with open(filename, "r") as f:
            content = f.read()
        # Strip empty lines
        content = "\n".join(line for line in content.split("\n") if line.strip())
        converter = MarkdownConvert()
        return converter.parse(content)
    except FileNotFoundError:
        logging.warning(f"File {filename} not found. Starting with empty state.")
        return {}
    except Exception as e:
        logging.error(f"Error loading {filename}: {str(e)}")
        return {}


def merge_states(
    old_state: Dict[str, HostScanData], new_state: Dict[str, HostScanData]
) -> Dict[str, HostScanData]:
    merged_state = old_state.copy()
    for ip, new_host_data in new_state.items():
        if ip not in merged_state:
            logging.debug(f"Added host {ip}")
            merged_state[ip] = new_host_data
        else:
            existing_ports = {(p.port, p.protocol): p for p in merged_state[ip].ports}
            for new_port in new_host_data.ports:
                key = (new_port.port, new_port.protocol)
                if key in existing_ports:
                    if not existing_ports[key] == new_port:
                        existing_ports[key].update(new_port)
                else:
                    logging.debug(f"Added port {new_port}")
                    existing_ports[key] = new_port

            merged_state[ip].ports = list(existing_ports.values())
    return merged_state


def search_port_or_service(
    global_state: Dict[str, HostScanData], search_terms: List[str], url: bool
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
                    if not url:
                        matching_ips.add(f"{ip}:{port_nr}")
                    else:
                        service = port.service.replace("?", "")
                        matching_ips.add(f"{service}://{ip}:{port_nr}")
                    break
    return sorted(list(matching_ips))


def parse_file(parser: ScanParser) -> Tuple[str, Dict[str, HostScanData]]:
    try:
        return parser.file_path, parser.parse()
    except ParseError:
        logging.error(f"Could not load {parser.file_path}, invalid XML")
        return parser.file_path, {}


def parse_files_concurrently(
    parsers: List[ScanParser], max_workers: int = 1
) -> Dict[str, HostScanData]:
    global_state: Dict[str, HostScanData] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_parser = {
            executor.submit(parse_file, parser): parser for parser in parsers
        }
        for future in concurrent.futures.as_completed(future_to_parser):
            parser = future_to_parser[future]
            try:
                file_path, scan_results = future.result()
                global_state = merge_states(global_state, scan_results)

            except Exception as exc:
                logging.error(f"{parser.file_path} generated an exception: {exc}")
    return global_state


def filter_uncertain_services(
    global_state: Dict[str, HostScanData]
) -> Dict[str, HostScanData]:
    certain_services = {}
    for ip, host_data in global_state.items():
        service_ports = [port for port in host_data.ports if not "?" in port.service]
        if service_ports:
            new_host_data = HostScanData(ip)
            new_host_data.hostname = host_data.hostname
            new_host_data.ports = service_ports
            certain_services[ip] = new_host_data
    return certain_services


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Unitas v{__version__}: A network scan parser and analyzer",
        epilog="Example usage: python unitas.py /path/to/scan/folder -v --search 'smb'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("scan_folder", help="Folder containing scan files")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose output (sets log level to DEBUG)",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show the version number and exit",
    )
    parser.add_argument(
        "-u",
        "--update",
        action="store_true",
        help="Update existing markdown from state.md or stdin",
    )
    parser.add_argument(
        "-s",
        "--search",
        help="Search for specific port numbers or service names (comma-separated)",
    )
    parser.add_argument(
        "-U",
        "--url",
        action="store_true",
        default=False,
        help="Adds the protocol of the port as URL prefix",
    )
    parser.add_argument(
        "-S",
        "--service",
        action="store_true",
        default=False,
        help="Show only service scanned ports",
    )

    args = parser.parse_args()

    if args.update:
        existing_state = load_markdown_state("state.md")
    else:
        existing_state = {}

    setup_logging(args.verbose)

    logging.info(f"Unitas v{__version__} starting up.")

    if not os.path.exists(args.scan_folder):
        folder = os.path.abspath(args.scan_folder)
        logging.error(f"Source folder {folder} was not found!")
        return

    parsers = NessusParser.load_file(args.scan_folder) + NmapParser.load_file(
        args.scan_folder
    )
    if not parsers:
        logging.error("Could not load any kind of scan files")
        return

    global_state = parse_files_concurrently(parsers)

    for p in parsers:
        try:
            scan_results = p.parse()
            new_hosts = merge_states(global_state, scan_results)
            if new_hosts:
                logging.debug(
                    "New hosts added: %s", ", ".join(str(host) for host in new_hosts)
                )
        except ParseError:
            logging.error("Could not load %s, invalid XML", p.file_path)
        except ValueError as e:
            logging.error(f"Failed to parse {p.file_path}: {e}")

    final_state = merge_states(existing_state, global_state)
    if not final_state:
        logging.error("Did not find any open ports!")
        return

    if args.service:
        logging.info("Filtering non-service scanned ports")
        final_state = filter_uncertain_services(final_state)

    if args.search:
        search_terms = [term.strip().lower() for term in args.search.split(",")]
        matching_ips = search_port_or_service(final_state, search_terms, args.url)
        if matching_ips:
            logging.info(
                f"Systems with ports/services matching '{', '.join(search_terms)}':"
            )
            for ip in matching_ips:
                print(ip)
        else:
            logging.info(f"No systems found with port/service '{args.search}'")
    else:
        md_converter = MarkdownConvert(final_state)
        md_content = md_converter.convert()

        logging.info("Updated state saved to state.md")
        save_markdown_state(final_state, "state.md")

        logging.info("Scan Results (Markdown):")
        print()
        print(md_content)


if __name__ == "__main__":
    main()
