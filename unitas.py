import glob
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
import pickle
from typing import Dict, List, Optional, Tuple, Any, Type
import os
import argparse
import logging
from abc import ABC, abstractmethod


class PortDetails:
    def __init__(
        self, port: str, protocol: str, state: str, service: Optional[str] = None
    ):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service

    def __str__(self) -> str:
        return f"{self.port}/{self.protocol}({self.service})"

    def to_dict(self) -> Dict[str, str]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "PortDetails":
        return cls(data["port"], data["protocol"], data["state"], data["service"])


class HostScanData:
    def __init__(self, ip: str):
        self.ip = ip
        self.hostname: Optional[str] = None
        self.ports: List[PortDetails] = []

    @staticmethod
    def overwrite_service(old_service: str, new_service: str) -> bool:
        if "?" in old_service and "?" not in new_service:
            return True
        if "?" not in new_service and len(new_service) > len(old_service):
            return True
        return False

    def add_port(
        self, port: str, protocol: str, state: str, service: str = "unknown?"
    ) -> None:
        for p in self.ports:
            if p.port == port and p.protocol == protocol:
                if self.overwrite_service(p.service, service):
                    p.service = service
                return
        self.ports.append(PortDetails(port, protocol, state, service))

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


def save_to_file(hosts: Dict[str, HostScanData], filename: str = ".state.pkl") -> None:
    with open(filename, "wb") as file:
        pickle.dump(hosts, file)


def load_from_file(filename: str = ".state.pkl") -> Dict[str, HostScanData]:
    if not os.path.exists(filename):
        logging.warning("File not found. Using empty state.")
        return {}
    with open(filename, "rb") as file:
        return pickle.load(file)


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
                logging.debug(f"Adding file {f}")
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
            ip: str = block.attrib.get("name", "")
            host = HostScanData(ip=ip)

            hostname = block.find(".//tag[@name='host-fqdn']")
            if hostname is not None and hostname.text:
                host.set_hostname(hostname.text)

            self._parse_service_detection(block, host)
            self._parse_port_scanners(block, host)

            self.data[ip] = host
        return self.data

    def _parse_service_detection(self, block: ET.Element, host: HostScanData) -> None:
        for item in block.findall(".//ReportItem[@pluginFamily='Service detection']"):
            port: str = item.attrib.get("port", "")
            protocol: str = item.attrib.get("protocol", "")
            service: str = item.attrib.get("svc_name", "")
            if "TLS" in item.attrib.get("pluginName", "") or "SSL" in item.attrib.get(
                "pluginName", ""
            ):
                service += "/tls"
            state: str = "open"
            host.add_port(port, protocol, state, service)

    def _parse_port_scanners(self, block: ET.Element, host: HostScanData) -> None:
        for item in block.findall(".//ReportItem[@pluginFamily='Port scanners']"):
            port: str = item.attrib.get("port", "")
            if port == "0":  # host scan
                continue
            protocol: str = item.attrib.get("protocol", "")
            service: str = item.attrib.get("svc_name", "")
            if "?" not in service:  # append a ? for just port scans
                service += "?"
            state: str = "open"
            host.add_port(port, protocol, state, service)


class NmapParser(ScanParser):

    @staticmethod
    def get_extensions() -> List[str]:
        return ["xml"]

    def parse(self) -> Dict[str, HostScanData]:
        for host in self.root.findall(".//host"):
            status = host.find(".//status")
            if status is not None and status.attrib.get("state") == "up":
                address = host.find(".//address")
                if address is not None:
                    host_ip: str = address.attrib.get("addr", "")
                    h = HostScanData(ip=host_ip)
                    self._parse_ports(host, h)
                    self.data[host_ip] = h
        return self.data

    def _parse_ports(self, host: ET.Element, h: HostScanData) -> None:
        for port in host.findall(".//port"):
            protocol: str = port.attrib.get("protocol", "")
            portid: str = port.attrib.get("portid", "")
            state_elem = port.find(".//state")
            state: str = (
                state_elem.attrib.get("state", "") if state_elem is not None else ""
            )
            service_element = port.find(".//service")

            if service_element is not None:
                service: str = service_element.attrib.get("name", "")
                if service_element.attrib.get("method") == "table":
                    service += "?"
                if service_element.attrib.get("tunnel", "none") == "ssl":
                    service += "/tls"
            else:
                service = "unknown?"

            if state == "open":
                h.add_port(portid, protocol, state, service)


def merge_host_data(
    global_state: Dict[str, HostScanData], new_data: Dict[str, HostScanData]
) -> Tuple[List[HostScanData], Dict[str, List[PortDetails]]]:
    new_hosts = []
    updated_hosts = {}

    for ip, host_data in new_data.items():
        if ip in global_state:
            new_ports = global_state[ip].merge(host_data)
            if new_ports:
                updated_hosts[ip] = new_ports
        else:
            global_state[ip] = host_data
            new_hosts.append(host_data)

    return new_hosts, updated_hosts


def setup_logging(log_level: str = "INFO") -> None:
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Unitas Scan Parser")
    parser.add_argument("scan_folder", help="Folder containing scan files")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level",
    )
    args = parser.parse_args()

    setup_logging(args.log_level)

    parsers = NessusParser.load_file(args.scan_folder) + NmapParser.load_file(
        args.scan_folder
    )
    global_state = load_from_file()

    if not parsers:
        logging.error("Could not load any kind of scan files")
        return

    for p in parsers:
        try:
            scan_results = p.parse()
            new_hosts, updated_hosts = merge_host_data(global_state, scan_results)
            if new_hosts:
                logging.info(
                    "New hosts added: %s", ", ".join(str(host) for host in new_hosts)
                )
            if updated_hosts:
                for ip, ports in updated_hosts.items():
                    logging.info(
                        "Host %s updated with new ports: %s",
                        ip,
                        ", ".join(str(port) for port in ports),
                    )
        except ParseError:
            logging.error("Could not load %s, invalid XML", p.file_path)

    if global_state:
        logging.info("Scan Results:")
        print("|IP|Port|Status|Comment")
        print("|--|--|--|---|")
        for host in global_state.values():
            for row in host.to_markdown_rows():
                print(row)
    else:
        logging.info("Did not find any open ports!")

    save_to_file(global_state)


if __name__ == "__main__":
    main()
