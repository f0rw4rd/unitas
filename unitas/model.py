from ipaddress import ip_address
import logging
from typing import Any, Dict, List


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
        "cifs": "smb",
        "ms-wbt-server": "rdp",
        "ms-msql-s": "mssql",
    }

    @staticmethod
    def get_service_name(service: str, port: str):
        # some times nmap shows smb as netbios, but only overwrite this for port 445
        if port == "445" and "netbios" in service:
            return "smb"
        if service in PortDetails.SERVICE_MAPPING:
            return PortDetails.SERVICE_MAPPING[service]
        return service

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "PortDetails":
        return cls(data["port"], data["protocol"], data["state"], data["service"])


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
        state: str = "TBD",
        service: str = "unknown?",
        comment: str = "",
    ) -> None:
        new_port = PortDetails(port, protocol, state, service, comment)
        self.add_port_details(new_port)

    def set_hostname(self, hostname: str) -> None:
        self.hostname = hostname

    def get_sorted_ports(self) -> List[PortDetails]:
        return sorted(self.ports, key=lambda p: (p.protocol, int(p.port)))

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
