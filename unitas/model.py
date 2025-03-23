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
        source_type: str = "",
        source_file: str = "",
        detected_date: str = "",
    ):
        if not PortDetails.is_valid_port(port):
            raise ValueError(f'Port "{port}" is not valid!')
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.comment = comment

        # Store sources as a list of dictionaries
        self.sources = []
        if source_type or source_file or detected_date:
            self.add_source(source_type, source_file, detected_date)

    def add_source(self, source_type: str, source_file: str, detected_date: str):
        """Add a new source to the port information"""
        source = {"type": source_type, "file": source_file, "date": detected_date}

        # Check if this exact source already exists
        if source not in self.sources:
            self.sources.append(source)

    @property
    def source_type(self) -> str:
        """Return the primary source type (for backwards compatibility)"""
        return self.sources[0]["type"] if self.sources else ""

    @property
    def source_file(self) -> str:
        """Return the primary source file (for backwards compatibility)"""
        return self.sources[0]["file"] if self.sources else ""

    @property
    def detected_date(self) -> str:
        """Return the primary detected date (for backwards compatibility)"""
        return self.sources[0]["date"] if self.sources else ""

    def __str__(self) -> str:
        return f"{self.port}/{self.protocol}({self.service})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "comment": self.comment,
            "sources": self.sources,
        }

    def __eq__(self, other):
        if not isinstance(other, PortDetails):
            return NotImplemented
        return (
            self.port == other.port
            and self.protocol == other.protocol
            and self.state == other.state
            and self.service == other.service
            and self.comment == other.comment
        )

    def __repr__(self) -> str:
        return f"PortDetails({self.port}/{self.protocol} {self.state} {self.service} {self.comment} sources:{len(self.sources)})"

    def update(self, other: "PortDetails"):
        # Track if we updated anything significant
        updated = False

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
            updated = True

        # update the comments if comment is set
        if not self.comment and other.comment:
            logging.debug(f"Updating comment from {self.comment} -> {other.comment}")
            self.comment = other.comment
            updated = True

        if not self.state and other.state:
            logging.debug(f"Updating state from {self.state} -> {other.state}")
            self.state = other.state
            updated = True

        # Always merge sources regardless of whether we updated anything else
        for source in other.sources:
            self.add_source(source["type"], source["file"], source["date"])

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
    def from_dict(cls, data: Dict[str, Any]) -> "PortDetails":
        port_details = cls(
            data["port"],
            data["protocol"],
            data["state"],
            data.get("service", "unknown?"),
            data.get("comment", ""),
        )

        # Handle sources in the new format
        if "sources" in data and isinstance(data["sources"], list):
            for source in data["sources"]:
                port_details.add_source(
                    source.get("type", ""),
                    source.get("file", ""),
                    source.get("date", ""),
                )
        # Handle legacy format
        elif any(
            key in data for key in ["source_type", "source_file", "detected_date"]
        ):
            port_details.add_source(
                data.get("source_type", ""),
                data.get("source_file", ""),
                data.get("detected_date", ""),
            )

        return port_details


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
        source_type: str = "",
        source_file: str = "",
        detected_date: str = "",
    ) -> None:
        new_port = PortDetails(
            port,
            protocol,
            state,
            service,
            comment,
            source_type,
            source_file,
            detected_date,
        )
        self.add_port_details(new_port)

    def set_hostname(self, hostname: str) -> None:
        self.hostname = hostname

    def get_sorted_ports(self) -> List[PortDetails]:
        return sorted(self.ports, key=lambda p: (p.protocol, int(p.port)))


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
