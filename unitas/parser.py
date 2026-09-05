from abc import ABC, abstractmethod
import glob
import logging
import os
from typing import Dict, List, Optional, Tuple
from xml.etree.ElementTree import ParseError
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

from unitas.utils import service_lookup, hostup_dict, find_nmap_ip_address
from unitas.model import HostScanData, PortDetails, merge_states


class ScanParser(ABC):
    def __init__(self, file_path: str):
        self.file_path: str = file_path
        self.tree: ET.ElementTree = ET.parse(file_path)
        self.root: ET.Element = self.tree.getroot()
        self.data: Dict[str, HostScanData] = {}
        self.file_name: str = os.path.basename(file_path)
        self.scan_date: str = ""

    @abstractmethod
    def parse(self) -> Dict[str, HostScanData]:
        pass

    @staticmethod
    @abstractmethod
    def get_extensions() -> List[str]:
        pass

    @abstractmethod
    def get_scan_type(self) -> str:
        pass

    @classmethod
    def load_file(cls, directory: str) -> List["ScanParser"]:
        files = []
        for ext in cls.get_extensions():
            logging.debug(
                f'Looking in folder "{directory}" for "{ext}" files for parser {cls.__name__}'
            )
            for f in glob.glob(f"{directory}/**/*.{ext}", recursive=True):
                logging.debug("Adding file %s for parser %s", f, cls.__name__)
                try:
                    files.append(cls(f))
                except ParseError:
                    logging.error(f"Could not load XML from file {f}")
        return files


class NessusParser(ScanParser):

    @staticmethod
    def get_extensions() -> List[str]:
        return ["nessus"]

    def get_scan_type(self) -> str:
        return "nessus"

    @staticmethod
    def _host_tags(block: ET.Element) -> Dict[str, str]:
        """The <HostProperties> tags of a host as a plain dict."""
        properties = block.find("HostProperties")
        if properties is None:
            return {}
        return {
            tag.attrib["name"]: tag.text
            for tag in properties.findall("tag")
            if "name" in tag.attrib and tag.text
        }

    def _parse_mac_address(
        self, block: ET.Element, tags: Dict[str, str]
    ) -> Optional[str]:
        """Extract MAC address from Nessus plugin output."""
        # Look for ping plugin (plugin ID 10180)
        ping_item = next(
            (
                item
                for item in block.findall("ReportItem")
                if item.attrib.get("pluginID") == "10180"
            ),
            None,
        )
        if ping_item is not None:
            plugin_output = ping_item.find("plugin_output")
            if plugin_output is not None and plugin_output.text:
                # Extract MAC address from plugin output using regex
                import re

                mac_match = re.search(
                    r"Hardware address\s*:\s*([0-9A-Fa-f:]{17})", plugin_output.text
                )
                if mac_match:
                    return mac_match.group(1)

        # As a fallback, check MAC address tag
        return tags.get("mac-address")

    def parse(self) -> Dict[str, HostScanData]:
        for block in self.root.findall(".//ReportHost"):
            name: str = block.attrib.get("name", "")
            hostname: Optional[str] = None

            tags = self._host_tags(block)

            if HostScanData.is_valid_ip(name):
                ip = name
                hostname = tags.get("host-fqdn") or None
            else:
                hostname = name
                ip = tags.get("host-ip")
                if not ip:
                    raise ValueError(f"Could not find IP for host {hostname}")

            host = HostScanData(ip)
            if hostname:
                host.set_hostname(hostname)

            # Extract MAC address
            mac_address = self._parse_mac_address(block, tags)
            if mac_address:
                host.set_mac_address(mac_address)
                logging.debug(
                    f"Found MAC address in Nessus scan for {ip}: {mac_address}"
                )

            plugin_found = self._parse_report_items(block, host) > 0

            if plugin_found and len(host.ports) == 0:
                if not ip in hostup_dict:
                    hostup_dict[ip] = "nessus plugin seen"

            if len(host.ports) == 0:
                continue

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
        if port == "0":  # host scans return port zero, skip
            return None
        protocol: str = item.attrib.get("protocol")
        service: str = item.attrib.get("svc_name")
        service = PortDetails.get_service_name(service, port)
        comment: str = ""
        if "TLS" in item.attrib.get("pluginName") or "SSL" in item.attrib.get(
            "pluginName", ""
        ):
            if service == "http":
                service = "https"
            comment = "TLS"
        state: str = "TBD"

        # Include source information
        return PortDetails(
            port=port,
            service=service,
            comment=comment,
            state=state,
            protocol=protocol,
            source_type=self.get_scan_type(),
            source_file=self.file_name,
            detected_date=self.scan_date,
        )

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
            service = PortDetails.get_service_name(service, port)
        state: str = "TBD"

        # Include source information
        return PortDetails(
            port=port,
            service=service,
            state=state,
            protocol=protocol,
            source_type=self.get_scan_type(),
            source_file=self.file_name,
            detected_date=self.scan_date,
        )

    def _parse_report_items(self, block: ET.Element, host: HostScanData) -> int:
        """Parse the findings of one host.

        The service detection and the port scanner plugins are told apart by
        their plugin family in a single pass; two ".//ReportItem" walks of the
        same subtree used to cost more than everything else in the parser.
        """
        counter = 0
        # the service scan runs first, the port scanner must not overwrite an
        # identified service with its guess
        port_scanner_items = []

        for item in block.findall("ReportItem"):
            family = item.attrib.get("pluginFamily", "Port scanners").lower()
            if family == "settings":
                continue
            counter += 1
            if family == "port scanners":
                port_scanner_items.append(item)
            else:
                host.add_port_details(self._parse_service_item(item))

        for item in port_scanner_items:
            host.add_port_details(self._parse_port_item(item))

        return counter


class NmapParser(ScanParser):

    @staticmethod
    def get_extensions() -> List[str]:
        return ["xml"]

    def get_scan_type(self) -> str:
        return "nmap"

    def parse(self) -> Dict[str, HostScanData]:
        # All of these elements are direct children of <host>; ".//" would walk
        # the whole subtree of every host, which is the bulk of the work on a
        # large sweep (65k hosts with no ports).
        for host in self.root.findall("host"):
            status = host.find("status")
            if status is None or status.attrib.get("state") != "up":
                continue

            addresses = host.findall("address")
            host_ip: str = find_nmap_ip_address(addresses)
            if not host_ip:
                continue

            ports = self._parse_ports(host)
            if not ports:
                # a host that is up but has nothing open is only worth an entry
                # in the host-up list, so it never becomes a HostScanData
                if host_ip not in hostup_dict:
                    reason = status.attrib.get("reason", "")
                    if reason and reason != "user-set":
                        hostup_dict[host_ip] = reason
                continue

            h = HostScanData(ip=host_ip)
            for port in ports:
                h.add_port_details(port)

            for address in addresses:
                if address.attrib.get("addrtype") == "mac":
                    mac_address = address.attrib.get("addr", "")
                    if mac_address:
                        h.set_mac_address(mac_address)
                        logging.debug(
                            "Found MAC address: %s (Vendor: %s)",
                            mac_address,
                            address.attrib.get("vendor", ""),
                        )
                    break

            self.data[host_ip] = h

            hostnames = host.find("hostnames")
            if hostnames is not None:
                for x in hostnames:
                    if "name" in x.attrib:
                        h.set_hostname(x.attrib.get("name"))
                        if x.attrib.get("type", "") == "user":
                            break
        return self.data

    def _parse_port_item(self, port: ET.Element) -> PortDetails:
        if not all(attr in port.attrib for attr in ["portid", "protocol"]):
            logging.error(f"Failed to parse nmap scan: {ET.tostring(port)}")
            return None
        protocol: str = port.attrib.get("protocol")
        portid: str = port.attrib.get("portid")
        service_element = port.find(".//service")
        comment: str = ""
        tls_found: bool = False

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
                service = PortDetails.get_service_name(service, portid)
                product = service_element.attrib.get("product", "")
                if product:
                    comment += product
                version = service_element.attrib.get("version", "")
                if version:
                    comment += " " + version

            if service_element.attrib.get("tunnel", "none") == "ssl":
                # nmap is not is not consistent with http/tls and https
                tls_found = True
        else:
            service = service_lookup.get_service_name_for_port(
                portid, protocol, "unknown"
            )
            service += "?"

        if not tls_found:
            for script in port.findall(".//script"):
                # some services have TLS but nmap does not mark it via the tunnel e.g. FTP
                if script.attrib.get("id", "") == "ssl-cert":
                    tls_found = True
                    break

        if tls_found:
            if service == "http":
                service = "https"
            if comment:
                comment += ";"

            comment += "TLS"

        return PortDetails(
            port=portid,
            protocol=protocol,
            state="TBD",
            comment=comment,
            service=service,
            source_type=self.get_scan_type(),
            source_file=self.file_name,
            detected_date=self.scan_date,
        )

    def _parse_ports(self, host: ET.Element) -> List[PortDetails]:
        ports = host.find("ports")
        if ports is None:
            return []

        found = []
        for port in ports.findall("port"):
            # for some reason, doing a single xpath query fails with invalid attribute#
            # only allow open ports
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            details = self._parse_port_item(port)
            if details is not None:
                found.append(details)
        return found


def parse_file(parser: ScanParser) -> Tuple[str, Dict[str, HostScanData]]:
    try:
        return parser.file_path, parser.parse()
    except ParseError:
        logging.error(f"Could not load {parser.file_path}, invalid XML")
        return parser.file_path, {}


def parse_files_concurrently(
    parsers: List[ScanParser], max_workers: Optional[int] = None
) -> Dict[str, HostScanData]:
    """Parse the scans and merge them into one state.

    This used to run in a ThreadPoolExecutor, but every stage of the work
    (ElementTree and the model building) holds the GIL, so the pool only added
    contention: measured over the test corpus it was 6-12% slower than the
    plain loop, and it wrote to the global hostup_dict from several threads.
    max_workers is kept for callers that still pass it.
    """
    global_state: Dict[str, HostScanData] = {}

    for parser in parsers:
        try:
            _, scan_results = parse_file(parser)
            global_state = merge_states(global_state, scan_results)
        except Exception as exc:  # pylint: disable=broad-except
            logging.error(
                f"{parser.file_path} generated an exception: {exc}", exc_info=True
            )

    return global_state
