from abc import ABC, abstractmethod
import glob
import logging
import os
from unitas.utils import service_lookup, hostup_dict
from typing import Dict, List, Optional, Tuple
from xml.etree.ElementTree import ParseError
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError, Element
import concurrent.futures

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
                logging.debug(f"Adding file {f} for parser {cls.__name__}")
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

    def parse(self) -> Dict[str, HostScanData]:
        # Try to extract scan date from Nessus file
        report_element = self.root.find(".//Report")
        if report_element is not None:
            self.scan_date = report_element.get("name", "")

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
            plugin_found = (
                self._parse_service_detection(block, host) > 0
                or self._parse_port_scanners(block, host) > 0
            )
            # the idea here is if the host has some version or port scan, it must be up
            # sofar i have not seen a nessus file w
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

    def _parse_service_detection(self, block: ET.Element, host: HostScanData) -> int:
        counter = 0
        # xml module has only limited xpath support
        for item in [
            b
            for b in block.findall(".//ReportItem")
            if b.attrib.get("pluginFamily", "Port Scanner")
            not in ["Port Scanner", "Settings"]
        ]:
            counter += 1
            host.add_port_details(self._parse_service_item(item))
        return counter

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
        return PortDetails(port=port, service=service, state=state, protocol=protocol)

    def _parse_port_scanners(self, block: ET.Element, host: HostScanData) -> int:
        counter = 0
        for item in block.findall(".//ReportItem[@pluginFamily='Port scanners']"):
            counter += 1
            host.add_port_details(self._parse_port_item(item))
        return counter


class NmapParser(ScanParser):

    @staticmethod
    def get_extensions() -> List[str]:
        return ["xml"]

    def get_scan_type(self) -> str:
        return "nmap"

    def parse(self) -> Dict[str, HostScanData]:
        if self.root.get("start"):
            try:
                start_timestamp = self.root.get("start")
                self.scan_date = self.root.get("startstr", "")
                if not self.scan_date and start_timestamp:
                    import datetime

                    self.scan_date = datetime.datetime.fromtimestamp(
                        int(start_timestamp)
                    ).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                self.scan_date = ""

        for host in self.root.findall(".//host"):
            status = host.find(".//status")
            if status is not None and status.attrib.get("state") == "up":
                address = host.find(".//address")
                if address is not None:  # explicit None check is needed
                    host_ip: str = address.attrib.get("addr", "")
                    h = HostScanData(ip=host_ip)

                    self._parse_ports(host, h)
                    if len(h.ports) == 0:  # do not parse host that have no IP
                        if not host_ip in hostup_dict:
                            reason = status.attrib.get("reason", "")
                            if reason and not reason == "user-set":
                                hostup_dict[host_ip] = reason
                        continue

                    self.data[host_ip] = h

                    hostnames = host.find(".//hostnames")
                    if hostnames is not None:
                        for x in hostnames:
                            if "name" in x.attrib:
                                h.set_hostname(x.attrib.get("name"))
                                # prefer the user given hostname instead of the PTR
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

    def _parse_ports(self, host: ET.Element, h: HostScanData) -> None:
        for port in host.findall(".//port[state]"):
            # for some reason, doing a single xpath query fails with invalid attribute#
            # only allow open ports
            if port.find("state[@state='open']") is not None:
                h.add_port_details(self._parse_port_item(port))


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
                _, scan_results = future.result()
                global_state = merge_states(global_state, scan_results)

            except Exception as exc:
                logging.error(
                    f"{parser.file_path} generated an exception: {exc}", exc_info=True
                )
    return global_state
