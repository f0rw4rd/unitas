import glob
import threading
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError, Element
from typing import Dict, List, Optional, Tuple, Any, Type
import os
import concurrent.futures
import argparse
import re
import socket
from ipaddress import ip_address
import logging
from collections import defaultdict
from abc import ABC, abstractmethod
from functools import lru_cache
import time
import requests
import urllib3 
import configparser


__version__ = "1.0.0"

class UnitasConfig:
    def __init__(self, config_file: str='~/.unitas'):
        self.config_file = os.path.expanduser(config_file)
        self.config = configparser.ConfigParser()

        if not os.path.exists(self.config_file):
            logging.error(f"Config file {config_file} was not found creating default")
            self.create_template_config()
        else:
            self.config.read(self.config_file)

    def create_template_config(self):
        self.config['nessus'] = {
            'secret_key': '',
            'access_key': '',
            'url': 'https://127.0.0.1:8834'
        }
        with open(self.config_file, 'w') as file:
            self.config.write(file)
        logging.info(f"Template config file created at {self.config_file}. Please update the settings.")

    def get_secret_key(self):
        return self.config.get('nessus', 'secret_key')

    def get_access_key(self):
        return self.config.get('nessus', 'access_key')

    def get_url(self):
        return self.config.get('nessus', 'url')



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
hostup_dict = defaultdict(dict)
config = UnitasConfig()

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
    def convert(self, formatted: bool = False) -> str:
        output = ["|IP|Hostname|Port|Status|Comment|"]
        output.append("|--|--|--|--|---|")

        max_ip_len = max_hostname_len = max_port_len = max_status_len = (
            max_comment_len
        ) = 0

        if formatted:
            # Find the maximum length of each column
            for host in self.global_state.values():
                max_ip_len = max(max_ip_len, len(host.ip))
                max_hostname_len = max(max_hostname_len, len(host.hostname))
                for port in host.get_sorted_ports():
                    port_info = f"{port.port}/{port.protocol}({port.service})"
                    max_port_len = max(max_port_len, len(port_info))
                    max_status_len = max(max_status_len, len(port.state))
                    max_comment_len = max(max_comment_len, len(port.comment))

        for host in self.global_state.values():
            for port in host.get_sorted_ports():
                service = f"{port.port}/{port.protocol}({port.service})"
                output.append(
                    f"|{host.ip.ljust(max_ip_len)}|{host.hostname.ljust(max_hostname_len)}|{service.ljust(max_port_len)}|{port.state.ljust(max_status_len)}|{port.comment.ljust(max_comment_len)}|"
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

            if len(host.ports) == 0:
                pass  # TBD: implement this thing, to find nessus host that are up but have no ports

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
                service = PortDetails.get_service_name(service)
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
        )

    def _parse_ports(self, host: ET.Element, h: HostScanData) -> None:
        for port in host.findall(".//port[state]"):
            # for some reason, doing a single xpath query fails with invalid attribute#
            # only allow open ports
            if port.find("state[@state='open']") is not None:
                h.add_port_details(self._parse_port_item(port))

class NessusExporter:

    def __init__(self):
        access_key, secret_key, url = config.get_access_key(), config.get_secret_key(), config.get_url()
        if not access_key or not secret_key:
            raise ValueError("Secret or access key was empty!")
        self.access_key = access_key
        self.secret_key = secret_key
        self.url = url

        self.ses = requests.Session()
        self.ses.headers.update({'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}'})
        self.ses.verify = False # yeah i know :D

        def error_handler(r, *args, **kwargs):            
            if not r.ok:
                logging.error(f"Problem with nessus API: {r.text}")
            r.raise_for_status()

        self.ses.hooks = {
            'response': error_handler
        }
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    
    def upload_scan(self, file_path: str, name: str):
        for scan in  self._list_scans():
            # 2 is the trash folder
            if scan["name"] == "Merged Report" and scan["folder_id"] != 2:
                logging.info(f"Deleting scan {scan['id']}")                
                self.ses.delete(f"{self.url}/scans/{scan['id']}")
        self._upload_file(file_path)        
        # 
        
    def _upload_file(self, filename: str):
        if not os.path.isfile(filename):
            raise Exception("This file does not exist.")
        with open(filename, "rb") as file:
            resp = self.ses.post(f"{self.url}/file/upload", files={"Filedata": file, "no_enc": "0"})
            file_name = resp.json()['fileuploaded']
            self.ses.post(f"http://127.0.0.1:1234/scans/import", json={"folder_id": 3, "file": file_name})

    def _initiate_export(self, scan_id):        
        logging.info(f"Initiating export for scan ID: {scan_id} nessus format")
        return self.ses.post(f"{self.url}/scans/{scan_id}/export", json={"format": "nessus", 'chapters': ''}).json()['file']

    def _check_export_status(self, scan_id, file_id):
        logging.info(f"Checking export status for scan ID: {scan_id}, file ID: {file_id}")
        while True:
            status = self.ses.get(f'{self.url}/scans/{scan_id}/export/{file_id}/status').json()['status']
            if status == 'ready':
                logging.info(f"Export is ready for download for scan ID: {scan_id}")
                break
            logging.debug("Export is not ready yet, waiting 5 seconds...")
            time.sleep(5)


    def _list_scans(self) -> List[Dict]:
        logging.info("Listing nessus scans")
        scans = self.ses.get(f"{self.url}/scans").json()['scans']
        export_scans = []
        for x in scans:
            if x["status"] in ["cancled", "running"]: 
                logging.warning(f"Skipping scan \"{x['name']}\" because status is {x['status']}")            
            else: 
                export_scans.append(x)
        return export_scans

    def _download_export(self, scan: dict, file_id: str):
        scan_id = scan['id']
        scan_name = scan['name'].replace(' ', '_').replace('/', '_').replace('\\', '_')  # Sanitize filename
        filename = f"{scan_name}.nessus"
        if os.path.exists(filename):
            logging.error(f"Export file {filename} already exists. Skipping download.")
            return
        logging.info(f"Downloading export for scan ID: {scan_id}, Scan Name: {scan_name}")     
        response = self.ses.get(f"{self.url}/scans/{scan_id}/export/{file_id}/download", stream=True)
        response.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Download completed successfully for scan {scan_name}")


    def export(self, target_dir: str):
        scans = self._list_scans()

        if not scans: 
            logging.error("No scans found!")
            return
        
        for scan in scans:
            scan_id = scan['id']
            scan_name = scan['name']
            if scan_name.lower() == "merged":
                logging.info(f"Skipping export for scan named 'merged'")
                continue
            
            sanitized_scan_name = scan_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
            nessus_filename = f"{sanitized_scan_name}.nessus"

            if not os.path.exists(nessus_filename):
                nessus_file_id = self._initiate_export(scan_id)
                self._check_export_status(scan_id, nessus_file_id)
                self._download_export(scan, nessus_file_id)
            else:
                logging.info(f"Skipping export for {nessus_filename} as it already exists.")

class ScanMerger(ABC): 
    def __init__(self, directory: str, output_directory: str):
        self.directory = directory
        self.output_directory = output_directory     
        self.output_file: str = None
        self.filter: str = None   

    def search(self, wildcard: str) -> List[str]:
        files = glob.glob(os.path.join(self.directory, '**', wildcard), recursive=True)
        return [file for file in files if self.output_directory not in file]

    def parse(self):
        pass



class NmapHost: 

    def __init__(self, ip: str, host: Element):
        self.ip = ip
        self.host: Element = host
        self.hostnames: List[Element] = []
        self.ports: List[Element] = []
        self.hostscripts: List[Element] = []
        self.os_e: Element = None        

    def elements_equal(self, e1: Element, e2: Element):
        if e1.tag != e2.tag: return False
        if e1.text != e2.text: return False
        if e1.tail != e2.tail: return False
        if e1.attrib != e2.attrib: return False
        if len(e1) != len(e2): return False
        return all(self.elements_equal(c1, c2) for c1, c2 in zip(e1, e2))

    def find_port(self, protocol: str, portid: str) -> Element:
        for p in self.ports:
            if p.get('protocol') == protocol and p.get('portid') == portid:
                return p
        return None

    def add_port(self, port: Element):
        p_old = self.find_port(port.get("protocol"), port.get("portid"))
        if not p_old: 
            self.ports.append(port)
        elif len(ET.tostring(p_old)) < len(ET.tostring(port)):
            self.ports.remove(p_old)
            self.ports.append(port)

    def add_hostname(self, hostname: Element):
        if not any(self.elements_equal(e, hostname) for e in self.hostnames):
            self.hostnames.append(hostname)
    
    def add_hostscript(self, hostscript: Element):
        if not any(self.elements_equal(e, hostscript) for e in self.hostscripts):
            self.hostscripts.append(hostscript)



class NmapMerger(ScanMerger):

    def __init__(self, directory: str, output_directory: str):        
        super().__init__(directory, output_directory)
        self.output_file: str = "merged_nmap.xml"
        self.filter: str = "*.xml"         
        self.template: str = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.94 scan initiated Sun Sep 24 17:54:20 2023 as: nmap -sS -sV -sC -T5 -p- -n -Pn -oA ./mailsrv1/full_scan.nmap 192.168.214.242 -->
<nmaprun scanner="nmap" args="nmap -sS -sV -sC -T5 -p- -n -Pn -oA ./mailsrv1/full_scan.nmap 192.168.214.242" start="1695570860" startstr="Sun Sep 24 17:54:20 2023" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<verbose level="0"/>
<debugging level="0"/>
{{host}}
<runstats>
<finished time="1315618434" timestr="Fri Sep  9 18:33:54 2011" elapsed="13.66" summary="Nmap done at Fri Sep  9 18:33:54 2011; 1 IP address (1 host up) scanned in 13.66 seconds" exit="success"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
        """

    def parse(self):
        hosts: Dict[str, NmapHost] = {}
        for file_path in self.search(self.filter):
            logging.info(f"Trying to parse {file_path}")
            try: 
                root = ET.parse(file_path)
                for host in root.findall(".//host"):                    
                    status = host.find(".//status")
                    if status is not None and status.attrib.get("state") == "up":
                        address = host.find(".//address")                        
                        if address is not None:  # explicit None check is needed
                            host_ip: str = address.attrib.get("addr", "")                            
                            if not host_ip in hosts:
                                nhost = NmapHost(host_ip, host)
                                hosts[host_ip] = nhost
                            else: 
                                nhost = hosts[host_ip]
                            ports = host.find("ports")
                            if  ports is not None:                                                                 
                                for x in ports.findall("extraports"): 
                                    ports.remove(x)

                                for port in ports.findall("port[state]"):                                    
                                    if port.find("state[@state='open']") is not None:
                                        nhost.add_port(port)
                                    ports.remove(port)

                            hostnames = host.find("hostnames")
                            if hostnames is not None: 
                                for x in hostnames:
                                    hostnames.remove(x)
                                    nhost.add_hostname(x)  

                            for x in host.findall(".//hostscript"):
                                host.remove(x)
                                nhost.add_hostscript(x) 
                                

                            os_e = host.find(".//os")                       
                            if os_e is not None: 
                                host.remove(os_e)
                                nhost.os_e = os_e
            except ParseError as e:
                logging.error("Failed to parse nmap xml")
                continue
        self._render_template(hosts)
            
    def _render_template(self, hosts: Dict[str, NmapHost]) -> str:
        payload: str = ""
        for ip, nhost in hosts.items():
            host = nhost.host
            ports = host.find("ports")

            if len(nhost.ports) == 0:
                continue

            for p in nhost.ports:
                ports.append(p)
            # clear all child elements
            # add all of them
            hostnames = host.find("hostnames")
            for p in nhost.hostnames:
                hostnames.append(p)

            hostnames = host.find("hostnames")
            for p in nhost.hostnames:
                hostnames.append(p)            

            hostscripts = host.find("hostscripts")
            if not hostscripts:
                hostscripts = ET.fromstring("<hostscripts></hostscripts>")
                host.append(hostscripts)
            for p in nhost.hostscripts:
                hostscripts.append(p)

            payload += ET.tostring(host).decode()
        data = self.template.replace("{{host}}", payload)
        
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)
        
        output_file = os.path.join(self.output_directory, self.output_file)
        
        with open(output_file, "w") as f:
            f.write(data)
        
        logging.info(f"Saving merged scan to {output_file}")

        os.system(f"xsltproc {output_file} -o {output_file}.html")

        return output_file
        

    def save_report(self) -> str:
        pass
        # TBD add code to convert HTML

    
class NessusMerger(ScanMerger):

    def __init__(self, directory: str, output_directory: str):        
        super().__init__(directory, output_directory)        
        self.tree: ET.ElementTree = None
        self.root: ET.Element = None        
        self.output_file: str = "merged_report.nessus"
        self.filter: str = "*.nessus"

    def parse(self):        
        first_file_parsed = True        
        for file_path in self.search(self.filter):            
            logging.info(f"Parsing - {file_path}")
            try:
                if first_file_parsed:
                    self.tree = ET.parse(file_path)
                    self.report = self.tree.find('Report')
                    self.report.attrib['name'] = 'Merged Report'            
                    first_file_parsed = False
                else: 
                    tree = ET.parse(file_path)                
                    self._merge_hosts(tree)
            except ParseError:
                logging.error("Failed to parse")            

    def _merge_hosts(self, tree):
        for host in tree.findall('.//ReportHost'):
            existing_host = self.report.find(f".//ReportHost[@name='{host.attrib['name']}']")
            if not existing_host:
                logging.debug(f"Adding host: {host.attrib['name']}")
                self.report.append(host)
            else:
                self._merge_report_items(host, existing_host)

    def _merge_report_items(self, host, existing_host):
        for item in host.findall('ReportItem'):
            if not existing_host.find(f"ReportItem[@port='{item.attrib['port']}'][@pluginID='{item.attrib['pluginID']}']"):
                logging.debug(f"Adding finding: {item.attrib['port']}:{item.attrib['pluginID']}")
                existing_host.append(item)

    def save_report(self) -> str: 
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)
        output_file = os.path.join(self.output_directory, self.output_file)
        self.tree.write(output_file, encoding="utf-8", xml_declaration=True)
        logging.info(f"Saving merged scan to {output_file}")
        return output_file


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
    global_state: Dict[str, HostScanData], search_terms: List[str], with_url: bool
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
                    url += ":" + port_nr
                    matching_ips.add(url)

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


def generate_nmap_scan_command(global_state: Dict[str, HostScanData]) -> str:
    scan_types: set[str] = set()
    tcp_ports: set[str] = set()
    udp_ports: set[str] = set()
    targets: set[str] = set()
    for ip, host_data in global_state.items():
        for port in host_data.ports:
            if "?" in port.service:
                if port.protocol == "tcp":
                    tcp_ports.add(port.port)
                    scan_types.add("S")
                elif port.protocol == "udp":
                    udp_ports.add(port.port)
                    scan_types.add("U")
                targets.add(ip)

    if not tcp_ports and not udp_ports:
        return "no ports found for re-scanning"
    ports = "-p"
    if tcp_ports:
        ports += "T:" + ",".join(tcp_ports)
    if udp_ports:
        if tcp_ports:
            ports += ","
        ports += "U:" + ",".join(udp_ports)
    return f"sudo nmap -s{''.join(scan_types)} -sV -v {ports} {' '.join(targets)}"


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

    parser.add_argument(
        "-r",
        "--rescan",
        action="store_true",
        default=False,
        help="Print a nmap command to re-scan the ports not service scanned",
    )

    parser.add_argument(
        "-e",
        "--export",
        action="store_true",
        default=False,
        help="Export all scans from nessus",
    )

    parser.add_argument(
        "-m",
        "--merge",
        action="store_true",
        default=False,
        help="Merge scans in the folder",
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

    if args.export: 
        logging.info(f"Starting nessus export to {os.path.abspath(args.scan_folder)}")
        NessusExporter().export(args.scan_folder)        
        return

    if args.merge: 
        logging.info("Starting to merge scans!")        

        merger = NmapMerger(args.scan_folder, os.path.join(args.scan_folder, "merged"))
        merger.parse()        

        merger = NessusMerger(args.scan_folder, os.path.join(args.scan_folder, "merged"))
        merger.parse()
        merger.save_report()
        

        # upload does not work on scanner because tenable disabled support for manager only :-/
        #logging.info("Trying to upload the merged scan!")
        #NessusExporter().upload_scan(file, "merged")
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

    if hostup_dict:
        logging.info(
            f"Found {len(hostup_dict)} hosts that are up, but have no open ports"
        )
        up_file: str = "/tmp/up.txt"
        with open(up_file, "w") as f:
            for ip, reason in hostup_dict.items():
                print(f"UP:{ip}:{reason}")
                f.write(f"{ip}\n")
            logging.info(f"Wrote list of host without open ports to {up_file}")

    if args.rescan:
        logging.info("nmap command to re-scan all non service scanned ports")
        logging.info(generate_nmap_scan_command(final_state))
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
        md_content = md_converter.convert(True)

        logging.info("Updated state saved to state.md")
        with open("state.md", "w") as f:
            f.write(md_content)

        logging.info("Scan Results (Markdown):")
        print()
        print(md_content)


if __name__ == "__main__":
    main()
