from abc import ABC
from copy import deepcopy
import glob
import logging
import os
import shutil
from typing import Dict, List
from xml.etree.ElementTree import ParseError
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError, Element

from .exporter import NessusExporter


class ScanMerger(ABC):
    def __init__(self, directory: str, output_directory: str):
        self.directory = directory
        self.output_directory = output_directory
        self.output_file: str = None
        self.filter: str = None

    def search(self, wildcard: str) -> List[str]:
        files = []
        for file in glob.glob(
            os.path.join(self.directory, "**", wildcard), recursive=True
        ):
            # Skip if it's a directory
            if os.path.isdir(file):
                continue

            # Skip output directory files
            if os.path.abspath(self.output_directory) in os.path.abspath(file):
                logging.warning(
                    f"Skipping file {file} to prevent merging a merged scan!"
                )
            else:
                files.append(file)

        return files

    def parse(self):
        pass


class NmapHost:

    def __init__(self, ip: str, host: Element):
        self.ip = ip
        self.host: Element = host
        self.hostnames: List[Element] = []
        self.ports: Dict[str, ET.Element] = {}
        self.hostscripts: Dict[str, ET.Element] = {}
        self.os_e: Element = None
        self.reason: str = None

    def elements_equal(self, e1: Element, e2: Element):
        if e1.tag != e2.tag:
            return False
        if e1.text != e2.text:
            return False
        if e1.tail != e2.tail:
            return False
        if e1.attrib != e2.attrib:
            return False
        if len(e1) != len(e2):
            return False
        return all(self.elements_equal(c1, c2) for c1, c2 in zip(e1, e2))

    def find_port(self, protocol: str, portid: str) -> Element:
        for p in self.ports:
            if p.get("protocol") == protocol and p.get("portid") == portid:
                return p
        return None

    def add_port(self, port: ET.Element):
        key = self._get_port_key(port)

        if key in self.ports:
            self._merge_port_info(self.ports[key], port)
        else:
            self.ports[key] = deepcopy(port)

    def _get_port_key(self, port: ET.Element) -> str:
        key = f"{port.get('protocol')}_{port.get('portid')}"
        state = port.find("state")
        if state is not None:
            key += f"_{state.get('state')}"
        return key

    def _merge_port_info(self, existing_port: ET.Element, new_port: ET.Element):
        # Merge service information
        existing_service = existing_port.find("service")
        new_service = new_port.find("service")
        if existing_service is not None and new_service is not None:
            self._merge_service_info(existing_service, new_service)
        elif new_service is not None:
            existing_port.append(deepcopy(new_service))

        # Merge script results
        existing_scripts = {
            script.get("id"): script for script in existing_port.findall("script")
        }
        for new_script in new_port.findall("script"):
            script_id = new_script.get("id")
            if script_id not in existing_scripts:
                existing_port.append(deepcopy(new_script))

    def _merge_service_info(
        self, existing_service: ET.Element, new_service: ET.Element
    ):
        for attr, value in new_service.attrib.items():
            if attr not in existing_service.attrib or existing_service.get(attr) == "":
                existing_service.set(attr, value)

    def add_hostname(self, hostname: Element):
        if not any(self.elements_equal(e, hostname) for e in self.hostnames):
            self.hostnames.append(hostname)

    def _merge_script_info(self, existing_script: ET.Element, new_script: ET.Element):
        # Update output if it's different
        if existing_script.get("output") != new_script.get("output"):
            existing_script.set("output", new_script.get("output"))

        # Merge or update table elements
        existing_tables = {
            table.get("key"): table for table in existing_script.findall("table")
        }
        for new_table in new_script.findall("table"):
            table_key = new_table.get("key")
            if table_key not in existing_tables:
                existing_script.append(deepcopy(new_table))
            else:
                self._merge_table_info(existing_tables[table_key], new_table)

    def _merge_table_info(self, existing_table: ET.Element, new_table: ET.Element):
        existing_elems = {
            elem.get("key"): elem for elem in existing_table.findall("elem")
        }
        for new_elem in new_table.findall("elem"):
            elem_key = new_elem.get("key")
            if elem_key not in existing_elems:
                existing_table.append(deepcopy(new_elem))
            elif existing_elems[elem_key].text != new_elem.text:
                existing_elems[elem_key].text = new_elem.text

    def add_hostscript(self, hostscript: ET.Element):
        script_id = hostscript.get("id")
        if script_id not in self.hostscripts:
            self.hostscripts[script_id] = deepcopy(hostscript)
        else:
            self._merge_script_info(self.hostscripts[script_id], hostscript)


class NmapMerger(ScanMerger):

    def __init__(self, directory: str, output_directory: str):
        super().__init__(directory, output_directory)
        self.output_file: str = "merged_nmap.xml"
        self.filter: str = "*.xml"
        self.template: str = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Merge scan generated -->
<nmaprun scanner="nmap" args="non merged" start="1695570860" startstr="Sun Sep 24 17:54:20 2023" version="7.94" xmloutputversion="1.05">
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

                            nhost.reason = status.attrib.get("reason", "user-set")
                            ports = host.find("ports")
                            if ports is not None:
                                for x in ports.findall("extraports"):
                                    ports.remove(x)

                                for port in ports.findall("port[state]"):
                                    state = port.find("state")
                                    if (
                                        port.attrib.get("protocol", "udp") == "udp"
                                        and state.attrib.get("state", "open|filtered")
                                        == "open|filtered"
                                        and state.attrib.get("reason", "no-response")
                                        == "no-response"
                                    ):
                                        pass
                                    else:
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
            except IsADirectoryError:
                logging.error("Seems like we tried to open a dir")
                continue
            except ParseError:
                logging.error("Failed to parse nmap xml")
                continue
        if hosts:
            self._render_template(hosts)
        else:
            logging.error("No hosts found, could not generate merged nmap scan!")

    def _render_template(self, hosts: Dict[str, NmapHost]) -> str:
        payload: str = ""
        for ip, nhost in hosts.items():
            host = nhost.host
            ports = host.find("ports")

            # odd case where the host is up, but not port was found
            if nhost.reason == "user-set" and len(nhost.ports) == 0:
                continue

            # if the first scan had no ports, we need to add the element again
            if ports is None:

                ports = ET.fromstring("<ports></ports>")
                host.append(ports)

            for _, p in nhost.ports.items():
                ports.append(p)
            # clear all child elements
            # add all of them
            hostnames = host.find("hostnames")
            for p in nhost.hostnames:
                hostnames.append(p)

            hostscripts = host.find("hostscripts")
            if not hostscripts:
                hostscripts = ET.fromstring("<hostscripts></hostscripts>")
                host.append(hostscripts)
            for _, p in nhost.hostscripts.items():
                hostscripts.append(p)

            payload += ET.tostring(host).decode()
        data = self.template.replace("{{host}}", payload)

        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        output_file = os.path.join(self.output_directory, self.output_file)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(data)

        logging.info(f"Saving merged scan to {output_file}")
        if shutil.which("xsltproc") is None:
            logging.error(
                "xsltproc is not installed and nmap html report will not generated!"
            )
        else:
            os.system(f"xsltproc {output_file} -o {output_file}.html")

        return output_file

    def save_report(self) -> str:
        pass
        # TBD add code to convert HTML


class NessusMerger(ScanMerger):

    def __init__(self, directory: str, output_directory: str, report_title: str = None):
        super().__init__(directory, output_directory)
        self.tree: ET.ElementTree = None
        self.root: ET.Element = None
        self.output_file: str = "merged_report.nessus"
        self.filter: str = "*.nessus"
        self.report_title: str = report_title or NessusExporter.report_name

    def parse(self):
        first_file_parsed = True
        for file_path in self.search(self.filter):
            logging.info(f"Parsing - {file_path}")
            try:
                if first_file_parsed:
                    self.tree = ET.parse(file_path)
                    self.report = self.tree.find("Report")
                    self.report.attrib["name"] = self.report_title
                    first_file_parsed = False
                else:
                    tree = ET.parse(file_path)
                    self._merge_hosts(tree)
            except IsADirectoryError:
                logging.error("Seems like we tried to open a dir")
            except ParseError:
                logging.error("Failed to parse")

    def _merge_hosts(self, tree):
        for host in tree.findall(".//ReportHost"):
            existing_host = self.report.find(
                f".//ReportHost[@name='{host.attrib['name']}']"
            )
            if not existing_host:
                logging.debug(f"Adding host: {host.attrib['name']}")
                self.report.append(host)
            else:
                self._merge_report_items(host, existing_host)

    def _merge_report_items(self, host, existing_host):
        for item in host.findall("ReportItem"):
            if not existing_host.find(
                f"ReportItem[@port='{item.attrib['port']}'][@pluginID='{item.attrib['pluginID']}']"
            ):
                logging.debug(
                    f"Adding finding: {item.attrib['port']}:{item.attrib['pluginID']}"
                )
                existing_host.append(item)

    def save_report(self) -> str:
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)
        output_file = os.path.join(self.output_directory, self.output_file)
        if self.tree is None:
            logging.error("Generated Nessus was empty")
            return
        self.tree.write(output_file, encoding="utf-8", xml_declaration=True)
        logging.info(f"Saving merged scan to {output_file}")
        return output_file
