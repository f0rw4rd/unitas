from abc import ABC, abstractmethod
from ipaddress import ip_address
import json
import logging
import re
import time
from typing import Dict

from unitas import HostScanData
from unitas.utils import get_version


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
        global_state: Dict[str, HostScanData],
    ) -> Dict[str, HostScanData]:
        sorted_ips = sorted(global_state.keys(), key=ip_address)
        return {ip: global_state[ip] for ip in sorted_ips}


class GrepConverter(Convert):

    def convert_with_up(self, hostup_dict: dict) -> str:
        output = []
        for ip, reason in hostup_dict.items():
            output.append(f"{ip}|host-up({reason})")
        return "\n".join(output) + "\n" + self.convert()

    def convert(self):
        output = []
        for host in self.global_state.values():
            services = ""
            for port in host.get_sorted_ports():
                services += f"{port.port}/{port.protocol}({port.service}) "
            output.append(f"{host.ip}|{services}")
        return "\n".join(output) + "\n"

    def parse(self, content: str) -> Dict[str, HostScanData]:
        raise ValueError("not implemented")


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


class JsonExport(Convert):
    """
    Export scan results as a structured JSON file that can be loaded
    by the standalone HTML viewer or used for other data analysis.
    """

    def __init__(
        self,
        global_state: Dict[str, HostScanData] = None,
        hostup_dict: Dict[str, str] = None,
    ):
        super().__init__(global_state)
        self.hostup_dict = hostup_dict or {}

    def convert(self) -> str:
        """Convert the scan data to a JSON string."""
        # Prepare hosts data
        hosts_data = []
        for ip, host in self.global_state.items():
            host_entry = {
                "ip": ip,
                "hostname": host.hostname,
                "ports": [],
                "hasOpenPorts": len(host.ports) > 0,
            }
            for port in host.ports:
                host_entry["ports"].append(
                    {
                        "port": port.port,
                        "protocol": port.protocol,
                        "service": port.service,
                        "state": port.state,
                        "comment": port.comment,
                        "uncertain": "?" in port.service,
                        "tls": "TLS" in port.comment,
                    }
                )
            hosts_data.append(host_entry)

        # Prepare hosts-up data
        hostup_data = []
        for ip, reason in self.hostup_dict.items():
            hostup_data.append({"ip": ip, "reason": reason})

        # Build complete data structure
        data = {
            "metadata": {
                "version": get_version(),
                "timestamp": time.time(),
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "stats": {
                    "totalHosts": len(hosts_data),
                    "totalPorts": sum(len(host["ports"]) for host in hosts_data),
                    "hostsUp": len(hostup_data),
                },
            },
            "hosts": hosts_data,
            "hostsUp": hostup_data,
        }

        # Return pretty-printed JSON
        return json.dumps(data, indent=2)

    def parse(self, content: str) -> Dict[str, HostScanData]:
        """
        Parse a JSON string back into a Unitas state structure.
        This allows importing previously exported JSON data.
        """
        try:
            data = json.loads(content)
            result = {}

            # Parse hosts
            for host_entry in data.get("hosts", []):
                ip = host_entry.get("ip")
                if not ip or not HostScanData.is_valid_ip(ip):
                    logging.warning(f"Invalid IP in JSON data: {ip}")
                    continue

                host = HostScanData(ip)
                host.set_hostname(host_entry.get("hostname", ""))

                for port_entry in host_entry.get("ports", []):
                    try:
                        host.add_port(
                            port_entry.get("port", ""),
                            port_entry.get("protocol", "tcp"),
                            port_entry.get("state", "TBD"),
                            port_entry.get("service", "unknown?"),
                            port_entry.get("comment", ""),
                        )
                    except ValueError as e:
                        logging.warning(f"Error adding port: {e}")

                result[ip] = host

            return result

        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON data: {e}")
            return {}
        except Exception as e:
            logging.error(f"Error importing JSON data: {e}")
            return {}


def load_markdown_state(filename: str) -> Dict[str, HostScanData]:
    try:
        with open(filename, "r", encoding="utf-8") as f:
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
