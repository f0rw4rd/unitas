#!/bin/python
# pylint: disable=fixme, line-too-long, logging-fstring-interpolation, missing-function-docstring, missing-class-docstring
from typing import Dict, Set
import os

import argparse
import logging

from hashlib import sha512
from xml.etree.ElementTree import ParseError
from unitas.convert import (
    GrepConverter,
    JsonExport,
    MarkdownConvert,
    load_markdown_state,
)
from unitas.merger import NessusMerger, NmapMerger
from unitas.exporter import NessusExporter
from unitas.model import HostScanData, merge_states
from unitas.parser import NessusParser, NmapParser, parse_files_concurrently
from unitas.utils import hostup_dict, search_port_or_service, get_version
from unitas.webserver import start_http_server


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


def generate_nmap_scan_command(global_state: Dict[str, HostScanData]) -> str:
    scan_types: Set[str] = set()
    tcp_ports: Set[str] = set()
    udp_ports: Set[str] = set()
    targets: Set[str] = set()
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
    targets_str = " ".join(targets)
    # -Pn: we know that the host is up and skip pre scan
    return f"sudo nmap -n -r --reason -Pn -s{''.join(scan_types)} -sV -v {ports} {targets_str} -oA service_scan_{sha512(targets_str.encode()).hexdigest()[:5]}"


def filter_uncertain_services(
    global_state: Dict[str, HostScanData],
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


BANNER = """              __________               
____  ___________(_)_  /______ ________
_  / / /_  __ \_  /_  __/  __ `/_  ___/
/ /_/ /_  / / /  / / /_ / /_/ /_(__  ) 
\__,_/ /_/ /_//_/  \__/ \__,_/ /____/  
                                       """


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Unitas v{get_version()}: A network scan parser and analyzer",
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
        version=f"%(prog)s {get_version()}",
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
        "-p",
        "--hide-ports",
        action="store_true",
        default=False,
        help="Hide ports from search",
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

    parser.add_argument(
        "-g",
        "--grep",
        action="store_true",
        default=False,
        help="Output the scan results in grepable format (including hosts that are up, but have no port open e.g. via ICMP)",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        default=False,
        help="Export scan results as a JSON file that can be loaded by the HTML viewer",
    )

    parser.add_argument(
        "-T",
        "--report-title",
        help="Specify a custom title for the merged Nessus report",
        default=None,
    )
    parser.add_argument(
        "-H",
        "--http-server",
        action="store_true",
        default=False,
        help="Start an HTTP server to visualize scan results in a web browser",
    )
    parser.add_argument(
        "-P",
        "--port",
        type=int,
        default=8000,
        help="Port to use for HTTP server (default: 8000)",
    )

    args = parser.parse_args()

    if args.update:
        existing_state = load_markdown_state("state.md")
    else:
        existing_state = {}

    setup_logging(args.verbose)

    logging.info(f"Unitas v{get_version()} starting up.")
    logging.info(BANNER)

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

        merger = NessusMerger(
            args.scan_folder,
            os.path.join(args.scan_folder, "merged"),
            args.report_title,
        )
        merger.parse()
        merger.save_report()
        # upload does not work on Nessus pro. because tenable disabled API support.
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

    if hostup_dict:
        # check if the host is up in the final state
        for ip in final_state.keys():
            if ip in hostup_dict:
                del hostup_dict[ip]

        logging.info(
            f"Found {len(hostup_dict)} hosts that are up, but have no open ports"
        )
        up_file: str = "/tmp/up.txt"
        with open(up_file, "w", encoding="utf-8") as f:
            for ip, reason in hostup_dict.items():
                logging.info(f"UP:{ip}:{reason}")
                f.write(f"{ip}\n")
            logging.info(f"Wrote list of host without open ports to {up_file}")

    if not final_state:
        logging.error("Did not find any open ports!")
        return

    if args.rescan:
        logging.info("nmap command to re-scan all non service scanned ports")
        logging.info(generate_nmap_scan_command(final_state))
        return

    if args.grep:
        grep_conv = GrepConverter(final_state)
        logging.info("Scan Results (grep):")
        print()
        print(grep_conv.convert_with_up(hostup_dict))
        return

    if args.http_server:
        logging.info("Starting HTTP server to visualize scan results")

        # Generate JSON data
        json_exporter = JsonExport(final_state, hostup_dict)
        json_content = json_exporter.convert()

        # Start the HTTP server
        start_http_server(json_content, args.port)
        return

    if args.json:
        json_exporter = JsonExport(final_state, hostup_dict)
        json_content = json_exporter.convert()
        output_file = f"unitas.json"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(json_content)
        logging.info(f"Exported JSON data to {os.path.abspath(output_file)}")
        return

    if args.service:
        logging.info("Filtering non-service scanned ports")
        final_state = filter_uncertain_services(final_state)

    if args.search:
        hide_ports = args.hide_ports
        search_terms = [term.strip().lower() for term in args.search.split(",")]
        matching_ips = search_port_or_service(
            final_state, search_terms, args.url, hide_ports
        )
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
        with open("state.md", "w", encoding="utf-8") as f:
            f.write(md_content)

        logging.info("Scan Results (Markdown):")
        print()
        print(md_content)


if __name__ == "__main__":
    main()
