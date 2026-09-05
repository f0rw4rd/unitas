# pylint: skip-file
import unittest
from unittest.mock import patch, MagicMock
import os
import shutil
import socket
import sys
import time
import tempfile
import json
import re
import requests
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
from concurrent.futures import ThreadPoolExecutor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from unitas import (
    PortDetails,
    HostScanData,
    merge_states,
    NmapHost,
    NmapParser,
    NessusParser,
    search_port_or_service,
    MarkdownConvert,
    JsonConverter,
    ThreadSafeServiceLookup,
)
from unitas.exporter import NessusExporter
from unitas.merger import NessusMerger, NmapMerger
from unitas.model import PortDetails
from unitas.utils import (
    WEB_PORT_HINTS,
    TLS_PORT_HINTS,
    find_nmap_ip_address,
    generate_service_urls,
)
from unitas.report import (
    build_single_file_report,
    find_resources_dir,
    _embed_json,
    _guard_script_source,
)
from unitas.utils import hostup_dict


class TestThreadSafeServiceLookup(unittest.TestCase):
    def setUp(self):
        self.service_lookup = ThreadSafeServiceLookup()
        # These tests drive the resolver fallback, so start with an empty view
        # of /etc/services (which the lookup normally reads once and caches).
        self.service_lookup._known = {}

    def test_known_services_are_read_once(self):
        """The services file replaces one getservbyport call per port"""
        lookup = ThreadSafeServiceLookup()
        with patch.object(
            ThreadSafeServiceLookup,
            "_load_known_services",
            return_value={"80tcp": "http", "443tcp": "https"},
        ) as mock_load:
            with patch("socket.getservbyport") as mock_getservbyport:
                self.assertEqual(lookup.get_service_name_for_port("80"), "http")
                self.assertEqual(lookup.get_service_name_for_port("443"), "https")
                mock_getservbyport.assert_not_called()
        self.assertEqual(mock_load.call_count, 1)

    def test_unknown_port_falls_back_to_the_resolver(self):
        lookup = ThreadSafeServiceLookup()
        with patch.object(
            ThreadSafeServiceLookup, "_load_known_services", return_value={}
        ):
            with patch("socket.getservbyport", return_value="weird") as mock_lookup:
                self.assertEqual(lookup.get_service_name_for_port("12345"), "weird")
                mock_lookup.assert_called_once_with(12345, "tcp")

    def test_services_file_parsing(self):
        lookup = ThreadSafeServiceLookup()
        with tempfile.NamedTemporaryFile("w", suffix=".services", delete=False) as f:
            f.write(
                "# comment\n"
                "http\t80/tcp\twww\n"
                "domain\t53/udp\n"
                "broken line\n"
                "http\t80/tcp\t# duplicate, first one wins\n"
            )
            path = f.name
        try:
            with patch.object(ThreadSafeServiceLookup, "SERVICES_FILE", path):
                known = lookup._load_known_services()
        finally:
            os.unlink(path)

        self.assertEqual(known.get("80tcp"), "http")
        self.assertEqual(known.get("53udp"), "domain")
        self.assertNotIn("brokentcp", known)

    def test_missing_services_file_is_not_fatal(self):
        lookup = ThreadSafeServiceLookup()
        with patch.object(
            ThreadSafeServiceLookup, "SERVICES_FILE", "/nonexistent/services"
        ):
            self.assertEqual(lookup._load_known_services(), {})

    def test_valid_port_lookup(self):
        """Test lookup with a valid port number"""
        with patch("socket.getservbyport") as mock_getservbyport:
            mock_getservbyport.return_value = "http"
            result = self.service_lookup.get_service_name_for_port("80")
            self.assertEqual(result, "http")
            mock_getservbyport.assert_called_once_with(80, "tcp")

    def test_invalid_port_raises_error(self):
        """Test that invalid ports raise ValueError"""
        invalid_ports = ["-1", "65536", "abc", ""]
        for port in invalid_ports:
            with self.assertRaises(ValueError):
                self.service_lookup.get_service_name_for_port(port)

    def test_cache_hit(self):
        """Test that cached values are returned without socket lookup"""
        with patch("socket.getservbyport") as mock_getservbyport:
            mock_getservbyport.return_value = "http"

            # First call should hit socket
            first_result = self.service_lookup.get_service_name_for_port("80")

            # Second call should use cache
            second_result = self.service_lookup.get_service_name_for_port("80")

            self.assertEqual(first_result, second_result)
            mock_getservbyport.assert_called_once()  # Should only be called once

    def test_different_protocols(self):
        """Test that different protocols create different cache entries"""
        with patch("socket.getservbyport") as mock_getservbyport:
            mock_getservbyport.return_value = "service"

            tcp_result = self.service_lookup.get_service_name_for_port("80", "tcp")
            udp_result = self.service_lookup.get_service_name_for_port("80", "udp")

            self.assertEqual(mock_getservbyport.call_count, 2)
            self.assertEqual(len(self.service_lookup._cache), 2)

    def test_socket_error_handling(self):
        """Test handling of socket.error"""
        with patch("socket.getservbyport") as mock_getservbyport:
            mock_getservbyport.side_effect = socket.error()

            result = self.service_lookup.get_service_name_for_port(
                "12345", default_service="custom-default"
            )
            self.assertEqual(result, "custom-default")

    def test_thread_safety(self):
        """Test thread safety by concurrent access"""

        def concurrent_lookup(port):
            return self.service_lookup.get_service_name_for_port(str(port))

        with patch("socket.getservbyport") as mock_getservbyport:
            mock_getservbyport.return_value = "service"

            # Test with multiple concurrent lookups
            with ThreadPoolExecutor(max_workers=10) as executor:
                ports = [80] * 20  # Multiple concurrent lookups of the same port
                results = list(executor.map(concurrent_lookup, ports))

            # All results should be identical
            self.assertEqual(len(set(results)), 1)
            # Socket lookup should happen only once due to caching
            self.assertEqual(mock_getservbyport.call_count, 1)

    def test_custom_default_service(self):
        """Test custom default service value"""
        with patch("socket.getservbyport") as mock_getservbyport:
            mock_getservbyport.side_effect = socket.error()

            result = self.service_lookup.get_service_name_for_port(
                "8080", default_service="custom-service"
            )
            self.assertEqual(result, "custom-service")
            mock_getservbyport.assert_called_once()


class TestNmapParser(unittest.TestCase):
    def setUp(self):
        self.test_files_dir = os.path.join(os.path.dirname(__file__), "nmap_files")

    def _get_path(self, file):
        return os.path.join(self.test_files_dir, file)

    def _get_element(self, xml):
        return ET.fromstring(xml)

    def test_parse_file(self):
        self.assertIsNotNone(NmapParser(self._get_path("nmap-sample-1.xml")).parse())
        self.assertIsNotNone(NmapParser(self._get_path("nmap-sample-2.xml")).parse())

    def test_parse_results(self):
        self.assertEqual(
            len(NmapParser(self._get_path("nmap-sample-1.xml")).parse()), 1
        )
        self.assertEqual(
            len(NmapParser(self._get_path("nmap-sample-2.xml")).parse()), 1
        )
        self.assertEqual(
            len(NmapParser(self._get_path("nmap-sample-3.xml")).parse()), 0
        )
        self.assertEqual(
            len(NmapParser(self._get_path("nmap-sample-4.xml")).parse()), 0
        )

    def test_port_and_service_parser(self):
        parser = NmapParser(self._get_path("nmap-sample-1.xml"))
        # test a generic syn scan
        thing = parser._parse_port_item(
            self._get_element(
                b'<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64" /><service name="http" method="table" conf="3" /></port>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "80",
                "protocol": "tcp",
                "state": "TBD",
                "service": "http?",
                "sources": [{"date": "", "file": "nmap-sample-1.xml", "type": "nmap"}],
                "comment": "",
            },
        )
        # test a generic syn scan
        thing = parser._parse_port_item(
            self._get_element(
                b'<port protocol="tcp" portid="8291"><state state="open" reason="syn-ack" reason_ttl="64" /></port>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "8291",
                "protocol": "tcp",
                "state": "TBD",
                "service": "unknown?",
                "sources": [{"date": "", "file": "nmap-sample-1.xml", "type": "nmap"}],
                "comment": "",
            },
        )
        # test a service scan
        thing = parser._parse_port_item(
            self._get_element(
                b'<port protocol="tcp" portid="143"><state state="open" reason="syn-ack" reason_ttl="125" /><service name="imap" product="hMailServer imapd" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service><script id="imap-capabilities" output="IDLE NAMESPACE IMAP4 CAPABILITY SORT completed ACL CHILDREN QUOTA IMAP4rev1 OK RIGHTS=texkA0001" /><script id="banner" output="* OK IMAPrev1" /></port>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "143",
                "protocol": "tcp",
                "state": "TBD",
                "service": "imap",
                "sources": [{"date": "", "file": "nmap-sample-1.xml", "type": "nmap"}],
                "comment": "hMailServer imapd",
            },
        )
        # test service scan with https
        thing = parser._parse_port_item(
            self._get_element(
                b'<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64" /><service name="http" product="lighttpd" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:lighttpd:lighttpd</cpe></service></port>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "443",
                "protocol": "tcp",
                "state": "TBD",
                "service": "https",
                "sources": [{"date": "", "file": "nmap-sample-1.xml", "type": "nmap"}],
                "comment": "lighttpd;TLS",
            },
        )
        # test service with TLS
        thing = parser._parse_port_item(
            self._get_element(
                b'<port protocol="tcp" portid="8729"><state state="open" reason="syn-ack" reason_ttl="64" /><service name="routeros-api" product="MikroTik RouterOS API" ostype="RouterOS" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/o:mikrotik:routeros</cpe></service></port>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "8729",
                "protocol": "tcp",
                "state": "TBD",
                "service": "routeros-api",
                "sources": [{"date": "", "file": "nmap-sample-1.xml", "type": "nmap"}],
                "comment": "MikroTik RouterOS API;TLS",
            },
        )
        # test if tcpwrapped is displayed as unknown
        thing = parser._parse_port_item(
            self._get_element(
                b'<port protocol="tcp" portid="40022"><state state="open" reason="syn-ack" reason_ttl="64" /><service name="tcpwrapped" method="probed" conf="8" /></port>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "40022",
                "protocol": "tcp",
                "state": "TBD",
                "service": "unknown?",
                "sources": [{"date": "", "file": "nmap-sample-1.xml", "type": "nmap"}],
                "comment": "",
            },
        )
        # test TLS detection on script output
        thing = parser._parse_port_item(
            self._get_element(
                b'<port protocol="tcp" portid="21"><state state="open" reason="syn-ack" reason_ttl="55"/><service name="ftp" product="ProFTPD or KnFTPD" ostype="Unix" method="probed" conf="10"/><script id="ssl-cert" output="x"><table key="subject"><elem key="commonName">webserver.x.x</elem><elem key="countryName">x</elem><elem key="localityName">x</elem><elem key="organizationName">ispgateway</elem><elem key="stateOrProvinceName">x</elem></table><table key="issuer"><elem key="commonName">x.x.de</elem><elem key="countryName">x</elem><elem key="localityName">x</elem><elem key="organizationName">x</elem><elem key="stateOrProvinceName">Bayern</elem></table><table key="pubkey"><elem key="type">rsa</elem><elem key="bits">2048</elem><elem key="modulus">x</elem><elem key="exponent">65537</elem></table><table key="extensions"><table><elem key="name">X509v3 Subject Key Identifier</elem><elem key="value">x</elem></table><table><elem key="name">X509v3 Authority Key Identifier</elem><elem key="value">xC</elem></table><table><elem key="name">X509v3 Basic Constraints</elem><elem key="value">CA:TRUE</elem></table></table><elem key="sig_algo">sha256WithRSAEncryption</elem><table key="validity"><elem key="notBefore">x</elem><elem key="notAfter">x</elem></table><elem key="md5">x</elem><elem key="sha1">x</elem><elem key="pem">x</elem></script></port>'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "21",
                "protocol": "tcp",
                "state": "TBD",
                "service": "ftp",
                "sources": [{"date": "", "file": "nmap-sample-1.xml", "type": "nmap"}],
                "comment": "ProFTPD or KnFTPD;TLS",
            },
        )

        # test a xml with missing attributes
        thing = parser._parse_port_item(self._get_element(b"<test>test</test>\n"))
        self.assertIsNone(thing)

    def test_parse_with_errors(self):
        with self.assertRaises(ParseError):
            NmapParser(self._get_path("nmap-error-1.xml"))
        with self.assertRaises(FileNotFoundError):
            NmapParser(self._get_path("nmap-error-does_not_exist.xml"))


class TestNessusParser(unittest.TestCase):
    def setUp(self):
        self.test_files_dir = os.path.join(os.path.dirname(__file__), "nessus_files")

    def _get_path(self, file):
        return os.path.join(self.test_files_dir, file)

    def _get_element(self, xml):
        return ET.fromstring(xml)

    def test_parse_file(self):
        self.assertIsNotNone(
            NessusParser(self._get_path("nessus-sample-1.nessus")).parse()
        )
        self.assertIsNotNone(
            NessusParser(self._get_path("nessus-sample-2.nessus")).parse()
        )

    def test_parse_results(self):
        # test the amount of hosts found
        self.assertEqual(
            len(NessusParser(self._get_path("nessus-sample-1.nessus")).parse()), 1
        )
        self.assertEqual(
            len(NessusParser(self._get_path("nessus-sample-2.nessus")).parse()), 7
        )

    def test_parse_with_errors(self):
        with self.assertRaises(ParseError):
            NmapParser(self._get_path("nessus-error-1.nessus"))
        with self.assertRaises(FileNotFoundError):
            NmapParser(self._get_path("nessus-error-does_not_exist.nessus"))

    def test_service_parser(self):
        parser = NessusParser(
            self._get_path("nessus-sample-1.nessus")
        )  # dumy file not parsed
        # test if a tls port with www is translated to https
        thing = parser._parse_service_item(
            self._get_element(
                b'<ReportItem port="443" svc_name="www" protocol="tcp" severity="0" pluginID="121010" pluginName="TLS Version 1.1 Protocol Detection" pluginFamily="Service detection">\n<asset_inventory>True</asset_inventory>\n<cwe>327</cwe>\n<description>The remote service accepts connections encrypted using TLS 1.1.\nTLS 1.1 lacks support for current and recommended cipher suites.\nCiphers that support encryption before MAC computation, and authenticated encryption modes such as GCM cannot be used with TLS 1.1\n\nAs of March 31, 2020, Endpoints that are not enabled for TLS 1.2 and higher will no longer function properly with major web browsers and major vendors.</description>\n<fname>tls11_detection.nasl</fname>\n<plugin_modification_date>2023/04/19</plugin_modification_date>\n<plugin_name>TLS Version 1.1 Protocol Detection</plugin_name>\n<plugin_publication_date>2019/01/08</plugin_publication_date>\n<plugin_type>remote</plugin_type>\n<risk_factor>None</risk_factor>\n<script_version>1.10</script_version>\n<see_also>https://tools.ietf.org/html/draft-ietf-tls-oldversions-deprecate-00\nhttp://www.nessus.org/u?c8ae820d</see_also>\n<solution>Enable support for TLS 1.2 and/or 1.3, and disable support for TLS 1.1.</solution>\n<synopsis>The remote service encrypts traffic using an older version of TLS.</synopsis>\n<xref>CWE:327</xref>\n<plugin_output>TLSv1.1 is enabled and the server supports at least one cipher.</plugin_output>\n</ReportItem>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "443",
                "protocol": "tcp",
                "state": "TBD",
                "service": "https",
                "sources": [
                    {"date": "", "file": "nessus-sample-1.nessus", "type": "nessus"}
                ],
                "comment": "TLS",
            },
        )

        # test snmp plugin
        thing = parser._parse_service_item(
            self._get_element(
                b'<ReportItem port="161" svc_name="snmp?" protocol="udp" severity="0" pluginID="185519" pluginName="SNMP Server Detection" pluginFamily="SNMP"><description>The remote service is an SNMP agent which provides management data about the device.</description></ReportItem>'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "161",
                "protocol": "udp",
                "state": "TBD",
                "service": "snmp?",
                "sources": [
                    {"date": "", "file": "nessus-sample-1.nessus", "type": "nessus"}
                ],
                "comment": "",
            },
        )

        # test a xml with missing attributes
        thing = parser._parse_service_item(self._get_element(b"<test>test</test>\n"))
        self.assertIsNone(thing)

    def test_port_parser(self):
        parser = NessusParser(
            self._get_path("nessus-sample-1.nessus")
        )  # dumy file not parsed
        # test basic parsing of a port scan
        thing = parser._parse_port_item(
            self._get_element(
                b'<ReportItem port="18181" svc_name="opsec-cvp?" protocol="tcp" severity="0" pluginID="11219" pluginName="Nessus SYN scanner" pluginFamily="Port scanners">\n<description>This plugin is a SYN \'half-open\' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded.</description>\n<fname>nessus_syn_scanner.nbin</fname>\n<plugin_modification_date>2024/05/20</plugin_modification_date>\n<plugin_name>Nessus SYN scanner</plugin_name>\n<plugin_publication_date>2009/02/04</plugin_publication_date>\n<plugin_type>remote</plugin_type>\n<risk_factor>None</risk_factor>\n<script_version>1.60</script_version>\n<solution>Protect your target with an IP filter.</solution>\n<synopsis>It is possible to determine which TCP ports are open.</synopsis>\n<plugin_output>Port 18181/tcp was found to be open</plugin_output>\n</ReportItem>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "18181",
                "protocol": "tcp",
                "state": "TBD",
                "service": "opsec-cvp?",
                "sources": [
                    {"date": "", "file": "nessus-sample-1.nessus", "type": "nessus"}
                ],
                "comment": "",
            },
        )
        # test for a normal syn scan
        thing = parser._parse_port_item(
            self._get_element(
                b'<ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="0" pluginID="11219" pluginName="Nessus SYN scanner" pluginFamily="Port scanners">\n<description>This plugin is a SYN \'half-open\' port scanner.\nIt shall be reasonably quick even against a firewalled target.\n\nNote that SYN scanners are less intrusive than TCP (full connect) scanners against broken services, but they might kill lame misconfigured firewalls. They might also leave unclosed connections on the remote target, if the network is loaded.</description>\n<fname>nessus_syn_scanner.nbin</fname>\n<plugin_modification_date>2011/04/05</plugin_modification_date>\n<plugin_name>Nessus SYN scanner</plugin_name>\n<plugin_type>remote</plugin_type>\n<risk_factor>None</risk_factor>\n<script_version>$Revision: 1.14 $</script_version>\n<solution>Protect your target with an IP filter.</solution>\n<synopsis>It is possible to determine which TCP ports are open.</synopsis>\n<plugin_output>Port 3389/tcp was found to be open</plugin_output>\n</ReportItem>\n'
            )
        )
        self.assertDictEqual(
            thing.__dict__,
            {
                "port": "3389",
                "protocol": "tcp",
                "state": "TBD",
                "service": "rdp?",
                "sources": [
                    {"date": "", "file": "nessus-sample-1.nessus", "type": "nessus"}
                ],
                "comment": "",
            },
        )
        # test a host scan
        thing = parser._parse_port_item(
            self._get_element(
                b'<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="10180" pluginName="Ping the remote host" pluginFamily="Port scanners">\n<description>Nessus was able to determine if the remote host is alive using one or more of the following ping types :\n\n  - An ARP ping, provided the host is on the local subnet     and Nessus is running over Ethernet.\n\n  - An ICMP ping.\n\n  - A TCP ping, in which the plugin sends to the remote host     a packet with the flag SYN, and the host will reply with     a RST or a SYN/ACK.\n\n  - A UDP ping (e.g., DNS, RPC, and NTP).</description>\n<fname>ping_host.nasl</fname>\n<plugin_modification_date>2024/03/25</plugin_modification_date>\n<plugin_name>Ping the remote host</plugin_name>\n<plugin_publication_date>1999/06/24</plugin_publication_date>\n<plugin_type>remote</plugin_type>\n<risk_factor>None</risk_factor>\n<script_version>2.38</script_version>\n<solution>n/a</solution>\n<synopsis>It was possible to identify the status of the remote host (alive or dead).</synopsis>\n<plugin_output>The remote host is up\nThe host replied to an ARP who-is query.\nHardware address : 78:5d:c8:98:28:c2</plugin_output>\n</ReportItem>\n'
            )
        )
        self.assertIsNone(thing)

        # test a xml with missing attributes
        thing = parser._parse_port_item(self._get_element(b"<test>test</test>\n"))
        self.assertIsNone(thing)


class TestNmapHost(unittest.TestCase):

    def setUp(self):
        self.host_element = ET.Element("host")
        self.nmap_host = NmapHost("192.168.1.1", self.host_element)

    def create_port_element(
        self, protocol, portid, state, service_name=None, product=None
    ):
        port = ET.Element("port", attrib={"protocol": protocol, "portid": portid})
        ET.SubElement(port, "state", attrib={"state": state})
        if service_name:
            service = ET.SubElement(port, "service", attrib={"name": service_name})
            if product:
                service.set("product", product)
        return port

    def create_script_element(self, script_id, output):
        script = ET.Element("script", attrib={"id": script_id, "output": output})
        return script

    def test_add_port_new(self):
        port = self.create_port_element("tcp", "80", "open", "http", "Apache")
        self.nmap_host.add_port(port)
        self.assertEqual(len(self.nmap_host.ports), 1)
        self.assertIn("tcp_80_open", self.nmap_host.ports)

    def test_add_port_existing_merge(self):
        port1 = self.create_port_element("tcp", "80", "open", "http", "Apache")
        port2 = self.create_port_element("tcp", "80", "open", "http", "Nginx")
        self.nmap_host.add_port(port1)
        self.nmap_host.add_port(port2)
        self.assertEqual(len(self.nmap_host.ports), 1)
        merged_port = self.nmap_host.ports["tcp_80_open"]
        self.assertEqual(merged_port.find("service").get("product"), "Apache")

    def test_add_port_different_state(self):
        port1 = self.create_port_element("tcp", "80", "open")
        port2 = self.create_port_element("tcp", "80", "closed")
        self.nmap_host.add_port(port1)
        self.nmap_host.add_port(port2)
        self.assertEqual(len(self.nmap_host.ports), 2)
        self.assertIn("tcp_80_open", self.nmap_host.ports)
        self.assertIn("tcp_80_closed", self.nmap_host.ports)

    def test_add_port_with_script(self):
        port = self.create_port_element("tcp", "443", "open", "https")
        script = self.create_script_element("ssl-cert", "Output of SSL cert script")
        port.append(script)
        self.nmap_host.add_port(port)
        self.assertIn("tcp_443_open", self.nmap_host.ports)
        self.assertEqual(len(self.nmap_host.ports["tcp_443_open"].findall("script")), 1)

    def test_add_port_merge_scripts(self):
        port1 = self.create_port_element("tcp", "443", "open", "https")
        script1 = self.create_script_element("ssl-cert", "Output 1")
        port1.append(script1)

        port2 = self.create_port_element("tcp", "443", "open", "https")
        script2 = self.create_script_element("ssl-cert", "Output 2")
        script3 = self.create_script_element("http-title", "Title")
        port2.append(script2)
        port2.append(script3)

        self.nmap_host.add_port(port1)
        self.nmap_host.add_port(port2)

        merged_port = self.nmap_host.ports["tcp_443_open"]
        self.assertEqual(len(merged_port.findall("script")), 2)
        self.assertEqual(
            merged_port.find(".//script[@id='ssl-cert']").get("output"), "Output 1"
        )

    def test_add_hostscript_new(self):
        script = self.create_script_element("ssh-hostkey", "SSH host key")
        self.nmap_host.add_hostscript(script)
        self.assertEqual(len(self.nmap_host.hostscripts), 1)
        self.assertIn("ssh-hostkey", self.nmap_host.hostscripts)

    def test_add_hostscript_existing_merge(self):
        script1 = self.create_script_element("ssh-hostkey", "SSH host key 1")
        script2 = self.create_script_element("ssh-hostkey", "SSH host key 2")
        self.nmap_host.add_hostscript(script1)
        self.nmap_host.add_hostscript(script2)
        self.assertEqual(len(self.nmap_host.hostscripts), 1)
        self.assertEqual(
            self.nmap_host.hostscripts["ssh-hostkey"].get("output"), "SSH host key 2"
        )

    def test_add_hostscript_with_table(self):
        script = ET.Element(
            "script", attrib={"id": "test-script", "output": "Test output"}
        )
        table = ET.SubElement(script, "table", attrib={"key": "test-table"})
        ET.SubElement(table, "elem", attrib={"key": "elem1"}).text = "Value1"
        self.nmap_host.add_hostscript(script)
        self.assertIn("test-script", self.nmap_host.hostscripts)
        self.assertEqual(
            len(self.nmap_host.hostscripts["test-script"].findall(".//elem")), 1
        )

    def test_add_hostscript_merge_tables(self):
        script1 = ET.Element(
            "script", attrib={"id": "test-script", "output": "Test output 1"}
        )
        table1 = ET.SubElement(script1, "table", attrib={"key": "test-table"})
        ET.SubElement(table1, "elem", attrib={"key": "elem1"}).text = "Value1"

        script2 = ET.Element(
            "script", attrib={"id": "test-script", "output": "Test output 2"}
        )
        table2 = ET.SubElement(script2, "table", attrib={"key": "test-table"})
        ET.SubElement(table2, "elem", attrib={"key": "elem1"}).text = "Value1-updated"
        ET.SubElement(table2, "elem", attrib={"key": "elem2"}).text = "Value2"

        self.nmap_host.add_hostscript(script1)
        self.nmap_host.add_hostscript(script2)

        merged_script = self.nmap_host.hostscripts["test-script"]
        self.assertEqual(merged_script.get("output"), "Test output 2")
        self.assertEqual(len(merged_script.findall(".//elem")), 2)
        self.assertEqual(
            merged_script.find(".//elem[@key='elem1']").text, "Value1-updated"
        )
        self.assertEqual(merged_script.find(".//elem[@key='elem2']").text, "Value2")


class TestPortDetails(unittest.TestCase):
    def test_source_information(self):
        port = PortDetails(
            "80", "tcp", "open", "http", "Web server", "nmap", "scan.xml", "2023-03-15"
        )
        self.assertEqual(port.source_type, "nmap")
        self.assertEqual(port.source_file, "scan.xml")
        self.assertEqual(port.detected_date, "2023-03-15")

        # Test adding source information
        port2 = PortDetails("443", "tcp", "open", "https")
        port2.add_source("nmap", "scan.xml", "2023-03-15")
        self.assertEqual(port2.source_type, "nmap")
        self.assertEqual(port2.source_file, "scan.xml")

    def test_port_details_creation(self):
        port = PortDetails("80", "tcp", "open", "http")
        self.assertEqual(port.port, "80")
        self.assertEqual(port.protocol, "tcp")
        self.assertEqual(port.state, "open")
        self.assertEqual(port.service, "http")

    def test_port_details_str(self):
        port = PortDetails("443", "tcp", "open", "https")
        self.assertEqual(str(port), "443/tcp(https)")

    def test_port_details_to_dict(self):
        port = PortDetails("22", "tcp", "open", "ssh")
        expected = {
            "port": "22",
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "sources": [],
            "comment": "",
        }
        self.assertEqual(port.to_dict(), expected)

    def test_port_details_from_dict(self):
        data = {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql"}
        port = PortDetails.from_dict(data)
        self.assertEqual(port.port, "3306")
        self.assertEqual(port.protocol, "tcp")
        self.assertEqual(port.state, "open")
        self.assertEqual(port.service, "mysql")

    def test_is_valid_port(self):
        self.assertTrue(PortDetails.is_valid_port("1"))
        self.assertTrue(PortDetails.is_valid_port("80"))
        self.assertTrue(PortDetails.is_valid_port("65535"))
        self.assertFalse(PortDetails.is_valid_port("0"))
        self.assertFalse(PortDetails.is_valid_port("65536"))
        self.assertFalse(PortDetails.is_valid_port("-1"))
        self.assertFalse(PortDetails.is_valid_port("abc"))
        self.assertFalse(PortDetails.is_valid_port(""))

    def test_update_service_unknown_to_known(self):
        port1 = PortDetails("80", "tcp", "open", "unknown?")
        port2 = PortDetails("80", "tcp", "open", "http")
        port1.update(port2)
        self.assertEqual(port1.service, "http")

    def test_update_service_unknown_to_known_with_unknown_as_service(self):
        port1 = PortDetails("80", "tcp", "open", "unknown")
        port2 = PortDetails("80", "tcp", "open", "http")
        port1.update(port2)
        self.assertEqual(port1.service, "http")

        port1 = PortDetails("80", "tcp", "open", "unknown")
        port2 = PortDetails("80", "tcp", "open", "http?")
        port1.update(port2)
        self.assertEqual(port1.service, "unknown")

    def test_update_service_uncertain_to_certain(self):
        port1 = PortDetails("443", "tcp", "open", "https?")
        port2 = PortDetails("443", "tcp", "open", "https")
        port1.update(port2)
        self.assertEqual(port1.service, "https")

    def test_update_service_no_change(self):
        port1 = PortDetails("22", "tcp", "open", "ssh")
        port2 = PortDetails("22", "tcp", "open", "ssh?")
        port1.update(port2)
        self.assertEqual(port1.service, "ssh")

    def test_update_comment(self):
        port1 = PortDetails("80", "tcp", "open", "http")
        port2 = PortDetails("80", "tcp", "open", "http", "Web server")
        port1.update(port2)
        self.assertEqual(port1.comment, "Web server")

    def test_update_comment_no_change(self):
        port1 = PortDetails("80", "tcp", "open", "http", "Existing comment")
        port2 = PortDetails("80", "tcp", "open", "http", "New comment")
        port1.update(port2)
        self.assertEqual(port1.comment, "Existing comment")

    def test_update_state(self):
        port1 = PortDetails("80", "tcp", "", "http")
        port2 = PortDetails("80", "tcp", "open", "http")
        port1.update(port2)
        self.assertEqual(port1.state, "open")

    def test_update_state_no_change(self):
        port1 = PortDetails("80", "tcp", "closed", "http")
        port2 = PortDetails("80", "tcp", "open", "http")
        port1.update(port2)
        self.assertEqual(port1.state, "closed")

    def test_invalid_port_creation(self):
        # Test that creating PortDetails with invalid ports raises ValueError
        with self.assertRaises(ValueError):
            PortDetails("0", "tcp", "open", "invalid")

        with self.assertRaises(ValueError):
            PortDetails("65536", "tcp", "open", "invalid")

        with self.assertRaises(ValueError):
            PortDetails("-1", "tcp", "open", "invalid")

        with self.assertRaises(ValueError):
            PortDetails("abc", "tcp", "open", "invalid")

    def test_valid_port_creation(self):
        # Test that creating PortDetails with valid ports doesn't raise an exception
        try:
            PortDetails("1", "tcp", "open", "service1")
            PortDetails("80", "tcp", "open", "http")
            PortDetails("65535", "udp", "open", "service2")
            PortDetails("65535", "udp", "open", "service2")

        except ValueError:
            self.fail("PortDetails raised ValueError unexpectedly!")


class TestPortDetailsServiceName(unittest.TestCase):
    def test_special_case_port_445(self):
        """Test the special case handling for port 445 with netbiosn service"""
        result = PortDetails.get_service_name("netbiosn", "445")
        self.assertEqual(result, "smb")

    def test_service_mapping(self):
        """Test that services are correctly mapped according to SERVICE_MAPPING"""
        test_cases = [
            ("www", "80", "http"),
            ("microsoft-ds", "445", "smb"),
            ("cifs", "445", "smb"),
            ("ms-wbt-server", "3389", "rdp"),
            ("ms-msql-s", "1433", "mssql"),
        ]

        for service, port, expected in test_cases:
            with self.subTest(service=service, port=port):
                result = PortDetails.get_service_name(service, port)
                self.assertEqual(result, expected)

    def test_unmapped_service_returns_unchanged(self):
        """Test that services not in mapping are returned unchanged"""
        test_cases = [
            ("ssh", "22"),
            ("ftp", "21"),
            ("https", "443"),
            ("custom-service", "9999"),
        ]

        for service, port in test_cases:
            with self.subTest(service=service, port=port):
                result = PortDetails.get_service_name(service, port)
                self.assertEqual(result, service)
                # Verify service is indeed not in the static mapping
                self.assertNotIn(service, PortDetails.SERVICE_MAPPING)

    def test_port_445_with_other_services(self):
        """Test that port 445 only affects 'netbiosn' service"""
        test_cases = [("smb", "445"), ("microsoft-ds", "445"), ("other-service", "445")]

        for service, port in test_cases:
            with self.subTest(service=service, port=port):
                result = PortDetails.get_service_name(service, port)
                self.assertEqual(
                    result, PortDetails.SERVICE_MAPPING.get(service, service)
                )

    def test_empty_strings(self):
        """Test behavior with empty strings"""
        result = PortDetails.get_service_name("", "")
        self.assertEqual(result, "")


class TestSearchFunction(unittest.TestCase):
    def setUp(self):
        self.global_state = {
            "192.168.1.1": HostScanData("192.168.1.1"),
            "192.168.1.2": HostScanData("192.168.1.2"),
            "192.168.1.3": HostScanData("192.168.1.3"),
        }
        self.global_state["192.168.1.1"].add_port("80", "tcp", "open", "http")
        self.global_state["192.168.1.1"].add_port("443", "tcp", "open", "https")
        self.global_state["192.168.1.2"].add_port("22", "tcp", "open", "ssh")
        self.global_state["192.168.1.3"].add_port("80", "tcp", "open", "http")
        self.global_state["192.168.1.3"].add_port("3306", "tcp", "open", "mysql")
        self.global_state["192.168.1.3"].add_port("12345", "tcp", "open", "rdp?")

    def test_search_by_port(self):
        result = search_port_or_service(self.global_state, [" 80"], False, True)
        self.assertEqual(result, ["192.168.1.1", "192.168.1.3"])

        result = search_port_or_service(self.global_state, ["22"], False, False)
        self.assertEqual(result, ["192.168.1.2"])

        result = search_port_or_service(self.global_state, ["3306"], False, True)
        self.assertEqual(result, ["192.168.1.3"])

    def test_search_by_service_url(self):
        result = search_port_or_service(
            self.global_state, ["ssh"], with_url=True, hide_ports=True
        )
        self.assertEqual(result, ["ssh://192.168.1.2"])

    def test_case_insensitive_search_url(self):
        result = search_port_or_service(
            self.global_state, ["HTTP"], with_url=True, hide_ports=False
        )
        self.assertEqual(result, ["http://192.168.1.1", "http://192.168.1.3"])

    def test_service_with_question_mark_url(self):
        self.global_state["192.168.1.2"].add_port("8080", "tcp", "TBD", "http-alt?")
        result = search_port_or_service(
            self.global_state, ["8080"], with_url=True, hide_ports=False
        )
        self.assertEqual(result, ["http-alt://192.168.1.2"])

    def test_search_by_service(self):
        result = search_port_or_service(self.global_state, ["http"], False, True)
        self.assertEqual(result, ["192.168.1.1", "192.168.1.3"])

        result = search_port_or_service(self.global_state, ["ssh"], False, True)
        self.assertEqual(result, ["192.168.1.2"])

        result = search_port_or_service(self.global_state, ["mysql"], False, True)
        self.assertEqual(result, ["192.168.1.3"])

    def test_case_insensitive_service_search(self):
        result = search_port_or_service(self.global_state, ["HTTP"], False, False)
        self.assertEqual(result, ["192.168.1.1", "192.168.1.3"])

    def test_search_non_existent(self):
        result = search_port_or_service(self.global_state, ["8080"], False, False)
        self.assertEqual(result, [])

        result = search_port_or_service(self.global_state, ["ftp"], False, False)
        self.assertEqual(result, [])

    def test_search_for_question_mark(self):
        result = search_port_or_service(self.global_state, ["rdp"], False, False)
        self.assertEqual(result, ["192.168.1.3:12345"])

    def test_search_for_two_ports_on_the_same_host(self):
        result = search_port_or_service(
            self.global_state, ["http", "https"], False, False
        )
        self.assertEqual(
            result, ["192.168.1.1:443", "192.168.1.1:80", "192.168.1.3:80"]
        )


class TestHostScanData(unittest.TestCase):
    def setUp(self):
        self.host = HostScanData("192.168.1.1")

    def test_valid_ipv4_addresses(self):
        valid_ipv4 = [
            "192.168.0.1",
            "10.0.0.0",
            "172.16.0.1",
            "255.255.255.255",
            "0.0.0.0",
        ]
        for ip in valid_ipv4:
            with self.subTest(ip=ip):
                self.assertTrue(HostScanData.is_valid_ip(ip))
                HostScanData(ip)  # Should not raise ValueError

    def test_valid_ipv6_addresses(self):
        valid_ipv6 = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fe80::1ff:fe23:4567:890a",
            "::",
            "::1",
            "2001:db8::",
            "fe80::",
        ]
        for ip in valid_ipv6:
            with self.subTest(ip=ip):
                self.assertTrue(HostScanData.is_valid_ip(ip))
                HostScanData(ip)  # Should not raise ValueError

    def test_invalid_ip_addresses(self):
        invalid_ips = [
            "256.0.0.1",
            "192.168.0.256",
            "192.168.0",
            "192.168.0.1.2",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334:7334",
            ":::",
            "2001::db8::1",
            "192.168.0.1:",
            "example.com",
            "localhost",
            "",
            "  ",
            "192.168.0.1 ",
            " 192.168.0.1",
        ]
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(HostScanData.is_valid_ip(ip))
                with self.assertRaises(ValueError):
                    HostScanData(ip)

    def test_edge_cases(self):
        edge_cases = [
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "::1",
        ]
        for ip in edge_cases:
            with self.subTest(ip=ip):
                self.assertTrue(HostScanData.is_valid_ip(ip))
                HostScanData(ip)

    def test_host_scan_data_creation(self):
        self.assertEqual(self.host.ip, "192.168.1.1")
        self.assertEqual(self.host.hostname, "")
        self.assertEqual(len(self.host.ports), 0)

    def test_add_port(self):
        self.host.add_port("80", "tcp", "open", "http")
        self.assertEqual(len(self.host.ports), 1)
        self.assertEqual(str(self.host.ports[0]), "80/tcp(http)")

    def test_set_hostname(self):
        self.host.set_hostname("example.com")
        self.assertEqual(self.host.hostname, "example.com")

    def test_get_sorted_ports(self):
        self.host.add_port("443", "tcp", "open", "https")
        self.host.add_port("80", "tcp", "open", "http")
        self.host.add_port("22", "tcp", "open", "ssh")
        sorted_ports = self.host.get_sorted_ports()
        self.assertEqual([p.port for p in sorted_ports], ["22", "80", "443"])


class TestMergeFunctions(unittest.TestCase):
    def test_merge_states(self):
        old_state = {
            "192.168.1.1": HostScanData("192.168.1.1"),
            "192.168.1.2": HostScanData("192.168.1.2"),
        }
        old_state["192.168.1.1"].add_port("80", "tcp", "open", "http")
        old_state["192.168.1.2"].add_port("22", "tcp", "open", "ssh")

        new_state = {
            "192.168.1.1": HostScanData("192.168.1.1"),
            "192.168.1.3": HostScanData("192.168.1.3"),
        }
        new_state["192.168.1.1"].add_port("443", "tcp", "open", "https")
        new_state["192.168.1.1"].add_port("80", "tcp", "open", "http-alt")
        new_state["192.168.1.3"].add_port("3306", "tcp", "open", "mysql")

        merged_state = merge_states(old_state, new_state)

        self.assertEqual(len(merged_state), 3)
        self.assertEqual(len(merged_state["192.168.1.1"].ports), 2)
        self.assertEqual(merged_state["192.168.1.1"].ports[0].service, "http-alt")
        self.assertIn("192.168.1.3", merged_state)


class TestMarkdownConvert(unittest.TestCase):
    def setUp(self):
        self.global_state = {
            "192.168.1.1": HostScanData("192.168.1.1"),
            "192.168.1.2": HostScanData("192.168.1.2"),
        }
        self.global_state["192.168.1.1"].set_hostname("host1.local")
        self.global_state["192.168.1.1"].add_port("80", "tcp", "Done", "http")
        self.global_state["192.168.1.1"].add_port("443", "tcp", "TBD", "https?")
        self.global_state["192.168.1.2"].add_port("22", "udp", "Done", "ssh")

        self.converter = MarkdownConvert(self.global_state)

    def test_convert_empty_state(self):
        empty_converter = MarkdownConvert({})
        expected_output = "|IP|Hostname|Port|Status|Comment|\n|--|--|--|--|---|\n"
        self.assertEqual(empty_converter.convert(), expected_output)

    def test_convert_with_data(self):
        expected_output = (
            "|IP|Hostname|Port|Status|Comment|\n"
            "|--|--|--|--|---|\n"
            "|192.168.1.1|host1.local|80/tcp(http)|Done||\n"
            "|192.168.1.1|host1.local|443/tcp(https?)|TBD||\n"
            "|192.168.1.2||22/udp(ssh)|Done||\n"
        )
        self.assertEqual(self.converter.convert(), expected_output)

    def test_parse_empty_content(self):
        content = "|IP|Hostname|Port|Status|Comment|\n|--|--|--|--|---|\n"
        result = self.converter.parse(content)
        self.assertEqual(len(result), 0)
        content = ""
        result = self.converter.parse(content)
        self.assertEqual(len(result), 0)

    def test_parse_with_data(self):
        content = (
            "|IP|Hostname|Port|Status|Comment|\n"
            "|--|--|--|--|---|\n"
            "|192.168.1.1|host1.local|80/tcp(http)|Done|Web server|\n"
            "|192.168.1.1|host1.local|443/tcp(https)|TBD||\n"
            "|192.168.1.2||22/tcp(ssh)|Done||\n"
        )
        result = self.converter.parse(content)

        self.assertEqual(len(result), 2)
        self.assertEqual(result["192.168.1.1"].hostname, "host1.local")
        self.assertEqual(len(result["192.168.1.1"].ports), 2)
        self.assertEqual(result["192.168.1.1"].ports[0].service, "http")
        self.assertEqual(result["192.168.1.1"].ports[0].state, "Done")
        self.assertEqual(result["192.168.1.2"].ports[0].service, "ssh")

    def test_parse_with_missing_fields(self):
        content = (
            "|IP|Hostname|Port|Status|Comment|\n"
            "|--|--|--|--|---|\n"
            "|192.168.1.1||80/tcp(http)|||\n"
        )
        result = self.converter.parse(content)

        self.assertEqual(len(result), 1)
        self.assertEqual(result["192.168.1.1"].hostname, "")
        self.assertEqual(result["192.168.1.1"].ports[0].state, "TBD")  # Default value

    def test_parse_with_invalid_lines(self):
        content = (
            "|IP|Hostname|Port|Status|Comment|\n"
            "|--|--|--|--|---|\n"
            "|192.168.1.1|host1.local|80/tcp(http)|Done|Web server|\n"
            "Invalid line\n"
            "|192.168.1.2||22/tcp(ssh)|Done||\n"
        )
        result = self.converter.parse(content)

        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.2", result)

    def test_parse_with_extra_whitespace(self):
        content = (
            "|IP|Hostname|Port|Status|Comment|\n"
            "|--|--|--|--|---|\n"
            "| 192.168.1.1 | host1.local | 80/tcp(http) | Done \t | Web server |\n"
        )
        result = self.converter.parse(content)

        self.assertEqual(len(result), 1)
        self.assertIn("192.168.1.1", result)
        self.assertEqual(result["192.168.1.1"].hostname, "host1.local")
        self.assertEqual(result["192.168.1.1"].ports[0].service, "http")
        self.assertEqual(result["192.168.1.1"].ports[0].state, "Done")


class TestNessusExporter(unittest.TestCase):
    def _make_exporter(self):
        with patch("unitas.exporter.config") as mock_config:
            mock_config.get_access_key.return_value = "access"
            mock_config.get_secret_key.return_value = "secret"
            mock_config.get_url.return_value = "https://nessus:8834"
            return NessusExporter()

    def test_check_export_status_polls_until_ready(self):
        exporter = self._make_exporter()
        exporter.ses = MagicMock()
        exporter.ses.get.return_value.json.side_effect = [
            {"status": "loading"},
            {"status": "ready"},
        ]

        with patch("unitas.exporter.time.sleep") as mock_sleep:
            exporter._check_export_status(15, 42)

        mock_sleep.assert_called_once_with(5)
        self.assertEqual(exporter.ses.get.call_count, 2)

    def test_a_stuck_export_gives_up_instead_of_polling_forever(self):
        exporter = self._make_exporter()
        exporter.ses = MagicMock()
        exporter.ses.get.return_value.json.return_value = {"status": "loading"}

        # the clock is what ends this, not the number of polls
        clock = iter([0, 10, 10 + exporter.EXPORT_DEADLINE])
        with patch("unitas.exporter.time.sleep"), patch(
            "unitas.exporter.time.monotonic", side_effect=lambda: next(clock)
        ):
            with self.assertRaises(TimeoutError) as raised:
                exporter._check_export_status(15, 42)

        self.assertIn("loading", str(raised.exception))

    def test_every_request_carries_a_timeout(self):
        """A Nessus that accepts the connection and then says nothing used to
        hang the export forever."""
        # the session is wrapped in the constructor, so the patch goes first
        with patch.object(requests.Session, "request") as request:
            exporter = self._make_exporter()
            request.return_value.json.return_value = {"file": 7}
            exporter._initiate_export(15)

        self.assertEqual(
            request.call_args.kwargs["timeout"], NessusExporter.REQUEST_TIMEOUT
        )

    def test_one_broken_scan_does_not_abandon_the_rest(self):
        exporter = self._make_exporter()
        exporter._list_scans = MagicMock(
            return_value=[
                {"id": 1, "name": "first"},
                {"id": 2, "name": "second"},
                {"id": 3, "name": "third"},
            ]
        )
        exporter._initiate_export = MagicMock(
            side_effect=[RuntimeError("403"), 20, TimeoutError("stuck")]
        )
        exporter._check_export_status = MagicMock()
        exporter._download_export = MagicMock()

        with tempfile.TemporaryDirectory() as folder:
            exporter.export(folder)

        # the second scan still downloaded despite the first and third failing
        self.assertEqual(exporter._download_export.call_count, 1)
        self.assertEqual(exporter._initiate_export.call_count, 3)


class TestNessusScanStatus(unittest.TestCase):
    """The "N of M exported" counter the web interface shows."""

    SCANS = {
        "scans": [
            {"id": 1, "name": "external net", "status": "completed"},
            {"id": 2, "name": "running one", "status": "running"},
            {"id": 3, "name": "merged", "status": "completed"},
        ]
    }

    def _make_exporter(self):
        with patch("unitas.exporter.config") as mock_config:
            mock_config.get_access_key.return_value = "access"
            mock_config.get_secret_key.return_value = "secret"
            mock_config.get_url.return_value = "https://nessus:8834"
            exporter = NessusExporter()
        exporter.ses = MagicMock()
        exporter.ses.get.return_value.json.return_value = self.SCANS
        return exporter

    def test_running_scans_and_merged_are_not_counted_as_missing(self):
        exporter = self._make_exporter()

        with tempfile.TemporaryDirectory() as folder:
            status = exporter.list_scans_status(folder)

        self.assertEqual(status["total"], 3)
        self.assertEqual(status["skipped"], 2)
        self.assertEqual(status["missing"], 1)
        self.assertEqual(status["exported"], 0)

    def test_a_file_already_in_the_folder_counts(self):
        exporter = self._make_exporter()

        with tempfile.TemporaryDirectory() as folder:
            # the name export() would write it under
            with open(
                os.path.join(folder, "external_net_1.nessus"), "w", encoding="utf-8"
            ) as f:
                f.write("<NessusClientData_v2/>")
            status = exporter.list_scans_status(folder)

        self.assertEqual(status["exported"], 1)
        self.assertEqual(status["missing"], 0)

    def test_is_configured_does_not_raise_on_missing_keys(self):
        with patch("unitas.exporter.config") as mock_config:
            mock_config.get_access_key.return_value = ""
            mock_config.get_secret_key.return_value = ""
            self.assertFalse(NessusExporter.is_configured())

            mock_config.get_access_key.return_value = "access"
            mock_config.get_secret_key.return_value = "secret"
            self.assertTrue(NessusExporter.is_configured())


class TestNessusPortScannerParsing(unittest.TestCase):
    """The port scanner plugins have their own family and must not be treated
    as service detections, but they still have to be parsed."""

    HOST = b"""<ReportHost name="10.0.0.1">
    <HostProperties><tag name="host-ip">10.0.0.1</tag></HostProperties>
    <ReportItem port="445" svc_name="cifs" protocol="tcp" pluginID="1" pluginName="SMB check" pluginFamily="Windows"/>
    <ReportItem port="8080" svc_name="http" protocol="tcp" pluginID="11219" pluginName="Nessus SYN scanner" pluginFamily="Port scanners"/>
    </ReportHost>"""

    def setUp(self):
        self.parser = NessusParser(
            os.path.join(os.path.dirname(__file__), "nessus_files", "nessus-sample-1.nessus")
        )
        self.parser.data = {}
        self.parser.root = ET.fromstring(
            b"<NessusClientData_v2><Report>" + self.HOST + b"</Report></NessusClientData_v2>"
        )

    def test_port_scanner_ports_are_parsed_and_marked_uncertain(self):
        result = self.parser.parse()
        ports = {p.port: p for p in result["10.0.0.1"].ports}
        self.assertIn("8080", ports, "port scanner plugins were skipped")
        self.assertIn("?", ports["8080"].service)
        # the service detection plugin stays certain
        self.assertEqual(ports["445"].service, "smb")


class TestNmapAddressLookup(unittest.TestCase):
    def test_mac_address_is_not_used_as_ip(self):
        host = ET.fromstring(
            b'<host><address addr="00:11:22:33:44:55" addrtype="mac"/>'
            b'<address addr="192.168.1.5" addrtype="ipv4"/></host>'
        )
        self.assertEqual(find_nmap_ip_address(host), "192.168.1.5")

    def test_ipv6_only_host(self):
        host = ET.fromstring(b'<host><address addr="::1" addrtype="ipv6"/></host>')
        self.assertEqual(find_nmap_ip_address(host), "::1")

    def test_mac_only_host_has_no_ip(self):
        host = ET.fromstring(
            b'<host><address addr="00:11:22:33:44:55" addrtype="mac"/></host>'
        )
        self.assertEqual(find_nmap_ip_address(host), "")


class TestMarkdownSourceRoundTrip(unittest.TestCase):
    def test_sources_survive_a_convert_parse_cycle(self):
        host = HostScanData("10.0.0.7")
        host.add_port(
            "443",
            "tcp",
            "TBD",
            "https",
            "TLS",
            source_type="nmap",
            source_file="scan.xml",
        )
        converter = MarkdownConvert({"10.0.0.7": host}, show_origin=True)
        parsed = MarkdownConvert(show_origin=True).parse(converter.convert())

        sources = parsed["10.0.0.7"].ports[0].sources
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["type"], "nmap")
        self.assertEqual(sources[0]["file"], "scan.xml")


class TestNessusMerger(unittest.TestCase):
    def test_existing_host_without_children_is_not_duplicated(self):
        merger = NessusMerger("/tmp", "/tmp/merged")
        merger.report = ET.fromstring(b'<Report><ReportHost name="10.0.0.1"/></Report>')
        tree = ET.ElementTree(
            ET.fromstring(b'<Report><ReportHost name="10.0.0.1"/></Report>')
        )
        merger._merge_hosts(tree)
        self.assertEqual(len(merger.report.findall("ReportHost")), 1)

    def test_existing_report_item_is_not_duplicated(self):
        merger = NessusMerger("/tmp", "/tmp/merged")
        item = b'<ReportItem port="443" pluginID="42"/>'
        existing_host = ET.fromstring(b'<ReportHost name="h">' + item + b"</ReportHost>")
        new_host = ET.fromstring(b'<ReportHost name="h">' + item + b"</ReportHost>")
        merger._merge_report_items(new_host, existing_host)
        self.assertEqual(len(existing_host.findall("ReportItem")), 1)

    def test_output_directory_check_does_not_match_siblings(self):
        merger = NessusMerger("/tmp/scans", "/tmp/scans/merged")
        self.assertTrue(merger._is_in_output_directory("/tmp/scans/merged/report.nessus"))
        self.assertFalse(merger._is_in_output_directory("/tmp/scans/merged_old.nessus"))


class TestNmapMergerParse(unittest.TestCase):
    SCAN = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up" reason="syn-ack"/>
<address addr="00:11:22:33:44:55" addrtype="mac"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="a.local" type="PTR"/><hostname name="b.local" type="user"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
<hostscript><script id="smb-os" output="windows"/><script id="nbstat" output="names"/></hostscript>
</host>
</nmaprun>
"""

    SECOND_SCAN = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up" reason="syn-ack"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="c.local" type="PTR"/><hostname name="d.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports>
</host>
</nmaprun>
"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        for name, scan in (("a_scan.xml", self.SCAN), ("b_scan.xml", self.SECOND_SCAN)):
            with open(os.path.join(self.tmp_dir, name), "w", encoding="utf-8") as f:
                f.write(scan)
        self.out_dir = os.path.join(self.tmp_dir, "merged")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _merged_host(self):
        NmapMerger(self.tmp_dir, self.out_dir).parse()
        merged = ET.parse(os.path.join(self.out_dir, "merged_nmap.xml"))
        return merged.find(".//host")

    def test_all_hostnames_are_kept(self):
        host = self._merged_host()
        names = sorted(h.get("name") for h in host.findall(".//hostname"))
        self.assertEqual(names, ["a.local", "b.local", "c.local", "d.local"])

    def test_hostscripts_are_kept_per_script_id(self):
        host = self._merged_host()
        scripts = host.findall("hostscript/script")
        self.assertEqual({s.get("id") for s in scripts}, {"smb-os", "nbstat"})

    def test_ports_of_all_scans_are_kept(self):
        host = self._merged_host()
        ports = sorted(p.get("portid") for p in host.findall(".//port"))
        self.assertEqual(ports, ["22", "80"])


class TestNmapHostFindPort(unittest.TestCase):
    def test_find_port_returns_the_element(self):
        nmap_host = NmapHost("192.168.1.1", ET.Element("host"))
        port = ET.Element("port", attrib={"protocol": "tcp", "portid": "80"})
        ET.SubElement(port, "state", attrib={"state": "open"})
        nmap_host.add_port(port)
        self.assertIsNotNone(nmap_host.find_port("tcp", "80"))
        self.assertIsNone(nmap_host.find_port("udp", "80"))


class TestPortValidation(unittest.TestCase):
    def test_non_string_ports_are_invalid(self):
        self.assertFalse(PortDetails.is_valid_port(None))
        self.assertFalse(PortDetails.is_valid_port(["80"]))
        self.assertFalse(PortDetails.is_valid_port("0"))
        self.assertTrue(PortDetails.is_valid_port("80"))


class TestSearchPortOrService(unittest.TestCase):
    def test_udp_default_port_uses_the_udp_lookup(self):
        host = HostScanData("10.0.0.9")
        # 161/udp is snmp, 161/tcp is not, so the port must not be appended
        host.add_port("161", "udp", "TBD", "snmp")
        result = search_port_or_service({"10.0.0.9": host}, ["snmp"], False, False)
        self.assertEqual(result, ["10.0.0.9"])


class TestServiceUrls(unittest.TestCase):
    def setUp(self):
        host = HostScanData("10.0.0.1")
        host.add_port("80", "tcp", "TBD", "http")
        host.add_port("443", "tcp", "TBD", "https")
        host.add_port("22", "tcp", "TBD", "ssh")
        host.add_port("161", "udp", "TBD", "snmp")
        # only port scanned, but a well known web port
        host.add_port("8080", "tcp", "TBD", "unknown?")
        # TLS, but not a web service
        host.add_port("3389", "tcp", "TBD", "msrdp", "TLS")
        # web service tagged as TLS by the scanner
        host.add_port("7002", "tcp", "TBD", "http", "TLS")

        ipv6_host = HostScanData("::1")
        ipv6_host.add_port("8000", "tcp", "TBD", "http")

        self.state = {"10.0.0.1": host, "::1": ipv6_host}

    def test_web_mode_only_returns_http_services(self):
        urls = generate_service_urls(self.state)
        self.assertEqual(
            urls,
            [
                "http://10.0.0.1:80",
                "https://10.0.0.1:443",
                "https://10.0.0.1:7002",
                "http://10.0.0.1:8080",
                "http://[::1]:8000",
            ],
        )

    def test_all_mode_uses_the_service_as_scheme(self):
        urls = generate_service_urls(self.state, "all")
        self.assertIn("ssh://10.0.0.1:22", urls)
        self.assertIn("snmp://10.0.0.1:161", urls)
        self.assertIn("msrdp://10.0.0.1:3389", urls)
        # a port without an identified service has no scheme to use
        self.assertNotIn("unknown://10.0.0.1:8080", urls)

    def test_uncertain_services_keep_their_scheme(self):
        host = HostScanData("10.0.0.2")
        host.add_port("8443", "tcp", "TBD", "https?")
        host.add_port("8081", "tcp", "TBD", "http-alt?")
        urls = generate_service_urls({"10.0.0.2": host})
        self.assertEqual(urls, ["http://10.0.0.2:8081", "https://10.0.0.2:8443"])

    def test_duplicates_are_removed(self):
        host = HostScanData("10.0.0.3")
        host.add_port("443", "tcp", "TBD", "https")
        host.add_port("443", "udp", "TBD", "https")
        self.assertEqual(
            generate_service_urls({"10.0.0.3": host}), ["https://10.0.0.3:443"]
        )

    def test_mixed_ip_versions_do_not_break_sorting(self):
        # sorting IPv4 against IPv6 with ip_address() raises a TypeError
        urls = generate_service_urls(self.state)
        self.assertEqual(urls[-1], "http://[::1]:8000")


class TestMixedIpVersionState(unittest.TestCase):
    def test_markdown_handles_ipv4_and_ipv6(self):
        v4 = HostScanData("10.0.0.1")
        v4.add_port("80", "tcp", "TBD", "http")
        v6 = HostScanData("fe80::1")
        v6.add_port("80", "tcp", "TBD", "http")
        content = MarkdownConvert({"10.0.0.1": v4, "fe80::1": v6}).convert()
        self.assertIn("10.0.0.1", content)
        self.assertIn("fe80::1", content)


class TestMarkdownEscaping(unittest.TestCase):
    def test_pipes_survive_a_round_trip(self):
        host = HostScanData("10.0.0.1")
        host.set_hostname("we|ird")
        host.add_port("80", "tcp", "Done", "http", "pipe | test")

        document = MarkdownConvert({"10.0.0.1": host}).convert(True)
        self.assertIn("we\\|ird", document)

        parsed = MarkdownConvert().parse(document)
        self.assertEqual(parsed["10.0.0.1"].hostname, "we|ird")
        self.assertEqual(parsed["10.0.0.1"].ports[0].comment, "pipe | test")
        self.assertEqual(parsed["10.0.0.1"].ports[0].state, "Done")

    def test_pipes_survive_with_the_source_column(self):
        host = HostScanData("10.0.0.1")
        host.add_port(
            "443", "tcp", "TBD", "https", "a | b", source_type="nmap", source_file="s.xml"
        )
        document = MarkdownConvert({"10.0.0.1": host}, show_origin=True).convert(True)
        parsed = MarkdownConvert(show_origin=True).parse(document)
        port = parsed["10.0.0.1"].ports[0]
        self.assertEqual(port.comment, "a | b")
        self.assertEqual(port.sources[0]["type"], "nmap")
        self.assertEqual(port.sources[0]["file"], "s.xml")


class TestSingleFileReport(unittest.TestCase):
    def setUp(self):
        host = HostScanData("10.0.0.1")
        host.add_port("443", "tcp", "TBD", "https")
        self.json_content = JsonConverter({"10.0.0.1": host}).convert()

    def test_report_inlines_everything(self):
        report = build_single_file_report(self.json_content)

        # no external or relative references are left
        self.assertNotIn('<script src="http', report)
        self.assertNotIn('<script src="static/', report)
        self.assertNotIn('<link rel="stylesheet"', report)

        # the assets and the data are in the document
        self.assertIn("--surface", report)  # a css custom property
        self.assertIn("function populateTables", report)
        self.assertIn("window.scanData =", report)
        self.assertIn("10.0.0.1", report)
        self.assertIn("validateAndDisplayData(window.scanData)", report)

    def test_report_ships_the_graph_library(self):
        report = build_single_file_report(self.json_content)
        self.assertIn("vis-network", report)

    def test_missing_resources_raise(self):
        with self.assertRaises(FileNotFoundError):
            build_single_file_report(self.json_content, resources_dir="/nonexistent")


class TestTargetRulesStayInSync(unittest.TestCase):
    """The viewer repeats the URL rules in JS; keep the port tables identical."""

    def _js_list(self, name, content):
        match = re.search(name + r"\s*=\s*\[(.*?)\]", content, re.S)
        self.assertIsNotNone(match, f"{name} not found in targets.js")
        return {value.strip().strip('"') for value in match.group(1).split(",") if value.strip()}

    def test_port_hints_match_the_python_rules(self):
        targets_js = os.path.join(
            find_resources_dir(), "static", "js", "targets.js"
        )
        with open(targets_js, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertEqual(self._js_list("WEB_PORT_HINTS", content), WEB_PORT_HINTS)
        self.assertEqual(self._js_list("TLS_PORT_HINTS", content), TLS_PORT_HINTS)


class TestPortIndexPerformance(unittest.TestCase):
    """add_port_details used to scan the port list per insert, so a host that
    answers on every port took over a minute to parse."""

    def test_many_ports_on_one_host_are_added_quickly(self):
        host = HostScanData("10.0.0.1")
        start = time.perf_counter()
        for number in range(1, 20001):
            host.add_port(str(number), "tcp", "TBD", "unknown?")
        elapsed = time.perf_counter() - start

        self.assertEqual(len(host.ports), 20000)
        # measured at ~0.05s; the linear scan needed ~6s for the same loop
        self.assertLess(elapsed, 2.0, f"adding 20k ports took {elapsed:.1f}s")

    def test_duplicate_ports_still_merge(self):
        host = HostScanData("10.0.0.1")
        host.add_port("80", "tcp", "TBD", "unknown?", source_type="nmap")
        host.add_port("80", "tcp", "TBD", "http", source_type="nessus")
        host.add_port("80", "udp", "TBD", "unknown?")

        self.assertEqual(len(host.ports), 2)
        tcp = next(p for p in host.ports if p.protocol == "tcp")
        self.assertEqual(tcp.service, "http")
        self.assertEqual({s["type"] for s in tcp.sources}, {"nmap", "nessus"})

    def test_the_index_follows_a_port_list_assignment(self):
        host = HostScanData("10.0.0.1")
        host.add_port("80", "tcp")
        host.add_port("443", "tcp")

        # filter_uncertain_services and merge_states both assign to .ports
        host.ports = [p for p in host.ports if p.port == "443"]
        host.add_port("443", "tcp", service="https")
        host.add_port("80", "tcp")

        self.assertEqual(sorted(p.port for p in host.ports), ["443", "80"])

    def test_from_dict_keeps_the_index_consistent(self):
        data = {
            "ip": "10.0.0.1",
            "hostname": "h",
            "ports": [
                {"port": "80", "protocol": "tcp", "state": "TBD", "service": "http"},
                {"port": "80", "protocol": "tcp", "state": "TBD", "service": "http"},
            ],
        }
        host = HostScanData.from_dict(data)
        self.assertEqual(len(host.ports), 1)
        host.add_port("80", "tcp")
        self.assertEqual(len(host.ports), 1)


class TestNmapSweepParsing(unittest.TestCase):
    """A ping sweep is mostly hosts without ports; they must not each build a
    HostScanData, and the elements are looked up as direct children."""

    def test_up_hosts_without_ports_are_recorded_not_built(self):
        hostup_dict.clear()
        xml = (
            b'<nmaprun>'
            b'<host><status state="up" reason="echo-reply"/>'
            b'<address addr="10.0.0.1" addrtype="ipv4"/></host>'
            b'<host><status state="down" reason="no-response"/>'
            b'<address addr="10.0.0.2" addrtype="ipv4"/></host>'
            b'<host><status state="up" reason="syn-ack"/>'
            b'<address addr="00:11:22:33:44:55" addrtype="mac" vendor="X"/>'
            b'<address addr="10.0.0.3" addrtype="ipv4"/>'
            b'<ports><port protocol="tcp" portid="22"><state state="open"/>'
            b'<service name="ssh"/></port>'
            b'<port protocol="tcp" portid="23"><state state="closed"/></port>'
            b'</ports></host>'
            b'</nmaprun>'
        )
        parser = NmapParser.__new__(NmapParser)
        parser.file_path = "mem"
        parser.file_name = "mem.xml"
        parser.scan_date = ""
        parser.data = {}
        parser.root = ET.fromstring(xml)

        result = parser.parse()

        self.assertEqual(list(result), ["10.0.0.3"])
        self.assertEqual([p.port for p in result["10.0.0.3"].ports], ["22"])
        self.assertEqual(result["10.0.0.3"].mac_address, "00:11:22:33:44:55")
        self.assertEqual(hostup_dict.get("10.0.0.1"), "echo-reply")
        self.assertNotIn("10.0.0.2", hostup_dict)
        hostup_dict.clear()


class TestReportEscaping(unittest.TestCase):
    """Scan data is written by the scanned hosts; it must not be able to end the
    inline script of a report that gets handed to somebody else."""

    PAYLOADS = [
        "</script><img src=x onerror=alert(1)>",
        "</SCRIPT >",
        "</ScRiPt",
        "<!--<script>",
        "plain < angle",
    ]

    def test_embedded_json_has_no_parser_visible_angle_bracket(self):
        for payload in self.PAYLOADS:
            with self.subTest(payload=payload):
                embedded = _embed_json({"service": payload})
                self.assertNotIn("<", embedded)
                # and it is still the same string after JSON.parse
                self.assertEqual(json.loads(embedded)["service"], payload)

    def test_inlined_script_source_guard_is_case_insensitive(self):
        guarded = _guard_script_source('a = "</SCRIPT >"; b = "</script>"; c = "</ScRiPt";')
        self.assertNotIn("</SCRIPT", guarded)
        self.assertNotIn("</script", guarded)
        self.assertNotIn("</ScRiPt", guarded)
        self.assertIn("<\\/SCRIPT >", guarded)

    def test_report_with_a_hostile_banner_stays_intact(self):
        host = HostScanData("10.0.0.1")
        host.set_hostname("</script><img src=x onerror=alert(1)>")
        host.add_port("80", "tcp", "TBD", "http", "</SCRIPT > banner")
        report = build_single_file_report(JsonConverter({"10.0.0.1": host}).convert())

        # the document must not gain a tag from the scan data
        self.assertNotIn("<img src=x", report)
        self.assertNotIn("</SCRIPT >", report)
        # the payload is still carried, escaped
        self.assertIn("\\u003c/script>", report)

    def test_the_viewer_ships_a_content_security_policy(self):
        index = os.path.join(find_resources_dir(), "index.html")
        with open(index, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("connect-src 'self'", html)
        self.assertIn("default-src 'none'", html)


class TestViewerEscapesScanData(unittest.TestCase):
    """The escaping in the viewer itself is covered by tests/test_viewer_xss.py,
    which drives a real browser. This keeps the sinks from growing back."""

    # helpers that escape their own output, so interpolating their result is fine
    SAFE_HELPERS = ("formatPortLine", "formatNodeTooltip", "formatEdgeTooltip")

    def test_no_unescaped_interpolation_into_markup(self):
        js_dir = os.path.join(find_resources_dir(), "static", "js")
        offenders = []

        for name in ("networkGraph.js", "analysis.js"):
            with open(os.path.join(js_dir, name), "r", encoding="utf-8") as f:
                for number, line in enumerate(f, 1):
                    if "${" not in line or "escapeHtml" in line:
                        continue
                    # values interpolated into markup, ignoring plain counts
                    for match in re.findall(r"\$\{([^}]+)\}", line):
                        expression = match.strip()
                        if any(helper in expression for helper in self.SAFE_HELPERS):
                            continue
                        if re.search(
                            r"\b(ip|hostname|service|comment|reason|banner|product|"
                            r"version|port|protocol|state|subnet)\b",
                            expression,
                        ) and not re.search(r"\.(length|size)\b", expression):
                            offenders.append(f"{name}:{number}: {expression}")

        self.assertEqual(offenders, [], "scan data interpolated into markup unescaped")


if __name__ == "__main__":
    unittest.main()


class TestStateFileLocation(unittest.TestCase):
    """Where the triage lives.

    `-u` used to read state.md from the current working directory while `-H`
    wrote it into the scan folder, so the documented round trip only worked
    from inside that folder. Both sides now use the scan folder.
    """

    SCAN = (
        '<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000">'
        '<host><status state="up" reason="syn-ack"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" method="probed"/></port>'
        # a port the triage below does not know about, so a merged rewrite is
        # visibly different from the file the test put there
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https" method="probed"/></port></ports>'
        "</host></nmaprun>"
    )

    TRIAGE = (
        "|IP|Hostname|Port|Status|Comment|\n"
        "|--|--|--|--|---|\n"
        "|10.0.0.1||80/tcp(http)|Done|already looked at|\n"
    )

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, ignore_errors=True)
        with open(os.path.join(self.folder, "scan.xml"), "w", encoding="utf-8") as f:
            f.write(self.SCAN)

        # somewhere else entirely, so a cwd relative path cannot pass by accident
        self.elsewhere = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.elsewhere, ignore_errors=True)
        cwd = os.getcwd()
        os.chdir(self.elsewhere)
        self.addCleanup(os.chdir, cwd)

    def run_unitas(self, *arguments):
        from unitas.unitas import main

        with patch("sys.argv", ["unitas", self.folder, *arguments]):
            main()

    def state_in(self, folder, name="state.md"):
        path = os.path.join(folder, name)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def write_triage(self, folder, name="state.md"):
        path = os.path.join(folder, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.TRIAGE)
        return path

    def test_the_state_file_is_written_into_the_scan_folder(self):
        self.run_unitas()

        self.assertIn("10.0.0.1", self.state_in(self.folder))
        self.assertIsNone(self.state_in(self.elsewhere), "wrote into the cwd")

    def test_update_reads_the_scan_folder(self):
        self.write_triage(self.folder)

        self.run_unitas("-u")

        # the comment survived the merge and went back into the same file
        updated = self.state_in(self.folder)
        self.assertIn("already looked at", updated)
        self.assertIn("Done", updated)
        # merged and written back, not just the file the test left there
        self.assertIn("443/tcp(https)", updated)
        self.assertIsNone(self.state_in(self.elsewhere), "wrote into the cwd")

    def test_a_state_file_in_the_working_directory_is_not_read(self):
        self.write_triage(self.elsewhere)

        with self.assertLogs(level="WARNING") as logs:
            self.run_unitas("-u")

        self.assertIn("no longer read", "\n".join(logs.output))
        self.assertNotIn("already looked at", self.state_in(self.folder))
        # and it is left alone rather than overwritten
        self.assertEqual(self.state_in(self.elsewhere), self.TRIAGE)

    def test_no_warning_once_the_scan_folder_has_one(self):
        self.write_triage(self.folder)
        self.write_triage(self.elsewhere)

        with patch("unitas.unitas.logging.warning") as warning:
            self.run_unitas("-u")

        said = " ".join(str(call) for call in warning.call_args_list)
        self.assertNotIn("no longer read", said)

    def test_state_file_overrides_both_sides(self):
        target = os.path.join(self.elsewhere, "triage.md")
        self.write_triage(self.elsewhere, "triage.md")

        self.run_unitas("-u", "--state-file", target)

        self.assertIn("already looked at", self.state_in(self.elsewhere, "triage.md"))
        self.assertIsNone(self.state_in(self.folder), "wrote the default as well")

    def test_an_unwritable_folder_is_reported_not_raised(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the write bit")
        os.chmod(self.folder, 0o500)
        self.addCleanup(os.chmod, self.folder, 0o700)

        with self.assertLogs(level="ERROR") as logs:
            self.run_unitas()

        self.assertIn("Could not write", "\n".join(logs.output))
