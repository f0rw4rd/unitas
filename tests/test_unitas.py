# pylint: skip-file
import unittest
import os
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from unitas import (
    PortDetails,
    HostScanData,
    merge_states,
    NmapHost,
    NmapParser,
    NessusParser,
    search_port_or_service,
    MarkdownConvert,
)


class TestNmapParser(unittest.TestCase):
    def setUp(self):
        self.test_files_dir = os.path.join(
            os.path.dirname(__file__),  "nmap_files"
        )

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
        self.test_files_dir = os.path.join(
            os.path.dirname(__file__),  "nessus_files"
        )

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
        result = search_port_or_service(self.global_state, [" 80"], False)
        self.assertEqual(result, ["192.168.1.1:80", "192.168.1.3:80"])

        result = search_port_or_service(self.global_state, ["22"], False)
        self.assertEqual(result, ["192.168.1.2:22"])

        result = search_port_or_service(self.global_state, ["3306"], False)
        self.assertEqual(result, ["192.168.1.3:3306"])

    def test_search_by_service_url(self):
        result = search_port_or_service(self.global_state, ["ssh"], with_url=True)
        self.assertEqual(result, ["ssh://192.168.1.2:22"])

    def test_case_insensitive_search_url(self):
        result = search_port_or_service(self.global_state, ["HTTP"], with_url=True)
        self.assertEqual(result, ["http://192.168.1.1:80", "http://192.168.1.3:80"])

    def test_service_with_question_mark_url(self):
        self.global_state["192.168.1.2"].add_port("8080", "tcp", "TBD", "http-alt?")
        result = search_port_or_service(self.global_state, ["8080"], with_url=True)
        self.assertEqual(result, ["http-alt://192.168.1.2:8080"])

    def test_search_by_service(self):
        result = search_port_or_service(self.global_state, ["http"], False)
        self.assertEqual(result, ["192.168.1.1:80", "192.168.1.3:80"])

        result = search_port_or_service(self.global_state, ["ssh"], False)
        self.assertEqual(result, ["192.168.1.2:22"])

        result = search_port_or_service(self.global_state, ["mysql"], False)
        self.assertEqual(result, ["192.168.1.3:3306"])

    def test_case_insensitive_service_search(self):
        result = search_port_or_service(self.global_state, ["HTTP"], False)
        self.assertEqual(result, ["192.168.1.1:80", "192.168.1.3:80"])

    def test_search_non_existent(self):
        result = search_port_or_service(self.global_state, ["8080"], False)
        self.assertEqual(result, [])

        result = search_port_or_service(self.global_state, ["ftp"], False)
        self.assertEqual(result, [])

    def test_search_for_question_mark(self):
        result = search_port_or_service(self.global_state, ["rdp"], False)
        self.assertEqual(result, ["192.168.1.3:12345"])

    def test_search_for_two_ports_on_the_same_host(self):
        result = search_port_or_service(self.global_state, ["http", "https"], False)
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


if __name__ == "__main__":
    unittest.main()
