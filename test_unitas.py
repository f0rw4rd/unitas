import unittest
from unitas import (
    PortDetails,
    HostScanData,
    merge_states,
    search_port_or_service,
    MarkdownConvert,
)


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

    def test_search_by_port(self):
        result = search_port_or_service(self.global_state, [" 80"], False)
        self.assertEqual(result, ["192.168.1.1:80", "192.168.1.3:80"])

        result = search_port_or_service(self.global_state, ["22"], False)
        self.assertEqual(result, ["192.168.1.2:22"])

        result = search_port_or_service(self.global_state, ["3306"], False)
        self.assertEqual(result, ["192.168.1.3:3306"])

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

    # TBD add testcase for the URL parameter


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
        self.global_state["192.168.1.2"].add_port("22", "tcp", "Done", "ssh")

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
            "|192.168.1.2||22/tcp(ssh)|Done||\n"
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
            "| 192.168.1.1 | host1.local | 80/tcp(http) | Done | Web server |\n"
        )
        result = self.converter.parse(content)

        self.assertEqual(len(result), 1)
        self.assertIn("192.168.1.1", result)
        self.assertEqual(result["192.168.1.1"].hostname, "host1.local")
        self.assertEqual(result["192.168.1.1"].ports[0].service, "http")
        self.assertEqual(result["192.168.1.1"].ports[0].state, "Done")


if __name__ == "__main__":
    unittest.main()
