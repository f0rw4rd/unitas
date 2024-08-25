import unittest
from unitas import PortDetails, HostScanData, merge_host_data, merge_states


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
        expected = {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh"}
        self.assertEqual(port.to_dict(), expected)

    def test_port_details_from_dict(self):
        data = {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql"}
        port = PortDetails.from_dict(data)
        self.assertEqual(port.port, "3306")
        self.assertEqual(port.protocol, "tcp")
        self.assertEqual(port.state, "open")
        self.assertEqual(port.service, "mysql")


class TestHostScanData(unittest.TestCase):
    def setUp(self):
        self.host = HostScanData("192.168.1.1")

    def test_host_scan_data_creation(self):
        self.assertEqual(self.host.ip, "192.168.1.1")
        self.assertIsNone(self.host.hostname)
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

    def test_merge_host_scan_data(self):
        other_host = HostScanData("192.168.1.1")
        self.host.add_port("80", "tcp", "open", "http")
        other_host.add_port("443", "tcp", "open", "https")
        other_host.add_port("80", "tcp", "open", "http?")
        new_ports = self.host.merge(other_host)
        self.assertEqual(len(self.host.ports), 2)
        self.assertEqual(len(new_ports), 1)
        self.assertEqual(str(new_ports[0]), "443/tcp(https)")

    def test_overwrite_service(self):
        self.assertTrue(HostScanData.overwrite_service("http?", "http"))
        self.assertFalse(HostScanData.overwrite_service("http", "http?"))
        self.assertTrue(HostScanData.overwrite_service("http", "http-alt"))
        self.assertFalse(HostScanData.overwrite_service("http-alt", "http"))


class TestMergeFunctions(unittest.TestCase):
    def test_merge_host_data(self):
        global_state = {
            "192.168.1.1": HostScanData("192.168.1.1"),
            "192.168.1.2": HostScanData("192.168.1.2"),
        }
        global_state["192.168.1.1"].add_port("80", "tcp", "open", "http")
        global_state["192.168.1.2"].add_port("22", "tcp", "open", "ssh")

        new_data = {
            "192.168.1.1": HostScanData("192.168.1.1"),
            "192.168.1.3": HostScanData("192.168.1.3"),
        }
        new_data["192.168.1.1"].add_port("443", "tcp", "open", "https")
        new_data["192.168.1.3"].add_port("3306", "tcp", "open", "mysql")

        new_hosts, updated_hosts = merge_host_data(global_state, new_data)

        self.assertEqual(len(new_hosts), 1)
        self.assertEqual(new_hosts[0].ip, "192.168.1.3")
        self.assertEqual(len(updated_hosts), 1)
        self.assertIn("192.168.1.1", updated_hosts)
        self.assertEqual(len(global_state), 3)
        self.assertEqual(len(global_state["192.168.1.1"].ports), 2)

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


if __name__ == "__main__":
    unittest.main()
