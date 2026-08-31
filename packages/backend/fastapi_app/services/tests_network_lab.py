from __future__ import annotations

from django.test import SimpleTestCase

from fastapi_app.services import network_lab_executor
from fastapi_app.services.engine_adapters import SUPPORTED_REAL_ENGINES


class NetworkLabAdapterTests(SimpleTestCase):
    def test_network_engines_are_real_registered(self):
        self.assertIn("network_nmap", SUPPORTED_REAL_ENGINES)
        self.assertIn("network_masscan", SUPPORTED_REAL_ENGINES)

    def test_nmap_parser_only_returns_open_ports_present_in_xml(self):
        xml = '<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9"/></port><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host></nmaprun>'
        observations = network_lab_executor._parse_nmap(xml)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["port"], 22)
        self.assertEqual(observations[0]["service"], "ssh")

    def test_masscan_parser_only_returns_discovered_ports(self):
        output = "Discovered open port 443/tcp on 192.0.2.10\nnot-a-discovery-line\n"
        observations = network_lab_executor._parse_masscan(output)
        self.assertEqual(observations, [{"host": "192.0.2.10", "protocol": "tcp", "port": 443, "state": "open"}])

    def test_network_target_limit_is_1024_addresses(self):
        self.assertEqual(network_lab_executor.target_kind("192.0.2.0/22"), "cidr")
        with self.assertRaises(ValueError):
            network_lab_executor.target_kind("192.0.2.0/21")
