import ipaddress

import pytest

from home_network_scanner import scanner
from home_network_scanner.models import ScanOptions


NMAP_XML = '<?xml version="1.0"?><nmaprun><host><status state="up"/></host></nmaprun>'


def test_default_command_uses_only_host_discovery():
    options = ScanOptions(network="192.168.1.0/24", interface="lan0")
    command = scanner.build_nmap_command("/usr/bin/nmap", options, ipaddress.ip_network(options.network))
    assert "-sn" in command
    assert "-sV" not in command
    assert "-O" not in command
    assert not any("--script" in item for item in command)


def test_detailed_detection_uses_only_the_bounded_port_list():
    options = ScanOptions(
        network="192.168.1.0/24",
        interface="lan0",
        detect_services=True,
        detect_os=True,
        ports=(22, 443),
    )
    command = scanner.build_nmap_command("/usr/bin/nmap", options, ipaddress.ip_network(options.network))
    assert "-sV" in command
    assert "-O" in command
    assert command[command.index("-p") + 1] == "22,443"


@pytest.mark.parametrize("ports", [(), (0,), (65536,), tuple(range(1, 102))])
def test_detailed_detection_rejects_invalid_port_lists(ports):
    options = ScanOptions(
        network="192.168.1.0/24",
        interface="lan0",
        detect_services=True,
        ports=ports,
    )
    with pytest.raises(ValueError):
        scanner.build_nmap_command("nmap", options, ipaddress.ip_network(options.network))


def test_parse_normalizes_python_nmap_result(monkeypatch):
    parsed = {
        "nmap": {"version": "7.95"},
        "scan": {
            "192.168.1.20": {
                "hostnames": [{"name": "office-printer"}],
                "addresses": {"ipv4": "192.168.1.20", "mac": "00:11:22:33:44:55"},
                "vendor": {"00:11:22:33:44:55": "Brother Industries"},
                "tcp": {
                    9100: {
                        "state": "open",
                        "name": "jetdirect",
                        "product": "Printer service",
                        "version": "1.0",
                        "extrainfo": "",
                    },
                    23: {"state": "closed", "name": "telnet"},
                },
                "osmatch": [
                    {
                        "accuracy": "97",
                        "name": "Linux 5.4",
                        "osclass": [{"osfamily": "Linux", "osgen": "5.X"}],
                    }
                ],
            }
        },
    }

    class FakePortScanner:
        def analyse_nmap_xml_scan(self, xml_output):
            assert xml_output == NMAP_XML
            return parsed

    monkeypatch.setattr(scanner.nmap, "PortScanner", FakePortScanner)
    devices, version = scanner.parse_nmap_xml(NMAP_XML)
    assert version == "7.95"
    assert len(devices) == 1
    assert devices[0].hostname == "office-printer"
    assert devices[0].vendor == "Brother Industries"
    assert devices[0].device_type == "Printer"
    assert devices[0].os_family == "Linux"
    assert devices[0].os_confidence == "high"
    assert [service.port for service in devices[0].services] == [9100]