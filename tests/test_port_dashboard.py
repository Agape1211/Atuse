import json
from pathlib import Path

import we547


def test_port_scan_detects_open_ports(monkeypatch):
    class FakeSocket:
        def __init__(self, *args, **kwargs):
            pass

        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            if address[1] in (22, 80):
                return 0
            return 1

        def close(self):
            pass

    monkeypatch.setattr(we547.socket, "socket", lambda *a, **k: FakeSocket())

    ports = we547.detect_open_ports("192.168.1.42", [22, 80, 443])

    assert ports == [22, 80]


def test_live_dashboard_state_contains_ports_and_metrics():
    devices = [
        {
            "ip": "192.168.1.1",
            "mac": "00:00:00:00:00:01",
            "hostname": "gateway",
            "vendor": "RouterOS",
            "ports": [22, 80],
        },
        {
            "ip": "192.168.1.42",
            "mac": "00:00:00:00:00:02",
            "hostname": "printer",
            "vendor": "HP",
            "ports": [80],
        },
    ]

    summary = we547.build_dashboard_state("192.168.1.1", devices)

    assert summary["gateway"] == "192.168.1.1"
    assert summary["device_count"] == 2
    assert summary["open_ports_total"] == 3
    assert summary["devices"][0]["ports"] == [22, 80]


def test_parse_port_list_supports_csv_and_ranges():
    assert we547.parse_port_list("22,443,8080") == [22, 443, 8080]
    assert we547.parse_port_list("80-90") == list(range(80, 91))
    assert we547.parse_port_list("22, 80-82") == [22, 80, 81, 82]
