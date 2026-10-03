import json
from pathlib import Path

import pytest

import we547


def test_gateway_and_cidr_parses_route_output():
    route_output = """default via 192.168.1.1 dev wlan0 proto static
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.15 metric 600
"""

    gateway, cidr = we547.gateway_and_cidr_from_route(route_output)

    assert gateway == "192.168.1.1"
    assert cidr == "192.168.1.0/24"


def test_normalize_device_includes_vendor_and_hostname():
    device = we547.normalize_device({
        "ip": "192.168.1.42",
        "mac": "00:11:22:33:44:55",
        "hostname": "nas.local",
        "vendor": "Example Vendor",
    })

    assert device["ip"] == "192.168.1.42"
    assert device["mac"] == "00:11:22:33:44:55"
    assert device["hostname"] == "nas.local"
    assert device["vendor"] == "Example Vendor"


def test_render_network_map_creates_html_file(tmp_path):
    output_path = tmp_path / "network-map.html"
    devices = [
        {"ip": "192.168.1.1", "mac": "00:00:00:00:00:01", "hostname": "router", "vendor": "RouterOS"},
        {"ip": "192.168.1.42", "mac": "00:00:00:00:00:02", "hostname": "printer", "vendor": "HP"},
    ]

    we547.render_network_map("192.168.1.1", devices, str(output_path))

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")
    assert "network" in html.lower()
    assert "192.168.1.42" in html
