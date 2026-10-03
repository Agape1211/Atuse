#!/usr/bin/env python3
"""Scan a local network and build a live topology map."""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from mac_vendor_lookup import MacLookup
from pyvis.network import Network
from scapy.all import ARP, Ether, srp


__version__ = "0.1.1"
DEFAULT_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 8080, 8443]


def parse_port_list(port_spec: str | Iterable[int] | None) -> list[int]:
    """Parse a comma-separated list of ports and ranges into a deduplicated integer list."""
    if port_spec is None:
        return list(DEFAULT_PORTS)

    if isinstance(port_spec, (list, tuple, set)):
        raw_items = [str(item) for item in port_spec]
    else:
        raw_items = str(port_spec).split(",")

    parsed: list[int] = []
    for raw_item in raw_items:
        item = raw_item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = [part.strip() for part in item.split("-", 1)]
            start_port = int(start_text)
            end_port = int(end_text)
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            parsed.extend(range(start_port, end_port + 1))
        else:
            parsed.append(int(item))

    unique_ports: list[int] = []
    seen: set[int] = set()
    for port in parsed:
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
        if port not in seen:
            seen.add(port)
            unique_ports.append(port)

    return unique_ports


def gateway_and_cidr_from_route(route_output: str) -> tuple[str, str]:
    """Parse the output of `ip route` into a gateway and local CIDR."""
    match = re.search(r"default via (?P<gateway>\S+) dev (?P<iface>\S+)", route_output)
    if not match:
        raise ValueError("Could not find the default gateway in the routing table.")

    gateway = match.group("gateway")
    iface = match.group("iface")
    cidr_match = re.search(rf"(?P<cidr>\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+{re.escape(iface)}\b", route_output)
    if not cidr_match:
        raise ValueError(f"Could not determine the local network CIDR for interface {iface!r}.")

    return gateway, cidr_match.group("cidr")


def gateway_and_cidr(interface: str | None = None) -> tuple[str, str]:
    """Discover the active gateway and CIDR for the current default route."""
    command = ["ip", "route"]
    if interface:
        command = ["ip", "route", "show", "dev", interface]

    route_output = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    return gateway_and_cidr_from_route(route_output)


def scan_network(cidr: str, iface: str | None = None, timeout: float = 2.0) -> list[dict]:
    """ARP-scan a CIDR block and return discovered devices."""
    if iface is None:
        interface = _default_interface()
    else:
        interface = iface

    answers, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
        iface=interface,
        timeout=timeout,
        verbose=0,
    )

    devices = []
    for _, response in answers:
        ip_address = response.psrc
        mac_address = response.hwsrc
        if ip_address and mac_address:
            devices.append({"ip": ip_address, "mac": mac_address})
    return devices


def _default_interface() -> str:
    route_output = subprocess.check_output(["ip", "route"], text=True, stderr=subprocess.DEVNULL)
    match = re.search(r"default via \S+ dev (?P<iface>\S+)", route_output)
    if not match:
        raise ValueError("No default route found. Connect to a network first.")
    return match.group("iface")


def _hostname_lookup(ip_address: str) -> str:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except OSError:
        return ""


def _vendor_lookup(mac_address: str) -> str:
    try:
        return MacLookup().lookup(mac_address)
    except Exception:
        return "Unknown"


def normalize_device(device: dict) -> dict:
    """Standardize a discovered device into a consistent record."""
    ip_address = str(device.get("ip", "")).strip()
    mac_address = str(device.get("mac", "")).strip()
    hostname = str(device.get("hostname") or device.get("host") or "").strip()
    if not hostname:
        hostname = _hostname_lookup(ip_address)

    vendor = str(device.get("vendor") or "").strip() or _vendor_lookup(mac_address)

    return {
        "ip": ip_address,
        "mac": mac_address,
        "hostname": hostname,
        "vendor": vendor,
    }


def detect_open_ports(ip_address: str, ports: Iterable[int] | None = None, timeout: float = 0.25) -> list[int]:
    """Probe a target IP for common open TCP ports."""
    chosen_ports = list(ports or DEFAULT_PORTS)
    open_ports: list[int] = []

    for port in chosen_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip_address, int(port))) == 0:
                open_ports.append(int(port))
        except OSError:
            pass
        finally:
            sock.close()

    return open_ports


def enrich_device_ports(device: dict, ports: Iterable[int] | None = None, timeout: float = 0.25) -> dict:
    """Attach open TCP ports to a device record."""
    ip_address = str(device.get("ip", "")).strip()
    device["ports"] = detect_open_ports(ip_address, ports=ports, timeout=timeout) if ip_address else []
    return device


def discover_devices(
    cidr: str,
    iface: str | None = None,
    timeout: float = 2.0,
    scan_ports: bool = True,
    ports: Iterable[int] | None = None,
    port_timeout: float = 0.25,
) -> list[dict]:
    """Find devices, enrich them with hostnames and vendors, and deduplicate them."""
    discovered = []
    seen_ips = set()

    for raw_device in scan_network(cidr, iface=iface, timeout=timeout):
        device = normalize_device(raw_device)
        if not device["ip"] or not device["mac"]:
            continue
        if device["ip"] in seen_ips:
            continue
        seen_ips.add(device["ip"])
        if scan_ports:
            enrich_device_ports(device, ports=ports, timeout=port_timeout)
        discovered.append(device)

    return discovered


def build_dashboard_state(gateway_ip: str, devices: Iterable[dict]) -> dict:
    """Create a metrics summary for the live dashboard."""
    device_list = [
        {
            "ip": device.get("ip"),
            "hostname": device.get("hostname") or device.get("ip"),
            "vendor": device.get("vendor") or "Unknown",
            "mac": device.get("mac") or "Unknown",
            "ports": device.get("ports") or [],
        }
        for device in devices
        if device.get("ip")
    ]

    open_ports_total = sum(len(device["ports"]) for device in device_list)
    summary = {
        "gateway": gateway_ip,
        "device_count": len(device_list),
        "open_ports_total": open_ports_total,
        "devices": device_list,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }
    return summary


def render_dashboard_html(output_path: str = "dashboard.html") -> str:
    """Render a live dashboard page that refreshes itself from JSON metrics."""
    dashboard_file = Path(output_path)
    dashboard_file.parent.mkdir(parents=True, exist_ok=True)

    html = """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta http-equiv=\"refresh\" content=\"15\" />
  <title>Network Dashboard</title>
  <style>
    :root {
      --bg: #0b1120; --panel: #111827; --panel-alt: #1f2937; --accent: #22c55e; --primary: #38bdf8; --text: #e5e7eb; --muted: #94a3b8; --danger: #f97316;
    }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Arial, sans-serif; background: linear-gradient(135deg, #020817, #111827); color: var(--text); }
    .container { width: min(1200px, 95%); margin: 32px auto; }
    header { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; }
    h1 { margin:0; font-size: clamp(2rem, 4vw, 3rem); }
    .badge { background: rgba(34,197,94,0.15); color: var(--accent); border: 1px solid rgba(34,197,94,0.3); padding: 8px 16px; border-radius: 999px; font-weight: bold; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; }
    .card { background: rgba(17,24,39,0.9); border: 1px solid rgba(148,163,184,0.2); border-radius: 16px; padding: 20px; }
    .label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; }
    .value { font-size: 2rem; font-weight: bold; margin-top: 8px; }
    table { width:100%; border-collapse: collapse; margin-top: 16px; }
    th, td { padding: 12px 14px; border-bottom: 1px solid rgba(148,163,184,0.2); text-align:left; }
    th { background: rgba(30,41,59,0.8); }
    .port-list { display:flex; flex-wrap: wrap; gap: 8px; }
    .port { background: rgba(56,189,248,0.18); color: #bae6fd; border:1px solid rgba(56,189,248,0.35); border-radius: 999px; padding: 4px 8px; font-size: 0.8rem; }
    .status { color: var(--accent); font-weight: bold; }
    .muted { color: var(--muted); }
  </style>
</head>
<body>
  <div class=\"container\">
    <header>
      <h1>Network Dashboard</h1>
      <div class=\"badge\" id=\"statusBadge\">Live</div>
    </header>
    <div class=\"grid\">
      <div class=\"card\"><div class=\"label\">Gateway</div><div class=\"value\" id=\"gatewayValue\">-</div></div>
      <div class=\"card\"><div class=\"label\">Devices</div><div class=\"value\" id=\"deviceCount\">0</div></div>
      <div class=\"card\"><div class=\"label\">Open Ports</div><div class=\"value\" id=\"portCount\">0</div></div>
      <div class=\"card\"><div class=\"label\">Last Update</div><div class=\"value\" id=\"lastUpdated\">-</div></div>
    </div>
    <div class=\"card\">
      <h2>Discovered Hosts</h2>
      <table>
        <thead>
          <tr><th>Host</th><th>IP</th><th>Vendor</th><th>Open Ports</th></tr>
        </thead>
        <tbody id=\"deviceTable\"></tbody>
      </table>
    </div>
  </div>

  <script>
    async function fetchData() {
      try {
        const response = await fetch('./dashboard_data.json', { cache: 'no-store' });
        const data = await response.json();
        document.getElementById('gatewayValue').textContent = data.gateway || '-';
        document.getElementById('deviceCount').textContent = data.device_count || 0;
        document.getElementById('portCount').textContent = data.open_ports_total || 0;
        document.getElementById('lastUpdated').textContent = data.generated_at || '-';
        const tbody = document.getElementById('deviceTable');
        tbody.innerHTML = '';
        for (const device of data.devices || []) {
          const row = document.createElement('tr');
          const portMarkup = (device.ports || []).map(port => `<span class="port">${port}</span>`).join('') || '<span class="muted">None</span>';
          row.innerHTML = `
            <td>${device.hostname || device.ip}</td>
            <td>${device.ip}</td>
            <td>${device.vendor || 'Unknown'}</td>
            <td><div class="port-list">${portMarkup}</div></td>
          `;
          tbody.appendChild(row);
        }
      } catch (error) {
        document.getElementById('statusBadge').textContent = 'Waiting';
      }
    }
    fetchData();
    setInterval(fetchData, 15000);
  </script>
</body>
</html>
"""
    dashboard_file.write_text(html, encoding="utf-8")
    return str(dashboard_file)


def write_dashboard_data(summary: dict, output_path: str = "dashboard_data.json") -> str:
    """Persist the dashboard summary as JSON for the live web panel."""
    data_file = Path(output_path)
    data_file.parent.mkdir(parents=True, exist_ok=True)
    data_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return str(data_file)


def render_network_map(gateway_ip: str, devices: Iterable[dict], output_path: str = "network_map.html") -> str:
    """Render a live network topology map as an HTML file."""
    network = Network(height="90vh", bgcolor="#111111", font_color="white", directed=False)
    network.add_node(gateway_ip, label=f"Gateway\n{gateway_ip}", color="#00e676", size=30, shape="dot")

    for device in devices:
        ip_address = str(device.get("ip") or "").strip()
        if not ip_address or ip_address == gateway_ip:
            continue

        hostname = str(device.get("hostname") or ip_address).strip() or ip_address
        vendor = str(device.get("vendor") or "Unknown").strip() or "Unknown"
        device_label = f"{hostname}\n{vendor}"
        device_title = f"IP: {ip_address}\nMAC: {device.get('mac', 'Unknown')}\nVendor: {vendor}"

        network.add_node(ip_address, label=device_label, title=device_title, color="#3b82f6", size=18, shape="box")
        network.add_edge(gateway_ip, ip_address, value=2)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    network.write_html(str(output_file))
    return str(output_file)


def _scan_once(
    interface: str | None = None,
    cidr: str | None = None,
    output: str = "network_map.html",
    dashboard_dir: str | None = None,
    port_scan: bool = True,
    timeout: float = 2.0,
    ports: Iterable[int] | None = None,
    port_timeout: float = 0.25,
) -> tuple[str, str, list[dict], str, str]:
    if cidr is None:
        gateway, effective_cidr = gateway_and_cidr(interface)
    else:
        iface = interface or _default_interface()
        gateway, effective_cidr = gateway_and_cidr_from_route(f"default via 0.0.0.0 dev {iface}\n{cidr} dev {iface}")

    devices = discover_devices(
        effective_cidr,
        iface=interface,
        timeout=timeout,
        scan_ports=port_scan,
        ports=ports,
        port_timeout=port_timeout,
    )
    map_path = render_network_map(gateway, devices, output)
    dashboard_dir = dashboard_dir or "dashboard"
    summary = build_dashboard_state(gateway, devices)
    dashboard_path = render_dashboard_html(str(Path(dashboard_dir) / "index.html"))
    data_path = write_dashboard_data(summary, str(Path(dashboard_dir) / "dashboard_data.json"))
    return gateway, effective_cidr, devices, map_path, dashboard_path + " | " + data_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover devices on your local network and render a live topology map.")
    parser.add_argument("--interface", "-i", help="Network interface to scan, for example wlan0 or eth0.")
    parser.add_argument("--cidr", help="CIDR block to scan, for example 192.168.1.0/24.")
    parser.add_argument("--output", "-o", default="network_map.html", help="Path to the generated HTML map.")
    parser.add_argument("--dashboard-dir", default="dashboard", help="Directory for the live HTML dashboard and JSON feed.")
    parser.add_argument("--ports", help="Comma-separated ports or ranges to scan, e.g. '22,80-90,443'.")
    parser.add_argument("--refresh", "-r", type=int, default=0, help="Seconds to wait between scans; 0 runs once.")
    parser.add_argument("--timeout", type=float, default=2.0, help="ARP scan timeout in seconds.")
    parser.add_argument("--json", action="store_true", help="Print JSON summary instead of the human-readable status output.")
    parser.add_argument("--skip-ports", action="store_true", help="Skip TCP port probing for faster scans.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if args.refresh < 0:
        parser.error("--refresh must be zero or a positive integer.")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    ports = parse_port_list(args.ports) if args.ports else None

    try:
        while True:
            gateway, cidr, devices, map_path, dashboard_paths = _scan_once(
                interface=args.interface,
                cidr=args.cidr,
                output=args.output,
                dashboard_dir=args.dashboard_dir,
                port_scan=not args.skip_ports,
                timeout=args.timeout,
                ports=ports,
                port_timeout=max(0.1, min(0.75, args.timeout / 3.0)),
            )

            if args.json:
                summary = build_dashboard_state(gateway, devices)
                summary["cidr"] = cidr
                summary["map_path"] = map_path
                print(json.dumps(summary, indent=2))
            else:
                print(f"Gateway: {gateway}")
                print(f"CIDR: {cidr}")
                print(f"Discovered {len(devices)} devices")
                print(f"Map written to {map_path}")
                print(f"Dashboard assets written to {dashboard_paths}")
                for device in devices:
                    hostname = device.get("hostname") or device["ip"]
                    ports_list = ", ".join(str(port) for port in device.get("ports", [])) or "none"
                    print(f"- {device['ip']} | {hostname} | {device.get('vendor', 'Unknown')} | ports: {ports_list}")

            if args.refresh <= 0:
                break
            time.sleep(args.refresh)
    except PermissionError as exc:
        print(f"Permission denied: {exc}", file=sys.stderr)
        print("Run this tool as root or with sudo to perform ARP scans.", file=sys.stderr)
        return 1
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Failed to scan the network: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())