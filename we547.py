#!/usr/bin/env python3
"""Scan a local network and build a live topology map."""

from __future__ import annotations

import argparse
from html import escape
import json
import re
import socket
import ssl
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
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 993, 995, 8443}


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


def fingerprint_service(ip_address: str, port: int, timeout: float = 0.25) -> dict:
    """Identify a TCP service from its port and a bounded protocol greeting."""
    service = SERVICE_NAMES.get(port)
    if service is None:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "unknown"

    banner = ""
    connection = None
    try:
        connection = socket.create_connection((ip_address, port), timeout=timeout)
        connection.settimeout(timeout)
        if port in TLS_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = context.wrap_socket(connection, server_hostname=ip_address)

        if port in HTTP_PORTS or port in TLS_PORTS and port in {443, 8443}:
            connection.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip_address}\r\nConnection: close\r\n\r\n".encode())
        response = connection.recv(512)
        decoded_response = response.decode("utf-8", errors="replace")
        banner = re.sub(r"[\x00-\x1f\x7f]", " ", decoded_response)
        banner = " ".join(banner.split())[:200]
    except (OSError, ssl.SSLError):
        pass
    finally:
        if connection is not None:
            connection.close()

    lowered_banner = banner.lower()
    if banner.startswith("SSH-"):
        service = "ssh"
    elif banner.startswith("HTTP/"):
        service = "http" if port not in TLS_PORTS else "https"
    elif "ftp" in lowered_banner and banner.startswith("220"):
        service = "ftp"
    elif banner.startswith("+ok"):
        service = "pop3"
    elif banner.startswith("* ok"):
        service = "imap"

    product = ""
    server_match = re.search(r"(?:^| )server:\s*([^\r\n]+)", banner, re.IGNORECASE)
    if server_match:
        product = server_match.group(1).strip()
    elif banner.startswith(("SSH-", "220", "+OK", "* OK")):
        product = banner.split(" ", 1)[0]

    return {
        "port": port,
        "service": service,
        "product": product,
        "banner": banner,
    }


def enrich_device_ports(device: dict, ports: Iterable[int] | None = None, timeout: float = 0.25) -> dict:
    """Attach open TCP ports and service fingerprints to a device record."""
    ip_address = str(device.get("ip", "")).strip()
    device["ports"] = detect_open_ports(ip_address, ports=ports, timeout=timeout) if ip_address else []
    device["services"] = [fingerprint_service(ip_address, port, timeout=timeout) for port in device["ports"]]
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
            "services": device.get("services") or [],
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
  <title>Network Dashboard</title>
  <style>
    :root {
            color-scheme: light;
            --bg: #f2f4ef; --panel: #ffffff; --ink: #1b2926; --muted: #687773;
            --line: #dce3dd; --accent: #187b65; --accent-soft: #e5f3ee;
            --signal: #bd643c; --signal-soft: #fbede6;
    }
    * { box-sizing: border-box; }
        body { margin:0; font-family: "Avenir Next", "Segoe UI", sans-serif; background: radial-gradient(ellipse at 80% 0%, #e2ece6 0, transparent 34rem), var(--bg); color:var(--ink); }
        .container { width:min(1320px, calc(100% - 48px)); margin:36px auto 56px; }
        header { display:flex; justify-content:space-between; align-items:flex-end; gap:20px; border-bottom:1px solid var(--line); padding-bottom:22px; margin-bottom:20px; }
        .eyebrow { color:var(--accent); font-size:.72rem; font-weight:800; text-transform:uppercase; letter-spacing:.12em; }
        h1 { margin:6px 0 0; font-family:Georgia, "Times New Roman", serif; font-size:2.25rem; font-weight:500; }
        .badge { display:inline-flex; align-items:center; gap:8px; color:var(--accent); font-size:.85rem; font-weight:700; }
        .badge::before { content:""; width:8px; height:8px; border-radius:50%; background:currentColor; box-shadow:0 0 0 4px var(--accent-soft); }
        .badge[data-state="waiting"] { color:var(--signal); }
        .badge[data-state="waiting"]::before { box-shadow:0 0 0 4px var(--signal-soft); }
        .grid { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); border:1px solid var(--line); background:rgba(255,255,255,.72); margin-bottom:30px; }
        .metric { min-width:0; padding:18px 20px; border-right:1px solid var(--line); }
        .metric:last-child { border-right:0; }
        .label { color:var(--muted); font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.08em; }
        .value { overflow-wrap:anywhere; font-family:Georgia, "Times New Roman", serif; font-size:1.65rem; margin-top:8px; }
        .section-heading { display:flex; justify-content:space-between; align-items:center; gap:16px; margin:0 0 12px; }
        h2 { margin:0; font-family:Georgia, "Times New Roman", serif; font-size:1.45rem; font-weight:500; }
        .search { width:min(300px, 100%); padding:10px 12px; border:1px solid var(--line); border-radius:4px; background:#fff; color:var(--ink); font:inherit; }
        .table-wrap { overflow-x:auto; border-top:2px solid var(--ink); background:var(--panel); }
        table { width:100%; border-collapse:collapse; text-align:left; }
        th, td { padding:13px 14px; border-bottom:1px solid var(--line); vertical-align:top; }
        th { color:var(--muted); font-size:.68rem; font-weight:800; text-transform:uppercase; letter-spacing:.07em; }
        td { font-size:.88rem; }
        td:first-child { min-width:150px; font-weight:700; }
        .host-ip { display:block; margin-top:4px; color:var(--muted); font: .78rem ui-monospace, SFMono-Regular, Consolas, monospace; }
        .port-list { display:flex; flex-wrap:wrap; gap:5px; min-width:90px; }
        .port { min-width:32px; padding:3px 6px; border:1px solid #c5dacf; border-radius:3px; background:var(--accent-soft); color:#155e4d; text-align:center; font: .76rem ui-monospace, SFMono-Regular, Consolas, monospace; }
        .service { display:inline-block; margin:1px 8px 4px 0; color:#315c70; font-size:.8rem; }
        .empty { padding:24px 14px; color:var(--muted); text-align:center; }
        @media (max-width:760px) {
            .container { width:calc(100% - 28px); margin:22px auto 36px; }
            .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); }
            .metric:nth-child(2) { border-right:0; }
            .metric:nth-child(-n+2) { border-bottom:1px solid var(--line); }
            .metric { padding:14px; }
            .value { font-size:1.35rem; }
            .section-heading { align-items:flex-start; flex-direction:column; }
            .search { width:100%; }
            .table-wrap { overflow:visible; border-top:0; background:transparent; }
            table, tbody { display:block; }
            thead { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0, 0, 0, 0); white-space:nowrap; }
            tbody tr { display:block; margin-bottom:10px; border:1px solid var(--line); background:var(--panel); }
            td, td:first-child { display:grid; grid-template-columns:92px minmax(0, 1fr); gap:10px; min-width:0; padding:10px 12px; }
            td::before { content:attr(data-label); color:var(--muted); font-size:.68rem; font-weight:800; text-transform:uppercase; letter-spacing:.05em; }
            .host-ip { grid-column:2; }
            .empty { display:block; }
        }
        @media (max-width:380px) { h1 { font-size:1.85rem; } td, td:first-child { grid-template-columns:76px minmax(0, 1fr); } }
  </style>
</head>
<body>
  <div class=\"container\">
    <header>
            <div><div class="eyebrow">Local network / topology</div><h1>Network overview</h1></div>
            <div class="badge" id="statusBadge" data-state="live" role="status">Live</div>
    </header>
    <div class=\"grid\">
            <div class="metric"><div class="label">Gateway</div><div class="value" id="gatewayValue">-</div></div>
            <div class="metric"><div class="label">Devices</div><div class="value" id="deviceCount">0</div></div>
            <div class="metric"><div class="label">Open ports</div><div class="value" id="portCount">0</div></div>
            <div class="metric"><div class="label">Last update</div><div class="value" id="lastUpdated">-</div></div>
    </div>
        <section aria-labelledby="hostsHeading">
            <div class="section-heading">
                <h2 id="hostsHeading">Discovered hosts</h2>
                <input class="search" id="hostSearch" type="search" placeholder="Filter hosts, vendors, or services" aria-label="Filter discovered hosts" />
            </div>
            <div class="table-wrap">
      <table>
        <thead>
                    <tr><th>Host</th><th>Vendor</th><th>Open ports</th><th>Services</th></tr>
        </thead>
                <tbody id="deviceTable"><tr><td class="empty" colspan="4">Waiting for scan data...</td></tr></tbody>
      </table>
            </div>
        </section>
  </div>

  <script>
    async function fetchData() {
      try {
        const response = await fetch('./dashboard_data.json', { cache: 'no-store' });
        const data = await response.json();
        const statusBadge = document.getElementById('statusBadge');
        statusBadge.textContent = 'Live';
        statusBadge.dataset.state = 'live';
        document.getElementById('gatewayValue').textContent = data.gateway || '-';
        document.getElementById('deviceCount').textContent = data.device_count || 0;
        document.getElementById('portCount').textContent = data.open_ports_total || 0;
        document.getElementById('lastUpdated').textContent = data.generated_at || '-';
        const tbody = document.getElementById('deviceTable');
        tbody.innerHTML = '';
                const devices = data.devices || [];
                for (const device of devices) {
          const row = document.createElement('tr');
                    row.dataset.search = [device.hostname, device.ip, device.vendor, ...(device.services || []).map(service => service.service)].join(' ').toLowerCase();
                    const hostCell = document.createElement('td');
                    hostCell.dataset.label = 'Host';
                    hostCell.append(document.createTextNode(device.hostname || device.ip || 'Unknown'));
                    const ipLabel = document.createElement('span');
                    ipLabel.className = 'host-ip';
                    ipLabel.textContent = device.ip || '';
                    hostCell.appendChild(ipLabel);
                    row.appendChild(hostCell);

                    const vendorCell = document.createElement('td');
                    vendorCell.dataset.label = 'Vendor';
                    vendorCell.textContent = device.vendor || 'Unknown';
                    row.appendChild(vendorCell);

                    const portsCell = document.createElement('td');
                    portsCell.dataset.label = 'Open ports';
                    const portList = document.createElement('div');
                    portList.className = 'port-list';
                    for (const port of device.ports || []) {
                        const badge = document.createElement('span');
                        badge.className = 'port';
                        badge.textContent = port;
                        portList.appendChild(badge);
                    }
                    if (!portList.childElementCount) portList.textContent = 'None observed';
                    portsCell.appendChild(portList);
                    row.appendChild(portsCell);

                    const servicesCell = document.createElement('td');
                    servicesCell.dataset.label = 'Services';
                    for (const service of device.services || []) {
                        const label = document.createElement('span');
                        label.className = 'service';
                        label.textContent = `${service.port}/${service.service}${service.product ? ` (${service.product})` : ''}`;
                        label.title = service.banner || service.product || service.service;
                        servicesCell.appendChild(label);
                    }
                    if (!servicesCell.childElementCount) servicesCell.textContent = 'None identified';
                    row.appendChild(servicesCell);
          tbody.appendChild(row);
        }
                if (!devices.length) tbody.innerHTML = '<tr><td class="empty" colspan="4">No devices found in the latest scan.</td></tr>';
                document.getElementById('hostSearch').dispatchEvent(new Event('input'));
      } catch (error) {
                const statusBadge = document.getElementById('statusBadge');
                statusBadge.textContent = 'Waiting for data';
                statusBadge.dataset.state = 'waiting';
      }
    }
        document.getElementById('hostSearch').addEventListener('input', event => {
            const query = event.target.value.trim().toLowerCase();
            for (const row of document.querySelectorAll('#deviceTable tr[data-search]')) {
                row.hidden = !row.dataset.search.includes(query);
            }
        });
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
    network = Network(height="90vh", width="100%", bgcolor="#101714", font_color="#f4f7f5", directed=False)
    network.set_options("""{
      "nodes": {"borderWidth": 1, "font": {"face": "Arial", "size": 16, "color": "#f4f7f5"}, "shadow": {"enabled": true, "color": "rgba(0,0,0,0.35)", "size": 10, "x": 0, "y": 4}},
      "edges": {"color": {"color": "#52645f", "highlight": "#d8a45b"}, "smooth": {"type": "continuous"}, "width": 1},
      "physics": {"solver": "barnesHut", "barnesHut": {"gravitationalConstant": -4500, "centralGravity": 0.25, "springLength": 160, "springConstant": 0.04, "damping": 0.2}, "stabilization": {"iterations": 500}},
      "interaction": {"hover": true, "navigationButtons": true, "keyboard": {"enabled": true}, "tooltipDelay": 150}
    }""")
    network.add_node(
        gateway_ip,
        label=f"Gateway\n{gateway_ip}",
        title=f"Default gateway\n{gateway_ip}",
        color={"background": "#d8a45b", "border": "#f0c987", "highlight": {"background": "#edbd70", "border": "#fff0d2"}},
        size=28,
        shape="dot",
    )

    for device in devices:
        ip_address = str(device.get("ip") or "").strip()
        if not ip_address or ip_address == gateway_ip:
            continue

        hostname = str(device.get("hostname") or ip_address).strip() or ip_address
        vendor = str(device.get("vendor") or "Unknown").strip() or "Unknown"
        ports = device.get("ports") or []
        port_count = len(ports)
        services = device.get("services") or []
        service_details = "\n".join(
            escape(
                f"{service.get('port')}/{service.get('service', 'unknown')}: "
                f"{service.get('product') or service.get('banner') or 'no banner'}"
            )
            for service in services
        )
        device_label = f"{hostname}\n{vendor} · {port_count} open port{'s' if port_count != 1 else ''}"
        device_title = f"IP: {ip_address}\nMAC: {device.get('mac', 'Unknown')}\nVendor: {vendor}\nOpen ports: {', '.join(map(str, ports)) or 'none'}"
        if service_details:
            device_title += f"\nServices:\n{service_details}"

        host_color = "#bd643c" if port_count else "#318678"
        network.add_node(
            ip_address,
            label=device_label,
            title=device_title,
            color={"background": host_color, "border": "#dce8e2", "highlight": {"background": "#e4b15f", "border": "#fff0d2"}},
            size=17 + min(port_count, 9),
            shape="dot",
        )
        network.add_edge(gateway_ip, ip_address, value=1 + min(port_count, 4) * 0.35, title=f"{port_count} open port{'s' if port_count != 1 else ''}")

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
                    services_list = ", ".join(
                        f"{service['port']}/{service['service']}"
                        + (f" ({service['product']})" if service.get("product") else "")
                        for service in device.get("services", [])
                    ) or "none"
                    print(f"- {device['ip']} | {hostname} | {device.get('vendor', 'Unknown')} | ports: {ports_list} | services: {services_list}")

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