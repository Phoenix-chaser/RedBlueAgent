"""
NmapParser - parses nmap XML output (via -oX -) into structured data.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from modules.tool_invocation.parsers.base_parser import BaseOutputParser


class NmapParser(BaseOutputParser):
    def parse(self, stdout: str, stderr: str = "") -> dict:
        result = {
            "hosts": [],
            "total_hosts_up": 0,
            "total_ports_open": 0,
            "scan_info": {},
        }

        if not stdout.strip():
            return result

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            # Fallback: try to extract from plain text
            return self._parse_plain_text(stdout)

        for host_el in root.findall("host"):
            host_data = self._parse_host(host_el)
            if host_data:
                result["hosts"].append(host_data)
                if host_data.get("state") == "up":
                    result["total_hosts_up"] += 1
                    result["total_ports_open"] += len(host_data.get("ports", []))

        return result

    def _parse_host(self, host_el: ET.Element) -> dict | None:
        status_el = host_el.find("status")
        state = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"

        # Get IP address
        ip = None
        hostname = None
        for addr_el in host_el.findall("address"):
            if addr_el.attrib.get("addrtype") == "ipv4":
                ip = addr_el.attrib.get("addr")
            elif addr_el.attrib.get("addrtype") == "ipv6" and ip is None:
                ip = addr_el.attrib.get("addr")

        # Get hostname
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.attrib.get("name")

        # Get OS
        os_info = None
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch_el = os_el.find("osmatch")
            if osmatch_el is not None:
                acc = osmatch_el.attrib.get("accuracy")
                os_info = {
                    "name": osmatch_el.attrib.get("name"),
                    "accuracy": int(acc) if acc and acc.isdigit() else acc,
                }

        # Get ports
        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_data = self._parse_port(port_el)
                if port_data and port_data.get("state") == "open":
                    ports.append(port_data)

        return {
            "ip": ip,
            "hostname": hostname,
            "state": state,
            "os": os_info,
            "ports": ports,
        }

    def _parse_port(self, port_el: ET.Element) -> dict:
        portid = int(port_el.attrib.get("portid", 0))
        protocol = port_el.attrib.get("protocol", "tcp")

        state_el = port_el.find("state")
        state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"

        service = "unknown"
        version = None
        banner = None

        service_el = port_el.find("service")
        if service_el is not None:
            service = service_el.attrib.get("name", "unknown")
            product = service_el.attrib.get("product", "")
            ver = service_el.attrib.get("version", "")
            extra = service_el.attrib.get("extrainfo", "")
            version = " ".join(filter(None, [product, ver, extra])).strip() or None

        # Extract banner from script output
        for script_el in port_el.findall("script"):
            if script_el.attrib.get("id") == "banner":
                banner = script_el.attrib.get("output", "")[:200]

        return {
            "port": portid,
            "protocol": protocol,
            "state": state,
            "service": service,
            "version": version,
            "banner": banner,
        }

    def _parse_plain_text(self, stdout: str) -> dict:
        """Fallback parser for plain-text nmap output."""
        result = {"hosts": [], "total_hosts_up": 0, "total_ports_open": 0}
        current_host = None

        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                parts = line.split()
                ip = parts[-1].strip("()")
                current_host = {"ip": ip, "state": "up", "ports": [], "os": None, "hostname": None}
                result["hosts"].append(current_host)
                result["total_hosts_up"] += 1
            elif current_host and "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "open":
                    port_proto = parts[0].split("/")
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else None
                    current_host["ports"].append({
                        "port": int(port_proto[0]),
                        "protocol": port_proto[1] if len(port_proto) > 1 else "tcp",
                        "state": "open",
                        "service": service,
                        "version": version,
                        "banner": None,
                    })
                    result["total_ports_open"] += 1

        return result
