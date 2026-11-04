"""Network discovery: ping sweep the local subnet, then read the ARP table for MAC addresses.

Uses only the OS `ping` and `arp` commands, so no admin rights or packet-capture drivers are needed.
"""

import ipaddress
import platform
import re
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

IS_WINDOWS = platform.system() == "Windows"
# Keeps ping/arp from flashing console windows when run from a windowed process.
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass
class ScanResult:
    ip: str
    mac: str | None
    hostname: str | None
    responded_to_ping: bool
    is_self: bool = False


def local_ip() -> str:
    """Return this machine's LAN IP (connecting a UDP socket sends no packets)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def default_subnet(prefix: int = 24) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{local_ip()}/{prefix}", strict=False)


def ping(ip: str, timeout_ms: int = 700) -> bool:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5, creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return False
    # Windows ping can exit 0 on "Destination host unreachable", so check for a real reply.
    return out.returncode == 0 and "TTL=" in out.stdout.upper()


def normalize_mac(mac: str) -> str:
    return mac.replace("-", ":").lower()


def arp_table() -> dict[str, str]:
    """Map IP -> MAC from the OS ARP cache."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10, creationflags=_NO_WINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    table = {}
    for line in out.splitlines():
        ip_match, mac_match = _IP_RE.search(line), _MAC_RE.search(line)
        if ip_match and mac_match:
            mac = normalize_mac(mac_match.group(0))
            if mac != "ff:ff:ff:ff:ff:ff":
                table[ip_match.group(1)] = mac
    return table


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def own_mac() -> str | None:
    node = uuid.getnode()
    if (node >> 40) & 1:  # multicast bit set means getnode() fell back to a random value
        return None
    return ":".join(f"{(node >> s) & 0xFF:02x}" for s in range(40, -1, -8))


def scan(subnet: ipaddress.IPv4Network, workers: int = 128) -> list[ScanResult]:
    """Sweep every host in `subnet` and return the ones that are online.

    A host counts as online if it answered the ping, or if pinging it put it in the ARP
    cache (many phones and firewalled PCs drop ping but still answer ARP).
    """
    hosts = [str(h) for h in subnet.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        replies = dict(zip(hosts, pool.map(ping, hosts)))

    arp = {ip: mac for ip, mac in arp_table().items() if ip in replies}
    me = local_ip()
    online = [ip for ip in hosts if replies[ip] or ip in arp or ip == me]

    with ThreadPoolExecutor(max_workers=32) as pool:
        names = dict(zip(online, pool.map(reverse_dns, online)))

    return [
        ScanResult(
            ip=ip,
            mac=own_mac() if ip == me else arp.get(ip),
            hostname=names[ip],
            responded_to_ping=replies[ip],
            is_self=ip == me,
        )
        for ip in online
    ]
