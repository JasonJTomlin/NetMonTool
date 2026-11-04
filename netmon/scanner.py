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

from . import identify
from .vendors import VendorDB

IS_WINDOWS = platform.system() == "Windows"
# Keeps ping/arp from flashing console windows when run from a windowed process.
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_TTL_RE = re.compile(r"ttl=(\d+)", re.IGNORECASE)
_TIME_RE = re.compile(r"time([=<])\s*([\d.]+)\s*ms", re.IGNORECASE)


@dataclass
class PingReply:
    ttl: int | None
    latency_ms: float | None


@dataclass
class ScanResult:
    ip: str
    mac: str | None
    hostname: str | None
    responded_to_ping: bool
    is_self: bool = False
    ttl: int | None = None
    latency_ms: float | None = None
    os_hint: str | None = None
    netbios_name: str | None = None
    mdns_name: str | None = None
    friendly_name: str | None = None
    vendor: str | None = None
    model: str | None = None
    device_type: str | None = None
    services: str | None = None


def local_ip() -> str:
    """Return this machine's LAN IP (connecting a UDP socket sends no packets)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def default_subnet(prefix: int = 24) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{local_ip()}/{prefix}", strict=False)


def ping(ip: str, timeout_ms: int = 700) -> PingReply | None:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5, creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return None
    # Windows ping can exit 0 on "Destination host unreachable", so check for a real reply.
    ttl = _TTL_RE.search(out.stdout)
    if out.returncode != 0 or not ttl:
        return None
    time_match = _TIME_RE.search(out.stdout)
    latency = None
    if time_match:
        # Windows prints "time<1ms" for sub-millisecond replies.
        latency = 0.5 if time_match.group(1) == "<" else float(time_match.group(2))
    return PingReply(int(ttl.group(1)), latency)


def os_hint(ttl: int | None) -> str | None:
    """Guess the OS family from a reply's TTL; each OS starts from a different default."""
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux, Android, macOS or iOS"
    if ttl <= 128:
        return "Windows"
    return "Network equipment"


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


def _identify(result: ScanResult) -> None:
    """Fill in the names and details a device reports about itself."""
    result.hostname = reverse_dns(result.ip)
    result.netbios_name = identify.netbios_name(result.ip)
    if mdns := identify.mdns_info(result.ip):
        result.mdns_name = mdns.hostname
        result.friendly_name = mdns.friendly_name
        result.model = mdns.model
        result.device_type = mdns.device_type
        result.services = ", ".join(mdns.services) or None


def scan(subnet: ipaddress.IPv4Network, vendors: VendorDB | None = None, workers: int = 128) -> list[ScanResult]:
    """Sweep every host in `subnet` and return the ones that are online, with whatever they say about themselves.

    A host counts as online if it answered the ping, or if pinging it put it in the ARP
    cache (many phones and firewalled PCs drop ping but still answer ARP).
    """
    hosts = [str(h) for h in subnet.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        replies = dict(zip(hosts, pool.map(ping, hosts)))

    arp = {ip: mac for ip, mac in arp_table().items() if ip in replies}
    me = local_ip()
    results = [
        ScanResult(
            ip=ip,
            mac=own_mac() if ip == me else arp.get(ip),
            hostname=None,
            responded_to_ping=replies[ip] is not None,
            is_self=ip == me,
            ttl=replies[ip].ttl if replies[ip] else None,
            latency_ms=replies[ip].latency_ms if replies[ip] else None,
        )
        for ip in hosts
        if replies[ip] or ip in arp or ip == me
    ]

    # SSDP is one multicast search for the whole network, so run it alongside the per-host lookups.
    with ThreadPoolExecutor(max_workers=32) as pool:
        upnp_future = pool.submit(identify.ssdp_discover, me)
        list(pool.map(_identify, results))
        upnp = upnp_future.result()

    for r in results:
        # Some PCs can't ping their own LAN address, so describe this machine directly.
        r.os_hint = f"{platform.system()} {platform.release()}" if r.is_self else os_hint(r.ttl)
        if r.is_self:
            r.hostname = r.hostname or socket.gethostname()
        r.vendor = vendors.lookup(r.mac) if vendors else None
        if info := upnp.get(r.ip):
            r.friendly_name = r.friendly_name or info.friendly_name
            r.model = r.model or info.model
            r.device_type = r.device_type or info.device_type
            r.vendor = r.vendor or info.manufacturer
    return results
