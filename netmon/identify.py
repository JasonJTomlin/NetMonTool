"""Ask devices to identify themselves: NetBIOS, mDNS/Bonjour and SSDP/UPnP.

Each lookup is best effort: a device that doesn't speak the protocol just times out,
and every function returns None or an empty result instead of raising.
"""

import ipaddress
import socket
import struct
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------------------------------------------------------- NetBIOS


def netbios_name(ip: str, timeout: float = 1.5) -> str | None:
    """Return the machine name from a NetBIOS node status query (Windows PCs, NAS, Samba)."""
    # Header, then the wildcard name "*" in NetBIOS first-level encoding, type NBSTAT, class IN.
    query = struct.pack(">HHHHHH", 0x4E42, 0, 1, 0, 0, 0) + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00" + struct.pack(">HH", 0x21, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (ip, 137))
            data, _ = s.recvfrom(2048)
    except OSError:
        return None
    try:
        offset = 12 + 34 + 10  # header, echoed name, type/class/ttl/rdlength
        count = data[offset]
        offset += 1
        for _ in range(count):
            raw, suffix, flags = data[offset:offset + 15], data[offset + 15], struct.unpack(">H", data[offset + 16:offset + 18])[0]
            offset += 18
            # Suffix 0x00 on a unique (non-group) name is the workstation name.
            if suffix == 0x00 and not flags & 0x8000:
                return raw.decode("ascii", "replace").strip() or None
    except (IndexError, struct.error):
        pass
    return None


# ---------------------------------------------------------------- mDNS

_PTR, _TXT = 12, 16

# mDNS service types worth asking about, and the device type they suggest.
_SERVICE_TYPES = {
    "_googlecast._tcp.local": "Chromecast / Google TV",
    "_airplay._tcp.local": "AirPlay device",
    "_raop._tcp.local": "AirPlay speaker",
    "_ipp._tcp.local": "Printer",
    "_ipps._tcp.local": "Printer",
    "_printer._tcp.local": "Printer",
    "_pdl-datastream._tcp.local": "Printer",
    "_scanner._tcp.local": "Scanner",
    "_hap._tcp.local": "HomeKit accessory",
    "_spotify-connect._tcp.local": "Speaker",
    "_sonos._tcp.local": "Sonos speaker",
    "_smb._tcp.local": "File server",
    "_companion-link._tcp.local": "Apple device",
    "_device-info._tcp.local": None,
}


def _dns_query(name: str, qtype: int) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
    return struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; return it and the offset just past it."""
    labels, end, jumps = [], None, 0
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            if jumps > 20:
                raise ValueError("compression loop")
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), end if end is not None else offset


def _parse_records(data: bytes) -> list[tuple[str, int, object]]:
    """Return (name, type, value) for every answer/authority/additional record we understand."""
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    offset = 12
    for _ in range(qd):
        _, offset = _read_name(data, offset)
        offset += 4
    records = []
    for _ in range(an + ns + ar):
        name, offset = _read_name(data, offset)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == _PTR:
            records.append((name, rtype, _read_name(data, offset)[0]))
        elif rtype == _TXT:
            txt, i = {}, 0
            while i < len(rdata):
                entry = rdata[i + 1:i + 1 + rdata[i]].decode("utf-8", "replace")
                i += 1 + rdata[i]
                key, _, value = entry.partition("=")
                txt[key.lower()] = value
            records.append((name, rtype, txt))
        offset += rdlen
    return records


@dataclass
class MdnsInfo:
    hostname: str | None = None
    friendly_name: str | None = None
    model: str | None = None
    device_type: str | None = None
    services: list[str] = field(default_factory=list)


def _mdns_round(sock: socket.socket, ip: str, queries: list[bytes], wait: float) -> list:
    for q in queries:
        sock.sendto(q, (ip, 5353))
    records, deadline = [], time.monotonic() + wait
    while (left := deadline - time.monotonic()) > 0:
        sock.settimeout(left)
        try:
            data, addr = sock.recvfrom(9000)
        except OSError:
            break
        if addr[0] == ip:
            try:
                records += _parse_records(data)
            except (ValueError, IndexError, struct.error):
                pass
    return records


def mdns_info(ip: str, timeout: float = 2.0) -> MdnsInfo | None:
    """Query a device directly over mDNS for its hostname and advertised services.

    Sending from an ordinary port makes this a "legacy unicast" query, which devices answer
    straight back to us without joining the multicast group.
    """
    reverse = ipaddress.ip_address(ip).reverse_pointer + "."
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            records = _mdns_round(s, ip, [_dns_query(reverse, _PTR), _dns_query("_services._dns-sd._udp.local", _PTR)], timeout)
            if not records:
                return None
            info = MdnsInfo()
            services = sorted({v for n, t, v in records if t == _PTR and n == "_services._dns-sd._udp.local"})
            info.services = [s.removesuffix(".local") for s in services]

            # Ask for the instances of the services we know how to read, then their TXT records.
            wanted = [svc for svc in services if svc in _SERVICE_TYPES]
            if wanted:
                records += _mdns_round(s, ip, [_dns_query(svc, _PTR) for svc in wanted], timeout / 2)
                instances = {v: n for n, t, v in records if t == _PTR and n in wanted}
                have_txt = {n for n, t, _ in records if t == _TXT}
                missing = [_dns_query(i, _TXT) for i in instances if i not in have_txt]
                if missing:
                    records += _mdns_round(s, ip, missing, timeout / 2)
            else:
                instances = {}
    except OSError:
        return None

    for name, rtype, value in records:
        if rtype == _PTR and name.lower() == reverse.rstrip(".").lower():
            info.hostname = value
    txts = {n: v for n, t, v in records if t == _TXT}
    for instance, svc in instances.items():
        txt = txts.get(instance, {})
        info.model = info.model or txt.get("md") or txt.get("model") or txt.get("ty") or txt.get("product", "").strip("()") or None
        info.device_type = info.device_type or _SERVICE_TYPES[svc]
        if svc != "_device-info._tcp.local":
            info.friendly_name = info.friendly_name or txt.get("fn") or instance.removesuffix("." + svc)
    return info


# ---------------------------------------------------------------- SSDP / UPnP

_UPNP_TYPES = {
    "InternetGatewayDevice": "Router",
    "WLANAccessPointDevice": "Wi-Fi access point",
    "MediaRenderer": "Media player",
    "MediaServer": "Media server",
    "Printer": "Printer",
    "ZonePlayer": "Sonos speaker",
    "tvdevice": "TV",
    "dial": "Smart TV / streaming device",
}


@dataclass
class UpnpInfo:
    friendly_name: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    device_type: str | None = None


def _upnp_description(url: str) -> UpnpInfo | None:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            root = ET.fromstring(resp.read(256 * 1024))
    except Exception:
        return None
    # Strip XML namespaces so we can look tags up by their plain names.
    for el in root.iter():
        el.tag = el.tag.rpartition("}")[2]
    device = root.find("device")
    if device is None:
        return None

    def text(tag: str) -> str | None:
        value = (device.findtext(tag) or "").strip()
        return value or None

    model = " ".join(filter(None, [text("modelName"), text("modelNumber")])) or text("modelDescription")
    dtype = text("deviceType") or ""
    kind = next((v for k, v in _UPNP_TYPES.items() if k.lower() in dtype.lower()), None)
    return UpnpInfo(text("friendlyName"), text("manufacturer"), model, kind)


def ssdp_discover(local_ip: str, wait: float = 3.0) -> dict[str, UpnpInfo]:
    """Multicast an SSDP search and return the UPnP description of each device that answers."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: upnp:rootdevice\r\n\r\n").encode()
    locations: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            # Send out of the LAN interface even if this PC also has VPN or virtual adapters.
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            s.bind((local_ip, 0))
            s.sendto(msg, ("239.255.255.250", 1900))
            s.sendto(msg, ("239.255.255.250", 1900))  # UDP is lossy; a second copy is cheap
            deadline = time.monotonic() + wait
            while (left := deadline - time.monotonic()) > 0:
                s.settimeout(left)
                try:
                    data, (ip, _) = s.recvfrom(4096)
                except OSError:
                    break
                for line in data.decode("utf-8", "replace").splitlines():
                    key, _, value = line.partition(":")
                    url = value.strip()
                    # Only follow description URLs that point back at the device that sent them.
                    if key.strip().lower() == "location" and urlparse(url).hostname == ip and urlparse(url).scheme == "http":
                        locations.setdefault(ip, url)
    except OSError:
        return {}

    results = {}
    for ip, url in locations.items():
        if info := _upnp_description(url):
            results[ip] = info
    return results
