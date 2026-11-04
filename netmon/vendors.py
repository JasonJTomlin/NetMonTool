"""Look up a device's manufacturer from its MAC address prefix.

Uses Wireshark's `manuf` list (built from the IEEE registry), downloaded once and refreshed monthly.
"""

import logging
import threading
import time
import urllib.request
from pathlib import Path

log = logging.getLogger("netmon")

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
MAX_AGE = 30 * 24 * 3600


_COMPANY_SUFFIXES = {"co", "ltd", "inc", "corp", "corporation", "corporate", "incorporated", "limited", "llc",
                     "gmbh", "ag", "sas", "sa", "bv", "plc", "pte", "pty", "srl", "spa", "kg", "oy", "ab", "as"}


def short_vendor(name: str) -> str:
    """'Visionscape Co,. Ltd.' -> 'Visionscape', so names fit in the dashboard."""
    words = name.split()
    while len(words) > 1 and "".join(c for c in words[-1].lower() if c.isalnum()) in _COMPANY_SUFFIXES:
        words.pop()
    return " ".join(words).rstrip(",.")


def is_private_mac(mac: str) -> bool:
    """True for randomized / locally administered MACs, which phones use for privacy."""
    return bool(int(mac[:2], 16) & 0x02)


class VendorDB:
    def __init__(self, path: Path):
        self.path = path
        self._prefixes: dict[int, dict[int, str]] = {}  # prefix length in bits -> prefix -> vendor
        self._lock = threading.Lock()

    def load(self) -> None:
        """Load the vendor list, downloading it first if it's missing or stale."""
        if not self.path.exists() or time.time() - self.path.stat().st_mtime > MAX_AGE:
            try:
                log.info("Downloading MAC vendor list from %s", MANUF_URL)
                with urllib.request.urlopen(MANUF_URL, timeout=30) as resp:
                    data = resp.read()
                tmp = self.path.with_suffix(".tmp")
                tmp.write_bytes(data)
                tmp.replace(self.path)
            except OSError as e:
                log.warning("Couldn't download MAC vendor list: %s", e)
        if not self.path.exists():
            return

        prefixes: dict[int, dict[int, str]] = {}
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            prefix, _, bits = parts[0].strip().partition("/")
            hex_digits = prefix.replace(":", "").replace("-", "")
            bits = int(bits) if bits else len(hex_digits) * 4
            vendor = short_vendor((parts[2] if len(parts) > 2 else parts[1]).strip())
            value = int(hex_digits.ljust(12, "0"), 16) >> (48 - bits)
            prefixes.setdefault(bits, {})[value] = vendor
        with self._lock:
            self._prefixes = prefixes
        log.info("Loaded %d MAC vendor prefixes", sum(len(p) for p in prefixes.values()))

    def lookup(self, mac: str | None) -> str | None:
        if not mac or is_private_mac(mac):
            return None
        value = int(mac.replace(":", ""), 16)
        with self._lock:
            # Longest (most specific) prefix wins: some vendors own only a /28 or /36 slice.
            for bits in sorted(self._prefixes, reverse=True):
                if vendor := self._prefixes[bits].get(value >> (48 - bits)):
                    return vendor
        return None
