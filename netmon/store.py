"""SQLite storage for discovered devices.

A device is identified by its MAC address when one is known (IPs change under DHCP),
and by IP otherwise.
"""

import sqlite3
import threading
from datetime import datetime, timezone

from .scanner import ScanResult
from .vendors import is_private_mac

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac         TEXT UNIQUE,
    ip          TEXT NOT NULL,
    hostname    TEXT,
    label       TEXT,
    is_self     INTEGER NOT NULL DEFAULT 0,
    online      INTEGER NOT NULL DEFAULT 0,
    is_new      INTEGER NOT NULL DEFAULT 1,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Details a device reports about itself. Names keep their last known value when a lookup
# misses (NetBIOS/mDNS are UDP and occasionally drop); ping stats always reflect the latest scan.
NAME_COLUMNS = ["netbios_name", "mdns_name", "friendly_name", "vendor", "model", "device_type", "services"]
PING_COLUMNS = ["ttl", "latency_ms", "os_hint"]
COLUMN_TYPES = {"ttl": "INTEGER", "latency_ms": "REAL"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DeviceStore:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(devices)")}
            for col in NAME_COLUMNS + PING_COLUMNS:
                if col not in existing:
                    self._conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {COLUMN_TYPES.get(col, 'TEXT')}")
            self._conn.commit()

    def _find(self, result: ScanResult) -> sqlite3.Row | None:
        cur = self._conn.cursor()
        if result.mac:
            row = cur.execute("SELECT * FROM devices WHERE mac = ?", (result.mac,)).fetchone()
            if row:
                return row
        # Fall back to an IP-only record, which gets the MAC attached once we learn it.
        return cur.execute("SELECT * FROM devices WHERE ip = ? AND mac IS NULL", (result.ip,)).fetchone()

    def record_scan(self, results: list[ScanResult], first_run: bool) -> list[int]:
        """Upsert scan results, mark everything else offline, and return ids of new devices.

        On the very first scan nothing is flagged new, since every device would be.
        """
        now = _now()
        seen, new_ids = [], []
        with self._lock, self._conn:
            for r in results:
                details = [getattr(r, c) for c in NAME_COLUMNS + PING_COLUMNS]
                row = self._find(r)
                if row:
                    sets = ", ".join([f"{c} = COALESCE(?, {c})" for c in NAME_COLUMNS] + [f"{c} = ?" for c in PING_COLUMNS])
                    self._conn.execute(
                        f"""UPDATE devices SET ip = ?, mac = COALESCE(?, mac), hostname = COALESCE(?, hostname),
                            is_self = ?, online = 1, last_seen = ?, {sets} WHERE id = ?""",
                        (r.ip, r.mac, r.hostname, int(r.is_self), now, *details, row["id"]),
                    )
                    seen.append(row["id"])
                else:
                    cols = NAME_COLUMNS + PING_COLUMNS
                    cur = self._conn.execute(
                        f"""INSERT INTO devices (mac, ip, hostname, is_self, online, is_new, first_seen, last_seen, {", ".join(cols)})
                            VALUES (?, ?, ?, ?, 1, ?, ?, ?, {", ".join("?" * len(cols))})""",
                        (r.mac, r.ip, r.hostname, int(r.is_self), int(not first_run), now, now, *details),
                    )
                    seen.append(cur.lastrowid)
                    if not first_run:
                        new_ids.append(cur.lastrowid)
            placeholders = ",".join("?" * len(seen)) or "NULL"
            self._conn.execute(f"UPDATE devices SET online = 0 WHERE id NOT IN ({placeholders})", seen)
            self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_scan', ?)", (now,))
        return new_ids

    def is_empty(self) -> bool:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0

    def devices(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM devices").fetchall()
        devices = [dict(r) for r in rows]
        for d in devices:
            d["online"], d["is_new"], d["is_self"] = bool(d["online"]), bool(d["is_new"]), bool(d["is_self"])
            d["private_mac"] = bool(d["mac"]) and is_private_mac(d["mac"])
            mdns = (d["mdns_name"] or "").removesuffix(".local") or None
            # Best name the device gave us, before falling back to the user's label in the UI.
            d["discovered_name"] = d["friendly_name"] or mdns or d["netbios_name"] or d["hostname"]
        return sorted(devices, key=lambda d: tuple(int(p) for p in d["ip"].split(".")))

    def last_scan(self) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'last_scan'").fetchone()
        return row[0] if row else None

    def set_label(self, device_id: int, label: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("UPDATE devices SET label = ? WHERE id = ?", (label.strip() or None, device_id))
        return cur.rowcount > 0

    def acknowledge(self, device_id: int | None = None) -> None:
        """Clear the 'new' flag on one device, or on all of them."""
        with self._lock, self._conn:
            if device_id is None:
                self._conn.execute("UPDATE devices SET is_new = 0")
            else:
                self._conn.execute("UPDATE devices SET is_new = 0 WHERE id = ?", (device_id,))

    def forget(self, device_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
