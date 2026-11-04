"""SQLite storage for discovered devices, their online/offline history and settings.

A device is identified by its MAC address when one is known (IPs change under DHCP),
and by IP otherwise.
"""

import bisect
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

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
-- One row per completed scan, so uptime = scans a device was seen in / scans since it first appeared.
CREATE TABLE IF NOT EXISTS scans (ts TEXT PRIMARY KEY);
-- One row per device per scan it was online in.
CREATE TABLE IF NOT EXISTS samples (
    device_id   INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    latency_ms  REAL
);
CREATE INDEX IF NOT EXISTS samples_device_ts ON samples (device_id, ts);
CREATE INDEX IF NOT EXISTS samples_ts ON samples (ts);
-- Status changes. device_id is NULL for internet up/down events.
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER,
    ts          TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ip          TEXT
);
CREATE INDEX IF NOT EXISTS events_device_ts ON events (device_id, ts);
CREATE TABLE IF NOT EXISTS wan (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    gateway_ms   REAL,
    internet_ms  REAL
);
CREATE INDEX IF NOT EXISTS wan_ts ON wan (ts);
CREATE TABLE IF NOT EXISTS speedtests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    down_mbps  REAL,
    up_mbps    REAL,
    error      TEXT
);
"""

# Details a device reports about itself. Names keep their last known value when a lookup
# misses (NetBIOS/mDNS are UDP and occasionally drop); ping stats always reflect the latest scan.
NAME_COLUMNS = ["netbios_name", "mdns_name", "friendly_name", "vendor", "model", "device_type", "services"]
PING_COLUMNS = ["ttl", "latency_ms", "os_hint"]
STATE_COLUMNS = ["watch", "missed_scans", "alerted", "online_since"]
COLUMN_TYPES = {"ttl": "INTEGER", "latency_ms": "REAL", "watch": "INTEGER NOT NULL DEFAULT 0",
                "missed_scans": "INTEGER NOT NULL DEFAULT 0", "alerted": "INTEGER NOT NULL DEFAULT 0"}

# A watched device must miss this many scans in a row before we alert, so a phone that
# naps through one scan doesn't page you.
OFFLINE_ALERT_AFTER = 2
INTERNET_DOWN_AFTER = 2
HISTORY_DAYS = 30

DEFAULT_SETTINGS = {"notify_desktop": True, "notify_new": True, "notify_offline": True, "notify_internet": True,
                    "webhook_url": "", "speedtest_hours": "3"}  # "0" turns scheduled speed tests off


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ago(**kwargs) -> str:
    return (datetime.now(timezone.utc) - timedelta(**kwargs)).isoformat(timespec="seconds")


def display_name(d: dict) -> str:
    """The name to show a person: their label, else the best name the device reported."""
    if d.get("label") or d.get("discovered_name"):
        return d.get("label") or d["discovered_name"]
    if d.get("vendor"):
        return f"{d['vendor']} device ({d['ip']})"
    return f"Unknown device ({d['ip']})"


def _decorate(d: dict) -> dict:
    for key in ("online", "is_new", "is_self", "watch"):
        d[key] = bool(d[key])
    d["private_mac"] = bool(d["mac"]) and is_private_mac(d["mac"])
    mdns = (d["mdns_name"] or "").removesuffix(".local") or None
    d["discovered_name"] = d["friendly_name"] or mdns or d["netbios_name"] or d["hostname"]
    d["name"] = display_name(d)
    return d


@dataclass
class ScanChanges:
    """What changed in a scan that someone might want to be told about."""
    new: list[dict] = field(default_factory=list)
    offline: list[dict] = field(default_factory=list)  # watched devices that just crossed the alert threshold
    back: list[dict] = field(default_factory=list)     # watched devices back after an offline alert


class DeviceStore:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(devices)")}
            for col in NAME_COLUMNS + PING_COLUMNS + STATE_COLUMNS:
                if col not in existing:
                    self._conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {COLUMN_TYPES.get(col, 'TEXT')}")
            # Backfill online_since for databases from before it existed: the device's last
            # came-online event, or when it was first seen if history doesn't go back that far.
            self._conn.execute(
                """UPDATE devices SET online_since = COALESCE(
                       (SELECT MAX(ts) FROM events e WHERE e.device_id = devices.id AND e.kind IN ('online', 'new')),
                       first_seen)
                   WHERE online = 1 AND online_since IS NULL""")
            self._conn.commit()

    # ------------------------------------------------------------ scans

    def _find(self, result: ScanResult) -> sqlite3.Row | None:
        cur = self._conn.cursor()
        if result.mac:
            row = cur.execute("SELECT * FROM devices WHERE mac = ?", (result.mac,)).fetchone()
            if row:
                return row
        # Fall back to an IP-only record, which gets the MAC attached once we learn it.
        return cur.execute("SELECT * FROM devices WHERE ip = ? AND mac IS NULL", (result.ip,)).fetchone()

    def _event(self, device_id: int | None, ts: str, kind: str, ip: str | None = None) -> None:
        self._conn.execute("INSERT INTO events (device_id, ts, kind, ip) VALUES (?, ?, ?, ?)", (device_id, ts, kind, ip))

    def _device(self, device_id: int) -> dict:
        return _decorate(dict(self._conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()))

    def record_scan(self, results: list[ScanResult], first_run: bool) -> ScanChanges:
        """Upsert scan results, update online/offline state and history, and report what changed.

        On the very first scan nothing is flagged new, since every device would be.
        """
        now = _now()
        changes = ScanChanges()
        seen = []
        with self._lock, self._conn:
            for r in results:
                details = [getattr(r, c) for c in NAME_COLUMNS + PING_COLUMNS]
                row = self._find(r)
                if row:
                    sets = ", ".join([f"{c} = COALESCE(?, {c})" for c in NAME_COLUMNS] + [f"{c} = ?" for c in PING_COLUMNS])
                    # SET expressions see the old row, so `online = 0` here means "was offline until now".
                    self._conn.execute(
                        f"""UPDATE devices SET ip = ?, mac = COALESCE(?, mac), hostname = COALESCE(?, hostname),
                            is_self = ?, online = 1, last_seen = ?, missed_scans = 0, alerted = 0,
                            online_since = CASE WHEN online = 0 OR online_since IS NULL THEN ? ELSE online_since END,
                            {sets} WHERE id = ?""",
                        (r.ip, r.mac, r.hostname, int(r.is_self), now, now, *details, row["id"]),
                    )
                    device_id = row["id"]
                    if not row["online"]:
                        self._event(device_id, now, "online", r.ip)
                    if row["alerted"]:
                        changes.back.append(device_id)
                else:
                    cols = NAME_COLUMNS + PING_COLUMNS
                    cur = self._conn.execute(
                        f"""INSERT INTO devices (mac, ip, hostname, is_self, online, is_new, first_seen, last_seen, online_since, {", ".join(cols)})
                            VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, {", ".join("?" * len(cols))})""",
                        (r.mac, r.ip, r.hostname, int(r.is_self), int(not first_run), now, now, now, *details),
                    )
                    device_id = cur.lastrowid
                    self._event(device_id, now, "online" if first_run else "new", r.ip)
                    if not first_run:
                        changes.new.append(device_id)
                seen.append(device_id)
                self._conn.execute("INSERT INTO samples (device_id, ts, latency_ms) VALUES (?, ?, ?)",
                                   (device_id, now, r.latency_ms))

            placeholders = ",".join("?" * len(seen)) or "NULL"
            missing = self._conn.execute(f"SELECT * FROM devices WHERE id NOT IN ({placeholders})", seen).fetchall()
            for row in missing:
                missed = row["missed_scans"] + 1
                alert = row["watch"] and not row["alerted"] and missed >= OFFLINE_ALERT_AFTER
                self._conn.execute("UPDATE devices SET online = 0, online_since = NULL, missed_scans = ?, alerted = alerted OR ? WHERE id = ?",
                                   (missed, int(alert), row["id"]))
                if row["online"]:
                    self._event(row["id"], now, "offline", row["ip"])
                if alert:
                    changes.offline.append(row["id"])

            self._conn.execute("INSERT OR IGNORE INTO scans (ts) VALUES (?)", (now,))
            self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_scan', ?)", (now,))
            cutoff = _ago(days=HISTORY_DAYS)
            for table in ("scans", "samples", "wan", "events", "speedtests"):
                self._conn.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))

            changes.new = [self._device(i) for i in changes.new]
            changes.offline = [self._device(i) for i in changes.offline]
            changes.back = [self._device(i) for i in changes.back]
        return changes

    def record_wan(self, gateway_ms: float | None, internet_ms: float | None) -> str | None:
        """Store an internet check and return "down" or "up" when the connection changes state."""
        now = _now()
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO wan (ts, gateway_ms, internet_ms) VALUES (?, ?, ?)",
                               (now, gateway_ms, internet_ms))
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'internet_state'").fetchone()
            state = row[0] if row else None
            recent = self._conn.execute("SELECT internet_ms FROM wan ORDER BY id DESC LIMIT ?", (INTERNET_DOWN_AFTER,)).fetchall()
            down = len(recent) == INTERNET_DOWN_AFTER and all(r[0] is None for r in recent)

            new_state = state
            if internet_ms is not None:
                new_state = "up"
            elif down:
                new_state = "down"
            if new_state == state:
                return None
            self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('internet_state', ?)", (new_state,))
            if state is None:
                return None  # first check since install: nothing changed from the user's point of view
            self._event(None, now, f"internet_{new_state}")
            return new_state

    # ------------------------------------------------------------ reads

    def is_empty(self) -> bool:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0

    def _uptime(self, scan_times: list[str], first_seen: str, online_count: int) -> float | None:
        possible = len(scan_times) - bisect.bisect_left(scan_times, first_seen)
        return min(1.0, online_count / possible) if possible else None

    def devices(self) -> list[dict]:
        since = _ago(hours=24)
        with self._lock:
            rows = self._conn.execute("SELECT * FROM devices").fetchall()
            scan_times = [r[0] for r in self._conn.execute("SELECT ts FROM scans WHERE ts >= ? ORDER BY ts", (since,))]
            online = dict(self._conn.execute(
                "SELECT device_id, COUNT(*) FROM samples WHERE ts >= ? GROUP BY device_id", (since,)).fetchall())
        devices = []
        for r in rows:
            d = _decorate(dict(r))
            d["uptime_24h"] = self._uptime(scan_times, max(since, d["first_seen"]), online.get(d["id"], 0))
            devices.append(d)
        return sorted(devices, key=lambda d: tuple(int(p) for p in d["ip"].split(".")))

    def history(self, device_id: int) -> dict | None:
        """Uptime, recent latency and status changes for one device."""
        with self._lock:
            row = self._conn.execute("SELECT first_seen FROM devices WHERE id = ?", (device_id,)).fetchone()
            if not row:
                return None
            result = {}
            for key, window in (("uptime_24h", _ago(hours=24)), ("uptime_7d", _ago(days=7))):
                start = max(window, row["first_seen"])
                scans = [r[0] for r in self._conn.execute("SELECT ts FROM scans WHERE ts >= ? ORDER BY ts", (start,))]
                count = self._conn.execute("SELECT COUNT(*) FROM samples WHERE device_id = ? AND ts >= ?",
                                           (device_id, start)).fetchone()[0]
                result[key] = self._uptime(scans, start, count)
            result["latency"] = [dict(r) for r in self._conn.execute(
                "SELECT ts, latency_ms FROM samples WHERE device_id = ? AND ts >= ? ORDER BY ts", (device_id, _ago(hours=24)))]
            result["events"] = [dict(r) for r in self._conn.execute(
                "SELECT ts, kind, ip FROM events WHERE device_id = ? ORDER BY ts DESC, id DESC LIMIT 15", (device_id,))]
        return result

    def recent_events(self, limit: int = 25) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT e.ts, e.kind, e.ip, e.device_id, d.label, d.friendly_name, d.mdns_name, d.netbios_name,
                          d.hostname, d.vendor
                   FROM events e LEFT JOIN devices d ON d.id = e.device_id
                   ORDER BY e.ts DESC, e.id DESC LIMIT ?""", (limit,)).fetchall()
        events = []
        for r in rows:
            e = dict(r)
            if e["device_id"] is not None:
                mdns = (e["mdns_name"] or "").removesuffix(".local") or None
                e["discovered_name"] = e["friendly_name"] or mdns or e["netbios_name"] or e["hostname"]
                e["name"] = display_name(e)
            events.append({k: e.get(k) for k in ("ts", "kind", "ip", "device_id", "name")})
        return events

    def wan_status(self) -> dict:
        since = _ago(hours=24)
        with self._lock:
            latest = self._conn.execute("SELECT * FROM wan ORDER BY id DESC LIMIT 1").fetchone()
            total, up = self._conn.execute(
                "SELECT COUNT(*), COUNT(internet_ms) FROM wan WHERE ts >= ?", (since,)).fetchone()
            state = self._conn.execute("SELECT value FROM meta WHERE key = 'internet_state'").fetchone()
            latency = [dict(r) for r in self._conn.execute(
                "SELECT ts, internet_ms AS latency_ms FROM wan WHERE ts >= ? ORDER BY ts", (since,))]
        return {
            "state": state[0] if state else None,
            "gateway_ms": latest["gateway_ms"] if latest else None,
            "internet_ms": latest["internet_ms"] if latest else None,
            "uptime_24h": up / total if total else None,
            "latency": latency,
        }

    def record_speedtest(self, down_mbps: float | None, up_mbps: float | None, error: str | None) -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO speedtests (ts, down_mbps, up_mbps, error) VALUES (?, ?, ?, ?)",
                               (_now(), down_mbps, up_mbps, error))

    def latest_speedtest(self) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT ts, down_mbps, up_mbps, error FROM speedtests ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def summary(self) -> dict:
        """Cheap status for the tray icon: device counts and internet state."""
        with self._lock:
            online, total = self._conn.execute("SELECT COUNT(*) FILTER (WHERE online = 1), COUNT(*) FROM devices").fetchone()
            state = self._conn.execute("SELECT value FROM meta WHERE key = 'internet_state'").fetchone()
        return {"online": online, "total": total, "internet": state[0] if state else None}

    def last_scan(self) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'last_scan'").fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------ edits

    def set_label(self, device_id: int, label: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("UPDATE devices SET label = ? WHERE id = ?", (label.strip() or None, device_id))
        return cur.rowcount > 0

    def set_watch(self, device_id: int, watch: bool) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("UPDATE devices SET watch = ?, alerted = 0 WHERE id = ?", (int(watch), device_id))
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
            self._conn.execute("DELETE FROM samples WHERE device_id = ?", (device_id,))
            self._conn.execute("DELETE FROM events WHERE device_id = ?", (device_id,))

    # ------------------------------------------------------------ settings

    def settings(self) -> dict:
        with self._lock:
            rows = dict(self._conn.execute("SELECT key, value FROM meta WHERE key LIKE 'setting:%'").fetchall())
        result = {}
        for key, default in DEFAULT_SETTINGS.items():
            value = rows.get(f"setting:{key}")
            result[key] = default if value is None else (value == "1" if isinstance(default, bool) else value)
        return result

    def update_settings(self, changes: dict) -> dict:
        with self._lock, self._conn:
            for key, value in changes.items():
                if key not in DEFAULT_SETTINGS:
                    continue
                stored = ("1" if value else "0") if isinstance(DEFAULT_SETTINGS[key], bool) else str(value).strip()
                self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (f"setting:{key}", stored))
        return self.settings()
