"""Flask web dashboard plus the background thread that rescans the network and raises alerts."""

import ipaddress
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from flask import Flask, abort, jsonify, render_template, request

from . import scanner, speedtest
from .notify import Notifier
from .store import HISTORY_DAYS, DeviceStore, ScanChanges
from .vendors import VendorDB

log = logging.getLogger("netmon")


class Monitor:
    """Rescans the subnet every `interval` seconds, or immediately when asked."""

    def __init__(self, store: DeviceStore, vendors: VendorDB, notifier: Notifier,
                 subnet: ipaddress.IPv4Network, interval: int):
        self.store, self.vendors, self.notifier = store, vendors, notifier
        self.subnet, self.interval = subnet, interval
        self.scanning = False
        self.gateway: str | None = None
        self._wake = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True, name="netmon-scanner").start()

    def scan_now(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        self.scanning = True
        self.vendors.load()
        while True:
            self._wake.clear()
            self.scanning = True
            try:
                started = time.monotonic()
                results = scanner.scan(self.subnet, self.vendors)
                changes = self.store.record_scan(results, first_run=self.store.is_empty())
                log.info("Scan of %s: %d online, %d new (%.1fs)",
                         self.subnet, len(results), len(changes.new), time.monotonic() - started)
                self._alert_devices(changes)
                self._check_internet()
            except Exception:
                log.exception("Scan failed")
            finally:
                self.scanning = False
            self._wake.wait(self.interval)

    def _check_internet(self) -> None:
        self.gateway = scanner.default_gateway() or self.gateway
        gateway_reply = scanner.ping(self.gateway) if self.gateway else None
        change = self.store.record_wan(gateway_reply.latency_ms if gateway_reply else None, scanner.internet_latency())
        if change == "down":
            router = "Your router is reachable, so the problem is likely your internet provider." if gateway_reply else \
                     "Your router isn't answering either."
            self.notifier.send("Internet connection down", router, kind="internet")
        elif change == "up":
            self.notifier.send("Internet connection restored", "Your internet connection is back.", kind="internet")

    def _alert_devices(self, changes: ScanChanges) -> None:
        if len(changes.new) > 3:
            names = ", ".join(d["name"] for d in changes.new[:5])
            self.notifier.send(f"{len(changes.new)} new devices joined your network", names, kind="new")
        else:
            for d in changes.new:
                self.notifier.send("New device on your network", f"{d['name']} · {d['ip']} · {d['mac'] or 'no MAC'}", kind="new")
        for d in changes.offline:
            self.notifier.send("Device offline", f"{d['name']} ({d['ip']}) has gone offline.", kind="offline")
        for d in changes.back:
            self.notifier.send("Device back online", f"{d['name']} ({d['ip']}) is back online.", kind="offline")


class SpeedTester:
    """Runs an internet speed test every `speedtest_hours` (a setting), or at once when asked.

    It has its own thread so a 10-20 s test never delays a network scan.
    """

    # Recheck at least this often, so a changed interval takes effect within a minute.
    RECHECK_SECONDS = 60

    def __init__(self, store: DeviceStore):
        self.store = store
        self.running = False
        self._wake = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True, name="netmon-speedtest").start()

    def run_now(self) -> None:
        self._wake.set()

    def interval_hours(self) -> float:
        try:
            return max(0.0, float(self.store.settings()["speedtest_hours"]))
        except ValueError:
            return 0.0

    def _seconds_until_due(self) -> float:
        hours = self.interval_hours()
        if not hours:
            return self.RECHECK_SECONDS
        last = self.store.latest_speedtest()
        if not last:
            return 0
        due = datetime.fromisoformat(last["ts"]) + timedelta(hours=hours)
        return min(self.RECHECK_SECONDS, max(0.0, (due - datetime.now(timezone.utc)).total_seconds()))

    def _run(self) -> None:
        time.sleep(30)  # let the first network scan finish before using the bandwidth
        while True:
            woken = self._wake.wait(self._seconds_until_due())
            self._wake.clear()
            if not (woken or (self.interval_hours() and self._seconds_until_due() == 0)):
                continue
            self.running = True
            try:
                result = speedtest.run()
                self.store.record_speedtest(result.down_mbps, result.up_mbps, result.error)
            except Exception:
                log.exception("Speed test crashed")
            finally:
                self.running = False


def create_app(db_path: Path, subnet: ipaddress.IPv4Network, interval: int) -> Flask:
    app = Flask(__name__)
    store = DeviceStore(str(db_path))
    vendors = VendorDB(db_path.with_name("manuf.txt"))
    notifier = Notifier(store.settings)
    monitor = Monitor(store, vendors, notifier, subnet, interval)
    monitor.start()
    speed = SpeedTester(store)
    speed.start()
    # The tray icon reads status and triggers scans through these.
    app.extensions["netmon"] = SimpleNamespace(store=store, monitor=monitor, notifier=notifier, speed=speed)

    def body() -> dict:
        return request.get_json(silent=True) or {}

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/devices")
    def devices():
        return jsonify(
            devices=store.devices(),
            wan=store.wan_status() | {"gateway": monitor.gateway},
            speed={"latest": store.latest_speedtest(), "running": speed.running, "interval_hours": speed.interval_hours()},
            last_scan=store.last_scan(),
            scanning=monitor.scanning,
            subnet=str(subnet),
            interval=interval,
        )

    @app.get("/api/devices/<int:device_id>/history")
    def history(device_id: int):
        result = store.history(device_id)
        if result is None:
            abort(404)
        return jsonify(result)

    @app.get("/api/events")
    def events():
        return jsonify(events=store.recent_events(min(request.args.get("limit", 25, type=int), 200)))

    @app.get("/api/internet")
    def internet_history():
        days = min(max(request.args.get("days", 7, type=float), 1 / 24), HISTORY_DAYS)
        return jsonify(store.internet_history(days) | {
            "days": days, "gateway": monitor.gateway, "targets": scanner.INTERNET_TARGETS, "interval": interval,
        })

    @app.get("/api/speedtests")
    def speedtest_history():
        days = min(max(request.args.get("days", 7, type=float), 1 / 24), HISTORY_DAYS)
        return jsonify(tests=store.speedtests(days), days=days, interval_hours=speed.interval_hours())

    @app.post("/api/speedtest")
    def speedtest_now():
        speed.run_now()
        return jsonify(ok=True)

    @app.post("/api/scan")
    def scan():
        monitor.scan_now()
        return jsonify(ok=True)

    @app.post("/api/devices/<int:device_id>/label")
    def label(device_id: int):
        if not store.set_label(device_id, body().get("label", "")):
            abort(404)
        return jsonify(ok=True)

    @app.post("/api/devices/<int:device_id>/watch")
    def watch(device_id: int):
        if not store.set_watch(device_id, bool(body().get("watch"))):
            abort(404)
        return jsonify(ok=True)

    @app.post("/api/devices/<int:device_id>/ack")
    def ack(device_id: int):
        store.acknowledge(device_id)
        return jsonify(ok=True)

    @app.post("/api/devices/ack")
    def ack_all():
        store.acknowledge()
        return jsonify(ok=True)

    @app.delete("/api/devices/<int:device_id>")
    def forget(device_id: int):
        store.forget(device_id)
        return jsonify(ok=True)

    @app.get("/api/settings")
    def get_settings():
        return jsonify(store.settings())

    @app.post("/api/settings")
    def set_settings():
        return jsonify(store.update_settings(body()))

    @app.post("/api/notify/test")
    def test_notification():
        notifier.send("Network Monitor test", "Alerts are working.", wait=True)
        return jsonify(ok=True)

    return app
