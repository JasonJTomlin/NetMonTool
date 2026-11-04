"""Flask web dashboard plus the background thread that rescans the network."""

import ipaddress
import logging
import threading
import time
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from . import scanner
from .store import DeviceStore
from .vendors import VendorDB

log = logging.getLogger("netmon")


class Monitor:
    """Rescans the subnet every `interval` seconds, or immediately when asked."""

    def __init__(self, store: DeviceStore, vendors: VendorDB, subnet: ipaddress.IPv4Network, interval: int):
        self.store, self.vendors, self.subnet, self.interval = store, vendors, subnet, interval
        self.scanning = False
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
                new_ids = self.store.record_scan(results, first_run=self.store.is_empty())
                log.info("Scan of %s: %d online, %d new (%.1fs)",
                         self.subnet, len(results), len(new_ids), time.monotonic() - started)
            except Exception:
                log.exception("Scan failed")
            finally:
                self.scanning = False
            self._wake.wait(self.interval)


def create_app(db_path: Path, subnet: ipaddress.IPv4Network, interval: int) -> Flask:
    app = Flask(__name__)
    store = DeviceStore(str(db_path))
    vendors = VendorDB(db_path.with_name("manuf.txt"))
    monitor = Monitor(store, vendors, subnet, interval)
    monitor.start()

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/devices")
    def devices():
        return jsonify(
            devices=store.devices(),
            last_scan=store.last_scan(),
            scanning=monitor.scanning,
            subnet=str(subnet),
            interval=interval,
        )

    @app.post("/api/scan")
    def scan():
        monitor.scan_now()
        return jsonify(ok=True)

    @app.post("/api/devices/<int:device_id>/label")
    def label(device_id: int):
        if not store.set_label(device_id, (request.get_json(silent=True) or {}).get("label", "")):
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

    return app
