import argparse
import ipaddress
import logging
import logging.handlers
import socket
import webbrowser
from pathlib import Path

from waitress.server import create_server

from . import scanner
from .app import create_app
from .notify import desktop_notification

log = logging.getLogger("netmon")


def already_running(host: str, port: int) -> bool:
    """True if something is already answering on the dashboard port (usually another netmon)."""
    target = "127.0.0.1" if host in ("0.0.0.0", "") else host
    try:
        with socket.create_connection((target, port), timeout=0.5):
            return True
    except OSError:
        return False


def setup_logging(tray: bool, log_path: Path) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Tray mode runs under pythonw with no console, so log to a small rotating file instead.
    handler = (logging.handlers.RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=2, encoding="utf-8")
               if tray else logging.StreamHandler())
    handler.setFormatter(fmt)
    logging.basicConfig(level=logging.INFO, handlers=[handler])


def main() -> None:
    parser = argparse.ArgumentParser(prog="netmon", description="Local network device monitor")
    parser.add_argument("--subnet", help="Subnet to scan, e.g. 192.168.0.0/24 (default: this machine's /24)")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between scans (default: 60)")
    parser.add_argument("--host", default="127.0.0.1", help="Address to serve the dashboard on (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--db", default="netmon.db", help="SQLite database file (default: netmon.db)")
    parser.add_argument("--tray", action="store_true", help="Run in the background with a system-tray icon")
    args = parser.parse_args()

    db = Path(args.db).resolve()
    setup_logging(args.tray, db.with_name("netmon.log"))
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '') else args.host}:{args.port}"

    if already_running(args.host, args.port):
        if args.tray:
            # Launched again (e.g. a second double-click): bring up the running dashboard, and say
            # why, since the copy that's running may be a terminal one with no tray icon.
            log.info("Already running at %s; opening the dashboard instead", url)
            webbrowser.open(url)
            desktop_notification("NetMonTool is already running",
                                 f"Opened its dashboard. To start the tray icon, first quit the copy using {url}.")
            return
        parser.exit(1, f"Something is already running at {url} (another NetMonTool?). Use --port to pick another.\n")

    subnet = ipaddress.ip_network(args.subnet, strict=False) if args.subnet else scanner.default_subnet()
    if subnet.num_addresses > 4096:
        parser.error(f"{subnet} has {subnet.num_addresses} addresses; use a /20 or smaller")

    app = create_app(db, subnet, args.interval)
    server = create_server(app, host=args.host, port=args.port, threads=8)

    if args.tray:
        from .tray import run_tray
        log.info("Monitoring %s", subnet)
        run_tray(app.extensions["netmon"], server, url)
    else:
        print(f"Monitoring {subnet} - dashboard at {url} (Ctrl+C to stop)")
        try:
            server.run()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
