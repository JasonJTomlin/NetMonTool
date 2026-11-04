import argparse
import ipaddress
import logging
from pathlib import Path

from . import scanner
from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="netmon", description="Local network device monitor")
    parser.add_argument("--subnet", help="Subnet to scan, e.g. 192.168.0.0/24 (default: this machine's /24)")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between scans (default: 60)")
    parser.add_argument("--host", default="127.0.0.1", help="Address to serve the dashboard on (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--db", default="netmon.db", help="SQLite database file (default: netmon.db)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    subnet = ipaddress.ip_network(args.subnet, strict=False) if args.subnet else scanner.default_subnet()
    if subnet.num_addresses > 4096:
        parser.error(f"{subnet} has {subnet.num_addresses} addresses; use a /20 or smaller")

    app = create_app(Path(args.db), subnet, args.interval)
    print(f"Monitoring {subnet} - dashboard at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
