# GHrepoTest — Network Monitor

A small, locally run network monitor with a web dashboard. It scans your local subnet,
discovers devices, and shows each one's online/offline status, IP address, MAC address
and hostname. Devices that show up for the first time are flagged as **NEW**.

Discovery uses only the operating system's `ping` and `arp` commands, so it needs no admin
rights and no packet-capture drivers.

## Setup

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

## Run

```bash
.venv\Scripts\python -m netmon
```

Then open http://127.0.0.1:5000.

| Option | Default | |
|---|---|---|
| `--subnet` | this machine's /24 | Subnet to scan, e.g. `192.168.0.0/24` |
| `--interval` | `60` | Seconds between automatic scans |
| `--host` / `--port` | `127.0.0.1` / `5000` | Where to serve the dashboard. Use `0.0.0.0` to reach it from other devices |
| `--db` | `netmon.db` | SQLite file that remembers devices between runs |

## How it works

- **Discovery:** every address in the subnet is pinged in parallel. A device counts as online
  if it replies, or if pinging it put its MAC address in the ARP cache. Many phones and
  firewalled PCs ignore ping but still answer ARP.
- **Identification:** each online device is asked for its name over NetBIOS (Windows PCs, NAS),
  mDNS/Bonjour (Apple devices, printers, Chromecasts, smart-home gear) and SSDP/UPnP (TVs,
  media players, routers). mDNS can also report the model and the services a device offers.
- **Manufacturer** comes from the MAC address prefix, using Wireshark's vendor list
  (downloaded to `manuf.txt` on first run and refreshed monthly). Phones often use a
  randomized "private" MAC, which has no manufacturer; these are labelled on the dashboard.
- **OS guess and latency** come from the ping reply: the TTL hints at the OS family.
- **Windows Firewall:** on a network set to *Public*, Windows blocks SSDP replies, so UPnP
  devices won't be identified. Setting your home network to *Private* lets them through.
- **MAC addresses** come from the ARP cache, so they're only available for devices on the
  same subnet as this machine (not across routers).
- **Devices are tracked by MAC address**, so a device keeps its name and history when DHCP
  gives it a new IP. Nothing is flagged NEW on the very first scan.
- **On the dashboard** click a device to see everything found about it. You can also rename devices, mark new ones as seen, filter by status, or
  forget a device.
