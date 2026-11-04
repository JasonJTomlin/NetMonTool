# NetMonTool — Network Monitor

A small, locally run network monitor with a web dashboard. It scans your local subnet, works
out what each device is, tracks whether it's online, and alerts you when something changes.

- **Discovers devices** with their IP address, MAC address, manufacturer and, where the device
  reports one, its name and model.
- **Tracks status:** online/offline, latency, 24-hour and 7-day uptime, and a log of changes.
- **Watches your connection:** checks the router and the internet on every scan, and tests
  download/upload speed on a schedule you choose (every 15 minutes to once a day) or on
  demand. Click the *Internet speed* box for a chart and history of your speeds over time.
- **Alerts** when a new device joins, a device you're watching goes offline, or the internet
  drops. Alerts arrive as Windows desktop notifications and/or in Discord, Slack or Teams.

It needs no admin rights or packet-capture drivers, and runs quietly in the system tray.

## Setup

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

## Run

**In the background (recommended):** double-click `NetMonTool.pyw`. A NetMonTool icon appears in
the system tray, with no console window. Its colour shows internet status (green up, red down,
amber alerts paused), and hovering shows how many devices are online. Right-click it for
*Open dashboard*, *Scan now*, *Pause alerts*, *Start with Windows* and *Quit*. Logs go to
`netmon.log`.

**In a terminal:**

```bash
.venv\Scripts\python -m netmon
```

Either way, the dashboard is at http://127.0.0.1:5000. Click a device to see everything found
about it, use the bell to watch it, and set up alerts and the speed-test schedule with the *Settings…* button. Only one copy
runs at a time; starting a second tray copy just opens the dashboard.

| Option | Default | |
|---|---|---|
| `--subnet` | this machine's /24 | Subnet to scan, e.g. `192.168.0.0/24` |
| `--interval` | `60` | Seconds between automatic scans |
| `--host` / `--port` | `127.0.0.1` / `5000` | Where to serve the dashboard. Use `0.0.0.0` to reach it from other devices |
| `--db` | `netmon.db` | SQLite file that remembers devices between runs |
| `--tray` | off | Run with a tray icon instead of in the terminal (what `NetMonTool.pyw` does) |

On first run the app downloads Wireshark's MAC vendor list (about 3 MB) to `manuf.txt`.

**Windows tip:** if your network is set to *Public*, the firewall blocks UPnP replies, so TVs
and media players may not be identified. Setting your home network to *Private* can help.

## How it works

See [docs/DESIGN.md](docs/DESIGN.md) for the architecture, how devices are identified, the data
model, alert rules, the API, and known limitations.
