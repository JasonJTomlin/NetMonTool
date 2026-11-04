"""System-tray icon: runs NetMonTool in the background and shows network status at a glance.

The web server runs on a background thread; pystray owns the main thread (some platforms require it).
"""

import logging
import os
import platform
import sys
import threading
import webbrowser
from pathlib import Path
from types import SimpleNamespace

import pystray
from PIL import Image, ImageDraw

log = logging.getLogger("netmon")

IS_WINDOWS = platform.system() == "Windows"
STATUS_COLORS = {"up": (34, 197, 94), "down": (239, 68, 68), None: (148, 163, 184)}
PAUSED_COLOR = (245, 158, 11)
REFRESH_SECONDS = 10

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "NetMonTool.pyw"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "NetMonTool"


def make_icon(color: tuple[int, int, int]) -> Image.Image:
    """A hub-and-spokes network glyph whose hub shows the status colour."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((1, 1, 63, 63), radius=14, fill=(23, 27, 33, 255))
    hub, nodes = (32, 34), [(15, 16), (49, 16), (32, 55)]
    for x, y in nodes:
        d.line((hub, (x, y)), fill=(200, 205, 214, 255), width=4)
    for x, y in nodes:
        d.ellipse((x - 6, y - 6, x + 6, y + 6), fill=(230, 233, 238, 255))
    d.ellipse((hub[0] - 12, hub[1] - 12, hub[0] + 12, hub[1] + 12), fill=(*color, 255))
    return img


# ---------------------------------------------------------------- start with Windows

def launch_command() -> str:
    """Run the launcher with the venv's console-less interpreter, so no window appears at login."""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return f'"{pythonw}" "{LAUNCHER}"'


def autostart_enabled() -> bool:
    if not IS_WINDOWS:
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, RUN_VALUE)
        return True
    except OSError:
        return False


def set_autostart(enabled: bool) -> None:
    """Add or remove this user's login entry (HKCU Run key, so no admin rights are needed)."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, launch_command())
        else:
            try:
                winreg.DeleteValue(key, RUN_VALUE)
            except FileNotFoundError:
                pass
    log.info("Start with Windows %s", "enabled" if enabled else "disabled")


# ---------------------------------------------------------------- tray

def run_tray(ctx: SimpleNamespace, server, url: str) -> None:
    """Serve the dashboard in the background and block on the tray icon until Quit."""
    store, monitor, notifier = ctx.store, ctx.monitor, ctx.notifier
    stop = threading.Event()
    threading.Thread(target=server.run, daemon=True, name="netmon-web").start()

    def refresh(icon: pystray.Icon) -> None:
        s = store.summary()
        internet = {"up": "up", "down": "DOWN", None: "checking"}[s["internet"]]
        title = f"NetMonTool - {s['online']}/{s['total']} online - internet {internet}"
        if notifier.paused:
            title += " - alerts paused"
        # Paused only recolours a healthy icon; an outage stays red so it isn't missed.
        color = PAUSED_COLOR if notifier.paused and s["internet"] != "down" else STATUS_COLORS[s["internet"]]
        if color != getattr(icon, "_netmon_color", None):
            icon.icon = make_icon(color)
            icon._netmon_color = color
        icon.title = title[:127]  # Windows tooltip limit

    def status_loop(icon: pystray.Icon) -> None:
        icon.visible = True
        while not stop.is_set():
            try:
                refresh(icon)
            except Exception:
                log.exception("Tray status update failed")
            stop.wait(REFRESH_SECONDS)

    def toggle_pause(icon, item) -> None:
        notifier.paused = not notifier.paused
        log.info("Alerts %s from the tray", "paused" if notifier.paused else "resumed")
        refresh(icon)

    def toggle_autostart(icon, item) -> None:
        try:
            set_autostart(not autostart_enabled())
        except OSError:
            log.exception("Couldn't change Start with Windows")

    def quit_app(icon, item) -> None:
        stop.set()
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem("Open dashboard", lambda icon, item: webbrowser.open(url), default=True),
        pystray.MenuItem("Scan now", lambda icon, item: monitor.scan_now()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Pause alerts", toggle_pause, checked=lambda item: notifier.paused),
        pystray.MenuItem("Start with Windows", toggle_autostart, checked=lambda item: autostart_enabled(),
                         visible=IS_WINDOWS),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit NetMonTool", quit_app),
    )
    icon = pystray.Icon("NetMonTool", make_icon(STATUS_COLORS[None]), "NetMonTool - starting", menu)
    log.info("Tray icon started; dashboard at %s", url)
    icon.run(setup=status_loop)

    # Let in-flight dashboard requests finish before closing the socket; closing first makes
    # Waitress's worker threads fail on a dead trigger socket and spill tracebacks into the log.
    server.task_dispatcher.shutdown(timeout=3)
    server.close()
    log.info("NetMonTool stopped")
    # Exit now rather than waiting on a network scan's worker pool (up to ~15 s). Every database
    # write is its own transaction, so stopping mid-scan loses at most that scan.
    logging.shutdown()
    os._exit(0)
