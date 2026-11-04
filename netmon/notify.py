"""Deliver alerts as desktop notifications and/or to a chat webhook (Discord, Slack, Teams...)."""

import json
import logging
import os
import platform
import shutil
import subprocess
import threading
import urllib.request
from urllib.parse import urlparse

log = logging.getLogger("netmon")

# Shows a Windows toast using only built-in PowerShell and WinRT, under PowerShell's app id.
# The text arrives through environment variables so it never has to be quoted into the script.
_TOAST_SCRIPT = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$t = [Security.SecurityElement]::Escape($env:NETMON_TITLE)
$b = [Security.SecurityElement]::Escape($env:NETMON_BODY)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
"""


def desktop_notification(title: str, body: str) -> None:
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _TOAST_SCRIPT],
                           env={**os.environ, "NETMON_TITLE": title, "NETMON_BODY": body},
                           capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
        elif system == "Darwin":
            subprocess.run(["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                            "-e", "end run", title, body], capture_output=True, timeout=10, check=True)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", title, body], capture_output=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("Desktop notification failed: %s", e)


def post_webhook(url: str, title: str, body: str) -> None:
    if urlparse(url).scheme not in ("http", "https"):
        log.warning("Ignoring webhook URL that isn't http(s): %s", url)
        return
    # "content" is what Discord reads; "text" is what Slack and Teams read. Each ignores the other.
    payload = json.dumps({"content": f"**{title}**\n{body}", "text": f"*{title}*\n{body}"}).encode()
    req = urllib.request.Request(url, data=payload, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "netmon"})
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except OSError as e:
        log.warning("Webhook delivery failed: %s", e)


class Notifier:
    def __init__(self, settings_source):
        """`settings_source` is a callable returning the current settings dict."""
        self._settings = settings_source

    def send(self, title: str, body: str, kind: str | None = None, wait: bool = False) -> None:
        """Deliver an alert on every enabled channel. `kind` ("new", "offline", "internet") is checked
        against the matching notify_* setting; None always sends (used for test messages)."""
        settings = self._settings()
        if kind and not settings.get(f"notify_{kind}", True):
            return
        log.info("Alert: %s - %s", title, body)
        jobs = []
        if settings["notify_desktop"]:
            jobs.append(threading.Thread(target=desktop_notification, args=(title, body), daemon=True))
        if settings["webhook_url"]:
            jobs.append(threading.Thread(target=post_webhook, args=(settings["webhook_url"], title, body), daemon=True))
        for job in jobs:
            job.start()
        if wait:
            for job in jobs:
                job.join(timeout=20)
