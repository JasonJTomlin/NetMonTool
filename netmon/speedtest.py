"""Internet speed test against Cloudflare's public speed endpoints (the ones behind speed.cloudflare.com).

Each direction steps up the transfer size until one transfer takes at least TARGET_SECONDS, so a
slow line isn't stuck on a huge file and a fast line isn't measured on a tiny one (where connection
setup dominates). Cloudflare refuses single downloads of 100 MB, so a line fast enough to finish
the largest size early repeats it until there's TARGET_SECONDS of data.
"""

import logging
import time
import urllib.request
from dataclasses import dataclass

log = logging.getLogger("netmon")

DOWN_URL = "https://speed.cloudflare.com/__down?bytes={}"
UP_URL = "https://speed.cloudflare.com/__up"
DOWN_SIZES = [1_000_000, 10_000_000, 25_000_000]
UP_SIZES = [1_000_000, 5_000_000, 25_000_000]
TARGET_SECONDS = 2.0
MAX_REPEATS = 4  # of the largest size, so a test never moves more than ~125 MB each way
HEADERS = {"User-Agent": "NetMonTool"}


@dataclass
class SpeedResult:
    down_mbps: float | None
    up_mbps: float | None
    error: str | None = None


def _download(size: int) -> tuple[int, float]:
    """Return (bytes, seconds), timed from the first byte so connection setup isn't counted."""
    req = urllib.request.Request(DOWN_URL.format(size), headers=HEADERS)
    with urllib.request.urlopen(req, timeout=60) as resp:
        first = resp.read(65536)
        start, got = time.perf_counter(), 0
        while chunk := resp.read(65536):
            got += len(chunk)
    return got or len(first), max(time.perf_counter() - start, 1e-6)


def _upload(size: int) -> tuple[int, float]:
    req = urllib.request.Request(UP_URL, data=b"0" * size, method="POST",
                                 headers={**HEADERS, "Content-Type": "application/octet-stream"})
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=60) as resp:
        resp.read()
    return size, max(time.perf_counter() - start, 1e-6)


def _measure(transfer, sizes: list[int]) -> float:
    plan = sizes + [sizes[-1]] * (MAX_REPEATS - 1)
    mbps, total_bytes, total_seconds = None, 0, 0.0
    for i, size in enumerate(plan):
        try:
            nbytes, seconds = transfer(size)
        except OSError as e:
            if mbps is None:
                raise
            log.info("Speed test step refused (%s); keeping the result so far", e)
            break
        if i >= len(sizes) - 1:
            # From the largest size on, pool the repeats into one longer sample.
            total_bytes, total_seconds = total_bytes + nbytes, total_seconds + seconds
            mbps = total_bytes * 8 / total_seconds / 1e6
            if total_seconds >= TARGET_SECONDS:
                break
        else:
            mbps = nbytes * 8 / seconds / 1e6
            if seconds >= TARGET_SECONDS:
                break
    return mbps


def run() -> SpeedResult:
    started = time.monotonic()
    try:
        down = _measure(_download, DOWN_SIZES)
        up = _measure(_upload, UP_SIZES)
    except OSError as e:  # includes URLError, HTTPError and timeouts
        log.warning("Speed test failed: %s", e)
        return SpeedResult(None, None, str(getattr(e, "reason", e)))
    log.info("Speed test: %.1f Mbps down, %.1f Mbps up (%.0fs)", down, up, time.monotonic() - started)
    return SpeedResult(round(down, 1), round(up, 1))
