"""Start NetMonTool in the system tray, with no console window.

Double-click this file, or let "Start with Windows" run it at login. It always runs with the
project's own .venv, so the dependencies are there even if Windows opens it with another Python.
"""

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV_PYTHONW = HERE / ".venv" / "Scripts" / "pythonw.exe"

if VENV_PYTHONW.exists() and Path(sys.prefix).resolve() != (HERE / ".venv").resolve():
    subprocess.Popen([str(VENV_PYTHONW), str(Path(__file__).resolve()), *sys.argv[1:]], cwd=HERE)
    sys.exit()

# Relative paths (netmon.db, manuf.txt, netmon.log) live next to this file, wherever it's started from.
os.chdir(HERE)
sys.path.insert(0, str(HERE))
sys.argv = [sys.argv[0], "--tray", *sys.argv[1:]]

from netmon.__main__ import main  # noqa: E402

main()
