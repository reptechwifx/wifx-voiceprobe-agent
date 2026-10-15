"""Version shipped with this Agent release, independent of Controller version."""

from pathlib import Path
import sys
import os

RELEASE_DIRECTORY = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
# The private WSL checkout uses a Linux symlink; public exports materialize it.
if os.name == "nt" and not getattr(sys, "frozen", False) and not (RELEASE_DIRECTORY / "VERSION").is_file():
    RELEASE_DIRECTORY = RELEASE_DIRECTORY.parent
VERSION = (RELEASE_DIRECTORY / "VERSION").read_text().strip()
DISPLAY_VERSION = "Bêta " + VERSION

BUILD_ID = (RELEASE_DIRECTORY / 'BUILD_ID').read_text().strip() if (RELEASE_DIRECTORY / 'BUILD_ID').is_file() else None
