"""Version shipped with this Agent release, independent of Controller version."""

from pathlib import Path

VERSION = (Path(__file__).resolve().parents[1] / "VERSION").read_text().strip()
DISPLAY_VERSION = "Bêta " + VERSION

BUILD_ID = (Path(__file__).resolve().parents[1] / 'BUILD_ID').read_text().strip() if (Path(__file__).resolve().parents[1] / 'BUILD_ID').is_file() else None
