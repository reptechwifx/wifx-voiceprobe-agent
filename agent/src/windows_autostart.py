"""Per-user startup for an adopted, persistent Windows portable Agent."""

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import uuid


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _name(instance_id):
    if str(uuid.UUID(instance_id)) != instance_id:
        raise ValueError("Invalid portable instance ID")
    return "WIFX Voice Probe " + instance_id


def _directory(instance_id):
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise OSError("Windows user profile unavailable")
    return Path(local) / "WIFX" / "VoiceProbe" / "PortableInstances" / str(uuid.UUID(instance_id))


def _sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def stage(instance_id, executable):
    """Copy the verified personalized EXE before it opens any network socket."""
    if os.name != "nt":
        raise OSError("Windows startup is unavailable")
    _name(instance_id)
    source = Path(executable).resolve(strict=True)
    if source.suffix.lower() != ".exe":
        raise ValueError("Portable executable expected")
    folder = _directory(instance_id)
    folder.mkdir(parents=True, exist_ok=True)
    digest = _sha256(source)
    # Windows firewall rules identify a program by path. Keep this path stable
    # across updates so each new package does not request another exception.
    target = folder / "WIFX-VoiceProbe.exe"
    if not target.exists() or _sha256(target) != digest:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=folder, prefix=".voiceprobe-", suffix=".tmp", delete=False) as output:
                temporary = Path(output.name)
                with source.open("rb") as original:
                    shutil.copyfileobj(original, output)
                output.flush()
                os.fsync(output.fileno())
            if _sha256(temporary) != digest:
                raise OSError("Portable copy failed integrity verification")
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return target


def install(instance_id, executable):
    """Register the staged EXE for this user only after adoption."""
    import winreg

    name = _name(instance_id)
    target = stage(instance_id, executable)
    command = '"' + str(target) + '"'
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        try:
            current, kind = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            current, kind = None, None
        if current != command or kind != winreg.REG_SZ:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
    return target


def remove(instance_id):
    """Remove only this Agent identity's HKCU Run value; preserve other users."""
    if os.name != "nt":
        raise OSError("Windows startup is unavailable")
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, _name(instance_id))
    except FileNotFoundError:
        pass
