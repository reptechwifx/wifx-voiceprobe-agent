#!/usr/bin/env python3
"""Construction Windows AMD64 locale : PJSIP 2.16 / CPython 3.13, aucun build client."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import hashlib
import json
import os
import re
import struct
from pathlib import Path
import subprocess
import tarfile

from pjsip_contract import validate_binding

SOURCE_SHA256 = "3af2e481d51aaa095897820fa2ee26c30e530590c6ca56d23e4133bbdad369eb"
BUILDER = "voiceprobe-agent-windows-pjsip-builder:1.0.0"
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]


def safe_extract(archive, destination):
    with tarfile.open(archive, "r:gz") as source:
        for entry in source.getmembers():
            path = Path(entry.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "pjproject-2.16":
                raise ValueError("Chemin archive PJSIP interdit.")
            if not (entry.isfile() or entry.isdir()):
                raise ValueError("Lien ou type spécial dans l’archive PJSIP.")
        source.extractall(destination, filter="data")


def validate_sdk(sdk):
    if not (sdk / "libs/python313.lib").is_file() or not (sdk / "include/Python.h").is_file():
        raise ValueError("SDK CPython 3.13 Windows AMD64 absent.")
    patchlevel = (sdk / "include/patchlevel.h").read_text()
    if not all(re.search(r"^#define\s+PY_" + key + r"_VERSION\s+" + value + r"\s*$", patchlevel, re.M) for key, value in (("MAJOR", "3"), ("MINOR", "13"))):
        raise ValueError("En-têtes CPython 3.13 requis.")
    runtime = (sdk / "python313.dll").read_bytes()
    if runtime[:2] != b"MZ" or len(runtime) < 64:
        raise ValueError("Runtime PE Windows absent.")
    offset = struct.unpack_from("<I", runtime, 0x3c)[0]
    if offset + 6 > len(runtime) or runtime[offset:offset + 4] != b"PE\0\0" or struct.unpack_from("<H", runtime, offset + 4)[0] != 0x8664:
        raise ValueError("Runtime Windows AMD64 requis.")


def validate_dependencies(header, runtime=False):
    if "pei-x86-64" not in header:
        raise ValueError("Module PE AMD64 attendu.")
    dependencies = [line.split(":", 1)[1].strip() for line in header.splitlines() if "DLL Name:" in line]
    expected = {"python313.dll", "libwinpthread-1.dll", "kernel32.dll", "msvcrt.dll", "ws2_32.dll", "ole32.dll", "winmm.dll", "iphlpapi.dll", "advapi32.dll"}
    observed = {name.lower() for name in dependencies}
    required = {"python313.dll", "libwinpthread-1.dll"}
    if runtime:
        expected = required = {"kernel32.dll", "msvcrt.dll"}
    if not required.issubset(observed) or observed - expected:
        raise ValueError("Dépendance native absente ou inattendue : audit nécessaire.")
    return dependencies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--python-sdk", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("VOICEPROBE_CONTROLLED_BUILD") != "marc-home":
        raise ValueError("Construction réservée au LAB Marc-Home.")
    if hashlib.sha256(args.source.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("Empreinte source PJSIP incorrecte.")
    if args.output.exists() or args.work.exists():
        raise ValueError("Destination existante refusée ; conserver les artefacts immuables.")
    sdk = args.python_sdk.resolve()
    validate_sdk(sdk)
    info = json.loads(subprocess.check_output(DOCKER + ["info", "--format", "{{json .}}"], text=True))
    if info.get("Name") != "docker-desktop":
        raise ValueError("Docker Desktop Marc-Home requis.")
    args.work.mkdir(parents=True, mode=0o700)
    args.output.mkdir(parents=True, mode=0o700)
    safe_extract(args.source, args.work)
    tool = Path(__file__).resolve().parent
    project = tool.parents[1]
    subprocess.run(['python3', str(project/'scripts/instrument-pjsip.py'), str(args.work/'pjproject-2.16'), str(project/'agent/installer/rtp-observer.h')], check=True)
    with (args.work / "build-private.log").open("wb") as log:
        subprocess.run(DOCKER + ["build", "--pull=false", "-t", BUILDER, "-f", str(tool / "Dockerfile.pjsip-cross"), str(tool)], check=True, stdout=log, stderr=subprocess.STDOUT)
        campaign = os.environ.get('VP_STORAGE_CAMPAIGN')
        if not campaign:
            raise ValueError('Campagne de stockage obligatoire pour le compilateur jetable.')
        labels = {'net.wifx.project':'voiceprobe', 'net.wifx.storage.workspace':str(project),
                  'net.wifx.storage.campaign':campaign, 'net.wifx.storage.disposable':'true'}
        command = DOCKER + ["create", "--pull=never", "--network=none", "--user", str(os.getuid())+':'+str(os.getgid())]
        for key, value in labels.items():
            command += ['--label', key+'='+value]
        for source, target, readonly in ((args.work.resolve(), "/build", False), (sdk, "/python", True), (tool / "build-pjsip-cross.sh", "/build-pjsip-cross.sh", True), (args.output.resolve(), "/output", False)):
            command += ["--mount", "type=bind,src=" + str(source) + ",dst=" + target + (",readonly" if readonly else "")]
        command += ["-e", "VOICEPROBE_CONTROLLED_BUILD=marc-home", "-e", "VOICEPROBE_BUILD_UID=" + str(os.getuid()), "-e", "VOICEPROBE_BUILD_GID=" + str(os.getgid()), BUILDER, "bash", "/build-pjsip-cross.sh"]
        cid = subprocess.check_output(command, text=True).strip()
        try:
            subprocess.run(['python3', str(project/'scripts/cleanup-voiceprobe.py'), 'register', '--', 'container', cid], check=True)
            subprocess.run(DOCKER+['start','-a',cid], check=True, stdout=log, stderr=subprocess.STDOUT)
            if json.loads(subprocess.check_output(DOCKER+['inspect',cid]))[0]['State']['ExitCode'] != 0:
                raise ValueError('Compilation Windows échouée.')
        finally:
            subprocess.run(DOCKER+['rm','-f',cid], check=True, stdout=subprocess.DEVNULL)
    # Container-created files belong to root; read-only publication tools can consume them.
    dependencies = validate_dependencies((args.output / "pe-headers.txt").read_text())
    runtime_dependencies = validate_dependencies((args.output / "winpthread-pe-headers.txt").read_text(), runtime=True)
    metadata = {"pjsip": "2.16", "python_abi": "cp313", "architecture": "AMD64", "cpu_baseline": "x86-64 generic", "source_sha256": SOURCE_SHA256, "codecs_required": ["G722", "PCMA", "PCMU"], "calls": 128, "accounts": 32, "sound": "null device", "sip_tls": False, "dependencies": dependencies, "runtime_dependencies": runtime_dependencies, "python_runtime_sha256": hashlib.sha256((sdk / "python313.dll").read_bytes()).hexdigest(), "builder_image": json.loads(subprocess.check_output(DOCKER + ["image", "inspect", BUILDER]))[0]["Id"], "windows_qualified": False, "rtcp_patch_sha256": hashlib.sha256((project/"scripts/instrument-pjsip.py").read_bytes()).hexdigest(), "rtcp_arithmetic": "vp-rtcp-safe-v1", "rtcp_arithmetic_sha256": hashlib.sha256((project/"agent/installer/rtcp-safe.h").read_bytes()).hexdigest(), "rtp_playout_distribution_protocol": 2, "rtp_observer_protocol": 1, "observer_sha256": hashlib.sha256((project/"agent/installer/rtp-observer.h").read_bytes()).hexdigest()}
    (args.output / "binary.json").write_text(json.dumps(metadata, indent=2) + "\n")
    validate_binding(args.output, project)
    checksums = "".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in sorted(args.output.iterdir()) if path.is_file() and path.name != "SHA256SUMS")
    (args.output / "SHA256SUMS").write_text(checksums)
    print("Bibliothèques PE AMD64 construites. Import et tests Windows restent obligatoires.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Construction PJSIP Windows refusée : " + str(exc))
