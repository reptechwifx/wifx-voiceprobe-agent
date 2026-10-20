#!/usr/bin/env python3
"""Contrôle Windows réel du binding précompilé ; aucun compte SIP ni appel."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if sys.platform != 'win32' or platform.machine().upper() != 'AMD64' or sys.version_info[:2] != (3, 13):
        raise ValueError('Windows AMD64 et Python 3.13 requis pour ce binaire.')
    directory = args.module_dir.resolve()
    sys.path.insert(0, str(directory))
    # Keep the DLL-directory handle alive until libDestroy has completed.
    with os.add_dll_directory(str(directory)):
        import pjsua2 as pj
        if not callable(getattr(pj.Call, 'getVoiceProbeStats', None)):
            raise ValueError('Observateur RTP absent du binding PJSIP Windows.')
        endpoint = pj.Endpoint()
        endpoint.libCreate()
        try:
            config = pj.EpConfig()
            config.uaConfig.threadCnt = 0
            config.uaConfig.mainThreadOnly = True
            config.logConfig.level = 0
            config.logConfig.consoleLevel = 0
            endpoint.libInit(config)
            endpoint.libStart()
            endpoint.audDevManager().setNullDev()
            version = endpoint.libVersion().full
            codecs = sorted(codec.codecId for codec in endpoint.codecEnum2())
            if version != '2.16' or not all(any(value.startswith(name + '/') for value in codecs) for name in ('G722', 'PCMA', 'PCMU')):
                raise ValueError('Version PJSIP ou codecs qualifiés absents.')
            report = {'platform': platform.platform(), 'architecture': platform.machine(), 'python': platform.python_version(), 'pjsip': version, 'codecs': codecs, 'receiver_timing': True, 'playout_observer': True, 'null_audio_device': True, 'lib_create_init_start_destroy': True, 'binding_sha256': hashlib.sha256((directory / '_pjsua2.pyd').read_bytes()).hexdigest()}
        finally:
            endpoint.libDestroy()
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit('Contrôle PJSIP Windows échoué : ' + str(exc))
