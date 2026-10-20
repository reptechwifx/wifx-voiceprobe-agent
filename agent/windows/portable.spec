# GPL-3.0-or-later. Build on Windows only; roots explicitly supplied by build-portable.ps1.
import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_dynamic_libs
root = Path(SPECPATH).parent.parent
sdk = Path(os.environ['VOICEPROBE_WINDOWS_SDK'])
trust = Path(os.environ['VOICEPROBE_WINDOWS_TRUST'])
qa = os.environ.get('VOICEPROBE_WINDOWS_CONSOLE') == '1'
data = [(str(root/'agent/windows/release/VERSION'), '.'), (str(root/'agent/windows/assets'), 'assets'), (str(trust/'provisioning-public.pem'), '.'), (str(trust/'build-trust.json'), '.')]
if (trust/'lab-ca.crt').is_file():
    data.append((str(trust/'lab-ca.crt'), '.'))
a = Analysis([str(root/'agent/windows/portable-entry.py')],
    pathex=[str(root/'agent/src'), str(root/'agent/windows'), str(sdk)],
    binaries=[(str(p), '.') for p in sorted(sdk.glob('*.dll'))] + [(str(p), '.') for p in sdk.glob('_pjsua2*.pyd')],
    datas=data,
    hiddenimports=['pjsua2', '_pjsua2', 'portable_agent', 'portable_runtime', 'portable_gui', 'portable_package', 'windows_identity', 'windows_autostart', 'portable_memory', 'windows_icmp_diagnostics', 'numpy', 'cryptography', 'psutil'],
    excludes=['gateway', 'tkinter', 'unittest', 'pip', 'setuptools'],
    noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [],
    name='WIFX-VoiceProbe-QA' if qa else 'WIFX-VoiceProbe',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=qa, disable_windowed_traceback=True, uac_admin=False,
    icon=str(root/'agent/windows/assets/wifx.ico'))
