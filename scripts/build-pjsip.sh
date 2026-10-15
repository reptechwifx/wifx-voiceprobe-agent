#!/usr/bin/env bash
set -euo pipefail
if [[ "${VOICEPROBE_CONTROLLED_BUILD:-}" != marc-home ]]; then
 echo 'Construction PJSIP réservée au LAB Marc-Home. Utiliser le binaire qualifié ; aucun fallback source automatique.' >&2
 exit 1
fi
PJSIP_VERSION=2.16
PJSIP_PREFIX=${VOICEPROBE_PJSIP_PREFIX:-/opt/voiceprobe/pjsip}
PYTHON_EXEC=${VOICEPROBE_PYTHON:-/opt/voiceprobe/venv/bin/python}
BUILD_DIR=${VOICEPROBE_BUILD_DIR:-/var/tmp/voiceprobe-pjsip-build}
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
if [[ ! -f pjproject-2.16.tar.gz ]];then
 curl --proto '=https' --proto-redir '=https' --retry 3 --retry-all-errors -fsSL https://codeload.github.com/pjsip/pjproject/tar.gz/refs/tags/2.16 -o pjproject-2.16.tar.gz
fi
echo '3af2e481d51aaa095897820fa2ee26c30e530590c6ca56d23e4133bbdad369eb  pjproject-2.16.tar.gz' | sha256sum -c -
tar xzf pjproject-2.16.tar.gz
cd pjproject-2.16
printf '#define PJSUA_MAX_CALLS 128\n#define PJSUA_MAX_ACC 32\n#define PJSUA_MAX_CONF_PORTS 512\n' > pjlib/include/pj/config_site.h
./configure --prefix="$PJSIP_PREFIX" CFLAGS='-fPIC -O2 -march=x86-64 -mtune=generic' CXXFLAGS='-fPIC -O2 -march=x86-64 -mtune=generic' --disable-video --disable-sound --disable-libyuv --disable-ffmpeg --disable-v4l2 --disable-openh264
make dep
make -j"${VOICEPROBE_BUILD_JOBS:-2}"
make install
cd pjsip-apps/src/swig/python
PATH="$(dirname "$PYTHON_EXEC"):$PATH" make
"$PYTHON_EXEC" setup.py install
"$PYTHON_EXEC" -c 'import pjsua2; print("PJSUA2 binding available")'

install -d -m 0755 "$PJSIP_PREFIX"
printf '%s\n' '2.16;calls=128;accounts=32;conf_ports=512' > "$PJSIP_PREFIX/voiceprobe-build.txt"
