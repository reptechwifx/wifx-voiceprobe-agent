#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Runs inside the local MinGW builder, never on a client.
set -euo pipefail
[[ "${VOICEPROBE_CONTROLLED_BUILD:-}" == marc-home ]] || { echo 'Construction réservée au LAB Marc-Home.' >&2; exit 1; }
[[ -f /python/include/Python.h && -f /python/libs/python313.lib ]] || { echo 'SDK CPython 3.13 AMD64 absent.' >&2; exit 1; }
cd /build/pjproject-2.16
cat > pjlib/include/pj/config_site.h <<'CONFIG'
#define PJSUA_MAX_CALLS 128
#define PJSUA_MAX_ACC 32
#define PJSUA_MAX_CONF_PORTS 512
CONFIG
./configure --host=x86_64-w64-mingw32 --target=x86_64-w64-mingw32 \
    CC=x86_64-w64-mingw32-gcc-posix CXX=x86_64-w64-mingw32-g++-posix \
    CFLAGS='-O2 -march=x86-64 -mtune=generic' CXXFLAGS='-O2 -march=x86-64 -mtune=generic' \
    --disable-video --disable-sound --disable-libyuv --disable-ffmpeg \
    --disable-v4l2 --disable-openh264 --disable-ssl
make dep
make -j"${VOICEPROBE_BUILD_JOBS:-2}" lib
cd pjsip-apps/src/swig/python
# Debian SWIG4.1 has no -doxygen switch; it affects documentation only.
swig -I../../../../pjlib/include -I../../../../pjlib-util/include \
    -I../../../../pjmedia/include -I../../../../pjsip/include \
    -I../../../../pjnath/include -c++ -w312 -threads -python -o pjsua2_wrap.cpp ../pjsua2.i
mapfile -t compile_flags < <(make --no-print-directory -f helper.mak cflags)
mapfile -t link_flags < <(make --no-print-directory -f helper.mak ldflags)
mapfile -t libraries < <(make --no-print-directory -f helper.mak libs)
link_libraries=(); for library in "${libraries[@]}"; do [[ "$library" == stdc++ ]] || link_libraries+=("-l$library"); done
mkdir -p /output
x86_64-w64-mingw32-g++-posix -O2 -march=x86-64 -mtune=generic \
    -I/python/include "${compile_flags[@]}" -c pjsua2_wrap.cpp -o pjsua2_wrap.o
x86_64-w64-mingw32-g++-posix -shared -static-libgcc -static-libstdc++ \
    pjsua2_wrap.o -o /output/_pjsua2.pyd "${link_flags[@]}" \
    "${link_libraries[@]}" /python/libs/python313.lib
x86_64-w64-mingw32-strip --strip-unneeded /output/_pjsua2.pyd
cp pjsua2.py /output/
# POSIX MinGW threads are a redistributable runtime dependency.
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll /output/
cp ../../../../COPYING /output/COPYING.pjsip
x86_64-w64-mingw32-objdump -p /output/_pjsua2.pyd > /output/pe-headers.txt
x86_64-w64-mingw32-objdump -p /output/libwinpthread-1.dll > /output/winpthread-pe-headers.txt
dpkg-query -W -f='${Package}\t${Version}\n' > /output/builder-packages.tsv
cp /usr/share/doc/mingw-w64-common/copyright /output/COPYING.mingw-w64
cp /usr/share/doc/gcc-12-base/copyright /output/COPYING.gcc-runtime
x86_64-w64-mingw32-g++-posix --version > /output/compiler-version.txt
swig -version > /output/swig-version.txt
python3 - <<'PYMETA'
import hashlib,json,pathlib
root=pathlib.Path('/output')
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file() and p.name!='SHA256SUMS'}
(root/'SHA256SUMS').write_text(''.join(digest+'  '+name+'\n' for name,digest in sorted(files.items())))
PYMETA
if [[ "${VOICEPROBE_BUILD_UID:-}" =~ ^[0-9]+$ && "${VOICEPROBE_BUILD_GID:-}" =~ ^[0-9]+$ ]]; then
    chown "$VOICEPROBE_BUILD_UID:$VOICEPROBE_BUILD_GID" /output/*
fi
