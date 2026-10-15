#!/usr/bin/env bash
set -euo pipefail
[[ "${VOICEPROBE_CONTROLLED_BUILD:-}" == marc-home ]] || { echo 'Parcours source réservé au LAB Marc-Home ; utiliser la distribution binaire signée.' >&2; exit 1; }
umask 077
trap 'echo "Voice Probe installation failed at line $LINENO; existing identity/configuration preserved" >&2' ERR
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_ARGS=("$@")
CONFIG_SOURCE=""; CONTAINER_MODE=0; CHECK_ONLY=0; ASK_PASSWORD=0
PASSWORD_FILE=""; ARCHIVE=""; ARCHIVE_URL=""; CHECKSUM=""; EXPECTED_VERSION=""; READ_AUTH_FILE=""
while (($#)); do
 case "$1" in
  --config|--password-file|--archive|--archive-url|--sha256|--expected-version|--read-auth-file)
   (($# >= 2)) || { echo "Missing value for $1" >&2; exit 2; }
   case "$1" in
    --config) CONFIG_SOURCE="$2";; --password-file) PASSWORD_FILE="$2";; --archive) ARCHIVE="$2";; --archive-url) ARCHIVE_URL="$2";; --sha256) CHECKSUM="$2";; --expected-version) EXPECTED_VERSION="$2";; --read-auth-file) READ_AUTH_FILE="$2";;
   esac
   shift 2;;
  --ask-password) ASK_PASSWORD=1; shift;;
  --container) CONTAINER_MODE=1; shift;;
  --check) CHECK_ONLY=1; shift;;
  *) echo 'Usage: install-agent.sh [--check] [--container] [--ask-password|--password-file protected-file] [--config protected-json] [--archive file|--archive-url HTTPS-URL --sha256 trusted-SHA] [--expected-version version] [--read-auth-file protected-netrc]' >&2; exit 2;;
 esac
done
[[ -f /etc/os-release ]] || { echo 'Unsupported OS: /etc/os-release missing' >&2; exit 1; }
. /etc/os-release
case "$ID ${ID_LIKE:-}" in
 *debian*|*raspbian*|ubuntu*) ;;
 *) echo "Debian-compatible apt distribution required: $ID" >&2; exit 1;;
esac
major=${VERSION_ID%%.*}
case "$ID" in
 ubuntu) [[ "$VERSION_ID" == 24.04 ]] || { echo 'Ubuntu 24.04 LTS required for the qualified Ubuntu installer' >&2; exit 1; };;
 *) [[ "$major" =~ ^[0-9]+$ && "$major" -ge 12 ]] || { echo 'Debian-compatible version 12 or newer required' >&2; exit 1; };;
esac
ARCH=$(uname -m)
case "$ARCH" in x86_64|aarch64) ;; *) echo "Unsupported architecture: $ARCH (AMD64/ARM64 required)" >&2; exit 1;; esac
command -v apt-get >/dev/null || { echo 'apt-get required' >&2; exit 1; }
SYSTEMD=0
if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then SYSTEMD=1; fi
printf 'Distribution: %s %s; architecture: %s; systemd active: %s; root: %s; sudo available: ' "$ID" "$VERSION_ID" "$ARCH" "$SYSTEMD" "$((EUID == 0))"
if command -v sudo >/dev/null; then echo yes; else echo no; fi
if ((CHECK_ONLY)); then exit 0; fi
if [[ "$EUID" -ne 0 ]]; then
 command -v sudo >/dev/null || { echo 'Run as root; sudo unavailable' >&2; exit 1; }
 exec sudo -- "$0" "${INSTALL_ARGS[@]}"
fi
if ((!CONTAINER_MODE && !SYSTEMD)); then echo 'No active systemd. Use --container for an explicit supervised/container installation; automatic native startup requires systemd.' >&2; exit 1; fi
if ((ASK_PASSWORD)) && [[ -n "$PASSWORD_FILE" ]]; then echo 'Choose --ask-password or --password-file' >&2; exit 2; fi
for protected in "$CONFIG_SOURCE" "$PASSWORD_FILE" "$READ_AUTH_FILE"; do
 if [[ -n "$protected" ]]; then
  [[ -f "$protected" && ! -L "$protected" ]] || { echo 'Protected input missing or symlink' >&2; exit 1; }
  perm=$(stat -c '%a' "$protected")
  [[ "$perm" == 600 || "$perm" == 400 ]] || { echo 'Protected inputs require mode 0600 or 0400' >&2; exit 1; }
 fi
done
export DEBIAN_FRONTEND=noninteractive
if [[ -n "$ARCHIVE" || -n "$ARCHIVE_URL" ]]; then
 [[ -n "$CHECKSUM" && "$CHECKSUM" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'Trusted out-of-band --sha256 required' >&2; exit 1; }
 [[ -z "$ARCHIVE" || -z "$ARCHIVE_URL" ]] || { echo 'Choose archive OR HTTPS URL' >&2; exit 2; }
 apt-get update
 apt-get install -y --no-install-recommends python3 curl ca-certificates
 workspace=$(mktemp -d /var/tmp/voiceprobe-distribution-XXXXXX)
 trap 'rm -rf -- "$workspace"' EXIT
 if [[ -n "$ARCHIVE_URL" ]]; then
  python3 - "$ARCHIVE_URL" <<'PY'
from urllib.parse import urlsplit
import sys
u=urlsplit(sys.argv[1]);assert u.scheme=='https' and u.hostname and not u.username and not u.password and not u.query and not u.fragment, 'HTTPS URL without embedded credentials/parameters required'
PY
  auth=(); if [[ -n "$READ_AUTH_FILE" ]]; then auth=(--netrc-file "$READ_AUTH_FILE"); fi
  curl --proto '=https' --proto-redir '=https' --fail --silent --show-error --location --max-redirs 0 "${auth[@]}" "$ARCHIVE_URL" -o "$workspace/agent.tar.gz"
  ARCHIVE="$workspace/agent.tar.gz"
 fi
 python3 "$ROOT/scripts/agent-distribution.py" extract "$ARCHIVE" "$workspace/extracted" --sha256 "$CHECKSUM"
 extracted=("$workspace"/extracted/voiceprobe-agent-*)
 forwarded=()
 ((CONTAINER_MODE)) && forwarded+=(--container)
 ((ASK_PASSWORD)) && forwarded+=(--ask-password)
 [[ -z "$PASSWORD_FILE" ]] || forwarded+=(--password-file "$PASSWORD_FILE")
 [[ -z "$CONFIG_SOURCE" ]] || forwarded+=(--config "$CONFIG_SOURCE")
 [[ -z "$EXPECTED_VERSION" ]] || forwarded+=(--expected-version "$EXPECTED_VERSION")
 bash "${extracted[0]}/scripts/install-agent.sh" "${forwarded[@]}"
 exit 0
fi
if ! command -v python3 >/dev/null; then
 apt-get update
 apt-get install -y --no-install-recommends python3 ca-certificates
fi
validation=(); [[ -z "$EXPECTED_VERSION" ]] || validation=(--version "$EXPECTED_VERSION")
python3 "$ROOT/scripts/agent-distribution.py" validate "$ROOT" "${validation[@]}"
if ((SYSTEMD && !CONTAINER_MODE)) && ! systemctl is-active --quiet voiceprobe-agent.service; then
 python3 - <<'PORT_PY'
import json,pathlib,socket
p=pathlib.Path('/var/lib/voiceprobe/config.json');c=json.loads(p.read_text()) if p.is_file() else {}
with socket.socket() as probe:
 try:probe.bind((c.get('bind','0.0.0.0'),c.get('port',18441)))
 except OSError:raise SystemExit('Port de gestion occupé : conserver le service existant et choisir une installation distincte. Aucune ressource ne sera arrêtée.')
PORT_PY
fi
apt-get update
apt-get install -y --no-install-recommends python3 python3-dev python3-venv python3-setuptools python3-requests python3-websockets python3-numpy ca-certificates openssl curl build-essential pkg-config swig libssl-dev libasound2-dev libopus-dev iproute2
install -d -m 0755 /opt/voiceprobe
if [[ ! -x /opt/voiceprobe/venv/bin/python ]]; then python3 -m venv --system-site-packages /opt/voiceprobe/venv; fi
if [[ ! -f /opt/voiceprobe/pjsip/voiceprobe-build.txt ]] || ! /opt/voiceprobe/venv/bin/python -c 'import pjsua2 as p; assert p.Endpoint().libVersion().full == "2.16" and p.__file__.startswith("/opt/voiceprobe/venv/")' 2>/dev/null; then
 "$ROOT/scripts/build-pjsip.sh"
fi
# Software is public-readable; only runtime identities/configuration stay private.
chmod -R a+rX /opt/voiceprobe/venv /opt/voiceprobe/pjsip
id voiceprobe >/dev/null 2>&1 || useradd --system --home-dir /var/lib/voiceprobe --shell /usr/sbin/nologin voiceprobe
runuser -u voiceprobe -- /opt/voiceprobe/venv/bin/python -c 'import pjsua2 as p; assert p.Endpoint().libVersion().full == "2.16"'
install -d -m 0755 /opt/voiceprobe/releases /opt/voiceprobe/admin
install -d -o voiceprobe -g voiceprobe -m 0700 /var/lib/voiceprobe
RELEASE=$(python3 - "$ROOT" <<'PY'
import hashlib,pathlib,sys
r=pathlib.Path(sys.argv[1]);files=[r/'VERSION']+[p for d in ['agent/src','agent/web'] for p in (r/d).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
if (r/'agent/BUILD_ID').is_file():files.append(r/'agent/BUILD_ID')
h=hashlib.sha256()
for p in sorted(files):h.update(str(p.relative_to(r)).encode()+b'\0'+p.read_bytes()+b'\0')
print(h.hexdigest()[:16])
PY
)
DEST=/opt/voiceprobe/releases/$RELEASE
if [[ ! -d "$DEST" ]]; then
 python3 - "$ROOT" "$DEST" "$RELEASE" <<'PY'
import pathlib,shutil,sys
r,d,release=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3]
d.mkdir(mode=0o755);(d/'agent').mkdir(mode=0o755)
for part in ['src','web']:shutil.copytree(r/'agent'/part,d/'agent'/part,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
shutil.copyfile(r/'VERSION',d/'agent/VERSION')
shutil.copyfile(r/'agent/BUILD_ID',d/'agent/BUILD_ID') if (r/'agent/BUILD_ID').is_file() else (d/'agent/BUILD_ID').write_text(release+'\n')
PY
 chmod -R a+rX "$DEST"
fi
if [[ ! -f /var/lib/voiceprobe/config.json ]]; then
 if [[ -n "$CONFIG_SOURCE" ]]; then
  install -o voiceprobe -g voiceprobe -m 0600 "$CONFIG_SOURCE" /var/lib/voiceprobe/config.json
 else
  passwords=(); ((ASK_PASSWORD)) && passwords=(--ask-password); [[ -z "$PASSWORD_FILE" ]] || passwords=(--password-file "$PASSWORD_FILE")
  python3 "$ROOT/scripts/configure-agent.py" /var/lib/voiceprobe/config.json "${passwords[@]}"
 fi
fi
python3 - <<'PY'
import json,pathlib,shutil,os,pwd,sys
p=pathlib.Path('/var/lib/voiceprobe/config.json');before=json.loads(p.read_text());c=dict(before);user=pwd.getpwnam('voiceprobe')
c['installation_type']='native'
for key in ('ca_file','tls_cert','tls_key'):
 if c.get(key) and c[key]!='/etc/ssl/certs/ca-certificates.crt':
  tls=p.parent/'tls';tls.mkdir(mode=0o700,exist_ok=True);os.chown(tls,user.pw_uid,user.pw_gid)
  source=pathlib.Path(c[key])
  if source.resolve().is_relative_to(p.parent.resolve()):
   continue
  target=tls/(key+'.pem')
  if source!=target:shutil.copyfile(source,target)
  target.chmod(0o600);os.chown(target,user.pw_uid,user.pw_gid);c[key]=str(target)
if c!=before:p.write_text(json.dumps(c,ensure_ascii=False,indent=2))
p.chmod(0o600);os.chown(p,user.pw_uid,user.pw_gid)
if c.get('identity_private_key'):os.chown(c['identity_private_key'],user.pw_uid,user.pw_gid)
PY
python3 "$ROOT/scripts/validate-agent-config.py" /var/lib/voiceprobe/config.json
install -m 0644 "$ROOT/scripts/reset-agent-password.py" /opt/voiceprobe/admin/reset-agent-password.py
previous=""; [[ ! -L /opt/voiceprobe/current ]] || previous=$(readlink /opt/voiceprobe/current)
if [[ "$previous" != "$DEST" ]]; then
 [[ -z "$previous" ]] || printf '%s\n' "$previous" > /opt/voiceprobe/previous-release
 ln -sfn "$DEST" /opt/voiceprobe/current.new
 mv -Tf /opt/voiceprobe/current.new /opt/voiceprobe/current
fi
install -d -m 0755 /etc/systemd/system
unit_changed=0
if ! cmp -s "$ROOT/infrastructure/agent/voiceprobe-agent.service" /etc/systemd/system/voiceprobe-agent.service; then
 install -m 0644 "$ROOT/infrastructure/agent/voiceprobe-agent.service" /etc/systemd/system/voiceprobe-agent.service; unit_changed=1
fi
if ((SYSTEMD && !CONTAINER_MODE)); then
 systemctl daemon-reload
 systemctl enable voiceprobe-agent.service
 if [[ "$previous" != "$DEST" ]] || ((unit_changed)); then systemctl restart voiceprobe-agent.service; else systemctl start voiceprobe-agent.service; fi
 systemctl is-active --quiet voiceprobe-agent.service
 systemctl is-enabled --quiet voiceprobe-agent.service
 python3 - <<'PY'
import http.client,json,ssl,time
c=json.load(open('/var/lib/voiceprobe/config.json'));tls=bool(c.get('tls_cert'));ok=False
for _ in range(30):
 try:
  conn=http.client.HTTPSConnection('127.0.0.1',c.get('port',18441),context=ssl.create_default_context(cafile=c['tls_cert']),timeout=2) if tls else http.client.HTTPConnection('127.0.0.1',c.get('port',18441),timeout=2)
  conn.request('GET','/login');response=conn.getresponse();response.read();ok=response.status==200;conn.close()
  if ok:break
 except OSError:pass
 time.sleep(1)
if not ok:raise SystemExit('Service actif mais interface locale indisponible ; vérifier journalctl -u voiceprobe-agent')
PY
 service_state=Actif
else
 service_state='Installé ; lancement explicite nécessaire dans ce conteneur'
fi
info=(); ((CONTAINER_MODE)) && info+=(--container)
python3 "$ROOT/scripts/installation-info.py" /var/lib/voiceprobe/config.json --service "$service_state" "${info[@]}"
