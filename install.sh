#!/bin/sh
# HTTPS bootstrap. Generated with a pinned public signing key; never source.
bootstrap_strict=0
for bootstrap_arg in "$@"; do [ "$bootstrap_arg" != --strict ] || bootstrap_strict=1; done
bootstrap_main() {
sh -s -- "$@" <<'VOICEPROBE_WORKER'
set -eu
umask 077
[ "$(id -u)" -eq 0 ] || { printf 'Exécuter avec sudo ou le compte root autorisé.\n' >&2; exit 1; }
bootstrap_base=https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/beta
bootstrap_backend=native
bootstrap_root=/var/lib/voiceprobe-agent
if [ -f /etc.defaults/VERSION ]; then
 bootstrap_backend=docker
 bootstrap_root=''
 for bootstrap_volume in /volume[0-9]*; do
  if [ -d "$bootstrap_volume" ] && [ -w "$bootstrap_volume" ]; then bootstrap_root=$bootstrap_volume/docker/voiceprobe-agent; break; fi
 done
fi
bootstrap_previous=''
bootstrap_check=0
for bootstrap_arg in "$@"; do
 case "$bootstrap_previous" in --backend) bootstrap_backend=$bootstrap_arg;; --data-root) bootstrap_root=$bootstrap_arg;; esac
 bootstrap_previous=$bootstrap_arg
 [ "$bootstrap_arg" != --check ] || bootstrap_check=1
done
case "$bootstrap_backend" in native|docker) ;; *) printf 'Mode non reconnu.\n' >&2; exit 1;; esac
bootstrap_cpu=$(uname -m)
case "$bootstrap_cpu" in x86_64|amd64|aarch64|arm64) ;; *) printf 'Architecture CPU non qualifiée.\n' >&2; exit 1;; esac
if [ "$bootstrap_backend" = native ]; then
 [ -r /etc/os-release ] || exit 1
 . /etc/os-release
 bootstrap_userspace=$(dpkg --print-architecture)
 case "$bootstrap_cpu:$bootstrap_userspace:$ID:$VERSION_ID" in x86_64:amd64:ubuntu:24.04|amd64:amd64:ubuntu:24.04|x86_64:amd64:debian:12|amd64:amd64:debian:12|aarch64:arm64:debian:13|arm64:arm64:debian:13) ;; *) printf 'OS natif non qualifié ; aucun fallback par compilation.\n' >&2; exit 1;; esac
 [ -d /run/systemd/system ] || { printf 'systemd actif requis pour le mode natif.\n' >&2; exit 1; }
 if ! command -v python3 >/dev/null || ! command -v openssl >/dev/null || ! command -v curl >/dev/null; then
  [ "$bootstrap_check" -eq 0 ] || { printf 'Prérequis absents ; contrôle sans installation refusé.\n' >&2; exit 1; }
  apt-get update >/dev/null
  apt-get install -y --no-install-recommends python3 openssl ca-certificates curl >/dev/null
 fi
else
 case "$bootstrap_cpu" in x86_64|amd64) ;; *) printf 'Docker ARM64 non qualifié ; utiliser Debian13 ARM64 natif.\n' >&2; exit 1;; esac
 bootstrap_docker_cli=$(command -v docker || true)
 if [ -z "$bootstrap_docker_cli" ]; then
  for bootstrap_cli in /usr/local/bin/docker /var/packages/ContainerManager/target/usr/bin/docker /var/packages/Docker/target/usr/bin/docker; do
   if [ -x "$bootstrap_cli" ]; then bootstrap_docker_cli=$bootstrap_cli;break;fi
  done
 fi
 [ -n "$bootstrap_docker_cli" ] || { printf 'CLI Docker inaccessible dans PATH et les chemins DSM connus ; Container Manager/Docker requis.\n' >&2; exit 1; }
 [ -n "$bootstrap_root" ] || { printf 'Volume DSM persistant introuvable ; préciser --data-root sur un volume dédié.\n' >&2; exit 1; }
 command -v openssl >/dev/null || { printf 'OpenSSL requis pour vérifier la signature.\n' >&2; exit 1; }
 command -v curl >/dev/null || { printf 'curl avec TLS requis pour le téléchargement.\n' >&2; exit 1; }
fi
if [ "$bootstrap_backend" = docker ]; then
 case "$bootstrap_root" in /*voiceprobe*) ;; *) printf 'Répertoire dédié Voice Probe requis.\n' >&2; exit 1;; esac
 case "$bootstrap_root" in *[!A-Za-z0-9_./-]*|*/../*|*/..|*//*|/) printf 'Chemin persistant refusé.\n' >&2; exit 1;; esac
 [ ! -L "$bootstrap_root" ] || { printf 'Répertoire symbolique refusé.\n' >&2; exit 1; }
 mkdir -p "$bootstrap_root"
 bootstrap_temp=$(mktemp -d "$bootstrap_root/.bootstrap.XXXXXXXXXX")
else
 bootstrap_temp=$(mktemp -d /tmp/voiceprobe-agent-bootstrap.XXXXXXXXXX)
fi
trap 'rm -rf -- "$bootstrap_temp"' EXIT HUP INT TERM
cat > "$bootstrap_temp/signing.pem" <<'VOICEPROBE_PUBLIC_KEY'
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmmRAgw2+zh0rOo0x4GI8
O3J3v3L0iCBSQALYfI6goV/ViTif349VePMw1bOVFESgNSZ5mkr5dA5B5ljWvx8T
sIXlt35cV+LVbSrswynoa2CkoQWXGKSiPL1gNatqAJutxSH4H3JM2cZECf3B/zqv
K6hBHSJFOqip3cZ5c9r7yfdurxvQk4w6taYkMEFP44f1LEXf0qEXuuFKykUPVn8/
pdyr4Jx42HJuYFCrv1SgPNBmNH+9vY46lr03ZPEEo3cWpBPsUxHbLwLwRh3HT21U
kSEruaFk8n1so0NCZd3jJG3C5noEsXLkeUvbBDv25ZNUpuNMeaBFVOVOcVKo+PKD
o3TPfsfz58jjhEZJP6Xat8UbHn4rfMwFADxOaBhIJRaf5c95kPHI+d4fIvbjapB3
hVKAozc09Jn5Y8LaxHB9y2vhK0jNB5QSDdZRYj+KO4iCEltREy2z2q29RZURcH5U
tHU2nLcVfyFyj3e72k1P9Ie0TEub0/xp8C3vtA0eRBSSdOsoVx9g0e3IAXJCF0wG
odfsv16pwnwuo099JJusMlWJBQbHyXgkpe4c1Ic7U9j9ny/+uG4fjSEAGbeop53H
2gnlvCsuRDWlsWt/QwLhGpMipnSufOm16V6ZUTG9ex+3nCiYWBQ/ylwbFbB4SA3n
Ftfy4T+e/HQAD0lHxi8m3z8CAwEAAQ==
-----END PUBLIC KEY-----
VOICEPROBE_PUBLIC_KEY
bootstrap_artifact_base=''
bootstrap_fetch() {
 bootstrap_origin=$bootstrap_base
 case "$1" in bootstrap.manifest|bootstrap.sig|manager.manifest|manager.sig) ;; *) [ -z "$bootstrap_artifact_base" ] || bootstrap_origin=$bootstrap_artifact_base;; esac
 bootstrap_url=$bootstrap_origin/$1
 bootstrap_hops=0
 while :; do
  bootstrap_status=$(curl -q --proto '=https' --proto-redir '=https' --max-redirs 0 --fail --silent --show-error --connect-timeout 15 --max-time 600 --max-filesize "${3:-1073741824}" --dump-header "$bootstrap_temp/headers" --write-out '%{http_code}' "$bootstrap_url" -o "$2.part")
  if [ "$bootstrap_status" = 200 ]; then mv -- "$2.part" "$2"; return; fi
  case "$bootstrap_status" in 301|302|303|307|308) ;; *) printf 'Téléchargement HTTPS refusé.\n' >&2; exit 1;; esac
  [ -n "$bootstrap_artifact_base" ] && [ "$bootstrap_origin" = "$bootstrap_artifact_base" ] && [ "$bootstrap_hops" -lt 3 ] || { printf 'Redirection de distribution refusée.\n' >&2; exit 1; }
  bootstrap_next=$(awk 'tolower($1)=="location:" {$1="";sub(/^[[:space:]]+/,"");sub(/\r$/,"");value=$0} END {print value}' "$bootstrap_temp/headers")
  case "$bootstrap_next" in
   https://release-assets.githubusercontent.com/github-production-release-asset*|https://objects.githubusercontent.com/github-production-release-asset*) ;;
   *) printf 'Redirection GitHub hors périmètre refusée.\n' >&2; exit 1;;
  esac
  case "$bootstrap_next" in *' '*|*'\'*|*'#'*) printf 'URL CDN GitHub invalide.\n' >&2; exit 1;; esac
  bootstrap_url=$bootstrap_next;bootstrap_hops=$((bootstrap_hops+1))
 done
}
bootstrap_hash() {
 bootstrap_actual=$(openssl dgst -sha256 "$2")
 bootstrap_actual=${bootstrap_actual##* }
 [ "$bootstrap_actual" = "$1" ] || { printf 'SHA-256 incorrect ; aucun artefact exécuté.\n' >&2; exit 1; }
}
bootstrap_fetch bootstrap.manifest "$bootstrap_temp/bootstrap.manifest" 262144
bootstrap_fetch bootstrap.sig "$bootstrap_temp/bootstrap.sig" 4096
openssl dgst -sha256 -verify "$bootstrap_temp/signing.pem" -signature "$bootstrap_temp/bootstrap.sig" "$bootstrap_temp/bootstrap.manifest" >/dev/null
bootstrap_manager=''; bootstrap_manager_sha=''; bootstrap_image=''; bootstrap_image_sha=''; bootstrap_reference=''; bootstrap_schema=''; bootstrap_expires=''; bootstrap_id1=''; bootstrap_id2=''
bootstrap_seen=':'
while IFS='=' read -r bootstrap_key bootstrap_value; do
 case "$bootstrap_seen" in *":$bootstrap_key:"*) printf 'Clé de manifeste dupliquée.\n' >&2; exit 1;; esac
 bootstrap_seen="$bootstrap_seen$bootstrap_key:"
 case "$bootstrap_key" in
  schema) [ "$bootstrap_value" = 1 ] || exit 1; bootstrap_schema=1;;
  expires) bootstrap_expires=$bootstrap_value;;
  artifact_source)
   case "$bootstrap_base" in https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/beta|https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/stable) ;; *) printf 'Canal GitHub inconnu.\n' >&2; exit 1;; esac
   case "$bootstrap_value" in https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/agent-*) ;; *) printf 'Release GitHub inconnue.\n' >&2; exit 1;; esac
   bootstrap_tag=${bootstrap_value##*/}
   [ "$bootstrap_value" = "https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/$bootstrap_tag" ] || exit 1
   case "$bootstrap_tag" in agent-?*) ;; *) exit 1;; esac
   case "$bootstrap_tag" in *[!A-Za-z0-9_.-]*|agent-|'') exit 1;; esac
   [ "${#bootstrap_tag}" -le 106 ] || exit 1
   bootstrap_artifact_base=$bootstrap_value;;
  docker_id1) bootstrap_id1=$bootstrap_value;; docker_id2) bootstrap_id2=$bootstrap_value;;
  manager) bootstrap_manager=$bootstrap_value;; manager_sha256) bootstrap_manager_sha=$bootstrap_value;;
  docker) bootstrap_image=$bootstrap_value;; docker_sha256) bootstrap_image_sha=$bootstrap_value;;
  docker_reference) bootstrap_reference=$bootstrap_value;;
  *) printf 'Contrat bootstrap inconnu.\n' >&2; exit 1;;
 esac
done < "$bootstrap_temp/bootstrap.manifest"
[ "$bootstrap_schema" = 1 ] || { printf 'Schéma bootstrap absent.\n' >&2; exit 1; }
case "$bootstrap_expires" in ''|*[!0-9]*) exit 1;; esac
[ "${#bootstrap_expires}" -le 11 ] && [ "$bootstrap_expires" -gt "$(date +%s)" ] || { printf 'Manifeste bootstrap expiré.\n' >&2; exit 1; }
for bootstrap_id in "$bootstrap_id1" "$bootstrap_id2"; do
 case "$bootstrap_id" in sha256:*) bootstrap_hash=${bootstrap_id#sha256:};; *) exit 1;; esac
 [ "${#bootstrap_hash}" -eq 64 ] || exit 1
 case "$bootstrap_hash" in *[!0-9a-f]*) exit 1;; esac
done
for bootstrap_sha in "$bootstrap_manager_sha" "$bootstrap_image_sha"; do
 [ "${#bootstrap_sha}" -eq 64 ] || exit 1
 case "$bootstrap_sha" in *[!0-9a-f]*) exit 1;; esac
done
for bootstrap_file in "$bootstrap_manager" "$bootstrap_image"; do
 case "$bootstrap_file" in ''|*[!A-Za-z0-9_.-]*|.*) printf 'Nom de fichier refusé.\n' >&2; exit 1;; esac
done
# The application image remains unchanged when only its root manager is repaired.
bootstrap_fetch manager.manifest "$bootstrap_temp/manager.manifest" 16384
bootstrap_fetch manager.sig "$bootstrap_temp/manager.sig" 4096
openssl dgst -sha256 -verify "$bootstrap_temp/signing.pem" -signature "$bootstrap_temp/manager.sig" "$bootstrap_temp/manager.manifest" >/dev/null
bootstrap_seen=':'; bootstrap_manager_sequence=''; bootstrap_manager_revision=''; bootstrap_manager_bytes=''; bootstrap_manager_expires=''; bootstrap_manager_schema=''; bootstrap_manager_origin=''
while IFS='=' read -r bootstrap_key bootstrap_value; do
 case "$bootstrap_seen" in *":$bootstrap_key:"*) printf 'Clé de manifeste gestionnaire dupliquée.\n' >&2; exit 1;; esac
 bootstrap_seen="$bootstrap_seen$bootstrap_key:"
 case "$bootstrap_key" in
  schema) [ "$bootstrap_value" = 1 ] || exit 1; bootstrap_manager_schema=1;;
  sequence) bootstrap_manager_sequence=$bootstrap_value;; expires) bootstrap_manager_expires=$bootstrap_value;;
  source_revision) bootstrap_manager_revision=$bootstrap_value;; manager_bytes) bootstrap_manager_bytes=$bootstrap_value;;
  manager) bootstrap_manager=$bootstrap_value;; manager_sha256) bootstrap_manager_sha=$bootstrap_value;;
  artifact_source) bootstrap_manager_origin=$bootstrap_value;;
  *) printf 'Contrat gestionnaire inconnu.\n' >&2; exit 1;;
 esac
done < "$bootstrap_temp/manager.manifest"
[ "$bootstrap_manager_schema" = 1 ] || exit 1
for bootstrap_number in "$bootstrap_manager_sequence" "$bootstrap_manager_expires" "$bootstrap_manager_bytes"; do
 case "$bootstrap_number" in ''|*[!0-9]*) exit 1;; esac
 [ "${#bootstrap_number}" -le 12 ] || exit 1
done
[ "$bootstrap_manager_expires" -gt "$(date +%s)" ] && [ "$bootstrap_manager_bytes" -gt 0 ] && [ "$bootstrap_manager_bytes" -le 1048576 ] || exit 1
case "$bootstrap_manager_revision:$bootstrap_manager_sha" in *[!0-9a-f:]*) exit 1;; esac
[ "${#bootstrap_manager_revision}" -eq 40 ] && [ "${#bootstrap_manager_sha}" -eq 64 ] || exit 1
case "$bootstrap_manager" in agent-manager-????????????.py) ;; *) exit 1;; esac
case "$bootstrap_manager" in *[!a-z0-9.-]*) exit 1;; esac
bootstrap_application_origin=$bootstrap_artifact_base
if [ -n "$bootstrap_manager_origin" ]; then
 case "$bootstrap_base" in https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/beta|https://raw.githubusercontent.com/reptechwifx/wifx-voiceprobe-agent/main/channel/stable) ;; *) exit 1;; esac
 bootstrap_tag=${bootstrap_manager_origin##*/}
 [ "$bootstrap_manager_origin" = "https://github.com/reptechwifx/wifx-voiceprobe-agent/releases/download/$bootstrap_tag" ] || exit 1
 case "$bootstrap_tag" in agent-?*) ;; *) exit 1;; esac
 case "$bootstrap_tag" in *[!A-Za-z0-9_.-]*|'') exit 1;; esac
 [ "${#bootstrap_tag}" -le 106 ] || exit 1
fi
bootstrap_artifact_base=$bootstrap_manager_origin
bootstrap_fetch "$bootstrap_manager" "$bootstrap_temp/manage.py" "$bootstrap_manager_bytes"
bootstrap_hash "$bootstrap_manager_sha" "$bootstrap_temp/manage.py"
bootstrap_artifact_base=$bootstrap_application_origin
case "${1-}" in install|update|update-manager|status|diagnose|rollback|version|help) ;; *) set -- install "$@";; esac
if [ "$bootstrap_backend" = native ]; then
 python3 "$bootstrap_temp/manage.py" --strict --backend native --source "$bootstrap_base" --key "$bootstrap_temp/signing.pem" "$@"
else
 case "$bootstrap_root" in /*voiceprobe*) ;; *) printf 'Répertoire persistant dédié Voice Probe requis.\n' >&2; exit 1;; esac
 case "$bootstrap_root" in *[!A-Za-z0-9_./-]*|*/../*|*/..|*//*|/) printf 'Chemin persistant refusé.\n' >&2; exit 1;; esac
 case "$bootstrap_reference" in voiceprobe-agent-runtime:[A-Za-z0-9]*) ;; *) printf 'Image bootstrap inconnue.\n' >&2; exit 1;; esac
 case "$bootstrap_reference" in *[!A-Za-z0-9_.:-]*) exit 1;; esac
 bootstrap_fetch "$bootstrap_image" "$bootstrap_temp/image.tar.gz"
 bootstrap_hash "$bootstrap_image_sha" "$bootstrap_temp/image.tar.gz"
 if [ "$bootstrap_check" -eq 1 ]; then printf 'Contrôle bootstrap Docker terminé ; aucune image chargée ou instance modifiée.\n'; exit 0; fi
 mkdir -p "$bootstrap_root"
 bootstrap_existing=$("$bootstrap_docker_cli" --host unix:///var/run/docker.sock image inspect --format '{{.Id}}' "$bootstrap_reference" 2>/dev/null || true)
 if [ -n "$bootstrap_existing" ]; then
  [ "$bootstrap_existing" = "$bootstrap_id1" ] || [ "$bootstrap_existing" = "$bootstrap_id2" ] || { printf 'Tag local occupé par une image différente ; aucune substitution.\n' >&2; exit 1; }
 else
  "$bootstrap_docker_cli" --host unix:///var/run/docker.sock load --input "$bootstrap_temp/image.tar.gz" >/dev/null
 fi
 bootstrap_existing=$("$bootstrap_docker_cli" --host unix:///var/run/docker.sock image inspect --format '{{.Id}}' "$bootstrap_reference")
 [ "$bootstrap_existing" = "$bootstrap_id1" ] || [ "$bootstrap_existing" = "$bootstrap_id2" ] || { printf 'Identité image différente du manifeste signé.\n' >&2; exit 1; }
 bootstrap_docker_run() {
  bootstrap_tty=$1; shift
  "$bootstrap_docker_cli" --host unix:///var/run/docker.sock run --rm --pull=never $bootstrap_tty --network host --user 0:0 --entrypoint python3 --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock --mount "type=bind,src=$bootstrap_root,dst=$bootstrap_root" --mount "type=bind,src=$bootstrap_root,dst=/var/lib/voiceprobe" --mount "type=bind,src=$bootstrap_temp,dst=$bootstrap_temp,readonly" "$bootstrap_existing" "$bootstrap_temp/manage.py" --strict --backend docker --data-root "$bootstrap_root" --source "$bootstrap_base" --key "$bootstrap_temp/signing.pem" "$@"
 }
 mkdir -p /usr/local/bin
 if [ -L /usr/local/bin/voiceprobe-agent-docker ] || { [ -e /usr/local/bin/voiceprobe-agent-docker ] && ! grep -q '# WIFX voiceprobe Agent management' /usr/local/bin/voiceprobe-agent-docker; }; then printf 'Commande voiceprobe-agent-docker homonyme inconnue ; aucune substitution.\n' >&2; exit 1; fi
 cat > "$bootstrap_temp/voiceprobe-agent-docker" <<VOICEPROBE_DOCKER_COMMAND
#!/bin/sh
# WIFX voiceprobe Agent management; immutable cached image, no Registry credential.
voiceprobe_strict=0
for voiceprobe_arg in "\$@"; do [ "\$voiceprobe_arg" != --strict ] || voiceprobe_strict=1; done
voiceprobe_instance=default
voiceprobe_previous=
for voiceprobe_arg in "\$@"; do
 [ "\$voiceprobe_previous" != --instance ] || voiceprobe_instance=\$voiceprobe_arg
 case "\$voiceprobe_arg" in --instance=*) voiceprobe_instance=\${voiceprobe_arg#--instance=};; esac
 voiceprobe_previous=\$voiceprobe_arg
done
case "\$voiceprobe_instance" in ''|*[!a-z0-9-]*) printf 'Instance invalide ; session conservée.\\nVOICEPROBE_AGENT_RESULT=CONTROLLED_FAILURE\\n' >&2; exit \$voiceprobe_strict;; esac
voiceprobe_manager=$bootstrap_root/instances/\$voiceprobe_instance/management/admin/manage.py
[ -f "\$voiceprobe_manager" ] || voiceprobe_manager=/opt/voiceprobe/installer/manage.py
voiceprobe_docker_cli=\$(command -v docker || true)
if [ -z "\$voiceprobe_docker_cli" ]; then
 for voiceprobe_cli in /usr/local/bin/docker /var/packages/ContainerManager/target/usr/bin/docker /var/packages/Docker/target/usr/bin/docker; do
  if [ -x "\$voiceprobe_cli" ]; then voiceprobe_docker_cli=\$voiceprobe_cli;break;fi
 done
fi
if [ -z "\$voiceprobe_docker_cli" ]; then printf 'CLI Docker inaccessible.\\nVOICEPROBE_AGENT_RESULT=CONTROLLED_FAILURE\\n' >&2; exit \$voiceprobe_strict; fi
voiceprobe_tty=
if [ -t 0 ] && [ -t 1 ]; then voiceprobe_tty=-it; fi
if "\$voiceprobe_docker_cli" --host unix:///var/run/docker.sock run --rm --pull=never \$voiceprobe_tty --network host --user 0:0 --entrypoint python3 --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock --mount type=bind,src=$bootstrap_root,dst=$bootstrap_root --mount type=bind,src=$bootstrap_root,dst=/var/lib/voiceprobe $bootstrap_existing "\$voiceprobe_manager" --strict --backend docker --data-root $bootstrap_root "\$@"; then exit 0; else voiceprobe_code=\$?; fi
printf 'ÉCHEC CONTRÔLÉ : commande Agent non vérifiée ; session conservée.\\nVOICEPROBE_AGENT_RESULT=CONTROLLED_FAILURE\\n' >&2
[ "\$voiceprobe_strict" -eq 0 ] || exit "\$voiceprobe_code"
exit 0
VOICEPROBE_DOCKER_COMMAND
 chmod 0755 "$bootstrap_temp/voiceprobe-agent-docker"
 mv -- "$bootstrap_temp/voiceprobe-agent-docker" /usr/local/bin/voiceprobe-agent-docker
 if { [ ! -e /usr/local/bin/voiceprobe-agent ] && [ ! -L /usr/local/bin/voiceprobe-agent ]; } || { [ -f /usr/local/bin/voiceprobe-agent ] && [ ! -L /usr/local/bin/voiceprobe-agent ] && grep -q '# WIFX voiceprobe Agent management' /usr/local/bin/voiceprobe-agent; }; then
  cp /usr/local/bin/voiceprobe-agent-docker "$bootstrap_temp/voiceprobe-agent"
  chmod 0755 "$bootstrap_temp/voiceprobe-agent"
  mv -- "$bootstrap_temp/voiceprobe-agent" /usr/local/bin/voiceprobe-agent
 else
  printf 'Commande existante conservée ; gestion Docker : sudo voiceprobe-agent-docker.\n'
 fi
 if [ -t 2 ] && ( : </dev/tty ) 2>/dev/null; then bootstrap_docker_run -it "$@" </dev/tty; else bootstrap_docker_run '' "$@"; fi
fi
VOICEPROBE_WORKER
}
if bootstrap_main "$@"; then
 exit 0
else
 bootstrap_code=$?
 printf 'ÉCHEC CONTRÔLÉ : installation/mise à jour non vérifiée ; session conservée.\nVOICEPROBE_AGENT_RESULT=CONTROLLED_FAILURE\n' >&2
 if [ "$bootstrap_strict" -eq 1 ]; then exit "$bootstrap_code"; fi
 exit 0
fi
