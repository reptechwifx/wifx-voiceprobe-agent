#!/bin/sh
# One update operation; existing identity/configuration never reinstalled.
agent_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 0
if python3 "$agent_root/agent/installer/manage.py" update "$@"; then agent_status=0; else agent_status=$?; fi
for agent_arg in "$@"; do
    if [ "$agent_arg" = --strict ]; then exit "$agent_status"; fi
done
exit 0
