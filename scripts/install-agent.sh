#!/bin/sh
# Current entry point: signed binary delivery; never source this program.
agent_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 0
if [ "${1-}" = --from-source ]; then
    shift
    if bash "$agent_root/scripts/install-agent-from-source.sh" "$@"; then agent_status=0; else agent_status=$?; fi
else
    if python3 "$agent_root/agent/installer/manage.py" install "$@"; then agent_status=0; else agent_status=$?; fi
fi
# Normal management already preserves PuTTY; strict callers opt in explicitly.
for agent_arg in "$@"; do
    if [ "$agent_arg" = --strict ]; then exit "$agent_status"; fi
done
exit 0
