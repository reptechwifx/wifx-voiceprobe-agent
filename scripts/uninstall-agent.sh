#!/usr/bin/env bash
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run as root' >&2;exit 1; }
if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]];then
 systemctl disable --now voiceprobe-agent.service
fi
if [[ -f /etc/systemd/system/voiceprobe-agent.service ]];then rm /etc/systemd/system/voiceprobe-agent.service;fi
if [[ -L /opt/voiceprobe/current ]];then rm /opt/voiceprobe/current;fi
if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]];then systemctl daemon-reload;fi
echo 'Service uninstalled. Configuration, results, local password, releases and user preserved for recovery.'
