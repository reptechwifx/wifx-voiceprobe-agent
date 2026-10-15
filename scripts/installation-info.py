#!/usr/bin/env python3
"""Print real addresses, never a guessed container host address or a password."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent/src'))
from telemetry import network_snapshot

p = argparse.ArgumentParser()
p.add_argument('configuration')
p.add_argument('--container', action='store_true')
p.add_argument('--service', default='Actif')
a = p.parse_args()
cfg = json.loads(Path(a.configuration).read_text())
version = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
print('\n=========================================\n WIFX Voice Probe\n Installation terminée\n=========================================')
print('Version       : Bêta ' + version)
print('Service       : ' + a.service)
print('Démarrage     : ' + ('Manuel dans le conteneur de qualification' if a.container else 'Automatique (systemd)'))
if a.container or Path('/.dockerenv').exists() or Path('/run/.containerenv').exists():
    print('Adresse IP    : Hôte non détectable depuis ce conteneur')
    print('Interface     : Utiliser le mapping hôte explicitement choisi ; aucune IP de conteneur annoncée comme accès technicien.')
else:
    addresses = []
    for interface in network_snapshot(cfg)['interfaces']:
        if not interface['up'] or interface['name'].startswith(('docker', 'br-', 'veth', 'lo')):
            continue
        for address in interface['addresses']:
            ip = ipaddress.ip_address(address['address'])
            if ip.version != 4 or ip.is_loopback or ip.is_link_local or not ip.is_private:
                continue
            addresses.append((interface['name'], str(ip)))
    scheme = 'https' if cfg.get('tls_cert') else 'http'
    for interface, address in addresses:
        print('Adresse IP    : ' + address + ' (' + interface + ')')
        print('Interface     : ' + scheme + '://' + ('[' + address + ']' if ':' in address else address) + ':' + str(cfg.get('port', 18441)))
    if not addresses:
        print('Adresse IP    : Aucune adresse de gestion privée détectée ; vérifier DHCP et le réseau de gestion.')
print('\nUtilisateur   : admin')
print('Mot de passe  : sudo cat /var/lib/voiceprobe/install-credentials.json (informations privées initiales)')
print('Personnalisation / réinitialisation : sudo python3 /opt/voiceprobe/admin/reset-agent-password.py')
print('\nLa sonde est prête à être configurée.\nOuvrez l’interface dans votre navigateur.\nHTTP local nécessite un LAN de confiance ; filtrer 18441/TCP, ne jamais publier sur Internet.\n=========================================')
