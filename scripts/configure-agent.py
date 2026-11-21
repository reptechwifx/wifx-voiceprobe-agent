#!/usr/bin/env python3
"""Prepare an offline agent; Controller/client configuration happens in the browser."""
import argparse
import getpass
import json
import os
from pathlib import Path
import socket
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent/src'))
from credentials import generate_password, hash_password
from identity import atomic_json, create_identity


def prepare(path, password=None, retain_credentials=True):
    path = Path(path)
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    password = password or generate_password()
    password_hash = hash_password(password)
    cfg = {'id': str(uuid.uuid4()), 'name': socket.gethostname()[:100], 'controller_url': '', 'wss_url': '', 'token': '', 'ca_file': '/etc/ssl/certs/ca-certificates.crt', 'local_password_hash': password_hash, 'max_calls': 4, 'bind': 'auto', 'port': 18441, 'allow_http': True, 'administrative': {}, 'adoption_state': 'unconfigured', 'installation_type': 'native'}
    cfg.update(create_identity(path.parent))
    atomic_json(path, cfg)
    if retain_credentials:
        atomic_json(path.parent / 'install-credentials.json', {'username': 'admin', 'password': password, 'note': 'Informations privées de préparation ; le processus Agent utilise uniquement le hash.'})
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('configuration')
    passwords = parser.add_mutually_exclusive_group()
    passwords.add_argument('--ask-password', action='store_true')
    passwords.add_argument('--password-file')
    args = parser.parse_args()
    if Path(args.configuration).exists():
        print('Configuration existante conservée ; aucune identité ou mot de passe régénéré.')
        raise SystemExit(0)
    value = None
    if args.ask_password:
        value = getpass.getpass('Mot de passe admin personnalisé (16 à 200 caractères) : ')
        if value != getpass.getpass('Confirmer : '):
            raise SystemExit('Confirmation différente.')
        hash_password(value)
    elif args.password_file:
        p = Path(args.password_file)
        if p.is_symlink() or p.stat().st_mode & 0o077:
            raise SystemExit('Le fichier de mot de passe doit être privé (0600 ou 0400).')
        value = p.read_text().rstrip('\r\n')
        hash_password(value)
    prepare(args.configuration, value)
    print('Agent préparé sans Controller. Identité persistante et mot de passe individuel générés ; valeurs omises.')
