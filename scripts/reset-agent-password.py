#!/usr/bin/env python3
"""Compatibility entrypoint; password reset uses the qualified transactional manager."""
import os
from pathlib import Path
import subprocess
import sys

if __name__=='__main__':
    command=Path('/usr/local/bin/voiceprobe-agent')
    if not command.is_file():
        print('ÉCHEC CONTRÔLÉ : installer l’outil de gestion qualifié avant la réinitialisation. Identité et credentials conservés.',file=sys.stderr)
        raise SystemExit(1 if '--strict' in sys.argv else 0)
    args=[a for a in sys.argv[1:] if a!='--generate']
    raise SystemExit(subprocess.call([str(command),'reset-password',*args]))
