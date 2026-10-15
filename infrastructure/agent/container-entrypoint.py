"""Idempotent private-volume bootstrap; Controller is configured in the web UI."""
import json, os, pathlib, sys
sys.path.insert(0, '/opt/voiceprobe/scripts')
import importlib.util
spec = importlib.util.spec_from_file_location('prepare_agent', '/opt/voiceprobe/scripts/configure-agent.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
path = pathlib.Path(os.environ.get('CONFIG_FILE', '/var/lib/voiceprobe/config.json'))
os.umask(0o077)
try:
    import ipaddress
    bind = os.environ.get('VOICEPROBE_LOCAL_BIND')
    if bind and ipaddress.ip_address(bind).version != 4:
        raise ValueError('IPv4 management bind required')
    ports = {}
    for variable, field, maximum in [('VOICEPROBE_SIP_PORT', 'sip_port', 65535), ('VOICEPROBE_RTP_BASE_PORT', 'rtp_base_port', 62355)]:
        value = os.environ.get(variable)
        if value:
            number = int(value)
            if not 1024 <= number <= maximum: raise ValueError('Invalid transport port')
            ports[field] = number
    created = module.prepare(path)
    if created or bind or ports:
        config = json.loads(path.read_text())
        config['installation_type'] = 'container'
        if bind: config['bind'] = bind
        config.update(ports)
        module.atomic_json(path, config)
        print('Agent configuré : admin, mot de passe individuel dans '+str(path.parent/'install-credentials.json')+'. Interface HTTP 18441. Valeurs privées omises.', flush=True)
except (OSError, ValueError) as error:
    raise SystemExit('Préparation Agent refusée : vérifier le volume privé et ses permissions.') from error
os.execvp(sys.argv[1], sys.argv[1:])
