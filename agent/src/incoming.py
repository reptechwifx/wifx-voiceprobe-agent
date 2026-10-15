"""Optional correlation and shared SIP account policy, independent of call admission."""
import re
import time

def correlate(prepared, account_id, message, source, trusted_sources, now=None):
    """A matching optional header identifies a run; timing/caller alone never does."""
    now = time.monotonic() if now is None else now
    header = re.search(r'^X-VoiceProbe-Test:\s*([a-f0-9-]{36})\s*$', message, re.I | re.M)
    if not header:
        return None
    run_id = header.group(1)
    preparation = prepared.get(run_id)
    return run_id if preparation and preparation['account_id'] == account_id and preparation['expires'] > now else None


def trusted_pbx_addresses(server):
    """Resolve the configured registrar/proxy; no operator-managed address list."""
    import socket
    from urllib.parse import urlsplit
    server = server.removeprefix('sips:').removeprefix('sip:').split(';', 1)[0]
    try:
        host = urlsplit('//' + server).hostname
        return {a[4][0] for a in socket.getaddrinfo(host, 5060, type=socket.SOCK_DGRAM)} if host else set()
    except (OSError, ValueError):
        return set()


def reception_status(config, mode, source, trusted_sources, capacity):
    """SIP admission never depends on From, Call-ID, or a prepared scenario."""
    if config.get('call_mode', 'bidirectional') == 'caller' or mode not in ('receiver', 'bidirectional'):
        return 405
    if source not in trusted_sources:
        return 403
    return 180 if capacity else 486


def outgoing_allowed(config, payload):
    if config.get('call_mode', 'bidirectional') == 'receiver':
        return False
    if payload.get('server') != config['server']:
        return False
    address = payload.get('destination', '')
    if config.get('destination_policy') != 'account-public-v1':
        return address in config.get('allowed_destinations', [])
    number = address
    external = False
    if address.startswith('sip:'):
        number, _, host = address[4:].partition('@')
        external = host.lower() != config['server'].lower()
    from urllib.parse import unquote
    number = unquote(number)
    public = payload.get('destination_public')
    if type(public) is not bool:
        public = external or number.startswith(('+', '00')) or (number.isdecimal() and len(number) >= 9)
    return not public or bool(config.get('public_calls_enabled', False))
